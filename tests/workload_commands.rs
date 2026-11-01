use anyhow::Result;
use komizo::{
    host::workload::{
        activation::Host,
        commands::Commands,
        effects::{ArchiveConsumer, Effects},
        files,
    },
    input::Input,
    wire::Bytes,
    workload::{activation::Context, policy::Policy},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Seek, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, PermissionsExt, symlink},
    },
    path::Path,
    time::{Duration, Instant},
};
struct NoEffects;
impl Effects for NoEffects {
    fn docker(&mut self, _: &Context, _: &[&str]) -> Result<String> {
        panic!("metadata command ran Docker")
    }
    fn archive(
        &mut self,
        _: &Context,
        _: &[&str],
        _: u64,
        _: &mut ArchiveConsumer<'_>,
    ) -> Result<()> {
        panic!("metadata command opened archive")
    }
    fn release_key(&mut self, _: &Context, _: &str) -> Result<komizo::workload::release::RsaKey> {
        panic!("metadata command requested a signing key")
    }
    fn program(
        &mut self,
        _: &Context,
        _: &Path,
        _: &Path,
        _: &[String],
        _: std::process::Stdio,
    ) -> Result<()> {
        panic!("metadata command ran a program")
    }
}
fn replace(body: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut output = vec![];
    let mut rest = body;
    while let Some(at) = rest.windows(from.len()).position(|part| part == from) {
        output.extend_from_slice(&rest[..at]);
        output.extend_from_slice(to);
        rest = &rest[at + from.len()..]
    }
    output.extend_from_slice(rest);
    output
}
fn input(body: &[u8]) -> Input {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(body).unwrap();
    file.rewind().unwrap();
    Input::new(file)
}
fn content(body: &[u8], operation: bool) -> Value {
    let mut value = serde_json::from_slice(body)
        .unwrap_or_else(|_| serde_json::to_value(Bytes::from(body.to_vec())).unwrap());
    if operation {
        let fields = value.as_object_mut().unwrap();
        for field in ["operation_id", "started_at", "deadline", "at"] {
            fields.remove(field);
        }
    }
    value
}
fn normalized_rows(rows: &[Value]) -> Value {
    let mut output = rows.to_vec();
    for row in &mut output {
        if !row["body"].is_null() {
            let body: Bytes = serde_json::from_value(row["body"].clone()).unwrap();
            row["body"] = content(
                &body,
                row["path"].as_str().unwrap().ends_with("operation.json"),
            )
        }
    }
    json!(output)
}
fn tree(root: &Path) -> Value {
    fn walk(root: &Path, path: &Path, rows: &mut Vec<Value>) {
        let mut paths = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let info = fs::symlink_metadata(&path).unwrap();
            let mut row = json!({"path":path.strip_prefix(root).unwrap(),"mode":info.permissions().mode()&0o777});
            if info.is_dir() {
                row["directory"] = json!(true)
            } else if info.file_type().is_symlink() {
                row["link"] = json!(
                    fs::read_link(&path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace(root.to_str().unwrap(), "$ROOT")
                )
            } else {
                let bytes = replace(
                    &fs::read(&path).unwrap(),
                    root.as_os_str().as_bytes(),
                    b"$ROOT",
                );
                row["body"] = content(&bytes, path.file_name().unwrap() == "operation.json")
            };
            rows.push(row);
            if info.is_dir() {
                walk(root, &path, rows)
            }
        }
    }
    let mut rows = vec![];
    walk(root, root, &mut rows);
    json!(rows)
}
#[test]
fn go_command_transport_preserves_policy_authority_validation_and_outputs() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-workload-commands.json")).unwrap();
    assert_eq!(cases.len(), 28);
    for case in &cases {
        if case["root"] == true && unsafe { libc::geteuid() } != 0 {
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let expand = |text: &str| text.replace("$ROOT", root.to_str().unwrap());
        for file in case["input"].as_array().unwrap() {
            let path = root.join(file["path"].as_str().unwrap());
            let mode = file["mode"].as_u64().unwrap() as u32;
            if file["directory"] == true {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(mode)
                    .create(&path)
                    .unwrap()
            } else if let Some(target) = file["link"].as_str() {
                symlink(expand(target), &path).unwrap()
            } else {
                let body: Bytes = serde_json::from_value(file["body"].clone()).unwrap();
                fs::write(&path, replace(&body, b"$ROOT", root.as_os_str().as_bytes())).unwrap()
            }
            if file["link"].is_null() {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap()
            }
        }
        let args: Vec<String> = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|arg| expand(arg.as_str().unwrap()))
            .collect();
        let body: Bytes = serde_json::from_value(case["stdin"].clone()).unwrap();
        let mut output = vec![];
        let result = Commands {
            host: Host::new(root.into(), NoEffects).unwrap(),
            input: Some(input(&body)),
            output: &mut output,
        }
        .run(
            &args,
            &Context::new(Instant::now() + Duration::from_secs(3)),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {result:?}",
            case["scenario"]
        );
        let expected: Bytes = serde_json::from_value(case["stdout"].clone()).unwrap();
        assert_eq!(
            content(
                &replace(&output, root.as_os_str().as_bytes(), b"$ROOT"),
                false
            ),
            content(&expected, false),
            "{} stdout",
            case["scenario"]
        );
        assert_eq!(
            tree(root),
            normalized_rows(case["output"].as_array().unwrap()),
            "{} files",
            case["scenario"]
        );
    }
}
#[test]
fn root_owner_secret_command_preserves_opaque_bytes_spaces_and_whole_batches() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let app = root.join("srv/example");
    fs::create_dir_all(&app).unwrap();
    let policy = root.join("policy.json");
    files::write_json(
        &policy,
        &Policy::new(
            "example",
            app.to_str().unwrap(),
            "ghcr.io/owner/example-config",
            "edge",
        )
        .unwrap(),
    )
    .unwrap();
    let env = app.join("secrets.env");
    fs::write(&env, b"KEEP=synthetic\n").unwrap();
    fs::set_permissions(&env, fs::Permissions::from_mode(0o600)).unwrap();
    for (name, value, accepted) in [
        ("PADDED", b"  synthetic value  \n\n".as_slice(), true),
        ("BINARY", b"raw\xffvalue\n", true),
        ("BAD", b"CRLF\r\n", false),
        ("GITHUB_TOKEN", b"synthetic", false),
    ] {
        let before = fs::read(&env).unwrap();
        let args = vec![
            "owner-secret".into(),
            "--policy".into(),
            policy.to_str().unwrap().into(),
            "--name".into(),
            name.into(),
        ];
        let mut output = vec![];
        let result = Commands {
            host: Host::new(root.into(), NoEffects).unwrap(),
            input: Some(input(value)),
            output: &mut output,
        }
        .run(
            &args,
            &Context::new(Instant::now() + Duration::from_secs(3)),
        );
        assert_eq!(result.is_ok(), accepted, "{name}: {result:?}");
        assert!(output.is_empty());
        let body = fs::read(&env).unwrap();
        if accepted {
            let mut expected = before;
            expected.extend_from_slice(name.as_bytes());
            expected.push(b'=');
            let mut value = value.to_vec();
            while value.last() == Some(&b'\n') {
                value.pop();
            }
            expected.extend_from_slice(&value);
            expected.push(b'\n');
            assert_eq!(body, expected)
        } else {
            assert_eq!(body, before)
        }
    }
    let args = vec![
        "owner-secret".into(),
        "--policy".into(),
        policy.to_str().unwrap().into(),
        "--name".into(),
        "opaque.bin".into(),
        "--file".into(),
    ];
    let mut output = vec![];
    let body = b"\0\xff\x01binary\n";
    Commands {
        host: Host::new(root.into(), NoEffects).unwrap(),
        input: Some(input(body)),
        output: &mut output,
    }
    .run(
        &args,
        &Context::new(Instant::now() + Duration::from_secs(3)),
    )
    .unwrap();
    assert_eq!(fs::read(app.join("secrets/opaque.bin")).unwrap(), body);
}
#[test]
fn relative_output_child() {
    let Ok(root) = std::env::var("KOMIZO_RELATIVE_OUTPUT_ROOT") else {
        return;
    };
    std::env::set_current_dir(&root).unwrap();
    files::write_json(Path::new("metadata.json"), &json!({"version":1})).unwrap();
    let root = Path::new(&root);
    let app = root.join("app");
    fs::create_dir(&app).unwrap();
    let args = vec![
        "init".into(),
        "--policy".into(),
        "policy.json".into(),
        "--app".into(),
        "example".into(),
        "--app-dir".into(),
        app.to_str().unwrap().into(),
        "--config-image".into(),
        "ghcr.io/owner/example-config".into(),
    ];
    let mut out = vec![];
    Commands {
        host: Host::new(root.into(), NoEffects).unwrap(),
        input: None,
        output: &mut out,
    }
    .run(
        &args,
        &Context::new(Instant::now() + Duration::from_secs(2)),
    )
    .unwrap();
}
#[test]
fn relative_policy_and_atomic_output_paths_use_the_command_working_directory() {
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "relative_output_child"])
        .env("KOMIZO_RELATIVE_OUTPUT_ROOT", root.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(root.path().join("policy.json").is_file());
    assert!(root.path().join("metadata.json").is_file());
}
