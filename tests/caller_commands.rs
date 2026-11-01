use komizo::{
    caller::{deployment, provision, reach, reconcile, secrets},
    host::App,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
#[test]
fn frozen_go_caller_decisions_and_command_help() {
    let data: Value = serde_json::from_str(include_str!("data/go-caller-commands.json")).unwrap();
    assert_eq!(data["secrets"].as_array().unwrap().len(), 336);
    let mut accepted = 0;
    for c in data["secrets"].as_array().unwrap() {
        let r = secrets::set_command(
            c["app"].as_str().unwrap(),
            c["name"].as_str().unwrap(),
            c["uid"].as_str().unwrap(),
            c["file"].as_bool().unwrap(),
        );
        assert_eq!(r.is_ok(), c["ok"], "{c}");
        if let Ok(command) = r {
            accepted += 1;
            assert_eq!(command, c["command"]);
        }
    }
    assert!(accepted > 20);
    for c in data["records"].as_array().unwrap() {
        let records = provision::records(c["body"].as_str().unwrap());
        let expected = c["expected"].as_array().unwrap();
        assert_eq!(records.len(), expected.len());
        for (r, e) in records.iter().zip(expected) {
            assert_eq!(
                json!(r),
                json!({"name":e["name"],"user":e["user"],"config":e["config"],"dir":e["dir"]})
            );
            assert_eq!(r.check().is_ok(), e["ok"]);
            assert_eq!(json!(r.environment()), e["env"]);
        }
    }
    let registered: Vec<App> = serde_json::from_value(data["registered"].clone()).unwrap();
    let mut accepted = 0;
    for c in data["inventories"].as_array().unwrap() {
        let r = reconcile::decode(c["body"].as_str().unwrap().as_bytes());
        assert_eq!(r.is_ok(), c["ok"], "{c}");
        if let Ok(inv) = r {
            accepted += 1;
            assert_eq!(json!(inv), c["expected"]);
            assert_eq!(json!(reconcile::compare(&inv, &registered)), c["findings"]);
        }
    }
    assert_eq!(accepted, 5);
    for c in data["acks"].as_array().unwrap() {
        let r = deployment::acknowledgement(c["body"].as_str().unwrap().as_bytes());
        assert_eq!(r.is_ok(), c["ok"]);
        if let Ok((id, previous)) = r {
            assert_eq!(id, c["id"]);
            assert_eq!(previous, c["previous"]);
        }
    }
    for c in data["reaches"].as_array().unwrap() {
        assert_eq!(
            reach::classify(c["body"].as_str().unwrap()) as i32,
            c["kind"].as_i64().unwrap() as i32
        );
    }
    for (command, help) in data["help"].as_object().unwrap() {
        let out = Command::new(env!("CARGO_BIN_EXE_komizo"))
            .arg("--json")
            .args(command.split(' '))
            .arg("--help")
            .output()
            .unwrap();
        let value: Value =
            serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{command}: {:?}", out));
        assert!(out.status.success(), "{command}: {value}");
        assert_eq!(value["data"]["text"], *help, "{command}");
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    home: PathBuf,
    trace: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        let home = dir.path().join("home");
        fs::create_dir(&path).unwrap();
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let trace = dir.path().join("trace");
        let script = path.join("ssh");
        fs::write(&script, include_str!("fixtures/caller-ssh.py")).unwrap();
        fs::set_permissions(script, fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            _dir: dir,
            path,
            home,
            trace,
        }
    }
    fn run(&self, args: &[&str], body: &[u8], extras: &[(&str, &str)]) -> (Output, Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_komizo"));
        command
            .arg("--json")
            .args(args)
            .env("PATH", format!("{}:/usr/bin:/bin", self.path.display()))
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("FIXTURE_TRACE", &self.trace)
            .env("FIXTURE_MODE", "normal");
        for (k, v) in extras {
            command.env(k, v);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(body).unwrap();
        let out = child.wait_with_output().unwrap();
        let value: Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: {e}: {out:?}"));
        (out, value)
    }
    fn trace(&self) -> Vec<Value> {
        fs::read_to_string(&self.trace)
            .unwrap_or_default()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
}
#[test]
fn native_commands_keep_keys_and_send_opaque_secrets_only_over_stdin() {
    let f = Fixture::new();
    let (out, v) = f.run(
        &[
            "add",
            "--host",
            "box.example",
            "--app",
            "demo",
            "--config",
            "ghcr.io/o/config",
            "--keep-key",
            "--known-as=",
            "--preview=false",
            "--task-script=",
            "--scoped-env=",
        ],
        &[],
        &[],
    );
    assert!(out.status.success(), "{v} {:?}", out);
    assert_eq!(v["data"]["key_unchanged"], true);
    let trace = f.trace();
    let add = trace
        .iter()
        .find(|r| r["env"]["APP_NAME"] == "demo")
        .unwrap();
    assert_eq!(add["env"]["CI_PUBKEY"], "");
    for name in [
        "CLEAR_KNOWN_AS",
        "PREVIEW_SET",
        "TASKS_SET",
        "SCOPED_ENV_SET",
    ] {
        assert_eq!(add["env"][name], "1");
    }
    assert_eq!(add["env"]["PREVIEW"], "0");
    let secret = f.home.join("secret");
    let bytes = b"opaque\0\xffsecret\n\n";
    fs::write(&secret, bytes).unwrap();
    let (out, v) = f.run(
        &[
            "set-secret",
            "--host",
            "box.example",
            "--app",
            "demo",
            "--file",
            "--name",
            "key.bin",
            "--from",
            secret.to_str().unwrap(),
        ],
        &[],
        &[],
    );
    assert!(out.status.success(), "{v}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("opaque"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("opaque"));
    let trace = f.trace();
    let sent = trace
        .iter()
        .find(|r| r["command"].as_str().unwrap().contains("owner-secret"))
        .unwrap();
    assert_eq!(
        sent["stdin_hex"],
        bytes.iter().map(|v| format!("{v:02x}")).collect::<String>()
    );
    assert!(!sent["command"].as_str().unwrap().contains("opaque"));
    let (out, v) = f.run(
        &[
            "add",
            "--host",
            "box.example",
            "--app",
            "demo",
            "--config",
            "ghcr.io/o/config",
        ],
        &[],
        &[],
    );
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(v["error"]["reconciliation_required"], false);
}
#[test]
fn deploy_acknowledgements_and_durable_identity_keep_uncertainty_visible() {
    let f = Fixture::new();
    let rev = "a".repeat(40);
    let args = [
        "deploy",
        "--host",
        "box.example",
        "--app",
        "demo",
        "--version",
        &rev,
        "--wait=false",
    ];
    let (out, v) = f.run(&args, &[], &[]);
    assert!(out.status.success(), "{v}");
    assert_eq!(v["data"]["submitted"], true);
    assert_eq!(v["data"]["completed"], false);
    let (out, v) = f.run(&args, &[], &[("FIXTURE_MODE", "bad-ack")]);
    assert!(!out.status.success());
    assert_eq!(v["error"]["reconciliation_required"], true);
    assert_eq!(v["next_action"][3], "inspect");
    let (out, v) = f.run(
        &[
            "deploy",
            "--host",
            "box.example",
            "--app",
            "demo",
            "--version",
            "bad",
        ],
        &[],
        &[],
    );
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(v["error"]["reconciliation_required"], false);
}
#[test]
fn setup_existing_app_never_regenerates_a_key_or_refreshes_host_programs() {
    let f = Fixture::new();
    let definition =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/go-caller-state-protocol.json");
    let data: Value = serde_json::from_slice(&fs::read(definition).unwrap()).unwrap();
    let defs = data["definitions"].as_array().unwrap();
    let case = defs.iter().find(|c| c["ok"] == true).unwrap();
    let file = f.home.join("definition.json");
    fs::write(&file, case["body"].as_str().unwrap()).unwrap();
    let (out, v) = f.run(
        &[
            "setup",
            "--host",
            "box.example",
            "--definition",
            file.to_str().unwrap(),
        ],
        &[],
        &[],
    );
    assert!(out.status.success(), "{v} {:?}", out);
    assert_eq!(v["data"]["key_unchanged"], true);
    assert_eq!(v["data"]["app_registered"], true);
    assert!(
        !f.trace()
            .iter()
            .any(|r| r["command"].as_str().unwrap().contains("sh -s")
                || r["command"].as_str().unwrap().eq("uname -m"))
    );
    assert!(!f.home.join(".config/komizo/keys").exists());
    let key = f.home.join("key");
    let (out, v) = f.run(
        &[
            "add",
            "--host",
            "box.example",
            "--app",
            "demo",
            "--config",
            "ghcr.io/o/config",
            "--key",
            key.to_str().unwrap(),
            "--no-instructions",
        ],
        &[],
        &[],
    );
    assert!(out.status.success(), "{v}");
    assert_eq!(fs::metadata(&key).unwrap().mode() & 0o777, 0o600);
    let before = fs::read(&key).unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("BEGIN OPENSSH"));
    let (out, _) = f.run(
        &[
            "add",
            "--host",
            "box.example",
            "--app",
            "demo",
            "--config",
            "ghcr.io/o/config",
            "--key",
            key.to_str().unwrap(),
            "--no-instructions",
        ],
        &[],
        &[],
    );
    assert!(!out.status.success());
    assert_eq!(fs::read(key).unwrap(), before);
}
