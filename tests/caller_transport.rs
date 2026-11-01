use komizo::{
    caller::{transport::*, validate},
    wire::Bytes,
    workload::activation::Context,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
#[test]
fn frozen_go_target_validation_ssh_arguments_quoting_and_terminal_output() {
    let data: Value = serde_json::from_str(include_str!("data/go-caller-transport.json")).unwrap();
    for case in data["targets"].as_array().unwrap() {
        let target = Target::parse(case["raw"].as_str().unwrap());
        assert_eq!(target.is_ok(), case["ok"].as_bool().unwrap());
        let mut target = match target {
            Ok(t) => t,
            Err(e) => {
                assert_eq!(e.to_string(), case["error"].as_str().unwrap());
                continue;
            }
        };
        target.port = case["port"].as_i64().unwrap();
        target.port_explicit = case["explicit"].as_bool().unwrap();
        target.aliases = vec![
            "alias.example.com".into(),
            target.host.clone(),
            "".into(),
            "alias.example.com".into(),
        ];
        assert_eq!(target.user, case["user"].as_str().unwrap());
        assert_eq!(target.host, case["host"].as_str().unwrap());
        assert_eq!(
            validate::host(&target.host).is_ok(),
            case["host_ok"].as_bool().unwrap()
        );
        assert_eq!(target.addr(), case["addr"].as_str().unwrap());
        assert_eq!(target.display(), case["display"].as_str().unwrap());
        assert_eq!(
            target.host_display(),
            case["host_display"].as_str().unwrap()
        );
        assert_eq!(json!(target.known_hosts_names()), case["known_hosts_names"]);
        assert_eq!(
            target.known_hosts(&[
                ("ssh-ed25519".into(), "AAAfixture".into()),
                ("ecdsa-sha2-nistp256".into(), "BBBfixture".into())
            ]),
            case["known_hosts"].as_str().unwrap()
        );
        assert_eq!(
            json!(target.ssh_args(Some("<CONTROL>"), &["printf 'fixture'".into()])),
            case["args"]
        );
    }
    for case in data["validations"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        let result = match case["kind"].as_str().unwrap() {
            "app" => validate::app(value),
            "user" => validate::user(value),
            "login" => validate::login_user(value),
            "host" => validate::host(value),
            "dir" => validate::app_dir(value),
            "network" => validate::network(value),
            "image" => validate::config_image(value),
            _ => unreachable!(),
        };
        assert_eq!(result.is_ok(), case["ok"].as_bool().unwrap(), "{case}");
        if let Err(e) = result {
            assert_eq!(e.to_string(), case["error"].as_str().unwrap(), "{case}");
        }
    }
    for case in data["scrubs"].as_array().unwrap() {
        let input: Bytes = serde_json::from_value(case["input"].clone()).unwrap();
        let mut output = vec![];
        let mut writer = ScrubWriter::new(&mut output);
        for part in input.chunks(case["chunk"].as_u64().unwrap() as usize) {
            writer.write_all(part).unwrap();
        }
        writer.finish().unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            case["expected"].as_str().unwrap(),
            "{case}"
        );
    }
    for case in data["prefixes"].as_array().unwrap() {
        let env: BTreeMap<String, String> =
            serde_json::from_value(case["environment"].clone()).unwrap();
        assert_eq!(
            env_prefix(&env).unwrap(),
            case["expected"].as_str().unwrap()
        );
    }
    for case in data["sockets"].as_array().unwrap() {
        assert_eq!(
            multiplex_socket_path(Path::new(case["directory"].as_str().unwrap()))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            case["expected"].as_str().unwrap()
        );
    }
}
#[test]
fn bounded_fake_ssh_preserves_arguments_stdin_streams_and_failure_hearing() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let program = temp.path().join("ssh");
    let args = temp.path().join("args");
    let input = temp.path().join("input");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\ncat > {}\nprintf 'fixture stdout'\nprintf 'fixture stderr' >&2\nexit 7\n",
        komizo::scripts::sh_quote(&args.to_string_lossy()),
        komizo::scripts::sh_quote(&input.to_string_lossy())
    );
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let remote = Remote {
        target: Target::parse("root@box.example.com").unwrap(),
        program,
        control: None,
    };
    let ctx = Context::new(Instant::now() + Duration::from_secs(3));
    let mut output = vec![];
    let mut progress = vec![];
    let body = "printf 'reviewed fixture'\n";
    let heard = remote.script(
        &ctx,
        body,
        &BTreeMap::from([("APP".into(), "fixture ' quote".into())]),
        &mut output,
        &mut progress,
    );
    assert!(heard.stdout && heard.stderr);
    assert!(heard.result.is_err());
    assert_eq!(output, b"fixture stdout");
    assert_eq!(progress, b"fixture stderr");
    assert_eq!(std::fs::read(input).unwrap(), body.as_bytes());
    let arguments = std::fs::read_to_string(args).unwrap();
    assert!(arguments.contains("ForwardAgent=no\n"));
    assert!(arguments.contains("StrictHostKeyChecking=yes\n"));
    assert!(arguments.contains("ControlPath=none\n"));
    assert!(arguments.ends_with("APP='fixture '\\'' quote' sh -s\n"));
    assert!(env_prefix(&BTreeMap::from([("BAD-NAME".into(), "value".into())])).is_err());
}
#[test]
fn port_resolution_and_protected_multiplex_fallback_remain_explicit() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let mut target = Target::parse("root@box.example.com").unwrap();
    target.resolve_port_from_output("user root\nport 2222\n");
    assert_eq!(target.port, 2222);
    target.port_explicit = true;
    target.resolve_port_from_output("port 3333\n");
    assert_eq!(target.port, 2222);
    let temp = tempfile::tempdir().unwrap();
    let short = temp.path().join("h");
    if multiplex_socket_path(&short.join(".ssh")).is_some() {
        let control = control_path(&short).unwrap();
        assert!(control.ends_with("komizo-%C"));
        assert_eq!(
            std::fs::metadata(short.join(".ssh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let real = temp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let malicious = temp.path().join("bad");
    std::fs::create_dir(&malicious).unwrap();
    symlink(&real, malicious.join(".ssh")).unwrap();
    assert!(control_path(&malicious).is_none());
    let long = temp.path().join("a".repeat(150));
    assert!(control_path(&long).is_none());
    assert!(!long.exists());
}
