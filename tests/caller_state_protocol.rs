use komizo::{
    caller::{protocol as p, state, transport::Target},
    flags::{Flag, Flags},
    workload::activation::Context,
};
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    time::{Duration, Instant},
};
#[test]
fn frozen_go_private_targets_deployment_declarations_and_machine_results() {
    let data: Value =
        serde_json::from_str(include_str!("data/go-caller-state-protocol.json")).unwrap();
    assert_eq!(
        data["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["ok"] == true)
            .count(),
        1
    );
    assert_eq!(data["machines"].as_array().unwrap().len(), 99);
    for case in data["targets"].as_array().unwrap() {
        let result = state::decode_targets(case["body"].as_str().unwrap().as_bytes());
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "target {case}"
        );
        if let Ok(config) = result {
            assert_eq!(json!(config), case["expected"]);
        }
    }
    for case in data["deployments"].as_array().unwrap() {
        let result = state::decode_deployment(case["body"].as_str().unwrap().as_bytes());
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "deployment {case}"
        );
        if let Ok(config) = result {
            assert_eq!(json!(config), case["expected"]);
        }
    }
    for case in data["definitions"].as_array().unwrap() {
        let result = state::decode_definition(case["body"].as_str().unwrap().as_bytes());
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "definition {case}"
        );
        if let Ok(config) = result {
            assert_eq!(json!(config), case["expected"]);
        }
    }
    for case in data["machines"].as_array().unwrap() {
        let args: Vec<String> = serde_json::from_value(case["args"].clone()).unwrap();
        let kind = case["kind"].as_str().unwrap();
        let mut output = p::Output::default();
        let result = match kind {
            "typed" => output.emit(json!({"ready":false,"integer":1234567890123456789i64})),
            "text" => {
                output.text.write_all(b"fixture text\n").unwrap();
                Ok(())
            }
            "failed" | "timeout" => Err(anyhow::anyhow!("fixture failure")),
            "local" => Err(p::local(anyhow::anyhow!("fixture validation"))),
            "mismatch" => Err(p::mismatch(anyhow::anyhow!("fixture state"))),
            "help" => {
                output.text.write_all(b"fixture help\n").unwrap();
                Err(komizo::flags::Help.into())
            }
            "output-limit" => {
                output
                    .text
                    .write_all(&vec![b'x'; p::MAX_OUTPUT + 1])
                    .unwrap();
                Ok(())
            }
            "empty" => Ok(()),
            _ => unreachable!(),
        };
        let ctx = Context::new(if kind == "timeout" {
            Instant::now() - Duration::from_secs(1)
        } else {
            Instant::now() + Duration::from_secs(5)
        });
        let result = p::finish(&ctx, &args, output, result, false);
        assert_eq!(json!(result), case["expected"], "{kind} {args:?}");
        assert_eq!(json!(result.exit_code), case["status"]);
        assert_eq!(
            p::mutating(&args[0], &args),
            case["mutating"].as_bool().unwrap()
        );
        assert_eq!(p::help(&args), case["help"].as_bool().unwrap());
        assert_eq!(
            json!(p::next_action(&args, p::mutating(&args[0], &args))),
            case["next"]
        );
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("must-not-appear")
        );
    }
}
#[test]
fn private_target_binding_is_idempotent_and_cannot_move_implicitly() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config/targets.json");
    let project = temp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("komizo.json"),
        b"{\"version\":1,\"repository\":\"example/site\"}",
    )
    .unwrap();
    let mut target = Target::parse("root@host.example").unwrap();
    target.port = 2222;
    state::bind_target(&path, "example/site", &target, "site").unwrap();
    state::bind_target(&path, "example/site", &target, "site").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let spec = [
        Flag::text("host", ""),
        Flag::integer("port", 22),
        Flag::text("app", ""),
    ];
    let mut flags = Flags::parse(&spec, &[]).unwrap();
    state::default_target(&project, &path, &mut flags).unwrap();
    assert_eq!(flags.text("host"), "root@host.example");
    assert_eq!(flags.integer("port"), 2222);
    assert!(flags.seen.contains("port"));
    assert_eq!(flags.text("app"), "site");
    for args in [
        vec!["--app".into(), "different".into()],
        vec!["--port".into(), "22".into()],
    ] {
        let mut flags = Flags::parse(&spec, &args).unwrap();
        assert!(state::default_target(&project, &path, &mut flags).is_err());
    }
    target.host = "other.example".into();
    let before = std::fs::read(&path).unwrap();
    assert!(state::bind_target(&path, "example/site", &target, "site").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(state::read_targets(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    let original = temp.path().join("original.json");
    std::fs::write(&original, b"{}").unwrap();
    symlink(&original, &path).unwrap();
    assert!(state::read_targets(&path).is_err());
}
#[test]
fn bounded_regular_inputs_and_scoped_adapters_do_not_follow_links_or_read_fifos() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input");
    std::fs::write(&path, b"opaque bytes\xff\x00").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        state::read_file(&path, 100, true).unwrap(),
        b"opaque bytes\xff\x00"
    );
    assert!(state::read_file(&path, 3, true).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(state::read_file(&path, 100, true).is_err());
    let fifo = temp.path().join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let start = Instant::now();
    assert!(state::read_file(&fifo, 100, false).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    let spec = temp.path().join("spec.json");
    let body = json!({"version":1,"profile":"unrelated.profile","schema":9,"files":["database.env","roles.env"],"provision_script":"provision.sh","status_script":"status.sh"});
    std::fs::write(&spec, serde_json::to_vec(&body).unwrap()).unwrap();
    for name in ["provision.sh", "status.sh"] {
        std::fs::write(temp.path().join(name), b"#!/bin/sh\nprintf fixture\n").unwrap();
    }
    let scoped = state::read_scoped(&spec).unwrap();
    assert_eq!(scoped.values.profile, "unrelated.profile");
    assert_eq!(scoped.values.schema, 9);
    assert!(scoped.provision.starts_with(b"#!/bin/sh"));
    std::fs::remove_file(temp.path().join("status.sh")).unwrap();
    symlink(&path, temp.path().join("status.sh")).unwrap();
    assert!(state::read_scoped(&spec).is_err());
    let mut bad = body;
    bad["status_script"] = "../status.sh".into();
    std::fs::write(&spec, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(state::read_scoped(&spec).is_err());
}
#[test]
fn typed_protocol_refuses_ambiguous_oversized_or_multiple_results() {
    let mut output = p::Output::default();
    for body in [
        b"{\"v\":1,\"v\":2}".as_slice(),
        b"{} {}",
        b"{\"nested\":{\"x\":1,\"x\":2}}",
    ] {
        assert!(output.protocol(body).is_err());
    }
    output
        .protocol(b"{\"v\":1,\"integer\":1234567890123456789}")
        .unwrap();
    assert_eq!(
        output.data.as_ref().unwrap()["integer"],
        json!(1234567890123456789i64)
    );
    assert!(output.emit(json!({})).is_err());
    let receipt = p::receipt(
        "stop",
        &Target::parse("root@fixture.example").unwrap(),
        "fixture",
        Value::Null,
    );
    assert_eq!(
        receipt,
        json!({"version":1,"action":"stop","host":"root@fixture.example","app":"fixture","details":{},"acknowledged":true})
    );
}
