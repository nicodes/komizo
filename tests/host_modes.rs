use komizo::{
    host::{
        self,
        commands::{self, agent, daemon, preview},
        credential,
    },
    wire::{Secret, Slice, Time},
    workload::activation::Context,
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
fn context() -> Context {
    Context::new(Instant::now() + Duration::from_secs(5))
}
#[test]
fn frozen_go_host_modes_preserve_keys_endpoints_preview_responses_and_refusals() {
    let data: Value = serde_json::from_str(include_str!("data/go-host-modes.json")).unwrap();
    assert_eq!(data["carries"].as_array().unwrap().len(), 72);
    for case in data["carries"].as_array().unwrap() {
        let previous: Slice<String> = serde_json::from_value(case["previous"].clone()).unwrap();
        let added: Slice<String> = serde_json::from_value(case["added"].clone()).unwrap();
        let (keys, dropped) = agent::carry_keys(
            &previous,
            case["old"].as_str().unwrap(),
            case["server"].as_str().unwrap(),
            &added,
            case["forget"].as_bool().unwrap(),
        );
        assert_eq!(json!(keys), case["keys"]);
        assert_eq!(json!(dropped), case["dropped"]);
    }
    for case in data["endpoints"].as_array().unwrap() {
        let host = case["host"].as_str().unwrap();
        assert_eq!(
            credential::is_ip_address(host),
            case["ip"].as_bool().unwrap()
        );
        assert_eq!(
            credential::validate_api_host(host).is_ok(),
            case["valid"].as_bool().unwrap()
        );
        let result = credential::api_host_for("203.0.113.10", host);
        assert_eq!(result.is_ok(), case["override_ok"].as_bool().unwrap());
        if let Ok(value) = result {
            assert_eq!(value, case["override"].as_str().unwrap());
        }
    }
    for case in data["responses"].as_array().unwrap() {
        let (knob, _) = host::preview::knob::parse(case["knob"].as_str().unwrap());
        let record = host::preview::Record {
            values: host::preview::RecordValues {
                app: "fixture".into(),
                pr: 32,
                host: case["host"].as_str().unwrap().into(),
                ..Default::default()
            },
            db_password: Secret::new("never-publish-this".into()),
        };
        let response = preview::response(record, &knob).unwrap();
        assert_eq!(response, case["expected"]);
        assert!(!response.to_string().contains("never-publish-this"));
    }
    for case in data["failures"].as_array().unwrap() {
        let args: Vec<String> = serde_json::from_value(case["args"].clone()).unwrap();
        let error = commands::run(&args, &context(), &mut vec![]).unwrap_err();
        assert_eq!(
            error.to_string(),
            case["error"].as_str().unwrap(),
            "{args:?}"
        );
    }
    for case in data["lines"].as_array().unwrap() {
        assert_eq!(
            agent::first_line(case["body"].as_str().unwrap().as_bytes()),
            case["expected"].as_str().unwrap()
        );
    }
}
struct Request {
    line: String,
    headers: Vec<String>,
    body: Vec<u8>,
}
fn server(
    status: u16,
    response: Vec<u8>,
) -> (
    String,
    Arc<Mutex<Option<Request>>>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let request = Arc::new(Mutex::new(None));
    let captured = request.clone();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut headers = vec![];
        let mut length = 0;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            if header == "\r\n" {
                break;
            }
            if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
            headers.push(header);
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        *captured.lock().unwrap() = Some(Request {
            line,
            headers,
            body,
        });
        write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).unwrap();
        stream.write_all(&response).unwrap();
    });
    (url, request, thread)
}
#[test]
fn report_courier_posts_verbatim_bytes_and_classifies_revocation_without_redirecting() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("report.json");
    let body = b" {\"v\":1, \"future\": 1234567890123456789}\n";
    std::fs::write(&path, body).unwrap();
    for status in [200, 204, 401, 403, 429, 500, 302] {
        let (url, request, thread) = server(status, b" response line \nsecond".to_vec());
        let conf = host::AgentConf {
            api: url,
            token: Secret::new("fixture-only-token".into()),
            ..Default::default()
        };
        let result = agent::post_report(&context(), &agent::client().unwrap(), &conf, &path);
        thread.join().unwrap();
        assert_eq!(result.is_ok(), (200..300).contains(&status));
        if matches!(status, 401 | 403) {
            assert!(result.unwrap_err().is::<agent::Revoked>());
        }
        let guard = request.lock().unwrap();
        let request = guard.as_ref().unwrap();
        assert!(request.line.starts_with("POST /v1/report HTTP/1.1"));
        assert_eq!(request.body, body);
        assert!(request.headers.iter().any(|h| {
            h.trim()
                .eq_ignore_ascii_case("authorization: Bearer fixture-only-token")
        }));
        assert!(request.headers.iter().any(|h| {
            h.trim()
                .eq_ignore_ascii_case("content-type: application/json")
        }));
    }
}
#[test]
fn enrollment_reply_cannot_plant_command_or_log_keys_and_endpoint_is_explicit() {
    for reply in [
        json!({"server_id":"srv_fixture","agent_token":"fixture","registry_key":"registry","operator_keys":["hostile"],"log_keys":["hostile"],"device_keys":["hostile"]}),
        json!({"SERVER_ID":"srv_fixture","AGENT_TOKEN":"fixture","REGISTRY_KEY":"registry","message":false}),
    ] {
        let (url, request, thread) = server(200, serde_json::to_vec(&reply).unwrap());
        let conf = agent::exchange(
            &context(),
            &agent::client().unwrap(),
            &url,
            "fixture-single-use",
            "box.example.com",
            &host::Report::default(),
        )
        .unwrap();
        thread.join().unwrap();
        assert_eq!(conf.server_id, "srv_fixture");
        assert_eq!(conf.registry_key, "registry");
        assert!(conf.operator_keys.is_empty());
        assert!(conf.log_keys.is_empty());
        let guard = request.lock().unwrap();
        let request = guard.as_ref().unwrap();
        assert!(request.line.starts_with("POST /v1/enrol "));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["endpoint"], "box.example.com");
        assert_eq!(body["token"], "fixture-single-use");
        assert!(body.get("operator_keys").is_none());
    }
    for (status, reply) in [
        (200, json!({"server_id":"missing-token"})),
        (403, json!({"message":"refused fixture"})),
    ] {
        let (url, _, thread) = server(status, serde_json::to_vec(&reply).unwrap());
        let error = agent::exchange(
            &context(),
            &agent::client().unwrap(),
            &url,
            "fixture",
            "",
            &host::Report::default(),
        )
        .unwrap_err();
        thread.join().unwrap();
        assert!(error.to_string().contains(if status == 200 {
            "issued no credential"
        } else {
            "refused fixture"
        }));
    }
}
#[test]
fn daemon_tick_persists_one_observation_and_clips_nonoverlapping_metric_history() {
    let temp = tempfile::tempdir().unwrap();
    let probe = host::Probe {
        root: temp.path().into(),
    };
    let paths = daemon::Paths {
        report: temp.path().join("served/report.json"),
        history: temp.path().join("served/history.jsonl"),
        metrics: temp.path().join("served/metrics.json"),
    };
    let at: Time = serde_json::from_str("\"2026-11-01T12:00:00Z\"").unwrap();
    let log = probe.path(host::paths::ACCESS_LOG);
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(
        &log,
        "{\"ts\":1793491200,\"status\":200,\"request\":{\"host\":\"example.com\"}}\n",
    )
    .unwrap();
    let report = host::Report {
        v: 1,
        at,
        ..Default::default()
    };
    assert!(daemon::persist_tick(&probe, &report, &paths).is_empty());
    assert_eq!(
        json!(host::store::read_report(&paths.report).unwrap()),
        json!(report)
    );
    let samples = host::store::read_samples(&paths.history, 0, at.utc().timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].at, at);
    let metrics: host::Metrics =
        serde_json::from_slice(&std::fs::read(&paths.metrics).unwrap()).unwrap();
    assert!(metrics.span.is_none());
    let cached = vec![
        "report".into(),
        "--cached".into(),
        "--report".into(),
        paths.report.to_string_lossy().into_owned(),
    ];
    let mut bytes = vec![];
    commands::run(&cached, &context(), &mut bytes).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!(report)
    );
    assert!(daemon::parse_flags(&["--root".into(), "/tmp".into()]).is_err());
    assert!(daemon::parse_flags(&["--interval".into(), "0".into()]).is_err());
}
#[test]
fn daemon_directory_handoff_follows_flag_paths_and_rejects_symlink_leaves() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let paths = [
        ("report", "run/report.json"),
        ("history", "history/served/history.jsonl"),
        ("metrics", "metrics/served/metrics.json"),
        ("state", "state"),
        ("socket-dir", "socket"),
        ("inbox", "inbox"),
        ("results", "results"),
        ("logs", "logs"),
    ];
    let mut args = vec![];
    for (flag, path) in paths {
        args.extend([
            format!("--{flag}"),
            temp.path().join(path).to_string_lossy().into_owned(),
        ]);
    }
    let flags = daemon::parse_flags(&args).unwrap();
    let prepared = daemon::prepare(&flags).unwrap();
    assert_eq!(prepared.report, temp.path().join("run/report.json"));
    assert_eq!(
        std::fs::metadata(temp.path().join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(temp.path().join("history/served"))
            .unwrap()
            .permissions()
            .mode()
            & 0o2777,
        0o2750
    );
    let real = temp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = temp.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(host::directories::prepare_state(&link).is_err());
}
#[cfg(not(packed_api))]
#[test]
fn native_api_supervisor_forwards_termination_and_reaps_the_child() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let api = temp.path().join("fake-api");
    let ready = temp.path().join("ready");
    let stopped = temp.path().join("stopped");
    let script = format!(
        "#!/bin/sh\ntrap 'printf stopped > {} ; exit 0' TERM INT\nprintf '%s\\n' \"$@\" > {}.pending\nmv {}.pending {}\nwhile :; do sleep 0.05; done\n",
        komizo::scripts::sh_quote(&stopped.to_string_lossy()),
        komizo::scripts::sh_quote(&ready.to_string_lossy()),
        komizo::scripts::sh_quote(&ready.to_string_lossy()),
        komizo::scripts::sh_quote(&ready.to_string_lossy())
    );
    std::fs::write(&api, script).unwrap();
    std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_komizo-box"))
        .arg("serve")
        .env("KOMIZO_API_BINARY", &api)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("API never started")
        };
        std::thread::sleep(Duration::from_millis(10));
    }
    let args = std::fs::read_to_string(&ready).unwrap();
    assert_eq!(args, format!("serve\n--parent-pid\n{}\n", child.id()));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("supervisor did not stop")
        };
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read_to_string(stopped).unwrap(), "stopped");
}
#[test]
fn repeatable_flags_preserve_order_and_stop_at_the_first_positional() {
    use komizo::flags::{Flag, Flags};
    let args = ["--key", "one", "--key=two", "positional", "--key=unused"].map(String::from);
    let flags = Flags::parse(&[Flag::list("key")], &args).unwrap();
    assert_eq!(flags.list("key"), ["one", "two"]);
    assert_eq!(flags.args, ["positional", "--key=unused"]);
}
#[cfg(packed_api)]
#[test]
fn native_packed_api_serves_authenticated_reads_without_developer_tools() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("api.sock");
    let report = temp.path().join("report.json");
    std::fs::write(&report, b"{\"v\":1,\"apps\":[]}").unwrap();
    let seed = [42; 32];
    let public = host::authority::keys::public_from_seed(&seed).unwrap();
    let mut private = seed.to_vec();
    private.extend_from_slice(&public);
    let conf = temp.path().join("agent.json");
    std::fs::write(&conf,serde_json::to_vec(&json!({"server_id":"fixture_box","registry_key":host::authority::keys::encode(&public)})).unwrap()).unwrap();
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600)).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_komizo-box"))
        .args(["serve", "--socket"])
        .arg(&socket)
        .arg("--config")
        .arg(&conf)
        .arg("--report")
        .arg(&report)
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", temp.path())
        .env_remove("KOMIZO_API_BINARY")
        .env_remove("KOMIZO_API_PAYLOAD")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "API socket never appeared");
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "API exited before binding"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let client = reqwest::blocking::Client::builder()
        .unix_socket(socket.clone())
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let response = client.get("http://fixture/v1/report").send().unwrap();
    assert_eq!(response.status().as_u16(), 401);
    let token = host::authority::keys::sign_read_token(
        &private,
        "fixture_box",
        Time((chrono::Utc::now() + chrono::Duration::minutes(1)).fixed_offset()),
    )
    .unwrap();
    assert!(host::authority::keys::verify_read_token(
        &public,
        &token,
        "fixture_box",
        Time(chrono::Utc::now().fixed_offset())
    ));
    let envelope = host::authority::commands::sign_command(
        &private,
        host::authority::Command {
            srv: "fixture_box".into(),
            op: "report.read".into(),
            exp: (chrono::Utc::now() + chrono::Duration::minutes(1)).timestamp(),
            ..Default::default()
        },
    )
    .unwrap();
    let response = client
        .post("http://fixture/v1/report")
        .bearer_auth(&token)
        .json(&envelope)
        .send()
        .unwrap();
    let status = response.status().as_u16();
    let raw = response.text().unwrap();
    assert_eq!(status, 200, "response {raw}");
    let body: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(body, json!({"v":1,"report":{"v":1,"apps":[]}}));
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o660
    );
    assert!(!std::fs::read_dir(temp.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("komizo-api-")
    }));
    unsafe {
        libc::kill(child.0.id() as i32, libc::SIGTERM);
    }
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "API did not stop");
        std::thread::sleep(Duration::from_millis(10));
    }
}
