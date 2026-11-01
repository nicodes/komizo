use komizo::host::{Probe, engine::*};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[test]
fn nineteen_go_engine_cases_reuse_a_read_only_local_connection_and_preserve_failures() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-docker-engine.json")).unwrap();
    assert_eq!(cases.len(), 19);
    for case in cases {
        let t = tempfile::tempdir().unwrap();
        let socket = t.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let responses = case["responses"].as_object().unwrap().clone();
        let seen = Arc::new(Mutex::new(vec![]));
        let requests = seen.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopping = stopped.clone();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let mut connections = 0;
            while !stopping.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                connections += 1;
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut input = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut first = String::new();
                    if input.read_line(&mut first).unwrap_or(0) == 0 {
                        break;
                    }
                    let parts: Vec<_> = first.split_whitespace().collect();
                    assert_eq!(parts[0], "GET");
                    let path = parts[1].to_owned();
                    let mut host = false;
                    loop {
                        let mut line = String::new();
                        input.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
                        if line.to_ascii_lowercase().starts_with("host: docker") {
                            host = true;
                        }
                    }
                    assert!(host);
                    requests.lock().unwrap().push(path.clone());
                    let response = &responses[&path];
                    let body = response["body"].as_str().unwrap();
                    let status = response["status"].as_u64().unwrap();
                    write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",body.len()).unwrap();
                    stream.flush().unwrap();
                }
            }
            connections
        });
        let engine = Engine::connect(&socket, Instant::now() + Duration::from_secs(4)).unwrap();
        let mut actual = json!({"selected":engine.is_some(),"available":engine.as_ref().is_some_and(|e|e.available)});
        if let Some(mut engine) = engine
            && engine.available
        {
            let inv = engine.inventory();
            let network = engine
                .network("edge")
                .unwrap_or_else(|e| panic!("case {}: {e}", case["kind"]));
            let p = Probe {
                root: t.path().into(),
            };
            let rows:Vec<_>=inv.sorted().iter().map(|c|json!({"id":c.id,"name":c.name,"pid":c.pid,"tty":c.tty,"inspection_unavailable":c.inspection_unavailable,"mount_count":c.mounts.len()})).collect();
            let map = actual.as_object_mut().unwrap();
            map.insert("status".into(), json!(inv.status));
            map.insert("failure".into(), json!(inv.failure));
            map.insert("rows".into(), json!(rows));
            map.insert(
                "containers".into(),
                json!(p.containers("/srv/fixture", &inv)),
            );
            map.insert("network_text".into(), json!(network));
        }
        stopped.store(true, Ordering::Release);
        let connections = server.join().unwrap();
        if matches!(
            case["kind"].as_str(),
            Some("ready" | "unhealthy" | "stopped" | "tty")
        ) {
            assert_eq!(connections, 1);
        }
        assert_eq!(actual, case["expected"], "case {}", case["kind"]);
        assert!(!actual.to_string().contains("never-export-this"));
        let paths = seen.lock().unwrap();
        assert_eq!(paths[0], "/version");
        assert!(
            paths
                .iter()
                .all(|p| p == "/version" || p.starts_with("/v1.45/"))
        );
    }
}
#[test]
fn protocol_and_context_selection_never_silently_replace_a_customized_daemon() {
    for (minimum, maximum, target, expected) in [
        ("1.40", "1.53", "1.45", true),
        ("1.46", "1.53", "1.45", false),
        ("1.40", "1.44", "1.45", false),
        ("2.0", "2.1", "1.45", false),
        ("1.44", "1.44", "1.44", true),
        ("1.bad", "1.99", "1.45", false),
    ] {
        assert_eq!(api_contains(minimum, maximum, target), expected);
    }
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("config.json");
    assert!(default_context(&path));
    for (body, expected) in [
        ("{}", true),
        (
            r#"{"currentContext":"default","auths":{"private":"never-used"}}"#,
            true,
        ),
        (r#"{"currentContext":"remote"}"#, false),
        ("bad", false),
    ] {
        std::fs::write(&path, body).unwrap();
        assert_eq!(default_context(&path), expected);
    }
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(!default_context(&link));
}
