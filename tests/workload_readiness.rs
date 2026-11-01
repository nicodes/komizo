use komizo::workload::{policy::Policy, readiness};
use serde_json::Value;
#[test]
fn go_readiness_matches_required_services_images_routes_and_core_reads() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("data/go-readiness.json")).unwrap();
    assert_eq!(cases.len(), 62);
    for (index, case) in cases.into_iter().enumerate() {
        let p: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
        let mut calls = 0;
        let mut requests = vec![];
        let mut run = |args: &[&str]| {
            let position = calls;
            calls += 1;
            assert_eq!(
                serde_json::to_value(args).unwrap(),
                case["calls"][position],
                "case {index} call {position}"
            );
            let response = &case["replies"][position];
            let error = response["error"].as_str().unwrap();
            if error.is_empty() {
                Ok(response["output"].as_str().unwrap().into())
            } else {
                Err(anyhow::anyhow!("{error}"))
            }
        };
        let candidate = case["candidate"].as_str().unwrap();
        let mut probe = |probe: &komizo::workload::policy::ReadinessProbe| {
            requests.push(serde_json::json!({"url":probe.url,"cache_control":"no-cache"}));
            readiness::check_route_response(
                case["status"].as_u64().unwrap() as u16,
                case["response_revision"].as_str().unwrap(),
                case["response"].as_str().unwrap().as_bytes(),
                candidate,
                probe,
            )
        };
        let result = if case["static"].as_bool().unwrap() {
            readiness::verify_static_readiness(&mut run, &mut probe, &p, candidate)
        } else {
            readiness::verify_readiness(
                &mut run,
                &mut probe,
                &p,
                candidate,
                case["compose_path"].as_str().unwrap(),
                case["compose"].as_str().unwrap().as_bytes(),
            )
        };
        assert_eq!(
            result.err().map(|e| e.to_string()).unwrap_or_default(),
            case["error"],
            "case {index} {} static={}",
            case["scenario"],
            case["static"]
        );
        assert_eq!(
            calls,
            case["calls"].as_array().map_or(0, Vec::len),
            "case {index}"
        );
        let expected: Vec<Value> = case["requests"].as_array().cloned().unwrap_or_default();
        assert_eq!(requests, expected, "case {index}");
    }
}
#[test]
fn native_http_probe_sends_only_no_cache_reads_and_enforces_response_bound() {
    use komizo::workload::{activation::Context, policy::ReadinessProbe};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::{Duration, Instant},
    };
    let candidate = "a".repeat(40);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for (status, revision, body, field, accepted) in [
        (200, candidate.clone(), "hello".into(), "", true),
        (
            200,
            candidate.clone(),
            format!("{{\"revision\":\"{candidate}\"}}"),
            "revision",
            true,
        ),
        (503, candidate.clone(), "hello".into(), "", false),
        (200, "old".into(), "hello".into(), "", false),
        (200, candidate.clone(), String::new(), "", false),
        (
            200,
            candidate.clone(),
            "x".repeat((1 << 20) + 1),
            "revision",
            false,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut header = vec![];
            let mut byte = [0];
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 8192);
                socket.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
            }
            let request = String::from_utf8(header).unwrap().to_lowercase();
            assert!(request.starts_with("get /ready http/1.1\r\n"));
            assert!(request.contains("\r\ncache-control: no-cache\r\n"));
            assert!(!request.contains("authorization:"));
            let response = format!(
                "HTTP/1.1 {status} Result\r\nX-Komizo-Revision: {revision}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
        });
        let result = readiness::probe_ready(
            &Context::new(Instant::now() + Duration::from_secs(2)),
            &client,
            &candidate,
            &ReadinessProbe {
                url: format!("http://{address}/ready"),
                revision_field: field.into(),
            },
        );
        assert_eq!(result.is_ok(), accepted);
        server.join().unwrap();
    }
}
