use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use komizo_api::{config::Authority, http::Monitor, store::Paths};
use serde_json::{Value, json};
use tower::ServiceExt;
fn public(key: &Ed25519KeyPair) -> [u8; 32] {
    key.public_key().as_ref().try_into().unwrap()
}
fn envelope(key: &Ed25519KeyPair, op: &str, id: &str, args: Value, now: i64) -> Vec<u8> {
    let payload = serde_json::to_vec(
        &json!({"v":1,"id":id,"srv":"fixture_box","exp":now+60,"op":op,"args":args}),
    )
    .unwrap();
    serde_json::to_vec(&json!({"payload":URL_SAFE_NO_PAD.encode(&payload),"sig":URL_SAFE_NO_PAD.encode(key.sign(&payload).as_ref())})).unwrap()
}
async fn request(
    app: &std::sync::Arc<Monitor>,
    method: &str,
    path: &str,
    token: &str,
    raw: Vec<u8>,
) -> (u16, Vec<u8>) {
    let response = app
        .router()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(raw))
                .unwrap(),
        )
        .await
        .unwrap();
    (
        response.status().as_u16(),
        to_bytes(response.into_body(), 8 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
}
#[tokio::test]
async fn signed_http_keeps_registry_observations_separate_from_logs_and_root_inbox() {
    let root = std::env::temp_dir().join(format!("komizo-monitor-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    for directory in ["results", "inbox", "logs", "apps"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    let paths = Paths {
        report: root.join("report.json"),
        history: root.join("history.jsonl"),
        metrics: root.join("metrics.json"),
        results: root.join("results"),
        inbox: root.join("inbox"),
        logs: root.join("logs"),
        apps: root.join("apps"),
    };
    std::fs::write(
        &paths.report,
        b"{\"v\":1,\"server\":{\"id\":\"fixture_box\"},\"apps\":[]}",
    )
    .unwrap();
    std::fs::write(
        paths.logs.join("web.log"),
        b"api\tfirst\nworker\tsecond\napi\tthird\n",
    )
    .unwrap();
    let registry = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let operator = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let logs = Ed25519KeyPair::from_seed_unchecked(&[3; 32]).unwrap();
    let app = Monitor::new(
        Authority {
            server: "fixture_box".into(),
            registry: public(&registry),
            operators: vec![public(&operator)],
            logs: vec![public(&operator), public(&logs)],
        },
        paths.clone(),
    );
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::to_vec(&json!({"srv":"fixture_box","exp":now+60})).unwrap();
    let token = format!(
        "kmz_rd_{}.{}",
        URL_SAFE_NO_PAD.encode(&claims),
        URL_SAFE_NO_PAD.encode(registry.sign(&claims).as_ref())
    );
    assert_eq!(request(&app, "GET", "/health", &token, vec![]).await.0, 401);
    assert_eq!(
        request(&app, "GET", "/v1/report", &token, vec![]).await.0,
        401
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/report",
            "forged",
            envelope(&registry, "report.read", "report", json!({}), now)
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/report",
            &token,
            envelope(&registry, "report.read", "report", json!({}), now)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request(&app, "POST", "/v1/report", &token, vec![]).await.0,
        403
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/logs",
            &token,
            envelope(&registry, "logs.read", "logs", json!({"app":"web"}), now)
        )
        .await
        .0,
        403
    );
    let (status, body) = request(
        &app,
        "POST",
        "/v1/logs",
        &token,
        envelope(
            &logs,
            "logs.read",
            "logs",
            json!({"app":"web","tail":"1","service":"api"}),
            now,
        ),
    )
    .await;
    assert_eq!(status, 200);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["lines"], "api\tthird");
    assert_eq!(value["services"], json!(["api", "worker"]));
    let raw = envelope(
        &operator,
        "app.stop",
        "owned_stop",
        json!({"app":"web"}),
        now,
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/commands",
            &token,
            envelope(
                &registry,
                "app.stop",
                "registry_stop",
                json!({"app":"web"}),
                now
            )
        )
        .await
        .0,
        403
    );
    assert!(!paths.inbox.join("registry_stop").exists());
    assert_eq!(
        request(&app, "POST", "/v1/commands", &token, raw.clone())
            .await
            .0,
        202
    );
    assert_eq!(std::fs::read(paths.inbox.join("owned_stop")).unwrap(), raw);
    assert_eq!(
        request(&app, "POST", "/v1/commands", &token, raw.clone())
            .await
            .0,
        202
    );
    assert_eq!(std::fs::read_dir(&paths.inbox).unwrap().count(), 1);
    assert_eq!(
        request(&app, "GET", "/v1/commands/pending", &token, vec![])
            .await
            .0,
        404
    );
    std::fs::write(
        paths.results.join("owned_stop.json"),
        format!(
            "{{\"v\":1,\"id\":\"owned_stop\",\"op\":\"app.stop\",\"at\":\"{}\",\"ok\":true}}",
            chrono::Utc::now().to_rfc3339()
        ),
    )
    .unwrap();
    assert_eq!(
        request(&app, "POST", "/v1/commands", &token, raw).await.0,
        200
    );
    for i in 1..128 {
        std::fs::write(paths.inbox.join(format!("pending_{i}")), b"pending").unwrap();
    }
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/commands",
            &token,
            envelope(
                &operator,
                "app.stop",
                "over_capacity",
                json!({"app":"web"}),
                now
            )
        )
        .await
        .0,
        503
    );
    assert_eq!(std::fs::read_dir(&paths.inbox).unwrap().count(), 128);
    std::fs::write(paths.results.join("broken.json"), b"truncated").unwrap();
    assert_eq!(
        request(&app, "GET", "/v1/commands/broken", &token, vec![])
            .await
            .0,
        500
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn native_monitor_uses_a_private_unix_socket_and_preserves_signed_reads() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let directory =
        std::env::temp_dir().join(format!("komizo-native-monitor-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let socket = directory.join("api.sock");
    let config = directory.join("agent.json");
    let report = directory.join("report.json");
    let registry = Ed25519KeyPair::from_seed_unchecked(&[4; 32]).unwrap();
    let now = chrono::Utc::now().timestamp();
    std::fs::write(&config,serde_json::to_vec(&json!({"server_id":"fixture_box","registry_key":URL_SAFE_NO_PAD.encode(public(&registry))})).unwrap()).unwrap();
    std::fs::write(&report, b"{\"v\":1,\"apps\":[]}").unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_komizo-api"))
        .arg("serve")
        .arg("--socket")
        .arg(&socket)
        .arg("--config")
        .arg(&config)
        .arg("--report")
        .arg(&report)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stream = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = tokio::net::UnixStream::connect(&socket).await {
                break stream;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o660
    );
    let claims = serde_json::to_vec(&json!({"srv":"fixture_box","exp":now+60})).unwrap();
    let token = format!(
        "kmz_rd_{}.{}",
        URL_SAFE_NO_PAD.encode(&claims),
        URL_SAFE_NO_PAD.encode(registry.sign(&claims).as_ref())
    );
    let body = envelope(&registry, "report.read", "report", json!({}), now);
    let header = format!(
        "POST /v1/report HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.take(1 << 20).read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(text.contains("\"report\":{\"apps\":[],\"v\":1}"));
    unsafe { libc::kill(child.id().unwrap() as i32, libc::SIGTERM) };
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn local_ui_reads_real_files_refuses_unknown_actions_and_holds_response_capacity() {
    use komizo_api::{config::Config, ui::Ui};
    let root = std::env::temp_dir().join(format!("komizo-ui-fixture-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("results")).unwrap();
    std::fs::create_dir(root.join("apps")).unwrap();
    std::fs::write(
        root.join("report.json"),
        br#"{"v":1,"apps":[{"name":"web","state":"running"}]}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("results/one.json"),
        br#"{"v":1,"id":"one","op":"app.stop","at":"2026-10-31T00:00:00Z","ok":true}"#,
    )
    .unwrap();
    let mut config = Config::parse(&[]).unwrap();
    config.paths.report = root.join("report.json");
    config.paths.results = root.join("results");
    config.paths.apps = root.join("apps");
    let (stop, _) = tokio::sync::watch::channel(false);
    let ui = Ui::new(config, stop);
    let router = ui.router();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/report")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(body["report"]["apps"][0]["state"], "running");
    for (raw, expected) in [
        (br#"{"app":"web","action":"deploy"}"#.as_slice(), 403),
        (br#"{"app":"../web","action":"stop"}"#.as_slice(), 400),
        (br#"{"app":"missing","action":"stop"}"#.as_slice(), 404),
        (b"broken".as_slice(), 400),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/action")
                    .body(Body::from(raw.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        drop(response);
    }
    let mut held = Vec::new();
    for _ in 0..8 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/report")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        held.push(response);
    }
    assert_eq!(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/report")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        503
    );
    held.pop();
    assert_eq!(
        router
            .oneshot(
                Request::builder()
                    .uri("/api/report")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        200
    );
    drop(held);
    ui.shutdown().await;
    std::fs::remove_dir_all(root).unwrap();
}
