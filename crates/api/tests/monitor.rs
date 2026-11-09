use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use komizo_api::{config::Config, ui::Ui};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc};
use tower::ServiceExt;
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUTH: &str = "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
struct Fixture {
    root: PathBuf,
    ui: Arc<Ui>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("komizo-local-ui-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let binary = root.join("owner");
        let script = format!(
            r#"#!/usr/bin/python3
import hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
root=Path({root})
args=sys.argv[1:]
with (root/'calls').open('a') as f:f.write(json.dumps(args)+'\n')
options=dict(zip(args[1::2],args[2::2]))
assert options['--host']=='host.example.test'
if args[0]=='status':
 if (root/'hold').exists():
  signal.signal(signal.SIGTERM,signal.SIG_IGN)
  child=subprocess.Popen(['/usr/bin/python3','-I','-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)'])
  (root/'pids').write_text(str(os.getpid())+' '+str(child.pid))
  time.sleep(60)
 if (root/'offline').exists():sys.exit(3)
 print(json.dumps({{'kind':'komizo.status','version':1,'instances':[{{'application':'mailroom','instance':'production','release_digest':'sha256:'+'a'*64,'desired_running':True,'operation_id':'c'*32,'services':{{'web':{{'state':'running','health':'healthy'}}}}}}]}}))
elif args[0]=='request':
 path=Path(options['--file']);assert path.stat().st_mode&0o777==0o600
 request=json.loads(path.read_text())
 assert set(request)=={{'kind','version','authority','application','instance','action','release_digest','nonce','issued_at','expires_at','timeout_seconds'}}
 assert request['authority']=='owner' and request['timeout_seconds']==1500
 identity=hashlib.sha256(('komizo-operation-v1\0'+request['application']+'\0'+request['instance']+'\0'+request['nonce']).encode()).hexdigest()[:32]
 result={{'kind':'komizo.operation','version':1,'application':request['application'],'instance':request['instance'],'release_digest':request['release_digest'],'operation_id':identity,'phase':'ready','ok':True,'reconciliation_required':False}}
 (root/'operation').write_text(json.dumps(result));(root/'request-path').write_text(str(path))
 if (root/'failed').exists():result.update(phase='failed',ok=False)
 if (root/'lost').exists():sys.exit(7)
 print(json.dumps(result))
 if (root/'failed').exists():sys.exit(1)
elif args[0]=='inspect':
 result=json.loads((root/'operation').read_text())
 assert options['--operation']==result['operation_id'] and options['--release']==result['release_digest']
 print(json.dumps(result))
elif args[0]=='logs':
 print(json.dumps({{'kind':'komizo.logs','version':1,'application':options['--application'],'instance':options['--instance'],'service':options['--service'],'container_id':'d'*64,'text':'<script>untrusted output</script>\n'}}))
else:sys.exit(9)
"#,
            root = serde_json::to_string(&root).unwrap()
        );
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = Config {
            bind: "127.0.0.1".into(),
            port: 8480,
            host: "host.example.test".into(),
            owner_client: binary,
            identity: None,
            parent_pid: None,
        };
        let (stop, _) = tokio::sync::watch::channel(false);
        let bootstrap = root.join("bootstrap");
        std::fs::create_dir(&bootstrap).unwrap();
        std::fs::set_permissions(&bootstrap, std::fs::Permissions::from_mode(0o700)).unwrap();
        let session = komizo_api::session::Session::receive(std::io::Cursor::new(serde_json::to_vec(&json!({
            "kind":"komizo.ui-session","version":1,"capability":TOKEN,"bootstrap_directory":bootstrap
        })).unwrap()), &config).unwrap();
        Self {
            root,
            ui: Ui::new(config, session, stop),
        }
    }
    fn calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.root.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
async fn call(
    ui: &Arc<Ui>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> (u16, Value) {
    call_as(ui, method, path, headers, body, Some(AUTH)).await
}
async fn call_as(
    ui: &Arc<Ui>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
    authorization: Option<&str>,
) -> (u16, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:8480");
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    for (key, value) in headers {
        request = request.header(*key, *value);
    }
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let response = ui
        .router()
        .oneshot(request.body(Body::from(bytes)).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    let bytes = to_bytes(response.into_body(), 8 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
fn action() -> Value {
    json!({"application":"mailroom","instance":"production","action":"restart","release_digest":format!("sha256:{}","a".repeat(64)),"nonce":"b".repeat(32)})
}
const WRITE: &[(&str, &str)] = &[
    ("origin", "http://127.0.0.1:8480"),
    ("content-type", "application/json"),
    ("x-komizo-request", "1"),
];

#[tokio::test]
async fn forged_local_headers_without_the_private_launch_capability_never_invoke_owner() {
    let f = Fixture::new();
    for (method, path) in [
        ("GET", "/api/status"),
        ("GET", "/api/history"),
        ("GET", "/api/logs"),
        ("GET", "/api/operation"),
        ("POST", "/api/actions"),
    ] {
        for capability in [
            None,
            Some("Bearer wrong"),
            Some("Bearer bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ] {
            let (status, value) = call_as(&f.ui, method, path, WRITE, action(), capability).await;
            assert_eq!(status, 403);
            assert!(!value.to_string().contains(TOKEN));
        }
        assert_eq!(
            call_as(
                &f.ui,
                method,
                path,
                &[("authorization", AUTH)],
                action(),
                Some(AUTH)
            )
            .await
            .0,
            403
        );
    }
    assert!(f.calls().is_empty());
    let response =
        f.ui.router()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "127.0.0.1:8480")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    let bytes = to_bytes(response.into_body(), 8 << 20).await.unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(TOKEN));
    f.ui.shutdown().await;
}

#[tokio::test]
async fn local_health_and_remote_status_are_separate_and_history_is_observed_only() {
    let f = Fixture::new();
    std::fs::write(f.root.join("offline"), b"unavailable").unwrap();
    assert_eq!(call(&f.ui, "GET", "/readyz", &[], Value::Null).await.0, 200);
    assert!(f.calls().is_empty());
    assert_eq!(
        call(&f.ui, "GET", "/api/status", &[], Value::Null).await.0,
        503
    );
    let history = call(&f.ui, "GET", "/api/history", &[], Value::Null).await.1;
    assert!(history["samples"].as_array().unwrap().is_empty());
    std::fs::remove_file(f.root.join("offline")).unwrap();
    let (status, value) = call(&f.ui, "GET", "/api/status", &[], Value::Null).await;
    assert_eq!(status, 200);
    assert_eq!(value["status"]["kind"], "komizo.status");
    assert_eq!(value["status"]["instances"][0]["desired_running"], true);
    let history = call(&f.ui, "GET", "/api/history", &[], Value::Null).await.1;
    assert_eq!(history["samples"].as_array().unwrap().len(), 1);
    f.ui.shutdown().await;
}
#[tokio::test]
async fn cross_origin_rebinding_forms_and_untrusted_methods_never_invoke_owner_client() {
    let f = Fixture::new();
    for headers in [
        vec![],
        vec![
            ("origin", "https://attacker.example"),
            ("content-type", "application/json"),
            ("x-komizo-request", "1"),
        ],
        vec![
            ("origin", "http://127.0.0.1:8480"),
            ("content-type", "text/plain"),
            ("x-komizo-request", "1"),
        ],
        vec![
            ("origin", "http://127.0.0.1:8480"),
            ("content-type", "application/json"),
            ("x-komizo-request", "1"),
            ("sec-fetch-site", "cross-site"),
        ],
    ] {
        assert!(
            call(&f.ui, "POST", "/api/actions", &headers, action())
                .await
                .0
                >= 400
        );
    }
    assert_eq!(
        call(
            &f.ui,
            "GET",
            "/api/status",
            &[("host", "attacker.example")],
            Value::Null
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(&f.ui, "POST", "/api/action", WRITE, action()).await.0,
        405
    );
    let mut invalid = action();
    invalid["action"] = json!("deploy; id");
    assert_eq!(
        call(&f.ui, "POST", "/api/actions", WRITE, invalid).await.0,
        403
    );
    let mut invalid = action();
    invalid["application"] = json!("../other");
    assert_eq!(
        call(&f.ui, "POST", "/api/actions", WRITE, invalid).await.0,
        400
    );
    let mut invalid = action();
    invalid["command"] = json!("shell");
    assert_eq!(
        call(&f.ui, "POST", "/api/actions", WRITE, invalid).await.0,
        400
    );
    assert!(f.calls().is_empty());
    f.ui.shutdown().await;
}
#[tokio::test]
async fn uncertain_acknowledgement_inspects_known_identity_and_never_retries_effect() {
    let f = Fixture::new();
    std::fs::write(f.root.join("lost"), b"lost ack").unwrap();
    let (status, value) = call(&f.ui, "POST", "/api/actions", WRITE, action()).await;
    assert_eq!(status, 200);
    assert_eq!(value["confirmation"], "observed");
    assert_eq!(value["operation_id"], "3a136f1b4cdd49cd0c83b4231129a21f");
    assert_eq!(
        value["result"]["release_digest"],
        action()["release_digest"]
    );
    let calls = f.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0][0], "request");
    assert_eq!(calls[1][0], "inspect");
    let path = PathBuf::from(std::fs::read_to_string(f.root.join("request-path")).unwrap());
    assert!(!path.exists());
    f.ui.shutdown().await;
}
#[tokio::test]
async fn logs_keep_literal_untrusted_text_and_exact_scoped_cli_selectors() {
    let f = Fixture::new();
    let (status, value) = call(
        &f.ui,
        "GET",
        "/api/logs?application=mailroom&instance=production&service=web",
        &[],
        Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(value["text"], "<script>untrusted output</script>\n");
    assert_eq!(
        f.calls()[0],
        json!([
            "logs",
            "--host",
            "host.example.test",
            "--application",
            "mailroom",
            "--instance",
            "production",
            "--service",
            "web"
        ])
    );
    assert_eq!(
        call(
            &f.ui,
            "GET",
            "/api/logs?application=mailroom&application=other&instance=production&service=web",
            &[],
            Value::Null
        )
        .await
        .0,
        400
    );
    assert_eq!(f.calls().len(), 1);
    f.ui.shutdown().await;
}
#[test]
fn only_loopback_fixed_host_owner_client_configuration_is_supported() {
    let binary = std::env::current_exe().unwrap();
    let args = vec![
        "ui".into(),
        "--host".into(),
        "host.example.test".into(),
        "--owner-client".into(),
        binary.to_str().unwrap().into(),
    ];
    assert_eq!(Config::parse(&args).unwrap().port, 0);
    for extra in [
        vec!["--bind", "0.0.0.0"],
        vec!["--bind", "192.0.2.1"],
        vec!["--port", "-1"],
        vec!["--port", "65536"],
        vec!["--hosts", "other"],
        vec!["--report", "/etc/private"],
        vec!["--host", "-oProxyCommand=bad"],
    ] {
        let mut bad = args.clone();
        bad.extend(extra.into_iter().map(str::to_owned));
        assert!(Config::parse(&bad).is_err());
    }
    for mode in ["serve", "preview-ask"] {
        assert!(Config::parse(&[mode.into()]).is_err());
    }
}

#[tokio::test]
async fn failed_confirmed_receipt_is_preserved_without_retry_or_reclassification() {
    let f = Fixture::new();
    std::fs::write(f.root.join("failed"), b"failure").unwrap();
    let (status, value) = call(&f.ui, "POST", "/api/actions", WRITE, action()).await;
    assert_eq!(status, 200);
    assert_eq!(value["confirmation"], "confirmed");
    assert_eq!(value["result"]["ok"], false);
    assert_eq!(value["result"]["phase"], "failed");
    assert_eq!(f.calls().len(), 1);
    f.ui.shutdown().await;
}
#[tokio::test]
async fn shutdown_reaps_owned_client_and_its_pipe_holding_descendant() {
    let f = Fixture::new();
    std::fs::write(f.root.join("hold"), b"hold").unwrap();
    let ui = f.ui.clone();
    let observation =
        tokio::spawn(async move { call(&ui, "GET", "/api/status", &[], Value::Null).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !f.root.join("pids").exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let pids: Vec<i32> = std::fs::read_to_string(f.root.join("pids"))
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    tokio::time::timeout(std::time::Duration::from_secs(5), f.ui.shutdown())
        .await
        .unwrap();
    assert_eq!(observation.await.unwrap().0, 503);
    for pid in pids {
        #[cfg(target_os = "linux")]
        assert!(
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .map_or(true, |value| value.split_whitespace().nth(2) == Some("Z")),
            "owned child still running: {pid}"
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "owned child still running: {pid}"
        );
    }
}
