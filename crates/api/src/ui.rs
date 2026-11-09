use crate::{
    config::{self, Config},
    static_files::Static,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{Semaphore, watch},
};

const MAX_DOCUMENT: usize = 4 << 20;
const MAX_DIAGNOSTIC: usize = 64 << 10;
#[derive(Default)]
struct History {
    samples: VecDeque<(usize, Value)>,
    bytes: usize,
}
impl History {
    fn push(&mut self, value: Value) {
        let size = serde_json::to_vec(&value).unwrap().len();
        if size > 2 << 20 {
            return;
        }
        self.samples.push_back((size, value));
        self.bytes += size;
        while self.samples.len() > 120 || self.bytes > 2 << 20 {
            self.bytes -= self.samples.pop_front().unwrap().0;
        }
    }
}

pub struct Ui {
    config: Config,
    files: Static,
    admission: Arc<Semaphore>,
    stop: watch::Sender<bool>,
    tasks: Arc<crate::tasks::Tasks>,
    history: Mutex<History>,
    session: crate::session::Session,
}
impl Ui {
    pub fn new(
        config: Config,
        session: crate::session::Session,
        stop: watch::Sender<bool>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            files: Static::default(),
            admission: Arc::new(Semaphore::new(8)),
            stop,
            tasks: Arc::new(crate::tasks::Tasks::default()),
            history: Mutex::new(History::default()),
            session,
        })
    }
    pub async fn shutdown(&self) {
        self.tasks.close();
        let _ = self.stop.send(true);
        self.tasks.join().await;
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .fallback(handle)
            .layer(axum::middleware::from_fn(httpcontract::observe))
            .with_state(self.clone())
    }
    async fn invoke(
        &self,
        action: &str,
        options: &[String],
        seconds: u64,
    ) -> Result<Captured, u16> {
        let lease = self.tasks.acquire().ok_or(503u16)?;
        let mut args = vec![action.to_owned(), "--host".into(), self.config.host.clone()];
        if let Some(identity) = &self.config.identity {
            args.extend(["--identity".into(), identity.to_string_lossy().into_owned()]);
        }
        args.extend_from_slice(options);
        owner_command(
            self.config.owner_client.clone(),
            args,
            seconds,
            self.stop.subscribe(),
            lease,
        )
        .await
    }
}
fn data(value: Value) -> Response {
    ([("cache-control", "no-store")], Json(value)).into_response()
}
fn error(status: u16, message: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [("cache-control", "no-store")],
        Json(json!({"error":{"message":message}})),
    )
        .into_response()
}
fn security(mut response: Response) -> Response {
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'",
        ),
    ] {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}
fn browser_boundary(config: &Config, request: &Request) -> Result<(), u16> {
    let headers = request.headers();
    let hosts: Vec<_> = headers.get_all("host").iter().collect();
    if hosts.len() != 1 {
        return Err(403);
    }
    let host = hosts[0].to_str().map_err(|_| 403u16)?;
    let allowed = [config.authority(), format!("localhost:{}", config.port)];
    if !allowed.iter().any(|value| value == host)
        || request
            .uri()
            .authority()
            .is_some_and(|authority| authority.as_str() != host)
    {
        return Err(403);
    }
    if request.uri().path().starts_with("/api/") {
        if headers.get_all("origin").iter().count() > 1 {
            return Err(403);
        }
        if let Some(origin) = headers.get("origin")
            && origin.to_str().ok() != Some(format!("http://{host}").as_str())
        {
            return Err(403);
        }
        if let Some(site) = headers.get("sec-fetch-site")
            && !matches!(site.to_str().ok(), Some("same-origin" | "none"))
        {
            return Err(403);
        }
        if request.method() == Method::POST {
            if headers.get("origin").is_none()
                || headers
                    .get("x-komizo-request")
                    .and_then(|value| value.to_str().ok())
                    != Some("1")
            {
                return Err(403);
            }
            if headers.get_all("content-type").iter().count() != 1
                || headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.split(';').next().unwrap().trim())
                    != Some("application/json")
            {
                return Err(415);
            }
        }
    }
    Ok(())
}
fn query(request: &Request, allowed: &[&str]) -> Result<BTreeMap<String, String>, u16> {
    let raw = request.uri().query().unwrap_or("");
    if raw.len() > 4096 {
        return Err(400);
    }
    let mut values = BTreeMap::new();
    for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
        if !allowed.contains(&key.as_ref())
            || values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(400);
        }
    }
    Ok(values)
}
fn scope(values: &BTreeMap<String, String>) -> Result<Vec<String>, u16> {
    let application = values.get("application").ok_or(400u16)?;
    let instance = values.get("instance").ok_or(400u16)?;
    if !config::name(application) || !config::name(instance) {
        return Err(400);
    }
    Ok(vec![
        "--application".into(),
        application.clone(),
        "--instance".into(),
        instance.clone(),
    ])
}
fn document(captured: &Captured) -> Result<Value, u16> {
    let value: Value = serde_json::from_slice(&captured.stdout).map_err(|_| 503u16)?;
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(503);
    }
    Ok(value)
}
fn status_valid(value: &Value) -> bool {
    value["kind"] == "komizo.status"
        && value["instances"].as_array().is_some_and(|instances| {
            instances.len() <= 512
                && instances.iter().all(|instance| {
                    instance["application"].as_str().is_some_and(config::name)
                        && instance["instance"].as_str().is_some_and(config::name)
                        && instance["release_digest"]
                            .as_str()
                            .is_some_and(config::digest)
                        && instance["desired_running"].is_boolean()
                        && instance["services"].as_object().is_some_and(|services| {
                            services.len() <= 64 && services.keys().all(|name| config::name(name))
                        })
                })
        })
}
fn operation_valid(value: &Value, action: &Action, operation: &str) -> bool {
    value["kind"] == "komizo.operation"
        && value["version"] == 1
        && value["application"] == action.application
        && value["instance"] == action.instance
        && value["release_digest"] == action.release_digest
        && value["operation_id"] == operation
        && value["ok"].is_boolean()
        && value["phase"].as_str().is_some_and(|phase| {
            matches!(
                phase,
                "admitted"
                    | "staging"
                    | "jobs"
                    | "installing"
                    | "activating"
                    | "readiness"
                    | "ready"
                    | "prepared_stopped"
                    | "failed"
                    | "needs_reconciliation"
            )
        })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    application: String,
    instance: String,
    action: String,
    release_digest: String,
    nonce: String,
}
pub fn operation_id(application: &str, instance: &str, nonce: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!("komizo-operation-v1\0{application}\0{instance}\0{nonce}").as_bytes()
        )
    )[..32]
        .to_owned()
}
struct RequestFile(PathBuf);
impl RequestFile {
    fn new(value: &Value) -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "komizo-ui-request-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let selected = Self(path);
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        Ok(selected)
    }
}
impl Drop for RequestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn change(ui: &Ui, action: Action) -> Response {
    if !config::name(&action.application)
        || !config::name(&action.instance)
        || !config::digest(&action.release_digest)
        || !config::hex(&action.nonce, 32)
    {
        return error(400, "invalid application operation identity");
    }
    if !matches!(
        action.action.as_str(),
        "start" | "stop" | "restart" | "backup"
    ) {
        return error(403, "unsupported owner action");
    }
    let proposed = operation_id(&action.application, &action.instance, &action.nonce);
    let now = chrono::Utc::now().timestamp();
    let request = json!({"kind":"komizo.request","version":1,"authority":"owner","application":action.application,
        "instance":action.instance,"action":action.action,"release_digest":action.release_digest,"nonce":action.nonce,
        "issued_at":now,"expires_at":now+120,"timeout_seconds":1500});
    let file = match RequestFile::new(&request) {
        Ok(file) => file,
        Err(_) => return error(503, "could not prepare the owner request"),
    };
    let submitted = ui
        .invoke(
            "request",
            &["--file".into(), file.0.to_string_lossy().into_owned()],
            35,
        )
        .await;
    if let Ok(captured) = &submitted
        && let Ok(value) = document(captured)
        && operation_valid(&value, &action, &proposed)
    {
        return data(
            json!({"kind":"komizo.ui.action","version":1,"confirmation":"confirmed","operation_id":proposed,"result":value}),
        );
    }
    if *ui.stop.borrow() {
        return error(
            503,
            "UI is stopping; inspect the proposed operation before another change",
        );
    }
    let options = vec![
        "--application".into(),
        action.application.clone(),
        "--instance".into(),
        action.instance.clone(),
        "--operation".into(),
        proposed.clone(),
        "--release".into(),
        action.release_digest.clone(),
    ];
    if let Ok(captured) = ui.invoke("inspect", &options, 20).await
        && let Ok(value) = document(&captured)
        && operation_valid(&value, &action, &proposed)
    {
        return data(
            json!({"kind":"komizo.ui.action","version":1,"confirmation":"observed","operation_id":proposed,"result":value}),
        );
    }
    data(
        json!({"kind":"komizo.ui.action","version":1,"confirmation":"unconfirmed","operation_id":proposed,
        "message":"Admission is unconfirmed. Inspect this operation before another change."}),
    )
}
async fn handle(State(ui): State<Arc<Ui>>, request: Request) -> Response {
    if let Err(status) = browser_boundary(&ui.config, &request) {
        return security(error(status, "local same-origin request required"));
    }
    if request.uri().path().starts_with("/api/") && !ui.session.authorizes(request.headers()) {
        return security(error(
            403,
            "open the owner-private launcher to access this session",
        ));
    }
    let Ok(permit) = ui.admission.clone().try_acquire_owned() else {
        return security(error(503, "local UI is busy"));
    };
    let head = request.method() == Method::HEAD;
    let mut response = dispatch(ui, request).await;
    if head {
        *response.body_mut() = axum::body::Body::empty();
    }
    security(crate::response::hold(response, permit))
}
async fn dispatch(ui: Arc<Ui>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let read = matches!(*request.method(), Method::GET | Method::HEAD);
    if read && matches!(path.as_str(), "/healthz" | "/readyz") {
        let ready = !*ui.stop.borrow();
        return (
            if ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            httpcontract::health(
                if ready { "ready" } else { "stopping" },
                option_env!("SOURCE_COMMIT").unwrap_or("development"),
            ),
        )
            .into_response();
    }
    if read && path == "/api/status" {
        if !request.uri().query().unwrap_or("").is_empty() {
            return error(400, "status takes no selectors");
        }
        let captured = match ui.invoke("status", &[], 20).await {
            Ok(value) => value,
            Err(_) => return error(503, "owner host status is unavailable"),
        };
        let value = match document(&captured) {
            Ok(value) if captured.success && status_valid(&value) => value,
            _ => return error(503, "owner host returned an invalid status document"),
        };
        let observation = json!({"captured_at":chrono::Utc::now().to_rfc3339(),"status":value});
        {
            let mut history = ui.history.lock().unwrap();
            history.push(observation.clone());
        }
        return data(
            json!({"kind":"komizo.ui.status","version":1,"host":ui.config.host,"captured_at":observation["captured_at"],"status":observation["status"]}),
        );
    }
    if read && path == "/api/history" {
        if !request.uri().query().unwrap_or("").is_empty() {
            return error(400, "history takes no selectors");
        }
        return data(
            json!({"kind":"komizo.ui.history","version":1,"scope":"local UI observations","samples":ui.history.lock().unwrap().samples.iter().map(|(_,value)|value.clone()).collect::<Vec<_>>()}),
        );
    }
    if read && matches!(path.as_str(), "/api/operation" | "/api/logs") {
        let values = match query(
            &request,
            if path == "/api/logs" {
                &["application", "instance", "service"]
            } else {
                &["application", "instance", "operation", "release_digest"]
            },
        ) {
            Ok(value) => value,
            Err(status) => return error(status, "invalid observation selectors"),
        };
        let mut options = match scope(&values) {
            Ok(value) => value,
            Err(status) => return error(status, "an application instance is required"),
        };
        let action = if path == "/api/logs" {
            let Some(service) = values.get("service").filter(|value| config::name(value)) else {
                return error(400, "one admitted service is required");
            };
            options.extend(["--service".into(), service.clone()]);
            "logs"
        } else {
            let Some(operation) = values
                .get("operation")
                .filter(|value| config::hex(value, 32))
            else {
                return error(400, "an exact operation identity is required");
            };
            let Some(release) = values
                .get("release_digest")
                .filter(|value| config::digest(value))
            else {
                return error(400, "an exact release identity is required");
            };
            options.extend([
                "--operation".into(),
                operation.clone(),
                "--release".into(),
                release.clone(),
            ]);
            "inspect"
        };
        let captured = match ui.invoke(action, &options, 20).await {
            Ok(value) => value,
            Err(_) => return error(503, "owner observation is unavailable"),
        };
        let value = match document(&captured) {
            Ok(value) if captured.success => value,
            _ => return error(503, "owner observation is unavailable"),
        };
        let valid = if action == "logs" {
            value["kind"] == "komizo.logs"
                && value["service"] == values["service"]
                && value["text"]
                    .as_str()
                    .is_some_and(|text| text.len() <= 256 << 10)
        } else {
            value["kind"] == "komizo.operation"
                && value["operation_id"] == values["operation"]
                && value["release_digest"] == values["release_digest"]
        };
        if !valid
            || value["application"] != values["application"]
            || value["instance"] != values["instance"]
        {
            return error(503, "owner observation identity changed");
        };
        return data(value);
    }
    if path == "/api/actions" && request.method() == Method::POST {
        if !request.uri().query().unwrap_or("").is_empty() {
            return error(400, "actions do not take URL selectors");
        };
        let raw =
            match tokio::time::timeout(Duration::from_secs(5), to_bytes(request.into_body(), 4096))
                .await
            {
                Ok(Ok(value)) => value,
                _ => return error(400, "bounded JSON action required"),
            };
        let action = match serde_json::from_slice::<Action>(&raw) {
            Ok(value) => value,
            Err(_) => return error(400, "closed JSON action required"),
        };
        return change(&ui, action).await;
    }
    if path.starts_with("/api/") {
        return error(
            if read { 404 } else { 405 },
            "unsupported local UI operation",
        );
    };
    ui.files
        .response(&path, request.method(), request.headers())
}
struct Captured {
    success: bool,
    stdout: Vec<u8>,
}
async fn limited(
    stream: impl tokio::io::AsyncRead + Unpin,
    maximum: usize,
) -> Result<Vec<u8>, u16> {
    let mut bytes = Vec::new();
    stream
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| 503u16)?;
    if bytes.len() > maximum {
        return Err(503);
    };
    Ok(bytes)
}
async fn owner_command(
    binary: PathBuf,
    args: Vec<String>,
    seconds: u64,
    mut stop: watch::Receiver<bool>,
    lease: crate::tasks::Lease,
) -> Result<Captured, u16> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let inherited = std::env::vars_os().filter(|(key, _)| {
        matches!(
            key.to_str(),
            Some(
                "PATH"
                    | "HOME"
                    | "USER"
                    | "LOGNAME"
                    | "SSH_AUTH_SOCK"
                    | "XDG_CONFIG_HOME"
                    | "LANG"
                    | "LC_ALL"
            )
        )
    });
    command.env_clear().envs(inherited);
    let mut child = command.spawn().map_err(|_| 503u16)?;
    let pid = child.id().ok_or(503u16)? as i32;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (mut sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _lease = lease;
        let result = {
            let work = async {
                let (stdout, _stderr) = tokio::try_join!(
                    limited(stdout, MAX_DOCUMENT),
                    limited(stderr, MAX_DIAGNOSTIC)
                )?;
                let success = child.wait().await.map_err(|_| 503u16)?.success();
                Ok(Captured { success, stdout })
            };
            tokio::pin!(work);
            tokio::select! {value=&mut work=>Some(value),_=sender.closed()=>None,_=stop.changed()=>Some(Err(503u16)),_=tokio::time::sleep(Duration::from_secs(seconds))=>Some(Err(504u16))}
        };
        if !matches!(result, Some(Ok(_))) {
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }
            // Keep the leader unreaped until the whole process group has been
            // stopped. A descendant can retain the pipes after its parent exits.
            tokio::time::sleep(Duration::from_secs(2)).await;
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        if let Some(result) = result {
            let _ = sender.send(result);
        }
    });
    receiver.await.map_err(|_| 503u16)?
}
