use crate::{config::Config, static_files::Static, store};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    sync::{Semaphore, watch},
};
pub struct Ui {
    config: Config,
    files: Static,
    admission: Arc<Semaphore>,
    stop: watch::Sender<bool>,
    tasks: Arc<crate::tasks::Tasks>,
}
impl Ui {
    pub fn new(config: Config, stop: watch::Sender<bool>) -> Arc<Self> {
        Arc::new(Self {
            config,
            files: Static::default(),
            admission: Arc::new(Semaphore::new(8)),
            stop,
            tasks: Arc::new(crate::tasks::Tasks::default()),
        })
    }
    pub async fn shutdown(&self) {
        self.tasks.close();
        let _ = self.stop.send(true);
        self.tasks.join().await;
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self.clone())
    }
}
fn data(value: Value) -> Response {
    (
        [
            ("x-content-type-options", "nosniff"),
            ("cache-control", "no-store"),
        ],
        Json(value),
    )
        .into_response()
}
fn error(status: u16, text: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [("cache-control", "no-store")],
        Json(json!({"error":text})),
    )
        .into_response()
}
#[derive(Deserialize)]
struct Action {
    app: String,
    action: String,
}
async fn handle(State(ui): State<Arc<Ui>>, request: Request) -> Response {
    let Ok(permit) = ui.admission.clone().try_acquire_owned() else {
        return error(503, "this box is busy");
    };
    crate::response::hold(dispatch(ui, request).await, permit)
}
async fn dispatch(ui: Arc<Ui>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let read = matches!(*request.method(), Method::GET | Method::HEAD);
    let paths = &ui.config.paths;
    if read && path == "/api/report" {
        return match store::report(&paths.report) {
            Ok(report) => data(json!({"v":1,"report":report})),
            Err(_) => error(
                503,
                "no report yet -- the agent writes one on its first tick",
            ),
        };
    }
    if read && (path == "/api/history" || path == "/api/metrics") {
        let query = request.uri().query().unwrap_or("");
        let pairs: Vec<_> = form_urlencoded::parse(query.as_bytes()).collect();
        let from = pairs
            .iter()
            .find(|(key, _)| key == "from")
            .map_or("", |(_, value)| value.as_ref());
        let to = pairs
            .iter()
            .find(|(key, _)| key == "to")
            .map_or("", |(_, value)| value.as_ref());
        let (from, to) = match store::window(from, to, chrono::Utc::now().timestamp()) {
            Ok(window) => window,
            Err(e) => return error(400, &e.message),
        };
        if path == "/api/history" {
            return data(
                json!({"v":1,"from":from,"to":to,"samples":store::samples(&paths.history,from,to).unwrap_or(None)}),
            );
        }
        return match store::metrics(&paths.metrics, from, to) {
            Ok(metrics) => data(json!({"v":1,"from":from,"to":to,"metrics":metrics})),
            Err(_) => error(503, "could not read what was measured"),
        };
    }
    if read && path == "/api/events" {
        let mut events = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&paths.results) {
            for entry in entries.take(10000).flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file())
                    && let Some(id) = entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.strip_suffix(".json"))
                    && let Ok(Some(value)) = store::outcome(&paths.results, id)
                {
                    events.push(value);
                }
            }
        }
        events.sort_by(|a, b| {
            b["at"]
                .as_str()
                .unwrap_or("")
                .cmp(a["at"].as_str().unwrap_or(""))
        });
        events.truncate(50);
        return data(json!({"v":1,"events":events}));
    }
    if read && path == "/api/backups" {
        return data(
            json!({"v":1,"backups":[],"note":"backups are not tracked on this box yet -- no box-local backup state exists, so this screen shows the absence rather than a guess. Planned for a later version."}),
        );
    }
    if path == "/api/action" {
        if request.method() != Method::POST {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                [("allow", "POST")],
                Json(json!({"error":"POST only"})),
            )
                .into_response();
        }
        let raw = match tokio::time::timeout(
            Duration::from_secs(30),
            to_bytes(request.into_body(), 4096),
        )
        .await
        {
            Ok(Ok(raw)) => raw,
            _ => return error(400, "could not read that request"),
        };
        let action: Action = match serde_json::from_slice(&raw) {
            Ok(action) => action,
            Err(_) => return error(400, "could not read that request"),
        };
        if !matches!(action.action.as_str(), "start" | "stop" | "restart") {
            return error(
                403,
                "not an action this serves: the allowlist is start, stop, restart",
            );
        }
        if !store::app(&action.app) || action.app.starts_with('_') {
            return error(400, "invalid app name");
        }
        if !paths.apps.join(format!("{}.env", action.app)).is_file() {
            return error(404, "not an app on this box");
        }
        // The independently installed privileged host executor retains its own
        // immutable-image, operation, stop-intent and resource authority. The
        // API invokes only its existing finite lifecycle command, never a Go
        // HTTP service or an arbitrary caller-supplied command line.
        let Some(lease) = ui.tasks.acquire() else {
            return error(503, "API is stopping");
        };
        return match lifecycle(
            Path::new("/usr/local/bin/komizo-box"),
            &action.app,
            &action.action,
            ui.stop.subscribe(),
            lease,
        )
        .await
        {
            Ok((ok, output)) => data(json!({"v":1,"ok":ok,"output":output})),
            Err(status) => error(
                status,
                if status == 504 {
                    "action did not finish in two minutes"
                } else {
                    "host lifecycle command unavailable"
                },
            ),
        };
    }
    if path.starts_with("/api/") {
        return error(404, "no such read");
    }
    ui.files
        .response(&path, request.method(), request.headers())
}
async fn lifecycle(
    binary: &Path,
    app: &str,
    action: &str,
    mut stop: watch::Receiver<bool>,
    lease: crate::tasks::Lease,
) -> Result<(bool, String), u16> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["app", action, "--app", app])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = command.spawn().map_err(|_| 503u16)?;
    let pid = child.id().unwrap_or(0) as i32;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (mut sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _lease = lease;
        let mut output = tokio::spawn(async move {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut stdout = stdout.take((1 << 20) + 1);
            let mut stderr = stderr.take((1 << 20) + 1);
            let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
            if a.is_err() || b.is_err() || out.len() > 1 << 20 || err.len() > 1 << 20 {
                return Err(503u16);
            }
            out.extend_from_slice(&err);
            Ok(String::from_utf8_lossy(&out).into_owned())
        });
        let result = tokio::select! {_=sender.closed()=>None,_=stop.changed()=>Some(Err(503u16)),_=tokio::time::sleep(Duration::from_secs(120))=>Some(Err(504u16)),status=child.wait()=>Some(status.map(|s|s.success()).map_err(|_|503u16))};
        if pid > 0 {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
        let captured = match tokio::time::timeout(Duration::from_secs(1), &mut output).await {
            Ok(result) => result.map_err(|_| 503u16).and_then(|result| result),
            Err(_) => {
                output.abort();
                let _ = output.await;
                Err(503u16)
            }
        };
        if let Some(result) = result {
            let _ = sender.send(result.and_then(|ok| captured.map(|output| (ok, output))));
        }
    });
    receiver.await.map_err(|_| 503u16)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn finite_host_executor_keeps_argv_failure_and_shutdown_owned() {
        let directory =
            std::env::temp_dir().join(format!("komizo-ui-executor-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let binary = directory.join("executor");
        std::fs::write(
            &binary,
            b"#!/bin/sh\nprintf '%s\\n' \"$@\"\nprintf 'diagnostic\\n' >&2\nexit 7\n",
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let tasks = Arc::new(crate::tasks::Tasks::default());
        let (stop, stopping) = watch::channel(false);
        let (ok, output) = lifecycle(&binary, "web", "stop", stopping, tasks.acquire().unwrap())
            .await
            .unwrap();
        assert!(!ok);
        assert_eq!(output, "app\nstop\n--app\nweb\ndiagnostic\n");
        std::fs::write(
            &binary,
            b"#!/bin/sh\nprintf '%s' \"$$\" > \"$0.pid\"\nexec sleep 30\n",
        )
        .unwrap();
        let pid_file = directory.join("executor.pid");
        let lease = tasks.acquire().unwrap();
        let command = tokio::spawn({
            let binary = binary.clone();
            let stopping = stop.subscribe();
            async move { lifecycle(&binary, "web", "restart", stopping, lease).await }
        });
        let pid = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(text) = std::fs::read_to_string(&pid_file)
                    && let Ok(pid) = text.parse::<i32>()
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tasks.close();
        let _ = stop.send(true);
        tokio::time::timeout(Duration::from_secs(3), tasks.join())
            .await
            .unwrap();
        assert!(command.await.unwrap().is_err());
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
