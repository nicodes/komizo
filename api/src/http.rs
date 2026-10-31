use crate::{
    config::Authority,
    signed::{self, Refusal},
    store::{self, Paths},
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
pub struct Monitor {
    pub authority: Authority,
    pub paths: Paths,
    admission: Arc<Semaphore>,
}
impl Monitor {
    pub fn new(authority: Authority, paths: Paths) -> Arc<Self> {
        Arc::new(Self {
            authority,
            paths,
            admission: Arc::new(Semaphore::new(8)),
        })
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(monitor).with_state(self.clone())
    }
}
fn plain(status: u16, message: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("x-content-type-options", "nosniff"),
        ],
        format!("{message}\n"),
    )
        .into_response()
}
fn document(status: u16, value: serde_json::Value) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        [("x-content-type-options", "nosniff")],
        Json(value),
    )
        .into_response()
}
fn refusal(error: Refusal, read: bool) -> Response {
    match error {
        Refusal::Unsupported(message) => plain(422, &message),
        Refusal::Forbidden => plain(
            403,
            if read {
                "this box will not answer that"
            } else {
                "this box will not act on that"
            },
        ),
    }
}
async fn envelope(request: Request) -> Result<Vec<u8>, Response> {
    tokio::time::timeout(
        Duration::from_secs(30),
        to_bytes(request.into_body(), signed::MAX_COMMAND),
    )
    .await
    .map_err(|_| plain(400, "could not read that request"))?
    .map(|b| b.to_vec())
    .map_err(|error| {
        if error.into_inner().is::<http_body_util::LengthLimitError>() {
            plain(413, "that request is too large")
        } else {
            plain(400, "could not read that request")
        }
    })
}
async fn monitor(State(app): State<Arc<Monitor>>, request: Request) -> Response {
    let now = chrono::Utc::now().timestamp();
    let authority = &app.authority;
    if request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .is_none_or(|token| !signed::read_token(&authority.registry, token, &authority.server, now))
    {
        return plain(401, "unauthorized");
    }
    let Ok(permit) = app.admission.clone().try_acquire_owned() else {
        return plain(503, "this box is busy");
    };
    crate::response::hold(dispatch(app, request, now).await, permit)
}
async fn dispatch(app: Arc<Monitor>, request: Request, now: i64) -> Response {
    let authority = &app.authority;
    let path = request.uri().path().to_owned();
    let method = request.method().clone();
    if matches!(method, Method::GET | Method::HEAD)
        && let Some(id) = path.strip_prefix("/v1/commands/")
    {
        if !signed::id(id) {
            return plain(401, "unauthorized");
        }
        return match store::outcome(&app.paths.results, id) {
            Ok(Some(result)) => document(200, json!({"v":1,"result":result})),
            Ok(None) => plain(404, "no result yet"),
            Err(_) => plain(500, "this box could not read the result of that command"),
        };
    }
    let op = match (method.as_str(), path.as_str()) {
        ("POST", "/v1/report") => "report.read",
        ("POST", "/v1/history") => "history.read",
        ("POST", "/v1/metrics") => "metrics.read",
        ("POST", "/v1/logs") => "logs.read",
        ("POST", "/v1/commands") => "commands",
        _ => return plain(401, "unauthorized"),
    };
    if op == "logs.read" && app.paths.logs.as_os_str().is_empty() {
        return plain(503, "this box is not collecting logs");
    }
    let keys = match op {
        "commands" => authority.operators.clone(),
        "logs.read" => authority.logs.clone(),
        _ => authority.reports(),
    };
    if keys.is_empty() {
        return plain(409, "this box takes orders from nobody");
    }
    if op == "commands"
        && (app.paths.inbox.as_os_str().is_empty() || app.paths.results.as_os_str().is_empty())
    {
        return plain(409, "this box takes orders from nobody");
    }
    let raw = match envelope(request).await {
        Ok(raw) => raw,
        Err(response) => return response,
    };
    let command = match signed::command(&keys, &raw, &authority.server, now) {
        Ok(command) => command,
        Err(error) => return refusal(error, op != "commands"),
    };
    if op != "commands" && command.op != op {
        return plain(403, "this box will not answer that");
    }
    match op {
        "report.read" => match store::report(&app.paths.report) {
            Ok(report) => document(200, json!({"v":1,"report":report})),
            Err(_) => plain(503, "no report yet"),
        },
        "history.read" | "metrics.read" => {
            let (from, to) = match store::window(
                command.args.get("from").map_or("", String::as_str),
                command.args.get("to").map_or("", String::as_str),
                now,
            ) {
                Ok(window) => window,
                Err(error) => return plain(400, &error.message),
            };
            if op == "history.read" {
                let samples = store::samples(&app.paths.history, from, to).unwrap_or(None);
                document(200, json!({"v":1,"from":from,"to":to,"samples":samples}))
            } else {
                match store::metrics(&app.paths.metrics, from, to) {
                    Ok(metrics) => {
                        document(200, json!({"v":1,"from":from,"to":to,"metrics":metrics}))
                    }
                    Err(_) => plain(503, "could not read what was measured"),
                }
            }
        }
        "logs.read" => {
            let name = command.args.get("app").map_or("", String::as_str);
            let service = command.args.get("service").map_or("", String::as_str);
            let tail = match command.args.get("tail").filter(|s| !s.is_empty()) {
                Some(value) => match value.parse::<usize>() {
                    Ok(tail) if (1..=2000).contains(&tail) => tail,
                    _ => return plain(400, "tail must be a number between 1 and 2000"),
                },
                None => 200,
            };
            match store::logs(&app.paths.logs, name, tail, service) {
                Ok(value) => document(200, value),
                Err(error) => plain(error.status.as_u16(), &error.message),
            }
        }
        "commands" => {
            if !signed::APPLY.contains(&command.op.as_str()) {
                return plain(422, "that is not something this route does");
            }
            match store::outcome(&app.paths.results, &command.id) {
                Ok(Some(result)) => return document(200, json!({"v":1,"result":result})),
                Ok(None) => {}
                Err(_) => return plain(500, "this box cannot read what it has already done"),
            }
            match store::enqueue(&app.paths.inbox, &command.id, &raw) {
                Ok(()) => document(202, json!({"v":1,"id":command.id,"status":"accepted"})),
                Err(error) => plain(error.status.as_u16(), &error.message),
            }
        }
        _ => plain(401, "unauthorized"),
    }
}
