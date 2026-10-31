use crate::error::{Result, fail, invalid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};
#[derive(Clone)]
pub struct Paths {
    pub report: PathBuf,
    pub history: PathBuf,
    pub metrics: PathBuf,
    pub results: PathBuf,
    pub logs: PathBuf,
    pub inbox: PathBuf,
    pub apps: PathBuf,
}
impl Default for Paths {
    fn default() -> Self {
        Self {
            report: "/run/komizo/report.json".into(),
            history: "/var/lib/komizo/served/history.jsonl".into(),
            metrics: "/var/lib/komizo/served/metrics.json".into(),
            results: "/var/lib/komizo/served/results".into(),
            logs: "/var/lib/komizo/served/logs".into(),
            inbox: "/run/komizo/inbox".into(),
            apps: "/var/lib/komizo/apps".into(),
        }
    }
}
pub fn bytes(path: &Path, maximum: usize) -> std::io::Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(std::io::Error::other("file exceeds bounded read"));
    }
    Ok(bytes)
}
pub fn report(path: &Path) -> Result<Value> {
    let value: Value =
        serde_json::from_slice(&bytes(path, 4 << 20)?).map_err(|_| fail(503, "no report yet"))?;
    if value["v"].as_i64().is_none_or(|v| v != 1) {
        return Err(fail(503, "unsupported report schema"));
    }
    Ok(value)
}
pub fn window(from: &str, to: &str, now: i64) -> Result<(i64, i64)> {
    let start = if from.is_empty() {
        now.saturating_sub(3600)
    } else {
        from.parse().map_err(|_| {
            invalid("from and to must be unix seconds, and from must not be after to")
        })?
    };
    let end = if to.is_empty() {
        now
    } else {
        to.parse().map_err(|_| {
            invalid("from and to must be unix seconds, and from must not be after to")
        })?
    };
    if start > end {
        return Err(invalid(
            "from and to must be unix seconds, and from must not be after to",
        ));
    }
    Ok((start, end))
}
pub fn samples(path: &Path, from: i64, to: i64) -> std::io::Result<Option<Vec<Value>>> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a history file"));
    }
    let offset = meta.len().saturating_sub(8 << 20);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(8 << 20).read_to_end(&mut bytes)?;
    let mut lines = bytes.split(|b| *b == b'\n');
    if offset > 0 {
        lines.next();
    }
    let mut rows = Vec::new();
    for line in lines {
        if line.len() > 4 << 20 {
            return Err(std::io::Error::other("history line exceeds limit"));
        }
        if let Ok(value) = serde_json::from_slice::<Value>(line)
            && let Some(at) = value["at"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            && at.timestamp() >= from
            && at.timestamp() <= to
        {
            rows.push(value);
        }
    }
    Ok((!rows.is_empty()).then_some(rows))
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct Metrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    span: Option<Span>,
    #[serde(default, deserialize_with = "nullable_rows")]
    rows: Vec<Metric>,
}
#[derive(Deserialize, Serialize)]
struct Span {
    from: i64,
    to: i64,
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct Metric {
    minute: i64,
    app: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    service: String,
    #[serde(skip_serializing_if = "zero")]
    c2: i64,
    #[serde(skip_serializing_if = "zero")]
    c3: i64,
    #[serde(skip_serializing_if = "zero")]
    c4: i64,
    #[serde(skip_serializing_if = "zero")]
    c5: i64,
}
fn nullable_rows<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Metric>, D::Error> {
    Ok(Option::<Vec<Metric>>::deserialize(deserializer)?.unwrap_or_default())
}
fn zero(n: &i64) -> bool {
    *n == 0
}
pub fn metrics(path: &Path, from: i64, to: i64) -> Result<Value> {
    let raw = match bytes(path, 4 << 20) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!({"rows":[]})),
        Err(e) => return Err(e.into()),
    };
    let mut metrics: Metrics =
        serde_json::from_slice(&raw).map_err(|_| fail(503, "could not read what was measured"))?;
    metrics.rows.retain(|r| r.minute >= from && r.minute <= to);
    metrics.span = metrics.span.and_then(|span| {
        let lo = span.from.max(from);
        let hi = span.to.min(to);
        (lo <= hi).then_some(Span { from: lo, to: hi })
    });
    serde_json::to_value(metrics).map_err(|_| fail(503, "could not read what was measured"))
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Outcome {
    pub v: i64,
    pub id: String,
    pub op: String,
    pub at: Option<chrono::DateTime<chrono::Utc>>,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}
pub fn outcome(directory: &Path, id: &str) -> Result<Option<Value>> {
    if !crate::signed::id(id) {
        return Err(invalid("invalid command id"));
    }
    let raw = match bytes(&directory.join(format!("{id}.json")), 1 << 20) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let value: Outcome = serde_json::from_slice(&raw)
        .map_err(|_| fail(500, "this box could not read the result of that command"))?;
    serde_json::to_value(value)
        .map(Some)
        .map_err(|_| fail(500, "this box could not read the result of that command"))
}
pub fn app(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
pub fn logs(directory: &Path, name: &str, tail: usize, service: &str) -> Result<Value> {
    if !app(name) || name.len() > 100 {
        return Err(invalid("that is not an app"));
    }
    if !(1..=2000).contains(&tail) {
        return Err(invalid("tail must be a number between 1 and 2000"));
    }
    if service.len() > 100 || service.chars().any(|c| c <= ' ' || c == '\x7f') {
        return Err(invalid("that is not a service name"));
    }
    let raw = match bytes(&directory.join(format!("{name}.log")), 8 << 20) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(fail(404, "nothing collected for that app yet"));
        }
        Err(_) => return Err(fail(503, "this box could not read that log")),
    };
    let text = String::from_utf8_lossy(&raw);
    let mut lines: Vec<_> = text.trim_end_matches('\n').split('\n').collect();
    let read = if service.is_empty() { tail } else { 2000 };
    if lines.len() > read {
        lines.drain(..lines.len() - read);
    }
    let mut services = Vec::new();
    let mut selected = Vec::new();
    for line in lines.into_iter().filter(|s| !s.is_empty()) {
        let (svc, _) = line.split_once('\t').unwrap_or(("", line));
        if !svc.is_empty() && !services.contains(&svc) {
            services.push(svc);
        }
        if service.is_empty() || svc == service {
            selected.push(line);
        }
    }
    if selected.len() > tail {
        selected.drain(..selected.len() - tail);
    }
    let mut value = json!({"v":1,"app":name,"lines":selected.join("\n")});
    if !service.is_empty() {
        value["service"] = json!(service);
    }
    if !services.is_empty() {
        value["services"] = json!(services);
    }
    Ok(value)
}
static INBOX: Mutex<()> = Mutex::new(());
pub fn enqueue(directory: &Path, id: &str, raw: &[u8]) -> Result<()> {
    if !crate::signed::id(id) || raw.len() > crate::signed::MAX_COMMAND {
        return Err(invalid("invalid command"));
    }
    let _guard = INBOX.lock().unwrap();
    let count = fs::read_dir(directory)?.take(128).count();
    if count >= 128 {
        return Err(fail(503, "this box has too many commands waiting"));
    }
    let final_path = directory.join(id);
    match fs::symlink_metadata(&final_path) {
        Ok(meta) => {
            if meta.is_file() {
                return Ok(());
            }
            return Err(fail(503, "command path is not a regular file"));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let temporary = directory.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(raw)?;
        file.sync_all()?;
        fs::rename(&temporary, &final_path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metrics_window_clips_coverage_and_drops_private_fields() {
        let directory =
            std::env::temp_dir().join(format!("komizo-rust-store-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("metrics.json");
        fs::write(&path,br#"{"span":{"from":1,"to":100},"rows":[{"minute":10,"app":"web","c2":1,"private_ip":"secret"},{"minute":50,"app":"web","c2":2}]}"#).unwrap();
        let value = metrics(&path, 20, 60).unwrap();
        assert_eq!(value["span"], json!({"from":20,"to":60}));
        assert_eq!(value["rows"].as_array().unwrap().len(), 1);
        assert!(!value.to_string().contains("secret"));
        assert!(metrics(&path, 101, 200).unwrap().get("span").is_none());
        fs::remove_dir_all(directory).unwrap();
    }
}
