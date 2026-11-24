//! Bounded advisory record of the latest maintenance outcome per service.
//!
//! The maintenance loop runs every second and used to discard every result.
//! One small protected file per service now names the most recent outcome, how
//! long it has lasted and whether the service has been down too long. The files
//! carry no authority: nothing reads them to decide an effect, an absent or
//! unreadable file is simply "no record", and a release that predates them
//! never opens the directory.
use super::{
    controller,
    store::{self, Store},
    units,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

/// A desired, eligible service that has not been running this long is stuck.
pub(super) const STUCK_SECONDS: i64 = 120;
/// An unchanged outcome is persisted at most this often.
const REWRITE_SECONDS: i64 = 60;
const MAX_BYTES: usize = 4096;
const ERROR_CHARS: usize = 256;
const KIND: &str = "komizo.service-maintenance";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Record {
    pub kind: String,
    pub version: u32,
    /// `ok`, `skipped:<reason>` or `error`.
    pub outcome: String,
    /// The maintenance step that failed; only present for `error`.
    pub stage: Option<String>,
    /// Sanitized and bounded; only present for `error`.
    pub error: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Consecutive passes with this same outcome and stage.
    pub count: u64,
    pub not_running_since: Option<i64>,
    pub stuck: bool,
}

/// What one maintenance pass concluded.
pub(super) struct Pass {
    pub outcome: String,
    pub stage: Option<String>,
    pub error: Option<String>,
    /// `Some` only when the pass observed the container itself.
    pub running: Option<bool>,
    /// False when the instance is not eligible for maintenance; this clears
    /// the not-running timer because nothing is expected to run.
    pub eligible: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Events {
    pub error_started: bool,
    pub stuck_started: bool,
    pub stuck_ended: bool,
}

/// Fold one pass into the previous record. Pure, so it is directly testable.
pub(super) fn advance(
    previous: Option<&Record>,
    pass: &Pass,
    sanitized: impl FnOnce(&str) -> String,
    now: i64,
) -> (Record, Events) {
    let same = previous.is_some_and(|p| p.outcome == pass.outcome && p.stage == pass.stage);
    let not_running_since = if !pass.eligible {
        None
    } else {
        match pass.running {
            Some(false) => previous.and_then(|p| p.not_running_since).or(Some(now)),
            Some(true) => None,
            None => previous.and_then(|p| p.not_running_since),
        }
    };
    let stuck = not_running_since.is_some_and(|since| now.saturating_sub(since) > STUCK_SECONDS);
    let error = match (&pass.error, same, previous) {
        (None, _, _) => None,
        (Some(_), true, Some(p)) if p.error.is_some() => p.error.clone(),
        (Some(raw), _, _) => Some(sanitized(raw)),
    };
    let events = Events {
        error_started: pass.outcome == "error" && !same,
        stuck_started: stuck && !previous.is_some_and(|p| p.stuck),
        stuck_ended: !stuck && previous.is_some_and(|p| p.stuck),
    };
    (
        Record {
            kind: KIND.into(),
            version: 1,
            outcome: pass.outcome.clone(),
            stage: pass.stage.clone(),
            error,
            first_seen: if same {
                previous.unwrap().first_seen
            } else {
                now
            },
            last_seen: now,
            count: if same { previous.unwrap().count + 1 } else { 1 },
            not_running_since,
            stuck,
        },
        events,
    )
}

/// Persist on a change, a stuck transition, or once per `REWRITE_SECONDS`.
fn persist_due(
    previous: Option<&Record>,
    written_at: Option<i64>,
    next: &Record,
    now: i64,
) -> bool {
    match (previous, written_at) {
        (Some(p), Some(at)) => {
            p.outcome != next.outcome
                || p.stage != next.stage
                || p.stuck != next.stuck
                || p.not_running_since.is_some() != next.not_running_since.is_some()
                || now.saturating_sub(at) >= REWRITE_SECONDS
        }
        _ => true,
    }
}

fn path(
    root: &std::path::Path,
    application: &str,
    instance: &str,
    service: &str,
) -> Result<PathBuf> {
    ensure!(
        !service.is_empty()
            && service
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid maintenance service name"
    );
    Ok(root
        .join("maintenance")
        .join(units::namespace(application, instance)?)
        .join(format!("{service}.json")))
}

fn load(
    root: &std::path::Path,
    application: &str,
    instance: &str,
    service: &str,
) -> Option<Record> {
    let path = path(root, application, instance, service).ok()?;
    let body = store::read_protected(&path, MAX_BYTES).ok()?;
    let record: Record = serde_json::from_slice(&body).ok()?;
    (record.kind == KIND && record.version == 1).then_some(record)
}

/// Advisory view for `status`; never fails the caller. An instance that is
/// deliberately stopped or removed is not expected to run, so it is never
/// reported stuck, whatever an older pass recorded.
pub(super) fn read(
    store: &Store,
    application: &str,
    instance: &str,
    service: &str,
    expected_running: bool,
) -> Value {
    let Some(mut record) = load(&store.root, application, instance, service) else {
        return Value::Null;
    };
    if !expected_running {
        record.stuck = false;
        record.not_running_since = None;
    }
    serde_json::to_value(record).unwrap_or(Value::Null)
}

struct Cached {
    record: Record,
    written_at: Option<i64>,
}
type Key = (PathBuf, String, String, String);
fn cache() -> &'static Mutex<BTreeMap<Key, Cached>> {
    static CACHE: OnceLock<Mutex<BTreeMap<Key, Cached>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Bound the generic text: first line of the cause chain, printable only.
pub(super) fn bounded(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(ERROR_CHARS)
        .collect()
}

/// Record one pass. `sanitize` redacts secrets from a new error text and runs
/// only when the outcome changes, never on every second.
pub(super) fn record(
    root: &std::path::Path,
    application: &str,
    instance: &str,
    service: &str,
    pass: &Pass,
    sanitize: impl FnOnce(&str) -> String,
) {
    let Ok(now) = controller::now() else {
        return;
    };
    let key: Key = (
        root.to_owned(),
        application.to_owned(),
        instance.to_owned(),
        service.to_owned(),
    );
    let (previous, written_at) = {
        let guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        match guard.get(&key) {
            Some(cached) => (Some(cached.record.clone()), cached.written_at),
            None => (None, None),
        }
    };
    // A restarted controller continues the durable record, so a stuck
    // condition and its start time survive it.
    let (previous, written_at) = if previous.is_none() {
        let loaded = load(root, application, instance, service);
        (loaded, None)
    } else {
        (previous, written_at)
    };
    let (next, events) = advance(previous.as_ref(), pass, |raw| bounded(&sanitize(raw)), now);
    let write = persist_due(
        previous.as_ref(),
        written_at.or(previous.as_ref().map(|p| p.last_seen)),
        &next,
        now,
    );
    let written = if write {
        let stored = path(root, application, instance, service).and_then(|path| {
            store::atomic(
                &path,
                &super::canonical(&serde_json::to_value(&next)?)?,
                0o600,
            )
        });
        stored.is_ok().then_some(now).or(written_at)
    } else {
        written_at
    };
    cache().lock().unwrap_or_else(|e| e.into_inner()).insert(
        key,
        Cached {
            record: next.clone(),
            written_at: written,
        },
    );
    let name = format!("{application}/{instance}/{service}");
    if events.error_started {
        log(
            libc::LOG_WARNING,
            &format!(
                "maintenance {name}: error at {}: {}",
                next.stage.as_deref().unwrap_or("unknown"),
                next.error.as_deref().unwrap_or("")
            ),
        );
    }
    if events.stuck_started {
        log(
            libc::LOG_ERR,
            &format!(
                "maintenance {name}: stuck, not running since {} (last outcome {})",
                next.not_running_since.unwrap_or(now),
                next.outcome
            ),
        );
    }
    if events.stuck_ended {
        log(
            libc::LOG_NOTICE,
            &format!("maintenance {name}: no longer stuck"),
        );
    }
}

#[cfg(not(test))]
fn log(priority: libc::c_int, message: &str) {
    let text = message.replace('\0', " ");
    if let Ok(text) = std::ffi::CString::new(text) {
        // Without openlog the identity defaults to the program name. The
        // constant format keeps the message from ever being interpreted.
        unsafe { libc::syslog(libc::LOG_DAEMON | priority, c"%s".as_ptr(), text.as_ptr()) };
    }
}
#[cfg(test)]
fn log(_priority: libc::c_int, _message: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn pass(outcome: &str, running: Option<bool>) -> Pass {
        Pass {
            outcome: outcome.into(),
            stage: None,
            error: None,
            running,
            eligible: true,
        }
    }
    fn failure(stage: &str, error: &str) -> Pass {
        Pass {
            outcome: "error".into(),
            stage: Some(stage.into()),
            error: Some(error.into()),
            running: None,
            eligible: true,
        }
    }
    fn plain(text: &str) -> String {
        text.to_owned()
    }

    #[test]
    fn repeated_outcomes_count_and_keep_first_seen() {
        let (one, _) = advance(None, &pass("ok", Some(true)), plain, 100);
        let (two, _) = advance(Some(&one), &pass("ok", Some(true)), plain, 101);
        assert_eq!((two.first_seen, two.last_seen, two.count), (100, 101, 2));
        let (three, _) = advance(Some(&two), &pass("skipped:lease-busy", None), plain, 102);
        assert_eq!((three.first_seen, three.count), (102, 1));
    }

    #[test]
    fn an_error_announces_once_per_stage_and_keeps_its_text() {
        let (one, events) = advance(None, &failure("snapshot", "boom"), plain, 10);
        assert!(events.error_started);
        let (two, events) = advance(Some(&one), &failure("snapshot", "different"), plain, 11);
        assert!(!events.error_started);
        assert_eq!(two.error.as_deref(), Some("boom"));
        let (_, events) = advance(Some(&two), &failure("inspect", "x"), plain, 12);
        assert!(events.error_started);
    }

    #[test]
    fn a_service_down_beyond_the_bound_is_stuck_even_when_nothing_is_attempted() {
        let (down, _) = advance(None, &pass("ok", Some(false)), plain, 1000);
        assert!(!down.stuck);
        let silent = pass("skipped:probe-busy", None);
        let (waiting, events) = advance(Some(&down), &silent, plain, 1000 + STUCK_SECONDS);
        assert!(!waiting.stuck && events == Events::default());
        let (stuck, events) = advance(Some(&waiting), &silent, plain, 1001 + STUCK_SECONDS);
        assert!(stuck.stuck && events.stuck_started);
        assert_eq!(stuck.not_running_since, Some(1000));
        let (still, events) = advance(Some(&stuck), &silent, plain, 2000);
        assert!(still.stuck && !events.stuck_started);
        let (healed, events) = advance(Some(&still), &pass("ok", Some(true)), plain, 2001);
        assert!(!healed.stuck && healed.not_running_since.is_none() && events.stuck_ended);
    }

    #[test]
    fn an_ineligible_instance_is_never_stuck() {
        let (down, _) = advance(None, &pass("ok", Some(false)), plain, 1);
        let mut off = pass("skipped:not-eligible", None);
        off.eligible = false;
        let (cleared, _) = advance(Some(&down), &off, plain, 5000);
        assert!(!cleared.stuck && cleared.not_running_since.is_none());
    }

    #[test]
    fn unchanged_outcomes_are_written_only_periodically() {
        let (one, _) = advance(None, &pass("ok", Some(true)), plain, 100);
        let (two, _) = advance(Some(&one), &pass("ok", Some(true)), plain, 101);
        assert!(!persist_due(Some(&one), Some(100), &two, 101));
        assert!(persist_due(
            Some(&one),
            Some(100),
            &two,
            100 + REWRITE_SECONDS
        ));
        let (changed, _) = advance(Some(&two), &pass("skipped:lease-busy", None), plain, 102);
        assert!(persist_due(Some(&two), Some(100), &changed, 102));
        assert!(persist_due(None, None, &changed, 102));
    }

    #[test]
    fn error_text_is_bounded_and_printable() {
        let text = bounded(&format!("a\nb\u{7}{}", "x".repeat(1000)));
        assert_eq!(text.chars().count(), ERROR_CHARS);
        assert!(!text.chars().any(char::is_control));
    }

    #[test]
    fn records_round_trip_and_unknown_files_read_as_absent() {
        let (record, _) = advance(None, &failure("snapshot", "boom"), plain, 7);
        let body = serde_json::to_vec(&record).unwrap();
        assert!(body.len() < MAX_BYTES);
        assert_eq!(serde_json::from_slice::<Record>(&body).unwrap(), record);
        assert!(path(std::path::Path::new("/s"), "mailroom", "production", "../x").is_err());
    }

    #[test]
    fn the_file_changes_only_on_a_new_outcome_and_a_missing_file_reads_as_null() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let store = Store::new(directory.path().join("state")).unwrap();
        let read = || read(&store, "mailroom", "production", "web", true);
        assert_eq!(read(), Value::Null);
        let go = |pass: &Pass| record(&store.root, "mailroom", "production", "web", pass, plain);
        go(&pass("ok", Some(true)));
        go(&pass("ok", Some(true)));
        go(&pass("ok", Some(true)));
        // Unchanged outcomes stay in memory; the file still shows the first.
        assert_eq!(read()["count"], 1);
        assert_eq!(read()["outcome"], "ok");
        go(&failure("snapshot", "boom"));
        let value = read();
        assert_eq!(
            (value["outcome"].as_str(), value["stage"].as_str()),
            (Some("error"), Some("snapshot"))
        );
        assert_eq!(value["error"], "boom");
        // A stopped instance is never reported stuck from an older record.
        let stopped = super::read(&store, "mailroom", "production", "web", false);
        assert_eq!(stopped["stuck"], false);
        let path = path(&store.root, "mailroom", "production", "web").unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
