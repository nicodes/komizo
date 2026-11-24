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
/// A record not refreshed for this long is stale: whatever it was timing no
/// longer describes an unbroken period (controller down, instance stopped).
const STALE_SECONDS: i64 = 120;
/// Starts within the window that make a crash loop.
const CRASH_WINDOW_SECONDS: i64 = 600;
const CRASH_STARTS: usize = 5;
const MAX_RESTARTS: usize = 8;
/// An unchanged outcome is persisted at most this often.
const REWRITE_SECONDS: i64 = 60;
/// A changed outcome is persisted at once unless it flaps faster than this.
const CHANGE_WRITE_SECONDS: i64 = 10;
/// A failed write is retried this soon.
const RETRY_WRITE_SECONDS: i64 = 5;
/// The same error is announced to syslog at most this often.
const ANNOUNCE_SECONDS: i64 = 600;
const MAX_BYTES: usize = 4096;
const ERROR_CHARS: usize = 256;
const KIND: &str = "komizo.service-maintenance";
/// Stuck reasons that do not come from a timer and end only on a healthy read.
const FORCED: [&str; 2] = ["probe-unavailable", "probe-unavailable-suppressed"];
/// Backoff waits belong to whatever streak they interrupt.
const NEUTRAL: &str = "skipped:restart-backoff-wait";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Record {
    pub kind: String,
    pub version: u32,
    /// `ok`, `skipped:<reason>` or `error`.
    pub outcome: String,
    /// The maintenance step that failed; only present for `error`.
    pub stage: Option<String>,
    /// Sanitized and bounded; present for `error` and for a no-reading skip.
    pub error: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Consecutive passes with this same outcome and stage.
    pub count: u64,
    pub not_running_since: Option<i64>,
    pub stuck: bool,
    /// Why: `not-running`, `crash-loop`, `persistent-error` or a forced reason.
    #[serde(default)]
    pub stuck_reason: Option<String>,
    /// Recent service starts by maintenance, oldest first and bounded.
    #[serde(default)]
    pub restarts: Vec<i64>,
    /// Identity of the instance state last observed; a change restarts timers.
    #[serde(default)]
    pub epoch: Option<String>,
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
    /// The instance state this pass covered, when it got far enough to know.
    pub epoch: Option<String>,
    /// The pass started a container, whatever happened afterwards.
    pub restarted: bool,
    /// The pass read the service as running and healthy.
    pub healthy: bool,
    /// A condition that is stuck regardless of any timer.
    pub force_stuck: Option<&'static str>,
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
    let stale = previous.is_some_and(|p| now.saturating_sub(p.last_seen) > STALE_SECONDS);
    let changed = match (&pass.epoch, previous.and_then(|p| p.epoch.as_ref())) {
        (Some(new), Some(old)) => new != old,
        _ => false,
    };
    // A restart of the clock: a long stop, a controller outage or a new
    // deployment must not be counted as one unbroken failure.
    let carry = if stale || changed { None } else { previous };
    let neutral = pass.outcome == NEUTRAL && carry.is_some_and(|p| p.outcome == "error");
    let (outcome, stage) = match (neutral, carry) {
        (true, Some(p)) => (p.outcome.clone(), p.stage.clone()),
        _ => (pass.outcome.clone(), pass.stage.clone()),
    };
    let same = carry.is_some_and(|p| p.outcome == outcome && p.stage == stage);
    let not_running_since = if !pass.eligible {
        None
    } else {
        match pass.running {
            Some(false) => carry.and_then(|p| p.not_running_since).or(Some(now)),
            Some(true) => None,
            None => carry.and_then(|p| p.not_running_since),
        }
    };
    let mut restarts: Vec<i64> = carry
        .map(|p| p.restarts.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|at| now.saturating_sub(*at) <= CRASH_WINDOW_SECONDS)
        .collect();
    if pass.restarted {
        restarts.push(now);
    }
    while restarts.len() > MAX_RESTARTS {
        restarts.remove(0);
    }
    let first_seen = if same { carry.unwrap().first_seen } else { now };
    // A forced reason holds until the service reads healthy again.
    let held = carry
        .and_then(|p| p.stuck_reason.as_deref())
        .filter(|reason| FORCED.contains(reason) && !pass.healthy)
        .map(str::to_owned);
    let stuck_reason = pass
        .force_stuck
        .map(str::to_owned)
        .or(held)
        .or_else(|| {
            not_running_since
                .is_some_and(|since| now.saturating_sub(since) > STUCK_SECONDS)
                .then(|| "not-running".to_owned())
        })
        .or_else(|| (restarts.len() >= CRASH_STARTS).then(|| "crash-loop".to_owned()))
        .or_else(|| {
            (outcome == "error" && now.saturating_sub(first_seen) > STUCK_SECONDS)
                .then(|| "persistent-error".to_owned())
        });
    let stuck = stuck_reason.is_some();
    let error = if neutral {
        carry.and_then(|p| p.error.clone())
    } else {
        match (&pass.error, same, carry) {
            (None, _, _) => None,
            (Some(_), true, Some(p)) if p.error.is_some() => p.error.clone(),
            (Some(raw), _, _) => Some(sanitized(raw)),
        }
    };
    let events = Events {
        error_started: outcome == "error" && !same,
        stuck_started: stuck && !previous.is_some_and(|p| p.stuck && !stale),
        stuck_ended: !stuck && previous.is_some_and(|p| p.stuck),
    };
    (
        Record {
            kind: KIND.into(),
            version: 1,
            outcome,
            stage,
            error,
            first_seen,
            last_seen: now,
            count: if same { carry.unwrap().count + 1 } else { 1 },
            not_running_since,
            stuck,
            stuck_reason,
            restarts,
            epoch: pass
                .epoch
                .clone()
                .or_else(|| previous.and_then(|p| p.epoch.clone())),
        },
        events,
    )
}

/// Whether to write now. A change is written at once unless it flaps faster
/// than `CHANGE_WRITE_SECONDS`; an unchanged record is rewritten once a
/// minute; a failed write is retried after `RETRY_WRITE_SECONDS`.
fn persist_due(
    previous: Option<&Record>,
    last_attempt: Option<i64>,
    failed: bool,
    dirty: bool,
    next: &Record,
    urgent: bool,
    now: i64,
) -> bool {
    let (Some(p), Some(at)) = (previous, last_attempt) else {
        return true;
    };
    let since = now.saturating_sub(at);
    if failed {
        return since >= RETRY_WRITE_SECONDS;
    }
    if urgent || p.stuck != next.stuck {
        return true;
    }
    let changed = dirty
        || p.outcome != next.outcome
        || p.stage != next.stage
        || p.not_running_since.is_some() != next.not_running_since.is_some()
        || p.restarts != next.restarts;
    if changed {
        since >= CHANGE_WRITE_SECONDS
    } else {
        since >= REWRITE_SECONDS
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
        record.stuck_reason = None;
        record.not_running_since = None;
    }
    serde_json::to_value(record).unwrap_or(Value::Null)
}

struct Cached {
    record: Record,
    last_attempt: Option<i64>,
    failed: bool,
    /// A change is waiting for its write.
    dirty: bool,
    /// The newest error text with the key it was produced for.
    error: Option<(String, String)>,
    announced: BTreeMap<String, i64>,
}
type Key = (PathBuf, String, String, String);
fn cache() -> &'static Mutex<BTreeMap<Key, Cached>> {
    static CACHE: OnceLock<Mutex<BTreeMap<Key, Cached>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Bound the generic text: printable only.
pub(super) fn bounded(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(ERROR_CHARS)
        .collect()
}

/// Whether the same announcement was made recently; records it otherwise.
fn announce(announced: &mut BTreeMap<String, i64>, key: &str, now: i64) -> bool {
    if announced
        .get(key)
        .is_some_and(|at| now.saturating_sub(*at) < ANNOUNCE_SECONDS)
    {
        return false;
    }
    announced.insert(key.to_owned(), now);
    while announced.len() > 16 {
        let oldest = announced
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => announced.remove(&k),
            None => break,
        };
    }
    true
}

/// Record one pass. `sanitize` redacts secrets from a new error text and runs
/// only when the text is new, never on every second.
pub(super) fn record(
    root: &std::path::Path,
    application: &str,
    instance: &str,
    service: &str,
    pass: &Pass,
    sanitize: impl FnOnce(&str) -> String,
) {
    if let Ok(now) = controller::now() {
        record_at(root, application, instance, service, pass, sanitize, now);
    }
}

fn record_at(
    root: &std::path::Path,
    application: &str,
    instance: &str,
    service: &str,
    pass: &Pass,
    sanitize: impl FnOnce(&str) -> String,
    now: i64,
) {
    let key: Key = (
        root.to_owned(),
        application.to_owned(),
        instance.to_owned(),
        service.to_owned(),
    );
    let mut cached = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key)
        .unwrap_or_else(|| {
            // A restarted controller continues the durable record, so a stuck
            // condition and its start time survive it.
            let loaded = load(root, application, instance, service);
            Cached {
                last_attempt: loaded.as_ref().map(|r| r.last_seen),
                record: loaded.unwrap_or_else(|| Record {
                    kind: KIND.into(),
                    version: 1,
                    outcome: String::new(),
                    stage: None,
                    error: None,
                    first_seen: now,
                    last_seen: now,
                    count: 0,
                    not_running_since: None,
                    stuck: false,
                    stuck_reason: None,
                    restarts: Vec::new(),
                    epoch: None,
                }),
                failed: false,
                dirty: false,
                error: None,
                announced: BTreeMap::new(),
            }
        });
    let fresh = cached.record.outcome.is_empty();
    let previous = (!fresh).then(|| cached.record.clone());
    let error_key = pass
        .error
        .as_ref()
        .map(|raw| format!("{}|{}", pass.stage.as_deref().unwrap_or(""), bounded(raw)));
    let reuse = match (&error_key, &cached.error) {
        (Some(key), Some((seen, text))) if key == seen => Some(text.clone()),
        _ => None,
    };
    let (next, mut events) = advance(
        previous.as_ref(),
        pass,
        |raw| reuse.unwrap_or_else(|| bounded(&sanitize(raw))),
        now,
    );
    if let (Some(key), Some(text)) = (error_key, &next.error) {
        cached.error = Some((key.clone(), text.clone()));
        let stage = next.stage.clone().unwrap_or_default();
        if events.error_started && !announce(&mut cached.announced, &stage, now) {
            events.error_started = false;
        }
    }
    let urgent = events.error_started;
    let write = persist_due(
        previous.as_ref(),
        cached.last_attempt,
        cached.failed,
        cached.dirty,
        &next,
        urgent,
        now,
    );
    if write {
        let stored = path(root, application, instance, service).and_then(|path| {
            store::atomic(
                &path,
                &super::canonical(&serde_json::to_value(&next)?)?,
                0o600,
            )
        });
        cached.last_attempt = Some(now);
        cached.failed = stored.is_err();
        cached.dirty = false;
    } else if previous.as_ref().is_some_and(|p| {
        p.outcome != next.outcome || p.stage != next.stage || p.restarts != next.restarts
    }) {
        cached.dirty = true;
    }
    cached.record = next.clone();
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, cached);
    let name = format!("{application}/{instance}/{service}");
    if events.error_started {
        log(
            libc::LOG_WARNING,
            format!(
                "maintenance {name}: error at {}: {}",
                next.stage.as_deref().unwrap_or("unknown"),
                next.error.as_deref().unwrap_or("")
            ),
        );
    }
    if events.stuck_started {
        log(
            libc::LOG_ERR,
            format!(
                "maintenance {name}: stuck ({}), last outcome {}",
                next.stuck_reason.as_deref().unwrap_or("unknown"),
                next.outcome
            ),
        );
    }
    if events.stuck_ended {
        log(
            libc::LOG_NOTICE,
            format!("maintenance {name}: no longer stuck"),
        );
    }
}

/// Best effort and never on the caller's thread: a blocked syslog socket
/// must not stall maintenance. A full queue drops the line.
#[cfg(not(test))]
fn log(priority: libc::c_int, message: String) {
    use std::sync::mpsc;
    static SINK: OnceLock<Option<mpsc::SyncSender<(libc::c_int, String)>>> = OnceLock::new();
    let sink = SINK.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<(libc::c_int, String)>(64);
        std::thread::Builder::new()
            .name("komizo-syslog".into())
            .spawn(move || {
                for (priority, message) in receiver {
                    if let Ok(text) = std::ffi::CString::new(message.replace('\0', " ")) {
                        // Without openlog the identity defaults to the program
                        // name. The constant format keeps the text inert.
                        unsafe {
                            libc::syslog(libc::LOG_DAEMON | priority, c"%s".as_ptr(), text.as_ptr())
                        };
                    }
                }
            })
            .ok()
            .map(|_| sender)
    });
    if let Some(sink) = sink {
        let _ = sink.try_send((priority, message));
    }
}
#[cfg(test)]
fn log(_priority: libc::c_int, _message: String) {}

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
            epoch: None,
            restarted: false,
            healthy: false,
            force_stuck: None,
        }
    }
    fn failure(stage: &str, error: &str) -> Pass {
        Pass {
            outcome: "error".into(),
            stage: Some(stage.into()),
            error: Some(error.into()),
            ..pass("error", None)
        }
    }
    fn plain(text: &str) -> String {
        text.to_owned()
    }
    /// Feed the same pass every `step` seconds, as the loop does.
    fn run(
        mut record: Option<Record>,
        pass: &Pass,
        from: i64,
        to: i64,
        step: i64,
    ) -> (Record, Events) {
        let mut at = from;
        loop {
            let (next, events) = advance(record.as_ref(), pass, plain, at);
            if at >= to {
                return (next, events);
            }
            record = Some(next);
            at += step;
        }
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
    fn a_no_reading_skip_keeps_its_text_in_the_record() {
        let mut skip = pass("skipped:engine-unavailable", None);
        skip.error = Some("native engine deadline expired".into());
        let (record, events) = advance(None, &skip, plain, 10);
        assert_eq!(
            record.error.as_deref(),
            Some("native engine deadline expired")
        );
        assert!(!events.error_started);
    }

    #[test]
    fn a_service_down_beyond_the_bound_is_stuck_even_when_nothing_is_attempted() {
        let (down, _) = advance(None, &pass("ok", Some(false)), plain, 1000);
        assert!(!down.stuck);
        let silent = pass("skipped:probe-lock-busy", None);
        let (waiting, events) = advance(Some(&down), &silent, plain, 1000 + STUCK_SECONDS);
        assert!(!waiting.stuck && events == Events::default());
        let (stuck, events) = advance(Some(&waiting), &silent, plain, 1001 + STUCK_SECONDS);
        assert!(stuck.stuck && events.stuck_started);
        assert_eq!(stuck.not_running_since, Some(1000));
        assert_eq!(stuck.stuck_reason.as_deref(), Some("not-running"));
        let (still, events) = advance(Some(&stuck), &silent, plain, 1100 + STUCK_SECONDS);
        assert!(still.stuck && !events.stuck_started);
        let (healed, events) = advance(
            Some(&still),
            &pass("ok", Some(true)),
            plain,
            1200 + STUCK_SECONDS,
        );
        assert!(!healed.stuck && healed.not_running_since.is_none() && events.stuck_ended);
    }

    #[test]
    fn a_missing_container_is_down_and_becomes_stuck() {
        let mut missing = failure("inspect-container", "desired native CID missing");
        missing.running = Some(false);
        let (before, _) = run(None, &missing, 0, STUCK_SECONDS, 10);
        assert!(!before.stuck);
        let (last, events) = run(
            Some(before),
            &missing,
            STUCK_SECONDS + 10,
            STUCK_SECONDS + 10,
            10,
        );
        assert!(last.stuck && events.stuck_started);
    }

    #[test]
    fn a_persistent_error_is_stuck_even_when_nothing_is_known_about_the_container() {
        let boom = failure("snapshot", "boom");
        let (early, _) = run(None, &boom, 0, STUCK_SECONDS, 10);
        assert!(!early.stuck);
        let (record, events) = run(
            Some(early),
            &boom,
            STUCK_SECONDS + 10,
            STUCK_SECONDS + 10,
            10,
        );
        assert!(events.stuck_started && record.stuck);
        assert_eq!(record.stuck_reason.as_deref(), Some("persistent-error"));
    }

    fn same_epoch() -> Pass {
        let mut same = pass("skipped:instance-lease-busy", None);
        same.epoch = Some("release-1".into());
        same
    }

    #[test]
    fn a_stale_record_or_a_new_instance_state_restarts_the_timer() {
        let mut down = pass("ok", Some(false));
        down.epoch = Some("release-1".into());
        let (record, _) = advance(None, &down, plain, 1000);
        // Nothing refreshed the record for a long stop: the timer starts over.
        let mut after_stop = pass("skipped:probe-lock-busy", None);
        after_stop.epoch = Some("release-1".into());
        let (resumed, events) = advance(Some(&record), &after_stop, plain, 1000 + 86_400);
        assert!(!resumed.stuck && resumed.not_running_since.is_none() && !events.stuck_started);
        // A new deployment while passes kept arriving also starts over.
        let mut deployed = pass("skipped:instance-lease-busy", None);
        deployed.epoch = Some("release-2".into());
        let (progress, _) = run(
            Some(record.clone()),
            &same_epoch(),
            1010,
            1000 + STUCK_SECONDS,
            10,
        );
        assert!(progress.not_running_since.is_some());
        let (redeployed, _) = advance(Some(&progress), &deployed, plain, 1000 + STUCK_SECONDS + 5);
        assert!(!redeployed.stuck && redeployed.not_running_since.is_none());
        // Without either, the same passes would have been stuck.
        let mut same = pass("skipped:instance-lease-busy", None);
        same.epoch = Some("release-1".into());
        let (stuck, _) = advance(Some(&record), &same, plain, 1000 + STUCK_SECONDS + 5);
        assert!(
            !stuck.stuck,
            "a single late pass after a stale gap is not proof"
        );
        let (kept, _) = run(
            Some(record.clone()),
            &same,
            1010,
            1000 + STUCK_SECONDS + 5,
            10,
        );
        assert!(kept.stuck);
    }

    #[test]
    fn an_ineligible_instance_is_never_stuck() {
        let (down, _) = advance(None, &pass("ok", Some(false)), plain, 1);
        let mut off = pass("skipped:not-eligible", None);
        off.eligible = false;
        let (cleared, _) = advance(Some(&down), &off, plain, 5);
        assert!(!cleared.stuck && cleared.not_running_since.is_none());
    }

    #[test]
    fn a_crash_loop_is_reported_though_the_service_is_often_running() {
        let mut record: Option<Record> = None;
        let mut reported = None;
        for round in 0..CRASH_STARTS as i64 {
            let now = round * 20;
            let mut started = pass("ok", Some(true));
            started.restarted = true;
            let (next, events) = advance(record.as_ref(), &started, plain, now);
            if events.stuck_started {
                reported = Some(now);
            }
            record = Some(next);
            // A pass between restarts sees it down, then up again.
            let (down, _) = advance(record.as_ref(), &pass("ok", Some(false)), plain, now + 5);
            let (up, _) = advance(Some(&down), &pass("ok", Some(true)), plain, now + 10);
            record = Some(up);
        }
        assert_eq!(reported, Some(80));
        assert_eq!(record.unwrap().stuck_reason.as_deref(), Some("crash-loop"));
        // Restarts spread beyond the window never add up.
        let mut spread: Option<Record> = None;
        for round in 0..10 {
            let mut started = pass("ok", Some(true));
            started.restarted = true;
            let (next, _) = advance(spread.as_ref(), &started, plain, round * 200);
            spread = Some(next);
        }
        assert!(!spread.unwrap().stuck);
    }

    #[test]
    fn a_forced_stuck_reason_is_reported_once() {
        let mut forced = failure(
            "probe-unavailable",
            "native health probe could not complete",
        );
        forced.force_stuck = Some("probe-unavailable");
        let (record, events) = advance(None, &forced, plain, 10);
        assert!(record.stuck && events.stuck_started && events.error_started);
        assert_eq!(record.stuck_reason.as_deref(), Some("probe-unavailable"));
    }

    #[test]
    fn a_backoff_wait_does_not_break_an_error_streak() {
        let (error, events) = advance(
            None,
            &failure("start-guard", "dependency starting"),
            plain,
            100,
        );
        assert!(events.error_started);
        let wait = pass("skipped:restart-backoff-wait", Some(false));
        let (waited, events) = advance(Some(&error), &wait, plain, 101);
        assert_eq!(
            (waited.outcome.as_str(), waited.count, waited.first_seen),
            ("error", 2, 100)
        );
        assert_eq!(waited.error, error.error);
        assert!(!events.error_started);
        let (again, events) = advance(
            Some(&waited),
            &failure("start-guard", "dependency starting"),
            plain,
            104,
        );
        assert!(!events.error_started && again.count == 3);
        // Outside an error streak a backoff wait is an ordinary outcome.
        let (ok, _) = advance(None, &pass("ok", Some(true)), plain, 1);
        let (other, _) = advance(Some(&ok), &wait, plain, 2);
        assert_eq!(other.outcome, "skipped:restart-backoff-wait");
    }

    #[test]
    fn announcements_for_the_same_error_are_rate_limited() {
        let mut announced = BTreeMap::new();
        assert!(announce(&mut announced, "snapshot|boom", 0));
        assert!(!announce(
            &mut announced,
            "snapshot|boom",
            ANNOUNCE_SECONDS - 1
        ));
        assert!(announce(&mut announced, "snapshot|other", 5));
        assert!(announce(&mut announced, "snapshot|boom", ANNOUNCE_SECONDS));
        for number in 0..100 {
            announce(&mut announced, &format!("k{number}"), 1000 + number);
        }
        assert!(announced.len() <= 16);
    }

    #[test]
    fn writes_are_limited_when_flapping_and_retried_soon_when_they_fail() {
        let (one, _) = advance(None, &pass("ok", Some(true)), plain, 100);
        let (two, _) = advance(Some(&one), &pass("ok", Some(true)), plain, 101);
        let (changed, _) = advance(
            Some(&two),
            &pass("skipped:probe-lock-busy", None),
            plain,
            102,
        );
        let due = |previous: &Record, next: &Record, failed, dirty, urgent, now| {
            persist_due(Some(previous), Some(100), failed, dirty, next, urgent, now)
        };
        assert!(!due(&one, &two, false, false, false, 101));
        assert!(due(&one, &two, false, false, false, 100 + REWRITE_SECONDS));
        // A change right after a write waits out the flap limit ...
        assert!(!due(&two, &changed, false, false, false, 102));
        assert!(due(
            &two,
            &changed,
            false,
            false,
            false,
            100 + CHANGE_WRITE_SECONDS
        ));
        // ... and stays pending: the next unchanged pass still writes it.
        assert!(!due(&changed, &changed, false, true, false, 105));
        assert!(due(
            &changed,
            &changed,
            false,
            true,
            false,
            100 + CHANGE_WRITE_SECONDS
        ));
        // Urgent changes and the first record are written at once.
        assert!(due(&two, &changed, false, false, true, 102));
        assert!(persist_due(None, None, false, false, &changed, false, 102));
        // A failed write is retried in seconds, not after a minute.
        assert!(!due(&one, &two, true, false, false, 101));
        assert!(due(
            &one,
            &two,
            true,
            false,
            false,
            100 + RETRY_WRITE_SECONDS
        ));
    }

    #[test]
    fn a_change_inside_the_flap_limit_still_reaches_the_disk_without_another_change() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let store = Store::new(directory.path().join("state")).unwrap();
        let go = |pass: &Pass, now| {
            record_at(
                &store.root,
                "mailroom",
                "production",
                "web",
                pass,
                plain,
                now,
            )
        };
        let read = || read(&store, "mailroom", "production", "web", true);
        let busy = pass("skipped:probe-lock-busy", None);
        go(&pass("ok", Some(true)), 1000);
        go(&busy, 1002);
        // Held back by the flap limit: the file still shows the first outcome.
        assert_eq!(read()["outcome"], "ok");
        go(&busy, 1004);
        assert_eq!(read()["outcome"], "ok");
        go(&busy, 1000 + CHANGE_WRITE_SECONDS);
        assert_eq!(read()["outcome"], "skipped:probe-lock-busy");
    }

    #[test]
    fn a_forced_stuck_reason_holds_until_the_service_reads_healthy() {
        let mut forced = pass("ok", Some(false));
        forced.force_stuck = Some("probe-unavailable");
        let (first, events) = advance(None, &forced, plain, 100);
        assert!(first.stuck && events.stuck_started);
        // Later passes without the force keep it, and log nothing new.
        let (mid, events) = run(
            Some(first),
            &pass("skipped:probe-lock-busy", None),
            110,
            400,
            10,
        );
        assert!(mid.stuck && !events.stuck_ended && !events.stuck_started);
        assert_eq!(mid.stuck_reason.as_deref(), Some("probe-unavailable"));
        let (running, events) = advance(Some(&mid), &pass("ok", Some(true)), plain, 410);
        assert!(
            running.stuck && !events.stuck_ended,
            "running is not healthy"
        );
        let mut healthy = pass("ok", Some(true));
        healthy.healthy = true;
        let (healed, events) = advance(Some(&running), &healthy, plain, 420);
        assert!(!healed.stuck && events.stuck_ended);
    }

    #[test]
    fn long_suppression_is_stuck_for_visibility_with_its_own_reason_until_healthy() {
        let mut suppressed = pass("skipped:probe-unavailable-suppressed", None);
        suppressed.force_stuck = Some("probe-unavailable-suppressed");
        let (first, events) = advance(None, &suppressed, plain, 100);
        assert!(first.stuck && events.stuck_started);
        assert_eq!(
            first.stuck_reason.as_deref(),
            Some("probe-unavailable-suppressed")
        );
        // Continued suppression passes keep it without another log line.
        let (next, events) = advance(Some(&first), &suppressed, plain, 130);
        assert!(next.stuck && !events.stuck_started);
        let mut healthy = pass("ok", Some(true));
        healthy.healthy = true;
        let (healed, events) = advance(Some(&next), &healthy, plain, 140);
        assert!(!healed.stuck && events.stuck_ended);
    }

    #[test]
    fn the_rate_limit_is_keyed_on_the_stage_not_the_varying_text() {
        let mut announced = BTreeMap::new();
        assert!(announce(&mut announced, "start-guard", 0));
        assert!(!announce(&mut announced, "start-guard", 30));
        assert!(announce(&mut announced, "snapshot", 30));
    }

    #[test]
    fn a_stopped_instance_reports_no_stuck_reason() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let store = Store::new(directory.path().join("state")).unwrap();
        let mut forced = pass("ok", Some(false));
        forced.force_stuck = Some("probe-unavailable");
        record(&store.root, "mailroom", "production", "web", &forced, plain);
        let running = read(&store, "mailroom", "production", "web", true);
        assert_eq!(running["stuck_reason"], "probe-unavailable");
        let stopped = read(&store, "mailroom", "production", "web", false);
        assert_eq!(
            (&stopped["stuck"], &stopped["stuck_reason"]),
            (&Value::Bool(false), &Value::Null)
        );
    }

    #[test]
    fn error_text_is_bounded_and_printable() {
        let text = bounded(&format!("a\nb\u{7}{}", "x".repeat(1000)));
        assert_eq!(text.chars().count(), ERROR_CHARS);
        assert!(!text.chars().any(char::is_control));
    }

    #[test]
    fn older_records_without_the_new_fields_still_read() {
        let old = br#"{"kind":"komizo.service-maintenance","version":1,"outcome":"ok","stage":null,"error":null,"first_seen":1,"last_seen":2,"count":1,"not_running_since":null,"stuck":false}"#;
        let record: Record = serde_json::from_slice(old).unwrap();
        assert!(record.restarts.is_empty() && record.epoch.is_none());
        let (record, _) = advance(None, &failure("snapshot", "boom"), plain, 7);
        let body = serde_json::to_vec(&record).unwrap();
        assert!(body.len() < MAX_BYTES);
        assert_eq!(serde_json::from_slice::<Record>(&body).unwrap(), record);
        assert!(path(std::path::Path::new("/s"), "mailroom", "production", "../x").is_err());
    }

    #[test]
    fn the_file_changes_rarely_redacts_only_new_text_and_a_missing_file_reads_as_null() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let store = Store::new(directory.path().join("state")).unwrap();
        let read = || read(&store, "mailroom", "production", "web", true);
        assert_eq!(read(), Value::Null);
        let redactions = std::cell::Cell::new(0);
        let go = |pass: &Pass| {
            record(&store.root, "mailroom", "production", "web", pass, |raw| {
                redactions.set(redactions.get() + 1);
                raw.to_owned()
            })
        };
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
        assert_eq!(redactions.get(), 1);
        // Flapping between the error and an ok pass and back reuses the text.
        go(&pass("ok", Some(true)));
        go(&failure("snapshot", "boom"));
        assert_eq!(redactions.get(), 1);
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
