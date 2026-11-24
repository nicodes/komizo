//! A bounded queue for exact service observations, separate from admitted effects.
use anyhow::{Result, anyhow};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::{Duration, Instant},
};

/// A healthy, unchanged service is inspected this often; every other state
/// (starting, stopped, in backoff, changed) keeps the one-second reaction.
const STEADY: Duration = Duration::from_secs(5);
/// An unhealthy running service must be seen unhealthy again at least this
/// many seconds later, backed by a fresh completed probe, before it is stopped.
const CONFIRM_SECONDS: i64 = 5;
/// A scope whose observation has occupied a worker this long is reported.
pub(super) const STALLED: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Scope {
    pub root: PathBuf,
    pub application: String,
    pub instance: String,
    pub service: String,
}

type Work = Arc<dyn Fn(&Scope) + Send + Sync>;

struct Scheduler {
    sender: mpsc::SyncSender<Scope>,
    pending: Arc<Mutex<BTreeMap<Scope, Instant>>>,
}

struct Pending {
    scope: Scope,
    pending: Arc<Mutex<BTreeMap<Scope, Instant>>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.scope);
    }
}

impl Scheduler {
    fn new(work: Work) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(64);
        let receiver = Arc::new(Mutex::new(receiver));
        let pending = Arc::new(Mutex::new(BTreeMap::new()));
        for _ in 0..4 {
            let receiver = receiver.clone();
            let pending = pending.clone();
            let work = work.clone();
            std::thread::Builder::new()
                .name("komizo-service-probe".into())
                .spawn(move || {
                    loop {
                        let item = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv();
                        let Ok(scope) = item else {
                            break;
                        };
                        let _pending = Pending {
                            scope,
                            pending: pending.clone(),
                        };
                        // A failed observation must release its dedupe slot and
                        // cannot consume a worker permanently after a panic.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            work(&_pending.scope)
                        }));
                    }
                })?;
        }
        Ok(Self { sender, pending })
    }

    fn enqueue(&self, scope: Scope) -> Result<bool> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.contains_key(&scope) {
            return Ok(false);
        }
        pending.insert(scope.clone(), Instant::now());
        match self.sender.try_send(scope.clone()) {
            Ok(()) => Ok(true),
            Err(mpsc::TrySendError::Full(_)) => {
                pending.remove(&scope);
                Ok(false)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                pending.remove(&scope);
                Err(anyhow!("service observation workers are unavailable"))
            }
        }
    }
}

fn scheduler() -> &'static Mutex<Option<Scheduler>> {
    static SCHEDULER: OnceLock<Mutex<Option<Scheduler>>> = OnceLock::new();
    SCHEDULER.get_or_init(|| Mutex::new(None))
}

/// How long this scope has owned its dedupe slot, if it does.
pub(super) fn in_flight(scope: &Scope) -> Option<Duration> {
    let scheduler = scheduler().lock().unwrap_or_else(|e| e.into_inner());
    let pending = scheduler
        .as_ref()?
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    pending.get(scope).map(Instant::elapsed)
}

pub(super) fn enqueue(scope: Scope) -> Result<bool> {
    let mut scheduler = scheduler().lock().unwrap_or_else(|e| e.into_inner());
    if scheduler.is_none() {
        *scheduler = Some(Scheduler::new(Arc::new(|scope| {
            let _ = super::maintain_service(scope);
        }))?);
    }
    scheduler.as_ref().unwrap().enqueue(scope)
}

/// Services last observed healthy and running, with the cheap identity of the
/// state that observation covered. Nothing here is authority: a miss only
/// means "inspect now".
#[derive(Default)]
struct Steady(BTreeMap<Scope, (Instant, String)>);
impl Steady {
    fn mark(&mut self, scope: &Scope, fingerprint: String, now: Instant) {
        self.0.insert(scope.clone(), (now, fingerprint));
    }
    fn skip(&self, scope: &Scope, fingerprint: &str, now: Instant) -> bool {
        self.0.get(scope).is_some_and(|(at, seen)| {
            seen == fingerprint && now.saturating_duration_since(*at) < STEADY
        })
    }
}
fn steady() -> &'static Mutex<Steady> {
    static CACHE: OnceLock<Mutex<Steady>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Steady::default()))
}
/// A healthy unchanged service needs no inspection yet.
pub(super) fn steady_skip(scope: &Scope, fingerprint: &str) -> bool {
    steady()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .skip(scope, fingerprint, Instant::now())
}
pub(super) fn steady_mark(scope: &Scope, fingerprint: String) {
    steady()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .mark(scope, fingerprint, Instant::now());
}
pub(super) fn steady_clear(scope: &Scope) {
    steady()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .0
        .remove(scope);
}
/// Drop entries for scopes that no longer exist.
pub(super) fn steady_retain(live: &BTreeSet<Scope>) {
    let mut cache = steady().lock().unwrap_or_else(|e| e.into_inner());
    cache.0.retain(|scope, _| live.contains(scope));
    unhealthy()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .0
        .retain(|scope, _| live.contains(scope));
}

/// First unhealthy sighting per container generation. A running service is
/// stopped only when a later pass, at least `CONFIRM_SECONDS` after the first
/// and backed by a freshly completed probe, still reads unhealthy.
#[derive(Default)]
struct Unhealthy(BTreeMap<Scope, (String, i64)>);
impl Unhealthy {
    fn confirm(&mut self, scope: &Scope, generation: &str, now: i64, fresh: bool) -> bool {
        match self.0.get(scope) {
            Some((seen, first)) if seen == generation => {
                fresh && now.saturating_sub(*first) >= CONFIRM_SECONDS
            }
            _ => {
                self.0.insert(scope.clone(), (generation.to_owned(), now));
                false
            }
        }
    }
}
fn unhealthy() -> &'static Mutex<Unhealthy> {
    static CACHE: OnceLock<Mutex<Unhealthy>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Unhealthy::default()))
}
pub(super) fn unhealthy_confirm(scope: &Scope, generation: &str, now: i64, fresh: bool) -> bool {
    unhealthy()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .confirm(scope, generation, now, fresh)
}
pub(super) fn unhealthy_clear(scope: &Scope) {
    unhealthy()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .0
        .remove(scope);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Condvar,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    fn scope(number: usize) -> Scope {
        Scope {
            root: "/synthetic".into(),
            application: "mailroom".into(),
            instance: "production".into(),
            service: format!("service-{number}"),
        }
    }
    fn until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "bounded worker control timed out"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn four_workers_dedupe_active_scopes_bound_the_queue_and_release_after_panics() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        struct Release(Arc<(Mutex<bool>, Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0.0.lock().unwrap() = true;
                self.0.1.notify_all();
            }
        }
        let release = Release(gate.clone());
        let work = {
            let active = active.clone();
            let maximum = maximum.clone();
            let gate = gate.clone();
            Arc::new(move |scope: &Scope| {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(count, Ordering::SeqCst);
                let mut open = gate.0.lock().unwrap();
                while !*open {
                    open = gate.1.wait(open).unwrap();
                }
                drop(open);
                active.fetch_sub(1, Ordering::SeqCst);
                if scope.service == "service-0" {
                    panic!("synthetic worker failure");
                }
            }) as Work
        };
        let scheduler = Scheduler::new(work).unwrap();
        for n in 0..4 {
            assert!(scheduler.enqueue(scope(n)).unwrap());
        }
        until(|| active.load(Ordering::SeqCst) == 4);
        assert!(!scheduler.enqueue(scope(0)).unwrap());
        for n in 4..68 {
            assert!(scheduler.enqueue(scope(n)).unwrap());
        }
        assert!(!scheduler.enqueue(scope(68)).unwrap());
        assert_eq!(scheduler.pending.lock().unwrap().len(), 68);
        drop(release);
        until(|| scheduler.pending.lock().unwrap().is_empty());
        assert_eq!(maximum.load(Ordering::SeqCst), 4);
        assert!(scheduler.enqueue(scope(0)).unwrap());
        until(|| scheduler.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn a_healthy_unchanged_service_is_inspected_every_five_seconds_not_every_second() {
        let mut cache = Steady::default();
        let service = scope(1);
        let start = Instant::now();
        assert!(!cache.skip(&service, "a", start));
        cache.mark(&service, "a".into(), start);
        for second in 1..5 {
            assert!(cache.skip(&service, "a", start + Duration::from_secs(second)));
        }
        assert!(!cache.skip(&service, "a", start + STEADY));
        // A changed identity reacts at once.
        assert!(!cache.skip(&service, "b", start + Duration::from_secs(1)));
    }

    #[test]
    fn unhealthy_needs_a_second_fresh_reading_a_few_seconds_later() {
        let mut cache = Unhealthy::default();
        let service = scope(1);
        assert!(!cache.confirm(&service, "g1", 100, true));
        assert!(!cache.confirm(&service, "g1", 102, true));
        assert!(!cache.confirm(&service, "g1", 105, false));
        assert!(cache.confirm(&service, "g1", 105, true));
        // A new generation starts over.
        assert!(!cache.confirm(&service, "g2", 200, true));
        assert!(!cache.confirm(&service, "g2", 201, true));
    }

    #[test]
    fn a_scope_reports_how_long_it_has_owned_its_slot() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let work = {
            let gate = gate.clone();
            Arc::new(move |_: &Scope| {
                let mut open = gate.0.lock().unwrap();
                while !*open {
                    open = gate.1.wait(open).unwrap();
                }
            }) as Work
        };
        let scheduler = Scheduler::new(work).unwrap();
        assert!(scheduler.enqueue(scope(9)).unwrap());
        std::thread::sleep(Duration::from_millis(5));
        let age = scheduler
            .pending
            .lock()
            .unwrap()
            .get(&scope(9))
            .map(Instant::elapsed);
        assert!(age.is_some_and(|age| age >= Duration::from_millis(5)));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        until(|| scheduler.pending.lock().unwrap().is_empty());
    }
}
