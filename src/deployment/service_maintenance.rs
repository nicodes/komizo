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
const CONFIRM: Duration = Duration::from_secs(5);
/// A scope whose worker has been inside one pass this long is reported. It
/// exceeds any legitimate pass, including a long graceful stop.
pub(super) const STALLED: Duration = Duration::from_secs(600);
/// Readings that keep failing for this long no longer retain a running
/// container; the previous behaviour (clean up and restart) resumes.
const NO_READING_LIMIT: Duration = Duration::from_secs(120);
const NO_READING_MINIMUM: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Scope {
    pub root: PathBuf,
    pub application: String,
    pub instance: String,
    pub service: String,
}

type Work = Arc<dyn Fn(&Scope) + Send + Sync>;

/// A dedupe slot; `started` is set when a worker actually takes the scope.
struct Slot {
    started: Option<Instant>,
}

struct Scheduler {
    sender: mpsc::SyncSender<Scope>,
    pending: Arc<Mutex<BTreeMap<Scope, Slot>>>,
}

struct Pending {
    scope: Scope,
    pending: Arc<Mutex<BTreeMap<Scope, Slot>>>,
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
                        if let Some(slot) = pending
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get_mut(&_pending.scope)
                        {
                            slot.started = Some(Instant::now());
                        }
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
        pending.insert(scope.clone(), Slot { started: None });
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

/// How long a worker has been inside this scope's pass, if one is.
pub(super) fn in_flight(scope: &Scope) -> Option<Duration> {
    let scheduler = scheduler().lock().unwrap_or_else(|e| e.into_inner());
    let pending = scheduler
        .as_ref()?
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    pending
        .get(scope)
        .and_then(|slot| slot.started)
        .map(|at| at.elapsed())
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
    no_readings()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .0
        .retain(|scope, _| live.contains(scope));
}

/// First unhealthy sighting per container generation, on the monotonic clock.
/// A running service is stopped only when a later pass, at least
/// `CONFIRM_SECONDS` after the first, still reads unhealthy with a probe
/// attempted in that pass. `due` asks the pass to probe at once.
#[derive(Default)]
struct Unhealthy(BTreeMap<Scope, (String, Instant)>);
impl Unhealthy {
    fn confirm(&mut self, scope: &Scope, generation: &str, now: Instant, probed: bool) -> bool {
        match self.0.get(scope) {
            Some((seen, first)) if seen == generation => {
                probed && now.saturating_duration_since(*first) >= CONFIRM
            }
            _ => {
                self.0.insert(scope.clone(), (generation.to_owned(), now));
                false
            }
        }
    }
    fn due(&self, scope: &Scope, generation: &str, now: Instant) -> bool {
        self.0.get(scope).is_some_and(|(seen, first)| {
            seen == generation && now.saturating_duration_since(*first) >= CONFIRM
        })
    }
}
fn unhealthy() -> &'static Mutex<Unhealthy> {
    static CACHE: OnceLock<Mutex<Unhealthy>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Unhealthy::default()))
}
/// An unhealthy sighting is old enough that this pass must probe again.
pub(super) fn unhealthy_due(scope: &Scope, generation: &str) -> bool {
    unhealthy()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .due(scope, generation, Instant::now())
}

/// Consecutive failed or overdue readings per container generation.
#[derive(Default)]
struct NoReadings(BTreeMap<Scope, (String, Instant, u32)>);
impl NoReadings {
    /// True once readings have failed past the bound.
    fn note(&mut self, scope: &Scope, generation: &str, now: Instant) -> bool {
        let entry = match self.0.get_mut(scope) {
            Some(entry) if entry.0 == generation => entry,
            _ => {
                self.0
                    .insert(scope.clone(), (generation.to_owned(), now, 0));
                self.0.get_mut(scope).unwrap()
            }
        };
        entry.2 += 1;
        entry.2 >= NO_READING_MINIMUM && now.saturating_duration_since(entry.1) >= NO_READING_LIMIT
    }
}
fn no_readings() -> &'static Mutex<NoReadings> {
    static CACHE: OnceLock<Mutex<NoReadings>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(NoReadings::default()))
}

/// What one health observation of a service established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Observed {
    Healthy,
    NotRunning,
    /// Running and reported unhealthy; `probed` when this pass attempted a probe.
    Unhealthy {
        probed: bool,
    },
    /// The reading could not be taken but nothing is wrong with the workload.
    Unreadable,
    /// A native command failed or hit its own deadline.
    NoReading,
    /// Confinement, ownership or identity could not be proven.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Leave the service alone.
    Keep,
    /// Leave it alone for this pass and say why.
    Wait(&'static str),
    /// Stop (if running) and restart it.
    Restart,
    /// Clean up the service exactly as a failed observation always did.
    /// `unavailable` is set when readings kept failing past their bound.
    Kill { unavailable: bool },
}

fn judge_with(
    unhealthy: &mut Unhealthy,
    readings: &mut NoReadings,
    scope: &Scope,
    observed: Observed,
    generation: &str,
    now: Instant,
) -> Verdict {
    match observed {
        Observed::Healthy => {
            readings.0.remove(scope);
            unhealthy.0.remove(scope);
            Verdict::Keep
        }
        Observed::NotRunning => {
            readings.0.remove(scope);
            unhealthy.0.remove(scope);
            Verdict::Restart
        }
        Observed::Unhealthy { probed } => {
            readings.0.remove(scope);
            if unhealthy.confirm(scope, generation, now, probed) {
                Verdict::Restart
            } else {
                Verdict::Wait("unhealthy-unconfirmed")
            }
        }
        Observed::Unreadable => Verdict::Keep,
        Observed::NoReading => {
            if readings.note(scope, generation, now) {
                Verdict::Kill { unavailable: true }
            } else {
                Verdict::Wait("engine-unavailable")
            }
        }
        Observed::Failed => Verdict::Kill { unavailable: false },
    }
}
pub(super) fn judge(scope: &Scope, observed: Observed, generation: &str) -> Verdict {
    judge_with(
        &mut unhealthy().lock().unwrap_or_else(|e| e.into_inner()),
        &mut no_readings().lock().unwrap_or_else(|e| e.into_inner()),
        scope,
        observed,
        generation,
        Instant::now(),
    )
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

    fn judged(state: &mut (Unhealthy, NoReadings), observed: Observed, at: Instant) -> Verdict {
        judge_with(&mut state.0, &mut state.1, &scope(1), observed, "g1", at)
    }

    #[test]
    fn unhealthy_needs_a_later_reading_with_a_probe_and_is_not_delayed_by_the_interval() {
        let mut state = (Unhealthy::default(), NoReadings::default());
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        let unhealthy = |probed| Observed::Unhealthy { probed };
        assert_eq!(
            judged(&mut state, unhealthy(false), at(0)),
            Verdict::Wait("unhealthy-unconfirmed")
        );
        // Too early, with or without a probe.
        assert_eq!(
            judged(&mut state, unhealthy(true), at(2)),
            Verdict::Wait("unhealthy-unconfirmed")
        );
        assert!(!state.0.due(&scope(1), "g1", at(4)));
        // Five seconds after the first sighting a probe is due, whatever the
        // health interval, and an attempted probe (even exit 125) confirms.
        assert!(state.0.due(&scope(1), "g1", at(5)));
        assert_eq!(
            judged(&mut state, unhealthy(false), at(5)),
            Verdict::Wait("unhealthy-unconfirmed")
        );
        assert_eq!(judged(&mut state, unhealthy(true), at(5)), Verdict::Restart);
        // A healthy reading forgets the sighting; a new generation starts over.
        judged(&mut state, Observed::Healthy, at(6));
        assert_eq!(
            judged(&mut state, unhealthy(true), at(7)),
            Verdict::Wait("unhealthy-unconfirmed")
        );
        assert_eq!(
            judge_with(
                &mut state.0,
                &mut state.1,
                &scope(1),
                unhealthy(true),
                "g2",
                at(20)
            ),
            Verdict::Wait("unhealthy-unconfirmed")
        );
    }

    #[test]
    fn a_probe_that_keeps_failing_is_retained_only_until_the_bound_then_restarted() {
        let mut state = (Unhealthy::default(), NoReadings::default());
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        for second in [0, 30, 60, 90] {
            assert_eq!(
                judged(&mut state, Observed::NoReading, at(second)),
                Verdict::Wait("engine-unavailable")
            );
        }
        assert_eq!(
            judged(&mut state, Observed::NoReading, at(120)),
            Verdict::Kill { unavailable: true }
        );
    }

    #[test]
    fn a_reading_or_a_new_generation_resets_the_failed_reading_streak() {
        let mut state = (Unhealthy::default(), NoReadings::default());
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        for second in [0, 50, 100] {
            judged(&mut state, Observed::NoReading, at(second));
        }
        judged(&mut state, Observed::Healthy, at(110));
        assert_eq!(
            judged(&mut state, Observed::NoReading, at(200)),
            Verdict::Wait("engine-unavailable")
        );
        for second in [210, 260] {
            judged(&mut state, Observed::NoReading, at(second));
        }
        // The same count and age under another generation does not trip.
        assert_eq!(
            judge_with(
                &mut state.0,
                &mut state.1,
                &scope(1),
                Observed::NoReading,
                "g2",
                at(330)
            ),
            Verdict::Wait("engine-unavailable")
        );
    }

    #[test]
    fn proof_failures_kill_at_once_and_stopped_containers_restart_promptly() {
        let mut state = (Unhealthy::default(), NoReadings::default());
        let now = Instant::now();
        assert_eq!(
            judged(&mut state, Observed::Failed, now),
            Verdict::Kill { unavailable: false }
        );
        assert_eq!(
            judged(&mut state, Observed::NotRunning, now),
            Verdict::Restart
        );
        assert_eq!(judged(&mut state, Observed::Unreadable, now), Verdict::Keep);
    }

    #[test]
    fn a_scope_reports_how_long_a_worker_has_been_inside_its_pass() {
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
        let queued = scope(9);
        let queued_only = scope(10);
        let held = |scope: &Scope| {
            let mut guard = scheduler_slot(&scheduler, scope);
            guard.take()
        };
        assert!(scheduler.enqueue(queued.clone()).unwrap());
        until(|| scheduler_slot(&scheduler, &queued).is_some());
        std::thread::sleep(Duration::from_millis(5));
        assert!(held(&queued).is_some_and(|age| age >= Duration::from_millis(5)));
        // A scope that no worker has begun reports nothing, however long queued.
        scheduler
            .pending
            .lock()
            .unwrap()
            .insert(queued_only.clone(), Slot { started: None });
        assert!(scheduler_slot(&scheduler, &queued_only).is_none());
        scheduler.pending.lock().unwrap().remove(&queued_only);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        until(|| scheduler.pending.lock().unwrap().is_empty());
    }

    fn scheduler_slot(scheduler: &Scheduler, scope: &Scope) -> Option<Duration> {
        scheduler
            .pending
            .lock()
            .unwrap()
            .get(scope)
            .and_then(|slot| slot.started)
            .map(|at| at.elapsed())
    }
}
