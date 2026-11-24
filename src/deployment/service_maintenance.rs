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
/// Back-to-back failed readings for this long, and at least this many, mean
/// the container itself cannot be read; the service is then restarted
/// gracefully. The bound exceeds any starvation a neighbour's deployment can
/// cause, and a host-wide guard suppresses it while the host is busy.
const NO_READING_LIMIT: Duration = Duration::from_secs(600);
const NO_READING_MINIMUM: u32 = 10;
/// Failures further apart than the gap are not back to back; the streak
/// restarts. A failed pass lasts up to the probe timeout plus its margin, so
/// the gap grows with the service's own timeout.
const NO_READING_GAP: Duration = Duration::from_secs(90);
/// How much longer than a failed pass the gap must allow.
const GAP_MARGIN: Duration = Duration::from_secs(60);
/// Probe deadline beyond the health timeout, as the pass allows it.
const PROBE_MARGIN: Duration = Duration::from_secs(15);
/// While the host is busy or most checked scopes are failing, an unhealthy
/// reading must persist this long before the service is restarted.
const STARVED_CONFIRM: Duration = Duration::from_secs(120);
/// Suppression lasting this long is reported as stuck (visibility only).
const SUPPRESSED_LONG: Duration = Duration::from_secs(600);
/// The host-busy answer is reused for this long; it walks the ledger.
const BUSY_TTL: Duration = Duration::from_secs(5);

/// The gap for a service whose health probe may take `timeout_seconds`.
fn probe_gap(timeout_seconds: u32) -> Duration {
    NO_READING_GAP.max(Duration::from_secs(u64::from(timeout_seconds)) + PROBE_MARGIN + GAP_MARGIN)
}

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
fn in_flight_in(scheduler: &Scheduler, scope: &Scope) -> Option<Duration> {
    let pending = scheduler.pending.lock().unwrap_or_else(|e| e.into_inner());
    pending
        .get(scope)
        .and_then(|slot| slot.started)
        .map(|at| at.elapsed())
}

pub(super) fn in_flight(scope: &Scope) -> Option<Duration> {
    let scheduler = scheduler().lock().unwrap_or_else(|e| e.into_inner());
    in_flight_in(scheduler.as_ref()?, scope)
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
/// Drop entries for scopes that no longer exist. `checked` is how many of
/// them have a health check; only those can ever fail a reading.
pub(super) fn steady_retain(live: &BTreeSet<Scope>, checked: usize) {
    LIVE.store(checked, std::sync::atomic::Ordering::Relaxed);
    let mut cache = steady().lock().unwrap_or_else(|e| e.into_inner());
    cache.0.retain(|scope, _| live.contains(scope));
    unhealthy()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .0
        .retain(|scope, _| live.contains(scope));
    let mut readings = no_readings().lock().unwrap_or_else(|e| e.into_inner());
    readings.streaks.retain(|scope, _| live.contains(scope));
    readings.recent.retain(|scope, _| live.contains(scope));
    readings.suppressed.retain(|scope, _| live.contains(scope));
}

/// First unhealthy sighting per container generation, on the monotonic clock.
/// A running service is stopped only when a later pass, at least the required
/// time after the first, still reads unhealthy with a probe attempted in that
/// pass. The required time is `CONFIRM`, or `STARVED_CONFIRM` while the host
/// is busy or starved. `due` asks the pass to probe at once.
#[derive(Default)]
struct Unhealthy(BTreeMap<Scope, (String, Instant)>);
impl Unhealthy {
    fn required(starved: bool) -> Duration {
        if starved { STARVED_CONFIRM } else { CONFIRM }
    }
    fn confirm(
        &mut self,
        scope: &Scope,
        generation: &str,
        now: Instant,
        probed: bool,
        starved: bool,
    ) -> bool {
        match self.0.get(scope) {
            Some((seen, first)) if seen == generation => {
                probed && now.saturating_duration_since(*first) >= Self::required(starved)
            }
            _ => {
                self.0.insert(scope.clone(), (generation.to_owned(), now));
                false
            }
        }
    }
    /// Age of the sighting for this generation, if any.
    fn age(&self, scope: &Scope, generation: &str, now: Instant) -> Option<Duration> {
        self.0
            .get(scope)
            .filter(|(seen, _)| seen == generation)
            .map(|(_, first)| now.saturating_duration_since(*first))
    }
}
fn unhealthy() -> &'static Mutex<Unhealthy> {
    static CACHE: OnceLock<Mutex<Unhealthy>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Unhealthy::default()))
}
/// An unhealthy sighting is old enough that this pass must probe again. The
/// host-wide answer is asked only for a sighting old enough to matter, and
/// never while a lock is held.
pub(super) fn unhealthy_due(scope: &Scope, generation: &str, busy: &dyn Fn() -> bool) -> bool {
    let now = Instant::now();
    let age = unhealthy()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .age(scope, generation, now);
    forced_probe(age, || starved(busy_cached(busy, now), now))
}
fn forced_probe(age: Option<Duration>, starved: impl FnOnce() -> bool) -> bool {
    match age {
        Some(age) if age >= CONFIRM => age >= STARVED_CONFIRM || !starved(),
        _ => false,
    }
}

/// Failed or overdue readings. A streak only grows from failures at most one
/// gap apart; any other reading removes everything about the scope.
#[derive(Default)]
struct NoReadings {
    streaks: BTreeMap<Scope, Streak>,
    /// Latest failure of each scope and its gap, for the host-wide view.
    recent: BTreeMap<Scope, (Instant, Duration)>,
    /// First and latest suppressed failure of each scope.
    suppressed: BTreeMap<Scope, (Instant, Instant)>,
}
struct Streak {
    generation: String,
    first: Instant,
    last: Instant,
    count: u32,
}
impl NoReadings {
    /// True once back-to-back readings have failed past the bound.
    fn note(&mut self, scope: &Scope, generation: &str, now: Instant, gap: Duration) -> bool {
        let continues = self.streaks.get(scope).is_some_and(|streak| {
            streak.generation == generation && now.saturating_duration_since(streak.last) <= gap
        });
        if !continues {
            self.streaks.insert(
                scope.clone(),
                Streak {
                    generation: generation.to_owned(),
                    first: now,
                    last: now,
                    count: 0,
                },
            );
        }
        let streak = self.streaks.get_mut(scope).unwrap();
        streak.last = now;
        streak.count += 1;
        streak.count >= NO_READING_MINIMUM
            && now.saturating_duration_since(streak.first) >= NO_READING_LIMIT
    }
    /// Scopes whose readings are failing right now.
    fn failing(&self, now: Instant) -> usize {
        self.recent
            .values()
            .filter(|(last, gap)| now.saturating_duration_since(*last) <= *gap)
            .count()
    }
    fn forget(&mut self, scope: &Scope) {
        self.streaks.remove(scope);
        self.recent.remove(scope);
        self.suppressed.remove(scope);
    }
}
fn no_readings() -> &'static Mutex<NoReadings> {
    static CACHE: OnceLock<Mutex<NoReadings>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(NoReadings::default()))
}

/// Most of the health-checked scopes are failing together.
fn majority(failing: usize, checked: usize) -> bool {
    failing >= 2 && failing * 2 > checked
}

/// The host is under load from something other than this container.
fn starved(busy: bool, now: Instant) -> bool {
    busy || majority(
        no_readings()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .failing(now),
        LIVE.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// Reuse a recent host-busy answer instead of walking the ledger again.
fn busy_cached(compute: &dyn Fn() -> bool, now: Instant) -> bool {
    static CACHE: OnceLock<Mutex<Option<(Instant, bool)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    busy_reuse(cache, compute, now)
}
fn busy_reuse(
    cache: &Mutex<Option<(Instant, bool)>>,
    compute: &dyn Fn() -> bool,
    now: Instant,
) -> bool {
    if let Some((at, answer)) = *cache.lock().unwrap_or_else(|e| e.into_inner())
        && now.saturating_duration_since(at) < BUSY_TTL
    {
        return answer;
    }
    // Computed without any lock held.
    let answer = compute();
    *cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((now, answer));
    answer
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
    /// The bound is held off because the host is busy or starved. `long` once
    /// that has lasted long enough to be worth reporting as stuck.
    Suppressed { long: bool },
    /// Stop (if running) and restart it.
    Restart,
    /// Clean up the service exactly as a failed observation always did. Only
    /// confinement, ownership and identity failures end here.
    Kill,
    /// Readings failed back to back past their bound with no host-wide cause:
    /// restart through the normal graceful stop path. The streak stays until
    /// the stop actually happens.
    GiveUp,
}

/// What is known about the host beyond this one service.
pub(super) struct Host {
    /// Any deploy, start, restart or backup is in a non-terminal phase.
    pub busy: bool,
    /// Health-checked scopes under maintenance.
    pub checked: usize,
    /// Allowed gap between back-to-back failures of this service.
    pub gap: Duration,
}

fn judge_with(
    unhealthy: &mut Unhealthy,
    readings: &mut NoReadings,
    scope: &Scope,
    observed: Observed,
    generation: &str,
    now: Instant,
    host: &Host,
) -> Verdict {
    match observed {
        Observed::Healthy | Observed::NotRunning => {
            readings.forget(scope);
            unhealthy.0.remove(scope);
            if observed == Observed::Healthy {
                Verdict::Keep
            } else {
                Verdict::Restart
            }
        }
        Observed::Unhealthy { probed } => {
            readings.forget(scope);
            let starved = host.busy || majority(readings.failing(now), host.checked);
            if unhealthy.confirm(scope, generation, now, probed, starved) {
                Verdict::Restart
            } else {
                Verdict::Wait("unhealthy-unconfirmed")
            }
        }
        Observed::Unreadable => {
            readings.forget(scope);
            Verdict::Keep
        }
        Observed::NoReading => {
            readings.recent.insert(scope.clone(), (now, host.gap));
            if host.busy || majority(readings.failing(now), host.checked) {
                // The host is starved or busy; this container is not shown
                // to be the broken one. Nothing accumulates meanwhile, so a
                // full quiet bound is needed once the host recovers.
                readings.streaks.remove(scope);
                let gap = host.gap;
                let (since, _) = *readings
                    .suppressed
                    .entry(scope.clone())
                    .and_modify(|(since, last)| {
                        if now.saturating_duration_since(*last) > gap {
                            *since = now;
                        }
                        *last = now;
                    })
                    .or_insert((now, now));
                Verdict::Suppressed {
                    long: now.saturating_duration_since(since) >= SUPPRESSED_LONG,
                }
            } else {
                readings.suppressed.remove(scope);
                if readings.note(scope, generation, now, host.gap) {
                    Verdict::GiveUp
                } else {
                    Verdict::Wait("engine-unavailable")
                }
            }
        }
        Observed::Failed => Verdict::Kill,
    }
}
/// `timeout_seconds` is the service's health timeout. The host-busy question
/// is answered, from cache when recent, before any lock is taken.
pub(super) fn judge(
    scope: &Scope,
    observed: Observed,
    generation: &str,
    timeout_seconds: u32,
    busy: &dyn Fn() -> bool,
) -> Verdict {
    let now = Instant::now();
    let busy = matches!(observed, Observed::NoReading | Observed::Unhealthy { .. })
        && busy_cached(busy, now);
    judge_with(
        &mut unhealthy().lock().unwrap_or_else(|e| e.into_inner()),
        &mut no_readings().lock().unwrap_or_else(|e| e.into_inner()),
        scope,
        observed,
        generation,
        now,
        &Host {
            busy,
            checked: LIVE.load(std::sync::atomic::Ordering::Relaxed),
            gap: probe_gap(timeout_seconds),
        },
    )
}
static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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

    struct World {
        unhealthy: Unhealthy,
        readings: NoReadings,
        busy: bool,
        checked: usize,
        timeout: u32,
        generation: &'static str,
        scope: Scope,
    }
    impl World {
        fn new() -> Self {
            World {
                unhealthy: Unhealthy::default(),
                readings: NoReadings::default(),
                busy: false,
                checked: 1,
                timeout: 5,
                generation: "g1",
                scope: scope(1),
            }
        }
        fn judge(&mut self, observed: Observed, at: Instant) -> Verdict {
            judge_with(
                &mut self.unhealthy,
                &mut self.readings,
                &self.scope,
                observed,
                self.generation,
                at,
                &Host {
                    busy: self.busy,
                    checked: self.checked,
                    gap: probe_gap(self.timeout),
                },
            )
        }
    }
    const WAIT: Verdict = Verdict::Wait("engine-unavailable");
    const SUPPRESSED: Verdict = Verdict::Suppressed { long: false };

    fn times() -> (Instant, impl Fn(u64) -> Instant) {
        let t0 = Instant::now();
        (t0, move |seconds| t0 + Duration::from_secs(seconds))
    }

    #[test]
    fn unhealthy_needs_a_later_reading_with_a_probe_and_is_not_delayed_by_the_interval() {
        let mut world = World::new();
        let (_, at) = times();
        let unhealthy = |probed| Observed::Unhealthy { probed };
        let wait = Verdict::Wait("unhealthy-unconfirmed");
        assert_eq!(world.judge(unhealthy(false), at(0)), wait);
        assert_eq!(world.judge(unhealthy(true), at(2)), wait);
        assert_eq!(
            world.unhealthy.age(&scope(1), "g1", at(4)),
            Some(Duration::from_secs(4))
        );
        assert_eq!(world.judge(unhealthy(false), at(5)), wait);
        assert_eq!(world.judge(unhealthy(true), at(5)), Verdict::Restart);
        world.judge(Observed::Healthy, at(6));
        assert_eq!(world.judge(unhealthy(true), at(7)), wait);
        world.generation = "g2";
        assert_eq!(world.judge(unhealthy(true), at(20)), wait);
    }

    #[test]
    fn an_unhealthy_reading_needs_two_minutes_while_the_host_is_busy_or_starved() {
        let (_, at) = times();
        let unhealthy = Observed::Unhealthy { probed: true };
        let wait = Verdict::Wait("unhealthy-unconfirmed");
        let mut busy = World::new();
        busy.busy = true;
        assert_eq!(busy.judge(unhealthy, at(0)), wait);
        assert_eq!(busy.judge(unhealthy, at(5)), wait);
        assert_eq!(busy.judge(unhealthy, at(119)), wait);
        assert_eq!(busy.judge(unhealthy, at(120)), Verdict::Restart);
        // Most health-checked scopes failing together is the same condition.
        let mut crowded = World::new();
        crowded.checked = 3;
        for number in [2, 3] {
            crowded
                .readings
                .recent
                .insert(scope(number), (at(0), Duration::from_secs(90)));
        }
        assert_eq!(crowded.judge(unhealthy, at(0)), wait);
        assert_eq!(crowded.judge(unhealthy, at(30)), wait);
        crowded.readings.recent.clear();
        assert_eq!(crowded.judge(unhealthy, at(31)), Verdict::Restart);
        // The probe is forced early only when the host is quiet.
        let mut quiet = World::new();
        quiet.judge(unhealthy, at(0));
        assert!(quiet.unhealthy.age(&scope(1), "g1", at(5)).unwrap() >= CONFIRM);
    }

    #[test]
    fn a_forced_probe_waits_for_the_starved_bound_and_asks_the_host_late() {
        let asked = std::cell::Cell::new(0);
        let secs = |seconds| Some(Duration::from_secs(seconds));
        let ask = |answer: bool| {
            let asked = &asked;
            move || {
                asked.set(asked.get() + 1);
                answer
            }
        };
        assert!(!forced_probe(None, ask(false)));
        assert!(!forced_probe(secs(3), ask(false)));
        assert_eq!(asked.get(), 0, "no host walk for a young sighting");
        assert!(forced_probe(secs(5), ask(false)));
        assert!(!forced_probe(secs(5), ask(true)));
        assert_eq!(asked.get(), 2);
        assert!(forced_probe(secs(120), ask(true)));
        assert_eq!(asked.get(), 2, "an old sighting needs no host answer");
    }

    #[test]
    fn scattered_failures_never_add_up() {
        let mut world = World::new();
        let (_, at) = times();
        assert_eq!(world.judge(Observed::NoReading, at(0)), WAIT);
        assert_eq!(world.judge(Observed::NoReading, at(5_000)), WAIT);
        assert_eq!(world.judge(Observed::NoReading, at(5_010)), WAIT);
        assert_eq!(world.readings.streaks[&scope(1)].count, 2);
        for number in 0..40 {
            assert_eq!(
                world.judge(Observed::NoReading, at(10_000 + number * 200)),
                WAIT
            );
        }
    }

    #[test]
    fn a_neighbours_deployment_starving_the_host_for_minutes_takes_no_action() {
        let mut world = World::new();
        let (_, at) = times();
        for second in (0..=210).step_by(20) {
            assert_eq!(world.judge(Observed::NoReading, at(second)), WAIT);
        }
    }

    #[test]
    fn ten_continuous_quiet_minutes_of_failures_restart_gracefully() {
        let (_, at) = times();
        let mut quiet = World::new();
        for second in (0..600).step_by(30) {
            assert_eq!(quiet.judge(Observed::NoReading, at(second)), WAIT);
        }
        assert_eq!(quiet.judge(Observed::NoReading, at(600)), Verdict::GiveUp);
    }

    #[test]
    fn the_streak_survives_a_skipped_stop_so_the_restart_is_not_delayed_again() {
        let (_, at) = times();
        let mut world = World::new();
        for second in (0..600).step_by(30) {
            world.judge(Observed::NoReading, at(second));
        }
        assert_eq!(world.judge(Observed::NoReading, at(600)), Verdict::GiveUp);
        // The commit was skipped (lease busy): the next pass gives up again.
        assert_eq!(world.judge(Observed::NoReading, at(601)), Verdict::GiveUp);
        // Only a reading ends it.
        world.judge(Observed::Healthy, at(602));
        assert_eq!(world.judge(Observed::NoReading, at(603)), WAIT);
    }

    #[test]
    fn a_long_operation_ending_never_restarts_a_neighbour_on_its_first_failure() {
        let (_, at) = times();
        let mut world = World::new();
        world.busy = true;
        // The operation runs for twenty minutes while probes keep failing.
        for second in (0..1200).step_by(30) {
            assert!(matches!(
                world.judge(Observed::NoReading, at(second)),
                Verdict::Suppressed { .. }
            ));
        }
        assert!(
            world.readings.streaks.is_empty(),
            "nothing accumulates while busy"
        );
        // It turns terminal: ten quiet minutes of failure are needed first.
        world.busy = false;
        for second in (1200..1800).step_by(30) {
            assert_eq!(world.judge(Observed::NoReading, at(second)), WAIT);
        }
        assert_eq!(world.judge(Observed::NoReading, at(1800)), Verdict::GiveUp);
    }

    #[test]
    fn most_checked_scopes_failing_together_is_a_host_problem_not_a_broken_container() {
        let (_, at) = times();
        let mut world = World::new();
        world.checked = 3;
        for second in (0..600).step_by(30) {
            world
                .readings
                .recent
                .insert(scope(2), (at(second), Duration::from_secs(90)));
            assert_ne!(
                world.judge(Observed::NoReading, at(second)),
                Verdict::GiveUp
            );
        }
        world
            .readings
            .recent
            .insert(scope(2), (at(600), Duration::from_secs(90)));
        assert!(matches!(
            world.judge(Observed::NoReading, at(600)),
            Verdict::Suppressed { .. }
        ));
        // Unchecked scopes do not dilute the denominator: two of two checked
        // scopes failing is a majority even on a host with many other scopes.
        let mut diluted = World::new();
        diluted.checked = 2;
        diluted
            .readings
            .recent
            .insert(scope(2), (at(0), Duration::from_secs(90)));
        assert_eq!(diluted.judge(Observed::NoReading, at(0)), SUPPRESSED);
        // A lone failing scope among many healthy checked ones is the broken one.
        let mut lone = World::new();
        lone.checked = 5;
        for second in (0..600).step_by(30) {
            lone.judge(Observed::NoReading, at(second));
        }
        assert_eq!(lone.judge(Observed::NoReading, at(600)), Verdict::GiveUp);
    }

    #[test]
    fn long_suppression_is_reported_once_it_has_lasted_and_resets_with_a_gap() {
        let (_, at) = times();
        let mut world = World::new();
        world.busy = true;
        for second in (0..600).step_by(30) {
            assert_eq!(world.judge(Observed::NoReading, at(second)), SUPPRESSED);
        }
        assert_eq!(
            world.judge(Observed::NoReading, at(600)),
            Verdict::Suppressed { long: true }
        );
        // Failures stop for longer than the gap: a new suppression begins.
        assert_eq!(world.judge(Observed::NoReading, at(2000)), SUPPRESSED);
        world.judge(Observed::Healthy, at(2001));
        assert!(world.readings.suppressed.is_empty());
    }

    #[test]
    fn the_gap_follows_the_probe_timeout_so_slow_probes_can_still_give_up() {
        assert_eq!(probe_gap(5), Duration::from_secs(90));
        assert_eq!(probe_gap(300), Duration::from_secs(375));
        let (_, at) = times();
        let mut slow = World::new();
        slow.timeout = 300;
        // Each failed pass takes timeout + 15 s; ten of them take 47 minutes.
        for number in 0..9 {
            let verdict = slow.judge(Observed::NoReading, at(number * 316));
            assert_eq!(verdict, WAIT);
        }
        assert_eq!(
            slow.judge(Observed::NoReading, at(9 * 316)),
            Verdict::GiveUp
        );
        // With the default gap the same cadence would never accumulate.
        let mut fixed = World::new();
        for number in 0..=11 {
            assert_eq!(fixed.judge(Observed::NoReading, at(number * 316)), WAIT);
        }
        assert_eq!(fixed.readings.streaks[&scope(1)].count, 1);
    }

    #[test]
    fn the_host_busy_answer_is_cached_and_computed_outside_any_lock() {
        let cache = Mutex::new(None);
        let (_, at) = times();
        let calls = std::cell::Cell::new(0);
        let compute = || {
            calls.set(calls.get() + 1);
            // The cache lock is free while the ledger is being walked.
            assert!(cache.try_lock().is_ok());
            true
        };
        assert!(busy_reuse(&cache, &compute, at(0)));
        assert!(busy_reuse(&cache, &compute, at(4)));
        assert_eq!(calls.get(), 1);
        assert!(busy_reuse(&cache, &compute, at(5)));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn any_successful_reading_resets_the_streak() {
        let (_, at) = times();
        for reading in [
            Observed::Healthy,
            Observed::Unreadable,
            Observed::NotRunning,
            Observed::Unhealthy { probed: true },
        ] {
            let mut world = World::new();
            for second in (0..580).step_by(30) {
                world.judge(Observed::NoReading, at(second));
            }
            world.judge(reading, at(590));
            assert!(world.readings.streaks.is_empty(), "{reading:?}");
            assert_eq!(world.judge(Observed::NoReading, at(620)), WAIT);
        }
    }

    #[test]
    fn proof_failures_kill_at_once_and_stopped_containers_restart_promptly() {
        let mut world = World::new();
        let now = Instant::now();
        assert_eq!(world.judge(Observed::Failed, now), Verdict::Kill);
        assert_eq!(world.judge(Observed::NotRunning, now), Verdict::Restart);
        assert_eq!(world.judge(Observed::Unreadable, now), Verdict::Keep);
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
        let running = scope(9);
        assert_eq!(in_flight_in(&scheduler, &running), None);
        assert!(scheduler.enqueue(running.clone()).unwrap());
        until(|| in_flight_in(&scheduler, &running).is_some());
        std::thread::sleep(Duration::from_millis(5));
        assert!(in_flight_in(&scheduler, &running).unwrap() >= Duration::from_millis(5));
        // A scope no worker has begun reports nothing, however long queued.
        let queued = scope(10);
        scheduler
            .pending
            .lock()
            .unwrap()
            .insert(queued.clone(), Slot { started: None });
        assert_eq!(in_flight_in(&scheduler, &queued), None);
        scheduler.pending.lock().unwrap().remove(&queued);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        until(|| scheduler.pending.lock().unwrap().is_empty());
        assert_eq!(in_flight_in(&scheduler, &running), None);
    }
}
