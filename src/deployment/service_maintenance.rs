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
/// Failures further apart than this are not back to back; the streak restarts.
const NO_READING_GAP: Duration = Duration::from_secs(90);

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
/// Drop entries for scopes that no longer exist.
pub(super) fn steady_retain(live: &BTreeSet<Scope>) {
    LIVE.store(live.len(), std::sync::atomic::Ordering::Relaxed);
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

/// Continuous failed or overdue readings per container generation. A streak
/// only grows from failures at most `NO_READING_GAP` apart; any other
/// reading removes it.
#[derive(Default)]
struct NoReadings(BTreeMap<Scope, Streak>);
struct Streak {
    generation: String,
    first: Instant,
    last: Instant,
    count: u32,
}
impl NoReadings {
    /// True once back-to-back readings have failed past the bound.
    fn note(&mut self, scope: &Scope, generation: &str, now: Instant) -> bool {
        let continues = self.0.get(scope).is_some_and(|streak| {
            streak.generation == generation
                && now.saturating_duration_since(streak.last) <= NO_READING_GAP
        });
        if !continues {
            self.0.insert(
                scope.clone(),
                Streak {
                    generation: generation.to_owned(),
                    first: now,
                    last: now,
                    count: 0,
                },
            );
        }
        let streak = self.0.get_mut(scope).unwrap();
        streak.last = now;
        streak.count += 1;
        streak.count >= NO_READING_MINIMUM
            && now.saturating_duration_since(streak.first) >= NO_READING_LIMIT
    }
    /// Scopes whose readings are failing right now.
    fn failing(&self, now: Instant) -> usize {
        self.0
            .values()
            .filter(|streak| now.saturating_duration_since(streak.last) <= NO_READING_GAP)
            .count()
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
    /// Clean up the service exactly as a failed observation always did. Only
    /// confinement, ownership and identity failures end here.
    Kill,
    /// Readings failed back to back past their bound with no host-wide cause:
    /// restart through the normal graceful stop path.
    GiveUp,
}

/// What is known about the host beyond this one service.
pub(super) struct Host<'a> {
    /// Any deploy, start, restart or backup is in a non-terminal phase.
    pub busy: &'a dyn Fn() -> bool,
    /// Scopes under maintenance.
    pub live: usize,
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
        Observed::Unreadable => {
            readings.0.remove(scope);
            Verdict::Keep
        }
        Observed::NoReading => {
            if !readings.note(scope, generation, now) {
                Verdict::Wait("engine-unavailable")
            } else if readings.failing(now) >= 2 && readings.failing(now) * 2 > host.live
                || (host.busy)()
            {
                // The host is starved or busy; this container is not shown
                // to be the broken one.
                Verdict::Wait("probe-unavailable-suppressed")
            } else {
                readings.0.remove(scope);
                Verdict::GiveUp
            }
        }
        Observed::Failed => Verdict::Kill,
    }
}
pub(super) fn judge(
    scope: &Scope,
    observed: Observed,
    generation: &str,
    busy: &dyn Fn() -> bool,
) -> Verdict {
    judge_with(
        &mut unhealthy().lock().unwrap_or_else(|e| e.into_inner()),
        &mut no_readings().lock().unwrap_or_else(|e| e.into_inner()),
        scope,
        observed,
        generation,
        Instant::now(),
        &Host {
            busy,
            live: LIVE.load(std::sync::atomic::Ordering::Relaxed),
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
        live: usize,
        generation: &'static str,
        scope: Scope,
    }
    impl World {
        fn new() -> Self {
            World {
                unhealthy: Unhealthy::default(),
                readings: NoReadings::default(),
                busy: false,
                live: 1,
                generation: "g1",
                scope: scope(1),
            }
        }
        fn judge(&mut self, observed: Observed, at: Instant) -> Verdict {
            let busy = self.busy;
            judge_with(
                &mut self.unhealthy,
                &mut self.readings,
                &self.scope,
                observed,
                self.generation,
                at,
                &Host {
                    busy: &move || busy,
                    live: self.live,
                },
            )
        }
    }

    #[test]
    fn unhealthy_needs_a_later_reading_with_a_probe_and_is_not_delayed_by_the_interval() {
        let mut world = World::new();
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        let unhealthy = |probed| Observed::Unhealthy { probed };
        let wait = Verdict::Wait("unhealthy-unconfirmed");
        assert_eq!(world.judge(unhealthy(false), at(0)), wait);
        assert_eq!(world.judge(unhealthy(true), at(2)), wait);
        assert!(!world.unhealthy.due(&scope(1), "g1", at(4)));
        // Five seconds after the first sighting a probe is due, whatever the
        // health interval, and an attempted probe (even exit 125) confirms.
        assert!(world.unhealthy.due(&scope(1), "g1", at(5)));
        assert_eq!(world.judge(unhealthy(false), at(5)), wait);
        assert_eq!(world.judge(unhealthy(true), at(5)), Verdict::Restart);
        world.judge(Observed::Healthy, at(6));
        assert_eq!(world.judge(unhealthy(true), at(7)), wait);
        world.generation = "g2";
        assert_eq!(world.judge(unhealthy(true), at(20)), wait);
    }

    #[test]
    fn scattered_failures_never_add_up() {
        let mut world = World::new();
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        let wait = Verdict::Wait("engine-unavailable");
        // One failure, a long gap, two more: nothing happens.
        assert_eq!(world.judge(Observed::NoReading, at(0)), wait);
        assert_eq!(world.judge(Observed::NoReading, at(5_000)), wait);
        assert_eq!(world.judge(Observed::NoReading, at(5_010)), wait);
        assert_eq!(world.readings.0[&scope(1)].count, 2);
        // Even many sparse failures spanning hours stay below the bound.
        for number in 0..40 {
            assert_eq!(
                world.judge(Observed::NoReading, at(10_000 + number * 200)),
                wait
            );
        }
    }

    #[test]
    fn a_neighbours_deployment_starving_the_host_for_minutes_takes_no_action() {
        let mut world = World::new();
        let t0 = Instant::now();
        // 3.5 minutes of back-to-back failures.
        for second in (0..=210).step_by(20) {
            assert_eq!(
                world.judge(Observed::NoReading, t0 + Duration::from_secs(second)),
                Verdict::Wait("engine-unavailable")
            );
        }
    }

    #[test]
    fn ten_continuous_minutes_of_failures_restart_gracefully_only_when_the_host_is_quiet() {
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        let mut quiet = World::new();
        for second in (0..600).step_by(30) {
            assert_eq!(
                quiet.judge(Observed::NoReading, at(second)),
                Verdict::Wait("engine-unavailable")
            );
        }
        // Not a kill: a graceful restart, and the streak starts over.
        assert_eq!(quiet.judge(Observed::NoReading, at(600)), Verdict::GiveUp);
        assert!(quiet.readings.0.is_empty());
        // The same failures while an operation runs are suppressed, visibly.
        let mut busy = World::new();
        busy.busy = true;
        for second in (0..600).step_by(30) {
            busy.judge(Observed::NoReading, at(second));
        }
        assert_eq!(
            busy.judge(Observed::NoReading, at(600)),
            Verdict::Wait("probe-unavailable-suppressed")
        );
        // When the operation ends, the still-failing container is restarted.
        busy.busy = false;
        assert_eq!(busy.judge(Observed::NoReading, at(630)), Verdict::GiveUp);
    }

    #[test]
    fn most_scopes_failing_together_is_a_host_problem_not_a_broken_container() {
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
        let mut world = World::new();
        world.live = 3;
        let neighbour = |world: &mut World, second| {
            let other = scope(2);
            world.readings.note(&other, "g9", at(second));
        };
        for second in (0..600).step_by(30) {
            world.judge(Observed::NoReading, at(second));
            neighbour(&mut world, second);
        }
        // Two of three scopes are failing right now.
        assert_eq!(
            world.judge(Observed::NoReading, at(600)),
            Verdict::Wait("probe-unavailable-suppressed")
        );
        // A lone failing scope among many healthy ones is the broken one.
        let mut lone = World::new();
        lone.live = 5;
        for second in (0..600).step_by(30) {
            lone.judge(Observed::NoReading, at(second));
        }
        assert_eq!(lone.judge(Observed::NoReading, at(600)), Verdict::GiveUp);
    }

    #[test]
    fn any_successful_reading_resets_the_streak() {
        let t0 = Instant::now();
        let at = |seconds| t0 + Duration::from_secs(seconds);
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
            assert!(world.readings.0.is_empty(), "{reading:?}");
            assert_eq!(
                world.judge(Observed::NoReading, at(620)),
                Verdict::Wait("engine-unavailable")
            );
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
