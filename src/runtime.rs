use crate::workload::activation::Context;
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub const VERSION: &str = match option_env!("KOMIZO_VERSION") {
    Some(version) => version,
    None => "dev",
};
static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
extern "C" fn terminate(_: libc::c_int) {
    if let Some(stopping) = STOP.get() {
        stopping.store(true, Ordering::Release);
    }
}
pub fn signal_context() -> Context {
    let cancelled = STOP
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();
    unsafe {
        libc::signal(libc::SIGINT, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, terminate as *const () as libc::sighandler_t);
    }
    let mut ctx = Context::new(Instant::now() + Duration::from_secs(365 * 24 * 3600));
    ctx.cancelled = cancelled;
    ctx
}
pub fn bounded(parent: &Context, duration: Duration) -> Context {
    let mut ctx = parent.clone();
    ctx.deadline = ctx.deadline.min(Instant::now() + duration);
    ctx
}
pub fn sleep(ctx: &Context, duration: Duration) -> bool {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        if ctx.check().is_err() {
            return false;
        }
        std::thread::sleep(
            Duration::from_millis(20).min(end.saturating_duration_since(Instant::now())),
        );
    }
    ctx.check().is_ok()
}
pub struct Ticker {
    next: Instant,
    period: Duration,
}
impl Ticker {
    pub fn new(period: Duration) -> Self {
        assert!(!period.is_zero());
        Self {
            next: Instant::now() + period,
            period,
        }
    }
    pub fn wait(&mut self, ctx: &Context) -> bool {
        if !sleep(ctx, self.next.saturating_duration_since(Instant::now())) {
            return false;
        }
        let missed = Instant::now()
            .saturating_duration_since(self.next)
            .as_nanos()
            / self.period.as_nanos()
            + 1;
        self.next = if let Ok(missed) = u32::try_from(missed) {
            self.next + self.period * missed
        } else {
            Instant::now() + self.period
        };
        true
    }
}
