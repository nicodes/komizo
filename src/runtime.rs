//! Cancellation for the local owner client and supervised loopback API.
use anyhow::{Result, ensure};
use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[derive(Clone)]
pub struct Context {
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}
impl Context {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "operation cancelled"
        );
        ensure!(Instant::now() < self.deadline, "operation deadline expired");
        Ok(())
    }
}
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
    Context {
        deadline: Instant::now() + Duration::from_secs(365 * 24 * 3600),
        cancelled,
    }
}
