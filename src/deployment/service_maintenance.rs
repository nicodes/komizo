//! A bounded queue for exact service observations, separate from admitted effects.
use anyhow::{Result, anyhow};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, mpsc},
};

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
    pending: Arc<Mutex<BTreeSet<Scope>>>,
}

struct Pending {
    scope: Scope,
    pending: Arc<Mutex<BTreeSet<Scope>>>,
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
        let pending = Arc::new(Mutex::new(BTreeSet::new()));
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
        if !pending.insert(scope.clone()) {
            return Ok(false);
        }
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

pub(super) fn enqueue(scope: Scope) -> Result<bool> {
    static SCHEDULER: OnceLock<Mutex<Option<Scheduler>>> = OnceLock::new();
    let mut scheduler = SCHEDULER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if scheduler.is_none() {
        *scheduler = Some(Scheduler::new(Arc::new(|scope| {
            let _ = super::maintain_service(scope);
        }))?);
    }
    scheduler.as_ref().unwrap().enqueue(scope)
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
}
