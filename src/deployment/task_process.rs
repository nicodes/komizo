//! Reap exact owned children without making failed task cleanup wait forever.
use anyhow::{Result, ensure};
#[cfg(any(target_os = "linux", test))]
use std::process::Command;
use std::{
    process::{Child, ExitStatus},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
    },
    time::Duration,
};

const MAX_CHILDREN: usize = 64;
static CHILDREN: AtomicUsize = AtomicUsize::new(0);
static REAPER: OnceLock<Option<SyncSender<Retired>>> = OnceLock::new();

/// Called only in the child between fork and exec; all operations are syscalls.
#[cfg(target_os = "linux")]
pub(super) fn child_limits(reconciliation_output: bool) -> std::io::Result<()> {
    unsafe {
        libc::umask(0o077);
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Only reconciliation redirects output to an ordinary journal file.
        // Backup archives retain the inherited limit and their export budget.
        if reconciliation_output {
            let files = libc::rlimit {
                rlim_cur: 33_554_432,
                rlim_max: 33_554_432,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &files) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

struct Permit;
impl Permit {
    #[cfg(any(target_os = "linux", test))]
    fn acquire() -> Result<Self> {
        ensure!(
            CHILDREN
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| (value
                    < MAX_CHILDREN)
                    .then_some(value + 1))
                .is_ok(),
            "protected task child capacity is exhausted"
        );
        Ok(Self)
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        CHILDREN.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Retired {
    child: Child,
    _permit: Permit,
}

fn reaper() -> Result<&'static SyncSender<Retired>> {
    REAPER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<Retired>(MAX_CHILDREN);
            std::thread::Builder::new()
                .name("komizo-task-reaper".into())
                .stack_size(128 << 10)
                .spawn(move || {
                    let mut pending = Vec::<Retired>::new();
                    loop {
                        match receiver.recv_timeout(Duration::from_millis(20)) {
                            Ok(child) => pending.push(child),
                            Err(mpsc::RecvTimeoutError::Disconnected) => return,
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                        }
                        pending.retain_mut(|entry| !matches!(entry.child.try_wait(), Ok(Some(_))));
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("protected task reaper is unavailable"))
}

pub struct Process {
    child: Option<Child>,
    permit: Option<Permit>,
    kill_on_drop: bool,
}
impl Process {
    #[cfg(any(target_os = "linux", test))]
    pub fn spawn(command: &mut Command, kill_on_drop: bool) -> Result<Self> {
        reaper()?;
        let permit = Permit::acquire()?;
        Ok(Self {
            child: Some(command.spawn()?),
            permit: Some(permit),
            kill_on_drop,
        })
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .expect("owned child remains present")
            .try_wait()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let Some(permit) = self.permit.take() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        if self.kill_on_drop {
            let _ = child.kill();
        }
        // A watcher is deliberately not killed when its caller disappears:
        // its original absolute deadline still owns the runner and helpers.
        let retired = Retired {
            child,
            _permit: permit,
        };
        // There can be at most64 live permits including active and queued
        // children, so a64-entry queue cannot fill while this item is owned.
        // A failed reaper violates that safety invariant; OpenRC must restart
        // this controller while independent task watchdogs retain custody.
        if reaper()
            .and_then(|sender| {
                sender
                    .try_send(retired)
                    .map_err(|_| anyhow::anyhow!("protected task reaper failed"))
            })
            .is_err()
        {
            std::process::abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "linux")]
    #[test]
    fn file_limit_child() {
        use std::os::unix::fs::MetadataExt;
        let Ok(mode) = std::env::var("KOMIZO_TASK_FILE_LIMIT_TEST") else {
            return;
        };
        let reconcile = match mode.as_str() {
            "backup" => false,
            "reconcile" => true,
            _ => panic!("unknown child fixture"),
        };
        let mut before: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut before) },
            0
        );
        child_limits(reconcile).unwrap();
        let mut after: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut after) },
            0
        );
        if reconcile {
            assert_eq!((after.rlim_cur, after.rlim_max), (33_554_432, 33_554_432));
        } else {
            assert_eq!(
                (after.rlim_cur, after.rlim_max),
                (before.rlim_cur, before.rlim_max)
            );
        }
        let path =
            std::path::PathBuf::from(std::env::var_os("KOMIZO_TASK_FILE_LIMIT_PATH").unwrap());
        let file = std::fs::File::create_new(path).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o077, 0);
        if !reconcile && before.rlim_cur >= 33 << 20 {
            file.set_len(33 << 20)
                .expect("a backup must be able to exceed the reconciliation log limit");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_reconciliation_caps_regular_files_and_backup_keeps_its_export_budget() {
        let directory = tempfile::tempdir().unwrap();
        for mode in ["backup", "reconcile"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "deployment::native::task_process::tests::file_limit_child",
                    "--nocapture",
                ])
                .env("KOMIZO_TASK_FILE_LIMIT_TEST", mode)
                .env("KOMIZO_TASK_FILE_LIMIT_PATH", directory.path().join(mode))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn failed_runner_is_killed_and_reaped_without_blocking_its_caller() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let baseline = CHILDREN.load(Ordering::Acquire);
        let process = Process::spawn(&mut command, true).unwrap();
        let started = std::time::Instant::now();
        drop(process);
        assert!(started.elapsed() < Duration::from_secs(1));
        while CHILDREN.load(Ordering::Acquire) > baseline {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn dropping_the_caller_does_not_kill_an_independent_watchdog() {
        let _lock = TEST_LOCK.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("watcher-completed");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 0.05; printf watched > \"$1\"", "watcher"])
            .arg(&marker);
        let baseline = CHILDREN.load(Ordering::Acquire);
        let process = Process::spawn(&mut command, false).unwrap();
        let started = std::time::Instant::now();
        drop(process);
        assert!(started.elapsed() < Duration::from_secs(1));
        while !marker.exists() || CHILDREN.load(Ordering::Acquire) > baseline {
            assert!(started.elapsed() < Duration::from_secs(2));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(marker).unwrap(), b"watched");
    }
}
