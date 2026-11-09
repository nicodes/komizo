//! An absolute kernel timer owns a protected task's complete systemd cgroup.
use anyhow::{Result, ensure};
use std::{
    fs,
    time::{Duration, Instant},
};

pub fn monotonic_ns() -> Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } == 0,
        "protected task monotonic clock unavailable"
    );
    ensure!(
        value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "invalid monotonic clock"
    );
    u64::try_from(value.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| anyhow::anyhow!("monotonic deadline overflow"))
}

pub fn boot_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    ensure!(
        valid_boot_id(value),
        "protected task boot identity unavailable"
    );
    Ok(value.into())
}

pub fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

pub fn deadline(deadline: Instant, maximum_seconds: u32) -> Result<(String, u64)> {
    // Read the kernel clock first: time spent sampling cannot extend the bound.
    let clock = monotonic_ns()?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow::anyhow!("protected task deadline expired"))?
        .min(Duration::from_secs(u64::from(maximum_seconds)));
    ensure!(
        !remaining.is_zero() && remaining <= Duration::from_secs(1500),
        "invalid protected task lifetime"
    );
    Ok((
        boot_id()?,
        clock
            .checked_add(remaining.as_nanos().try_into()?)
            .ok_or_else(|| anyhow::anyhow!("protected task lifetime overflow"))?,
    ))
}

#[cfg(any(target_os = "linux", test))]
fn group(text: &str, unit: &str) -> Result<String> {
    let expected = format!("/komizo.slice/komizo-control.slice/{unit}");
    ensure!(
        text.trim() == format!("0::{expected}"),
        "protected task is outside its exact service cgroup"
    );
    Ok(expected)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::unix::{fs::OpenOptionsExt, io::AsRawFd},
        path::{Path, PathBuf},
        sync::atomic::{AtomicI32, Ordering},
    };
    static KILL_FD: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn expired(_: libc::c_int) {
        // write(2) and _exit(2) are async-signal-safe. cgroup.kill terminates the
        // wrapper and every descendant, including children with a new session.
        let fd = KILL_FD.load(Ordering::Relaxed);
        if fd >= 0 {
            unsafe {
                libc::write(fd, b"1".as_ptr().cast(), 1);
            }
        }
        // The unit's KillSignal=SIGKILL is a second boundary if the kernel write
        // fails. No task code resumes after a delivered expiry signal.
        unsafe {
            libc::_exit(124);
        }
    }

    struct Timer(libc::timer_t);
    impl Timer {
        fn arm(fd: i32, deadline: u64) -> Result<Self> {
            ensure!(
                KILL_FD
                    .compare_exchange(-1, fd, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok(),
                "protected task already owns a deadline timer"
            );
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = expired as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            ensure!(
                unsafe { libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()) } == 0,
                "cannot install protected task deadline handler"
            );
            let mut unblocked: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut unblocked);
                libc::sigaddset(&mut unblocked, libc::SIGALRM);
            }
            ensure!(
                unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &unblocked, std::ptr::null_mut()) }
                    == 0,
                "cannot unblock protected task deadline signal"
            );
            let mut signal: libc::sigevent = unsafe { std::mem::zeroed() };
            signal.sigev_notify = libc::SIGEV_SIGNAL;
            signal.sigev_signo = libc::SIGALRM;
            let mut timer = std::ptr::null_mut();
            ensure!(
                unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut signal, &mut timer) } == 0,
                "cannot create protected task kernel deadline"
            );
            let result = Self(timer);
            let specification = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: (deadline / 1_000_000_000).try_into()?,
                    tv_nsec: (deadline % 1_000_000_000).try_into()?,
                },
            };
            ensure!(
                unsafe {
                    libc::timer_settime(
                        timer,
                        libc::TIMER_ABSTIME,
                        &specification,
                        std::ptr::null_mut(),
                    )
                } == 0,
                "cannot arm protected task absolute deadline"
            );
            Ok(result)
        }
    }
    impl Drop for Timer {
        fn drop(&mut self) {
            unsafe {
                libc::timer_delete(self.0);
            }
        }
    }

    pub struct Lifetime {
        timer: Option<Timer>,
        kill: File,
        path: PathBuf,
        deadline: u64,
        settled: bool,
    }
    impl Lifetime {
        pub fn arm(unit: &str, boot: &str, deadline: u64) -> Result<Self> {
            let now = monotonic_ns()?;
            ensure!(
                boot == boot_id()?
                    && deadline
                        .checked_sub(now)
                        .is_some_and(|remaining| remaining > 0 && remaining <= 1_500_000_000_000),
                "protected task lifetime expired, unbounded or belongs to another boot"
            );
            let path = Path::new("/sys/fs/cgroup").join(
                group(&fs::read_to_string("/proc/self/cgroup")?, unit)?.trim_start_matches('/'),
            );
            let kill = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path.join("cgroup.kill"))?;
            let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
            ensure!(
                unsafe { libc::fstatfs(kill.as_raw_fd(), &mut filesystem) } == 0
                    && filesystem.f_type == 0x63677270,
                "protected task kill boundary is not unified cgroupfs"
            );
            let mut result = Self {
                timer: None,
                kill,
                path,
                deadline,
                settled: false,
            };
            result.timer = Some(Timer::arm(result.kill.as_raw_fd(), deadline)?);
            Ok(result)
        }
        pub fn finish(mut self) -> Result<()> {
            loop {
                let mut body = String::new();
                File::open(self.path.join("cgroup.procs"))?
                    .take(65537)
                    .read_to_string(&mut body)?;
                ensure!(
                    !body.trim().is_empty() && body.len() <= 65536,
                    "protected task lost its bounded cgroup process evidence"
                );
                if body
                    .lines()
                    .all(|line| line.parse::<u32>().ok() == Some(std::process::id()))
                {
                    break;
                }
                ensure!(
                    monotonic_ns()? < self.deadline,
                    "protected task descendants exceeded their absolute lifetime"
                );
                // Reaping a completed native helper may lag its synchronous
                // client. Keep the kernel deadline armed until all are gone.
                std::thread::sleep(Duration::from_millis(10));
            }
            self.timer.take();
            KILL_FD.store(-1, Ordering::SeqCst);
            self.settled = true;
            Ok(())
        }
    }
    impl Drop for Lifetime {
        fn drop(&mut self) {
            if !self.settled {
                // Never leave children behind on validation, spawn, wait or
                // cleanup errors. The exact task group includes this process.
                let _ = self.kill.write_all(b"1");
                unsafe {
                    libc::_exit(124);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn absolute_timer_child() {
            let Some(path) = std::env::var_os("KOMIZO_TASK_TIMER_TEST") else {
                return;
            };
            let file = OpenOptions::new().write(true).open(path).unwrap();
            let deadline = monotonic_ns().unwrap() + 50_000_000;
            // Simulate setup consuming the entire budget before the wrapper
            // arms its timer; an absolute expired timer fires immediately.
            std::thread::sleep(Duration::from_millis(100));
            let _timer = Timer::arm(file.as_raw_fd(), deadline).unwrap();
            std::thread::sleep(Duration::from_secs(10));
            panic!("absolute task timer did not terminate its independent process");
        }
        #[test]
        fn absolute_expiry_counts_setup_and_terminates_an_independent_process() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("event");
            File::create(&path).unwrap();
            let started = Instant::now();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "deployment::native::task_lifetime::linux::tests::absolute_timer_child",
                ])
                .env("KOMIZO_TASK_TIMER_TEST", &path)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(124));
            assert_eq!(fs::read(path).unwrap(), b"1");
            assert!(started.elapsed() < Duration::from_secs(3));
        }
    }
}
#[cfg(target_os = "linux")]
pub use linux::Lifetime;

#[cfg(not(target_os = "linux"))]
pub struct Lifetime;
#[cfg(not(target_os = "linux"))]
impl Lifetime {
    pub fn arm(_: &str, _: &str, _: u64) -> Result<Self> {
        anyhow::bail!("protected task lifetime requires Linux")
    }
    pub fn finish(self) -> Result<()> {
        anyhow::bail!("protected task lifetime requires Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_is_the_exact_operation_service_never_its_shared_parent() {
        let unit = "komizo-backup-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service";
        assert!(
            group(
                &format!("0::/komizo.slice/komizo-control.slice/{unit}\n"),
                unit
            )
            .is_ok()
        );
        for body in [
            "0::/",
            "0::/komizo.slice/komizo-control.slice",
            "0::/system.slice/other.service",
            "0::/komizo.slice/komizo-control.slice/foreign.service",
            "0::/komizo.slice/komizo-control.slice/foreign.service\n0::/",
        ] {
            assert!(group(body, unit).is_err());
        }
        assert!(valid_boot_id("a1234567-1234-1234-1234-123456789abc"));
        assert!(!valid_boot_id("../../another-boot"));
    }
}
