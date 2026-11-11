//! A task deadline remains owned after both its caller and runner disappear.
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;
use std::path::Path;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                fs::{MetadataExt, OpenOptionsExt},
                net::UnixStream,
            },
        },
    };

    struct Fence {
        kill: File,
        finished: bool,
    }
    impl Fence {
        fn kill(&mut self) -> Result<()> {
            self.kill.write_all(b"1")?;
            Ok(())
        }
    }
    impl Drop for Fence {
        fn drop(&mut self) {
            if !self.finished {
                let _ = self.kill.write_all(b"1");
            }
        }
    }

    fn cgroup_file(path: &Path, write: bool) -> Result<File> {
        let file = OpenOptions::new()
            .read(!write)
            .write(write)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0
                && unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } == 0
                && filesystem.f_type == 0x63677270,
            "task watchdog requires an owned kernel cgroup object"
        );
        Ok(file)
    }

    fn timer(deadline: u64) -> Result<OwnedFd> {
        let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
        ensure!(fd >= 0, "cannot create task watchdog kernel timer");
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
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
                libc::timerfd_settime(
                    fd.as_raw_fd(),
                    libc::TFD_TIMER_ABSTIME,
                    &specification,
                    std::ptr::null_mut(),
                )
            } == 0,
            "cannot arm task watchdog absolute deadline"
        );
        Ok(fd)
    }

    fn empty(path: &Path) -> Result<bool> {
        let mut raw = String::new();
        cgroup_file(&path.join("cgroup.events"), false)?
            .take(4097)
            .read_to_string(&mut raw)?;
        ensure!(
            raw.len() <= 4096,
            "task watchdog cgroup evidence exceeds bound"
        );
        let populated: Vec<_> = raw
            .lines()
            .filter_map(|line| line.strip_prefix("populated "))
            .collect();
        ensure!(
            populated.len() == 1 && matches!(populated[0], "0" | "1"),
            "task watchdog cgroup population is ambiguous"
        );
        Ok(populated[0] == "0")
    }

    /// The caller derives this path from its protected task intent. The socket
    /// is an anonymous owner-created pair; no file or executable is selected
    /// through this protocol. Dropping the caller endpoint never cancels time.
    pub fn serve(path: &Path, boot: &str, deadline: u64, mut channel: UnixStream) -> Result<()> {
        use super::super::task_lifetime;
        let unit = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let valid_unit = ["backup", "prepare", "reconcile"].iter().any(|kind| {
            unit.strip_prefix(&format!("komizo-{kind}-"))
                .and_then(|tail| tail.strip_suffix(".service"))
                .is_some_and(|id| super::super::super::validation::hex(id, 32))
        });
        ensure!(
            path.parent() == Some(Path::new("/sys/fs/cgroup/komizo/control")) && valid_unit,
            "task watchdog cannot select another kill boundary"
        );
        let now = task_lifetime::monotonic_ns()?;
        ensure!(
            unsafe { libc::geteuid() } == 0
                && boot == task_lifetime::boot_id()?
                && deadline
                    .checked_sub(now)
                    .is_some_and(|left| left > 0 && left <= 1_500_000_000_000),
            "task watchdog scope expired or belongs to another boot"
        );
        ensure!(
            std::fs::read_to_string("/proc/self/cgroup")?.trim() == "0::/komizo/control/watchdogs",
            "task watchdog escaped its protected infrastructure leaf"
        );
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    channel.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut credentials as *mut libc::ucred).cast(),
                    &mut size,
                )
            } == 0
                && credentials.uid == 0
                && credentials.pid > 0,
            "task watchdog channel is not an authenticated owner pair"
        );
        let mut fence = Fence {
            kill: cgroup_file(&path.join("cgroup.kill"), true)?,
            finished: false,
        };
        let timer = timer(deadline)?;
        channel.write_all(b"A")?;
        let mut control = channel.as_raw_fd();
        loop {
            let mut descriptors = [
                libc::pollfd {
                    fd: timer.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: control,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            ensure!(result >= 0, "task watchdog kernel wait failed");
            if descriptors[0].revents != 0 {
                fence.kill()?;
                anyhow::bail!("protected task reached its absolute deadline");
            }
            if descriptors[1].revents != 0 {
                let mut command = [0_u8];
                match channel.read(&mut command) {
                    Ok(0) => control = -1,
                    Ok(1) if command[0] == b'D' => {
                        ensure!(empty(path)?, "completed task still owns live descendants");
                        fence.finished = true;
                        channel.write_all(b"D")?;
                        return Ok(());
                    }
                    _ => anyhow::bail!("invalid task watchdog owner protocol"),
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn absolute_kernel_deadline_does_not_restart_when_owner_disappears() {
            let deadline = super::super::super::task_lifetime::monotonic_ns().unwrap() + 20_000_000;
            let timer = timer(deadline).unwrap();
            let (owner, watcher) = UnixStream::pair().unwrap();
            drop(owner);
            let mut descriptors = [
                libc::pollfd {
                    fd: timer.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: watcher.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            assert!(unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 100) } > 0);
            assert_ne!(descriptors[1].revents, 0);
            descriptors[1].fd = -1;
            descriptors[0].revents = 0;
            assert!(unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 100) } > 0);
            assert_ne!(descriptors[0].revents & libc::POLLIN, 0);
            assert!(super::super::super::task_lifetime::monotonic_ns().unwrap() >= deadline);
        }

        #[test]
        fn ordinary_files_cannot_substitute_for_kernel_kill_or_population_evidence() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("cgroup.kill");
            std::fs::write(&path, b"1").unwrap();
            assert!(cgroup_file(&path, true).is_err());
            assert!(cgroup_file(&path, false).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::serve;

#[cfg(not(target_os = "linux"))]
pub fn serve(_: &Path, _: &str, _: u64, _: std::os::unix::net::UnixStream) -> Result<()> {
    anyhow::bail!("protected task watchdog requires Linux kernel cgroup v2")
}
