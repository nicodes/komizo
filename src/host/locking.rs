use super::{Probe, paths::RUN_DIR};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    time::{Duration, Instant},
};
pub struct HostLock(File);
impl Drop for HostLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
impl HostLock {
    pub fn acquire(
        root: &Path,
        name: &str,
        wait: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self> {
        ensure!(
            !name.is_empty() && !name.contains(['/', '\0']) && name != "." && name != "..",
            "invalid host lock name"
        );
        let directory = if root.as_os_str().is_empty() {
            Path::new(RUN_DIR).to_owned()
        } else {
            root.join("run")
        };
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&directory)
            .context("preview lock directory unavailable")?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(name))
            .context("preview lock unavailable")?;
        ensure!(
            file.metadata()?.is_file(),
            "preview lock is not a regular file"
        );
        let deadline = Instant::now() + wait;
        loop {
            if cancelled() {
                bail!("context canceled");
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            ensure!(
                matches!(
                    error.raw_os_error(),
                    Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
                ),
                "preview lock unavailable: {error}"
            );
            ensure!(
                Instant::now() < deadline,
                "preview lock timed out; no preview mutation performed"
            );
            std::thread::sleep(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}
pub fn platform_idle(root: &Path) -> Result<()> {
    let path = Probe { root: root.into() }.path("/var/lib/komizo/upgrades/pending.json");
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        "platform migration requires recovery before workload effects"
    );
    Ok(())
}
pub struct DeploymentLock {
    _host: HostLock,
    _app: HostLock,
}
impl DeploymentLock {
    pub fn acquire(
        root: &Path,
        app: &str,
        wait: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self> {
        super::paths::app_state_path(root, app)?;
        let app = HostLock::acquire(root, &format!("deploy-{app}.lock"), wait, &cancelled)?;
        let host = HostLock::acquire(root, "operation.lock", wait, &cancelled)?;
        platform_idle(root)?;
        Ok(Self {
            _host: host,
            _app: app,
        })
    }
}
