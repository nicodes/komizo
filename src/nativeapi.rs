//! The Axum API remains a separate, supervised native process.
use crate::workload::activation::Context;
use anyhow::{Result, ensure};
use std::{
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub struct Prepared {
    pub path: PathBuf,
    temporary: Option<tempfile::TempDir>,
}
impl Prepared {
    fn started(&mut self) {
        self.temporary.take();
    }
}
#[cfg(packed_api)]
pub fn prepare() -> Result<Prepared> {
    use std::io::{Read, Write};
    let temporary = tempfile::Builder::new().prefix("komizo-api-").tempdir()?;
    let path = temporary.path().join("komizo-api");
    let reader =
        flate2::read::GzDecoder::new(include_bytes!(env!("KOMIZO_API_PAYLOAD")).as_slice());
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let size = std::io::copy(&mut reader.take((64 << 20) + 1), &mut file)?;
    ensure!(size <= 64 << 20, "native API payload exceeds its bound");
    file.flush()?;
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    drop(file);
    Ok(Prepared {
        path,
        temporary: Some(temporary),
    })
}
#[cfg(not(packed_api))]
pub fn prepare() -> Result<Prepared> {
    let path = std::env::var_os("KOMIZO_API_BINARY")
        .map(PathBuf::from)
        .unwrap_or(std::env::current_exe()?.with_file_name("komizo-api"));
    ensure!(path.is_absolute(), "KOMIZO_API_BINARY must be absolute");
    let metadata = std::fs::metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "native Rust API is unavailable; build api/ or use a release CLI"
    );
    Ok(Prepared {
        path,
        temporary: None,
    })
}
pub fn run(ctx: &Context, args: &[String]) -> Result<()> {
    let mut prepared = prepare()?;
    let mut command = Command::new(&prepared.path);
    command
        .args(args)
        .args(["--parent-pid", &std::process::id().to_string()])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);
    let mut child = command.spawn()?;
    prepared.started();
    let pid = child.id() as i32;
    let mut stopping = None;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                ensure!(
                    status.success() || ctx.check().is_err(),
                    "native API exited: {status}"
                );
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.wait();
                return Err(e.into());
            }
        }
        if ctx.check().is_err() {
            if let Some(deadline) = stopping {
                if Instant::now() >= deadline {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    let _ = child.wait();
                    return Ok(());
                }
            } else {
                unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                }
                stopping = Some(Instant::now() + Duration::from_secs(10));
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
