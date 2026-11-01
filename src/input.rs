//! Deadline-bound stdin reads leave task payloads unread after their proof line.
use crate::workload::activation::Context;
use anyhow::{Result, ensure};
use std::{
    fs::File,
    io::{self, Read},
    os::unix::io::{AsRawFd, FromRawFd},
    process::Stdio,
    time::{Duration, Instant},
};
pub struct Input(File);
impl Input {
    pub fn new(file: File) -> Self {
        Self(file)
    }
    pub fn stdin() -> Result<Self> {
        let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(fd >= 0, "stdin unavailable");
        Ok(Self(unsafe { File::from_raw_fd(fd) }))
    }
    fn wait(&self, ctx: &Context) -> Result<()> {
        loop {
            ctx.check()?;
            let mut descriptor = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let delay = ctx
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20))
                .as_millis() as i32;
            let ready = unsafe { libc::poll(&mut descriptor, 1, delay) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if ready > 0 {
                ensure!(
                    descriptor.revents & libc::POLLNVAL == 0,
                    "stdin unavailable"
                );
                return Ok(());
            }
        }
    }
    pub fn bounded(&mut self, ctx: &Context, maximum: usize) -> Result<Vec<u8>> {
        let mut body = vec![];
        let mut buffer = [0_u8; 65536];
        loop {
            self.wait(ctx)?;
            let limit = buffer
                .len()
                .min(maximum.saturating_sub(body.len()).saturating_add(1));
            match self.0.read(&mut buffer[..limit]) {
                Ok(0) => return Ok(body),
                Ok(count) => {
                    ensure!(count <= maximum - body.len(), "input exceeds its bound");
                    body.extend_from_slice(&buffer[..count])
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    pub fn line(&mut self, parent: &Context, maximum: usize) -> Result<Vec<u8>> {
        let mut ctx = parent.clone();
        ctx.deadline = ctx.deadline.min(Instant::now() + Duration::from_secs(10));
        let mut line = vec![];
        loop {
            self.wait(&ctx)?;
            let mut byte = [0_u8];
            match self.0.read(&mut byte) {
                Ok(0) => anyhow::bail!("proof line needs a newline"),
                Ok(_) => {
                    ensure!(line.len() < maximum, "proof line exceeds its bound");
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        return Ok(line);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
    pub fn into_stdio(self) -> Stdio {
        self.0.into()
    }
}
