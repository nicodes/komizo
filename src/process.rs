//! Bounded child capture retains the process-group leader until pipes close.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    os::unix::{io::AsRawFd, process::CommandExt},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
pub struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
struct Owned(Option<Child>);
impl Drop for Owned {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
        }
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "prepare child output: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
fn drain(reader: &mut impl Read, output: &mut Vec<u8>, maximum: usize, tail: bool) -> Result<bool> {
    let mut buffer = [0u8; 65536];
    for _ in 0..64 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if tail {
                    if count >= maximum {
                        output.clear();
                        output.extend_from_slice(&buffer[count - maximum..count]);
                    } else {
                        if output.len() + count > maximum {
                            output.drain(..output.len() + count - maximum);
                        }
                        output.extend_from_slice(&buffer[..count]);
                    }
                } else {
                    ensure!(
                        output.len() + count <= maximum,
                        "process output exceeded its bound"
                    );
                    output.extend_from_slice(&buffer[..count]);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}
pub fn capture(
    command: &mut Command,
    input: Option<&[u8]>,
    maximum: usize,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
) -> Result<Captured> {
    let mut input_file: Option<File> = None;
    if let Some(bytes) = input {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        file.rewind()?;
        input_file = Some(file);
    }
    command
        .stdin(input_file.map_or_else(Stdio::null, Stdio::from))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let child = command.spawn().context("start child process")?;
    let mut owned = Owned(Some(child));
    let child = owned.0.as_mut().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let (mut output, mut errors) = (vec![], vec![]);
    let (mut stdout_closed, mut stderr_closed) = (false, false);
    loop {
        ensure!(!cancelled(), "context canceled");
        ensure!(Instant::now() < deadline, "process deadline exceeded");
        if !stdout_closed {
            stdout_closed = drain(&mut stdout, &mut output, maximum, false)?;
        }
        if !stderr_closed {
            stderr_closed = drain(&mut stderr, &mut errors, 8192, true)?;
        }
        if stdout_closed
            && stderr_closed
            && let Some(status) = owned.0.as_mut().unwrap().try_wait()?
        {
            owned.0.take();
            return Ok(Captured {
                status,
                stdout: output,
                stderr: errors,
            });
        }
        let mut descriptors = [
            libc::pollfd {
                fd: if stdout_closed {
                    -1
                } else {
                    stdout.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stderr_closed {
                    -1
                } else {
                    stderr.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20))
            .as_millis() as i32;
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                wait,
            )
        };
        ensure!(
            result >= 0 || io::Error::last_os_error().kind() == io::ErrorKind::Interrupted,
            "read child output: {}",
            io::Error::last_os_error()
        );
    }
}
