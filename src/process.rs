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
fn drain(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    maximum: usize,
    tail: bool,
    mut sink: Option<&mut dyn Write>,
) -> Result<bool> {
    let mut buffer = [0u8; 65536];
    for _ in 0..64 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if let Some(sink) = sink.as_mut() {
                    sink.write_all(&buffer[..count])?;
                    sink.flush()?;
                }
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
    capture_with_streams(command, input, maximum, deadline, cancelled, None, None)
}
/// Feed bounded stdout directly to an archive reader while draining stderr.
/// The child leader stays unreaped until both pipes close, so descendants are
/// still owned by this process group on every error and deadline.
pub fn consume<T>(
    command: &mut Command,
    maximum: u64,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
    consumer: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let child = command.spawn().context("start archive process")?;
    let mut owned = Owned(Some(child));
    let child = owned.0.as_mut().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    struct Reader<'a, S, E, C> {
        stdout: &'a mut S,
        stderr: &'a mut E,
        cancelled: C,
        deadline: Instant,
        remaining: u64,
        errors: Vec<u8>,
        stdout_closed: bool,
        stderr_closed: bool,
    }
    impl<S: Read + AsRawFd, E: Read + AsRawFd, C: Fn() -> bool> Reader<'_, S, E, C> {
        fn check(&mut self) -> io::Result<()> {
            if (self.cancelled)() {
                return Err(io::Error::other("context canceled"));
            }
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "process deadline exceeded",
                ));
            }
            if !self.stderr_closed {
                self.stderr_closed = drain(self.stderr, &mut self.errors, 8192, true, None)
                    .map_err(io::Error::other)?
            }
            Ok(())
        }
        fn poll(&self) -> io::Result<()> {
            let mut descriptors = [
                libc::pollfd {
                    fd: if self.stdout_closed {
                        -1
                    } else {
                        self.stdout.as_raw_fd()
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if self.stderr_closed {
                        -1
                    } else {
                        self.stderr.as_raw_fd()
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let wait = self
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20))
                .as_millis() as i32;
            let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, wait) };
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    impl<S: Read + AsRawFd, E: Read + AsRawFd, C: Fn() -> bool> Read for Reader<'_, S, E, C> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            loop {
                self.check()?;
                if self.stdout_closed {
                    return Ok(0);
                }
                let limit = buffer.len().min(
                    self.remaining
                        .saturating_add(1)
                        .try_into()
                        .unwrap_or(usize::MAX),
                );
                match self.stdout.read(&mut buffer[..limit]) {
                    Ok(0) => {
                        self.stdout_closed = true;
                        return Ok(0);
                    }
                    Ok(count) => {
                        if count as u64 > self.remaining {
                            return Err(io::Error::other("process output exceeded its bound"));
                        }
                        self.remaining -= count as u64;
                        return Ok(count);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.poll()?,
                    Err(e) => return Err(e),
                }
            }
        }
    }
    let mut reader = Reader {
        stdout: &mut stdout,
        stderr: &mut stderr,
        cancelled,
        deadline,
        remaining: maximum,
        errors: vec![],
        stdout_closed: false,
        stderr_closed: false,
    };
    let value = consumer(&mut reader)?;
    io::copy(&mut reader, &mut io::sink())?;
    loop {
        reader.check()?;
        if reader.stderr_closed
            && let Some(status) = owned.0.as_mut().unwrap().try_wait()?
        {
            owned.0.take();
            ensure!(status.success(), "bounded archive process failed");
            return Ok(value);
        }
        reader.poll()?;
    }
}
struct Streams<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}
pub fn stream(
    command: &mut Command,
    input: Option<&[u8]>,
    maximum_tail: usize,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Captured> {
    capture_with_streams(
        command,
        input,
        maximum_tail,
        deadline,
        cancelled,
        Some(Streams { stdout, stderr }),
        None,
    )
}
pub fn stream_input(
    command: &mut Command,
    input: Stdio,
    maximum_tail: usize,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Captured> {
    capture_with_streams(
        command,
        None,
        maximum_tail,
        deadline,
        cancelled,
        Some(Streams { stdout, stderr }),
        Some(input),
    )
}
fn capture_with_streams(
    command: &mut Command,
    input: Option<&[u8]>,
    maximum: usize,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
    mut streams: Option<Streams<'_>>,
    stdin: Option<Stdio>,
) -> Result<Captured> {
    let mut input_file: Option<File> = None;
    if let Some(bytes) = input {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        file.rewind()?;
        input_file = Some(file);
    }
    command
        .stdin(stdin.unwrap_or_else(|| input_file.map_or_else(Stdio::null, Stdio::from)))
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
            let tail = streams.is_some();
            let sink = streams
                .as_mut()
                .map(|streams| &mut *streams.stdout as &mut dyn Write);
            stdout_closed = drain(&mut stdout, &mut output, maximum, tail, sink)?;
        }
        if !stderr_closed {
            let sink = streams
                .as_mut()
                .map(|streams| &mut *streams.stderr as &mut dyn Write);
            stderr_closed = drain(&mut stderr, &mut errors, 8192, true, sink)?;
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
