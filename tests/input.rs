use komizo::{input::Input, workload::activation::Context};
use std::{
    fs::File,
    io::{Seek, Write},
    os::unix::io::FromRawFd,
    time::{Duration, Instant},
};
fn context() -> Context {
    Context::new(Instant::now() + Duration::from_secs(2))
}
fn data(body: &[u8]) -> Input {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(body).unwrap();
    file.rewind().unwrap();
    Input::new(file)
}
#[test]
fn bounded_input_and_proof_lines_preserve_payload_and_refuse_partial_frames() {
    let mut input = data(b"proof\npayload\0bytes");
    assert_eq!(input.line(&context(), 6).unwrap(), b"proof\n");
    assert_eq!(input.bounded(&context(), 13).unwrap(), b"payload\0bytes");
    assert!(data(b"proof\n").line(&context(), 5).is_err());
    assert!(data(b"proof").line(&context(), 10).is_err());
    assert!(data(b"").line(&context(), 10).is_err());
    assert_eq!(data(b"exact").bounded(&context(), 5).unwrap(), b"exact");
    assert!(data(b"overrun").bounded(&context(), 6).is_err());
    assert_eq!(data(b"").bounded(&context(), 0).unwrap(), b"");
    assert!(data(b"x").bounded(&context(), 0).is_err());
}
#[test]
fn a_stalled_writer_cannot_hold_the_reader_past_deadline_or_cancel() {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let read = unsafe { File::from_raw_fd(fds[0]) };
    let mut write = unsafe { File::from_raw_fd(fds[1]) };
    write.write_all(b"partial").unwrap();
    let mut input = Input::new(read);
    let start = Instant::now();
    assert!(
        input
            .line(&Context::new(start + Duration::from_millis(60)), 128)
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    let ctx = context();
    ctx.cancelled
        .store(true, std::sync::atomic::Ordering::Release);
    let start = Instant::now();
    assert!(input.bounded(&ctx, 128).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}
