use komizo::process::capture;
use std::{
    process::Command,
    time::{Duration, Instant},
};
#[test]
fn bounded_capture_preserves_status_and_stdin_without_exposing_unbounded_errors() {
    let got = capture(
        Command::new("sh").args(["-c", "cat; printf err >&2; exit 7"]),
        Some(b"fixture\n"),
        32,
        Instant::now() + Duration::from_secs(2),
        || false,
    )
    .unwrap();
    assert_eq!(got.status.code(), Some(7));
    assert_eq!(got.stdout, b"fixture\n");
    assert_eq!(got.stderr, b"err");
    assert!(
        capture(
            Command::new("sh").args(["-c", "printf 123456789"]),
            None,
            4,
            Instant::now() + Duration::from_secs(2),
            || false
        )
        .is_err()
    );
}
#[test]
fn deadlines_and_cancellation_cover_inherited_pipes_and_continuous_stderr() {
    let started = Instant::now();
    let result = capture(
        Command::new("sh").args(["-c", "sleep 30 & exit 0"]),
        None,
        64,
        Instant::now() + Duration::from_millis(60),
        || false,
    );
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    let result = capture(
        Command::new("sh").args(["-c", "while :; do printf stderr >&2; done"]),
        None,
        64,
        Instant::now() + Duration::from_millis(60),
        || false,
    );
    assert!(result.is_err());
    let result = capture(
        Command::new("sh").args(["-c", "sleep 30"]),
        None,
        64,
        Instant::now() + Duration::from_secs(30),
        || true,
    );
    assert!(result.is_err());
}
#[test]
fn streaming_progress_reaches_the_caller_before_child_completion_and_retains_only_a_tail() {
    use std::io::Write;
    struct Progress {
        bytes: usize,
        ack: std::path::PathBuf,
    }
    impl Write for Progress {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes == 0 {
                std::fs::write(&self.ack, b"observed")?;
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut progress = Progress {
        bytes: 0,
        ack: root.path().join("ack"),
    };
    let mut errors = vec![];
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c","printf ready; while [ ! -f \"$ACK_PATH\" ]; do sleep 0.01; done; head -c 1048576 /dev/zero; printf done; printf stream-error >&2"]).env("ACK_PATH",&progress.ack);
    let captured = komizo::process::stream(
        &mut command,
        None,
        8192,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        || false,
        &mut progress,
        &mut errors,
    )
    .unwrap();
    assert!(captured.status.success());
    assert_eq!(progress.bytes, 1048576 + 9);
    assert_eq!(captured.stdout.len(), 8192);
    assert!(captured.stdout.ends_with(b"done"));
    assert_eq!(errors, b"stream-error");
    assert_eq!(captured.stderr, errors);
}
#[test]
fn streaming_an_inherited_input_starts_after_the_consumed_proof_and_keeps_finite_output() {
    use std::io::{Read, Seek, Write};
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(b"proof-line\npayload\0bytes\n").unwrap();
    input.rewind().unwrap();
    let mut proof = [0; 11];
    input.read_exact(&mut proof).unwrap();
    assert_eq!(&proof, b"proof-line\n");
    let mut output = vec![];
    let mut errors = vec![];
    let result = komizo::process::stream_input(
        Command::new("sh").args(["-c", "cat; printf complete >&2"]),
        std::process::Stdio::from(input),
        4,
        Instant::now() + Duration::from_secs(2),
        || false,
        &mut output,
        &mut errors,
    )
    .unwrap();
    assert!(result.status.success());
    assert_eq!(output, b"payload\0bytes\n");
    assert_eq!(errors, b"complete");
    assert_eq!(result.stdout, b"tes\n");
}
