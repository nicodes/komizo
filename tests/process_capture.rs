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
