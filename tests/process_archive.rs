use komizo::process::consume;
use std::{
    io::{Read, Write},
    process::Command,
    time::{Duration, Instant},
};
#[test]
fn archive_is_consumed_incrementally_while_stderr_is_drained() {
    let root = tempfile::tempdir().unwrap();
    let ack = root.path().join("ack");
    let mut command = Command::new("sh");
    command.args(["-c","printf ready; while [ ! -f \"$ACK_PATH\" ]; do sleep 0.01; done; head -c 1048576 /dev/zero >&2; head -c 8388608 /dev/zero"]).env("ACK_PATH",&ack);
    let count = consume(
        &mut command,
        9 << 20,
        Instant::now() + Duration::from_secs(5),
        || false,
        |reader| {
            let mut greeting = [0; 5];
            reader.read_exact(&mut greeting)?;
            assert_eq!(&greeting, b"ready");
            std::fs::write(&ack, b"continue")?;
            Ok(std::io::copy(reader, &mut std::io::sink())?)
        },
    )
    .unwrap();
    assert_eq!(count, 8 << 20);
}
#[test]
fn streaming_archive_enforces_bounds_status_deadline_and_cancellation() {
    for (script, maximum, cancelled) in [
        ("printf 12345", 4, false),
        ("printf good; exit 7", 64, false),
        ("sleep 30 & exit 0", 64, false),
        ("while :; do printf x >&2; done", 64, false),
        ("sleep 30", 64, true),
    ] {
        let start = Instant::now();
        let result = consume(
            Command::new("sh").args(["-c", script]),
            maximum,
            start + Duration::from_millis(80),
            || cancelled,
            |reader| Ok(std::io::copy(reader, &mut std::io::sink())?),
        );
        assert!(result.is_err(), "{script}");
        assert!(start.elapsed() < Duration::from_secs(2), "{script}");
    }
    let start = Instant::now();
    let result: Result<(), _> = consume(
        Command::new("sh").args(["-c", "sleep 30 & printf first; wait"]),
        64,
        start + Duration::from_secs(30),
        || false,
        |reader| {
            let mut first = [0];
            reader.read_exact(&mut first)?;
            anyhow::bail!("consumer refused")
        },
    );
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
}
#[test]
fn consumer_can_stop_at_tar_eof_without_leaving_a_writer_blocked() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive");
    let mut archive = tar::Builder::new(std::fs::File::create(&path).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(7);
    header.set_mode(0o600);
    header.set_cksum();
    archive
        .append_data(&mut header, "entry", &b"payload"[..])
        .unwrap();
    archive.finish().unwrap();
    drop(archive);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&vec![0; 1 << 20])
        .unwrap();
    let mut command = Command::new("cat");
    command.arg(path);
    let payload = consume(
        &mut command,
        2 << 20,
        Instant::now() + Duration::from_secs(2),
        || false,
        |reader| {
            let mut archive = tar::Archive::new(reader);
            let mut payload = vec![];
            for entry in archive.entries()? {
                entry?.read_to_end(&mut payload)?;
            }
            Ok(payload)
        },
    )
    .unwrap();
    assert_eq!(payload, b"payload");
}
