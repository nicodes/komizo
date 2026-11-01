use komizo::{
    host::{locking::*, stopped::*},
    wire::Time,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    time::{Duration, Instant},
};
#[test]
fn thirty_go_stop_record_rewrites_preserve_unmanaged_fields_and_owner_intent() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-stopped-records.json")).unwrap();
    assert_eq!(cases.len(), 30);
    for case in cases {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let path = root.join("var/lib/komizo/apps/fixture.env");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, case["input"].as_str().unwrap()).unwrap();
        assert_eq!(
            is_stopped(root, "fixture").unwrap(),
            case["before"].as_bool().unwrap()
        );
        let rev = state_revision(root, "fixture").unwrap();
        assert_eq!(rev, case["revision"].as_str().unwrap());
        let at: Time =
            serde_json::from_value(json!("2026-11-01T12:34:56.123456789+01:00")).unwrap();
        let mut changed = Value::Null;
        let result = match case["op"].as_str().unwrap() {
            "mark" => mark_stopped(root, "fixture", "cli", at),
            "clear" => clear_stopped(root, "fixture"),
            "unchanged" => clear_stopped_if_unchanged(root, "fixture", &rev).map(|v| {
                changed = json!(v);
            }),
            "changed" => clear_stopped_if_unchanged(root, "fixture", &"0".repeat(64)).map(|v| {
                changed = json!(v);
            }),
            "newline" => mark_stopped(root, "fixture", "bad\nAPP_DIR=/srv/other", at),
            "long" => mark_stopped(root, "fixture", &"x".repeat(129), at),
            _ => unreachable!(),
        };
        assert_eq!(
            result.err().map(|e| e.to_string()).unwrap_or_default(),
            case["error"].as_str().unwrap()
        );
        assert_eq!(changed, case["changed"]);
        assert_eq!(
            is_stopped(root, "fixture").unwrap(),
            case["after"].as_bool().unwrap()
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            case["output"].as_str().unwrap()
        );
    }
}
#[test]
fn host_locks_enforce_exclusion_cancellation_symlink_refusal_and_platform_fence() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    let lock =
        HostLock::acquire(root, "operation.lock", Duration::from_millis(100), || false).unwrap();
    let started = Instant::now();
    assert!(
        HostLock::acquire(root, "operation.lock", Duration::from_millis(40), || false).is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(HostLock::acquire(root, "other.lock", Duration::from_secs(10), || true).is_err());
    drop(lock);
    assert!(HostLock::acquire(root, "operation.lock", Duration::ZERO, || false).is_ok());
    fs::write(root.join("private"), "preserve").unwrap();
    symlink(root.join("private"), root.join("run/hostile.lock")).unwrap();
    assert!(HostLock::acquire(root, "hostile.lock", Duration::ZERO, || false).is_err());
    assert_eq!(
        fs::read_to_string(root.join("private")).unwrap(),
        "preserve"
    );
    let pending = root.join("var/lib/komizo/upgrades/pending.json");
    fs::create_dir_all(pending.parent().unwrap()).unwrap();
    fs::write(&pending, "{}").unwrap();
    assert!(DeploymentLock::acquire(root, "fixture", Duration::ZERO, || false).is_err());
    fs::remove_file(pending).unwrap();
    assert!(DeploymentLock::acquire(root, "fixture", Duration::ZERO, || false).is_ok());
}
