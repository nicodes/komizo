use komizo::{statefile, strict, wire::Time, workload::operation};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
#[test]
fn all_go_phase_pairs_and_864_journal_requests_match_the_frozen_producer() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/go-operation-journal.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(operation::contract()).unwrap(),
        fixture["contract"]
    );
    for (from, targets) in fixture["transitions"].as_object().unwrap() {
        for (to, expected) in targets.as_object().unwrap() {
            assert_eq!(
                operation::legal(from, to),
                expected.as_bool().unwrap(),
                "{from} -> {to}"
            );
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operation.json");
    for (index, frame) in fixture["frames"].as_array().unwrap().iter().enumerate() {
        statefile::write_private_json(&path, &frame["initial"]).unwrap();
        let now: Time = serde_json::from_value(frame["now"].clone()).unwrap();
        let result = operation::record(
            &path,
            "fixture",
            frame["candidate"].as_str().unwrap(),
            frame["previous"].as_str().unwrap(),
            frame["phase"].as_str().unwrap(),
            now,
        );
        let error = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert_eq!(error, frame["error"].as_str().unwrap(), "frame {index}");
        let mut after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let id = after["operation_id"].as_str().unwrap();
        if id != "0".repeat(32) {
            assert_eq!(id.len(), 32);
            assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
            after["operation_id"] = json!("NEW");
        }
        assert_eq!(after, frame["after"], "frame {index}");
    }
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}
#[test]
fn journals_require_admission_bind_identity_preserve_on_refusal_and_do_not_follow_links() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private/operation.json");
    let now = Time::now();
    assert!(operation::record(&path, "fixture", "candidate", "", "ready", now).is_err());
    assert!(!path.exists());
    operation::record(&path, "fixture", "candidate", "", "admitted", now).unwrap();
    let original = fs::read(&path).unwrap();
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for (app, candidate, phase) in [
        ("../escape", "candidate", "admitted"),
        ("fixture", "../candidate", "admitted"),
        ("fixture", "candidate", "unknown"),
        ("other", "candidate", "configured"),
    ] {
        assert!(operation::record(&path, app, candidate, "", phase, now).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    let link = directory.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(operation::record(&link, "fixture", "candidate", "", "configured", now).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
}
#[test]
fn privileged_documents_reject_duplicates_unknown_fields_depth_and_oversized_inputs() {
    assert!(operation::decode(br#"{"version":1,"version":1}"#).is_err());
    assert!(operation::decode(br#"{"version":1,"extra":{"version":1}}"#).is_err());
    assert!(strict::value(br#"{"nested":{"x":1,"x":2}}"#, 1024).is_err());
    assert!(strict::value(b"{} {}", 1024).is_err());
    assert!(
        strict::value(
            &vec![b' '; strict::RELEASE_MAX_BYTES + 1],
            strict::RELEASE_MAX_BYTES
        )
        .is_err()
    );
    let nested = format!("{}null{}", "[".repeat(33), "]".repeat(33));
    assert!(strict::value(nested.as_bytes(), 1024).is_err());
    let decoded = operation::decode(
        br#"{"VERSION":1,"APP":"fixture","PHASE":"admitted","candidate":"a","at":null}"#,
    )
    .unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.app, "fixture");
    assert!(decoded.at.is_zero());
}
