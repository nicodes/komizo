use komizo::deployment::{store::*, units, *};
use serde_json::json;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};

fn request() -> Request {
    serde_json::from_value(json!({"kind":"komizo.request","version":1,"authority":"github","application":"mailroom","instance":"production","action":"deploy","release_digest":format!("sha256:{}","a".repeat(64)),"nonce":"b".repeat(32),"issued_at":1000,"expires_at":1120,"proof":"SECRET_TOKEN","registry":{"server":"ghcr.io","username":"private","token":"REGISTRY_TOKEN"}})).unwrap()
}

#[test]
fn interrupted_atomic_writes_do_not_become_operations_and_committed_ids_cannot_be_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("state")).unwrap();
    let pending = store.root.join("operations/.komizo-pending-Ab12Cd");
    fs::write(&pending, b"{partial").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.operation_ids().unwrap().is_empty());
    assert_eq!(store.reconcile_interrupted().unwrap(), 0);
    let mut accepted = operation();
    store.create_operation(&accepted).unwrap();
    let original = fs::read(
        store
            .root
            .join("operations")
            .join(format!("{}.json", accepted.operation_id)),
    )
    .unwrap();
    accepted.transition("staging").unwrap();
    assert!(store.create_operation(&accepted).is_err());
    assert_eq!(
        fs::read(
            store
                .root
                .join("operations")
                .join(format!("{}.json", accepted.operation_id))
        )
        .unwrap(),
        original
    );
    assert_eq!(store.reconcile_interrupted().unwrap(), 1);
    fs::write(store.root.join("operations/unrecognized"), b"unknown").unwrap();
    assert!(store.operation_ids().is_err());
}
fn operation() -> Operation {
    Operation {
        kind: "komizo.operation".into(),
        version: 1,
        operation_id: "c".repeat(32),
        application: "mailroom".into(),
        instance: "production".into(),
        release_digest: request().release_digest,
        phase: "admitted".into(),
        ok: false,
        previous_release_digest: None,
        reconciliation_required: false,
        backup: None,
    }
}

#[test]
fn replay_and_concurrency_are_fenced_and_journal_never_stores_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let s = Store::new(directory.path().join("state")).unwrap();
    let guard = s.lock("mailroom", "production").unwrap();
    assert!(s.lock("mailroom", "production").is_err());
    assert!(s.lock("mailroom", "pr-1").is_ok());
    s.reserve(
        &request(),
        &format!("sha256:{}", "d".repeat(64)),
        &operation().operation_id,
    )
    .unwrap();
    assert!(
        s.reserve(
            &request(),
            &format!("sha256:{}", "d".repeat(64)),
            &operation().operation_id
        )
        .is_err()
    );
    let body = fs::read_to_string(
        s.root
            .join("nonces/mailroom--production")
            .join(&request().nonce),
    )
    .unwrap();
    assert!(!body.contains("SECRET_TOKEN") && !body.contains("REGISTRY_TOKEN"));
    assert!(!format!("{:?}", request()).contains("SECRET_TOKEN"));
    drop(guard);
    assert!(s.lock("mailroom", "production").is_ok());
}

#[test]
fn interrupted_effect_is_retained_as_reconciliation_and_cannot_automatically_retry_jobs() {
    let directory = tempfile::tempdir().unwrap();
    let s = Store::new(directory.path().join("state")).unwrap();
    let mut o = operation();
    o.transition("staging").unwrap();
    o.transition("jobs").unwrap();
    s.save_operation(&o).unwrap();
    assert_eq!(s.reconcile_interrupted().unwrap(), 1);
    let mut retained = s.operation(&o.operation_id).unwrap();
    assert!(retained.reconciliation_required && !retained.ok);
    assert!(retained.transition("jobs").is_err());
    assert_eq!(s.reconcile_interrupted().unwrap(), 0);
}

#[test]
fn protected_store_refuses_linked_and_other_writable_records() {
    let directory = tempfile::tempdir().unwrap();
    let s = Store::new(directory.path().join("state")).unwrap();
    let o = operation();
    let path = s
        .root
        .join("operations")
        .join(format!("{}.json", o.operation_id));
    let outside = directory.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(s.save_operation(&o).is_err());
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    fs::remove_file(&path).unwrap();
    s.save_operation(&o).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(s.operation(&o.operation_id).is_err());
}

#[test]
fn native_units_escape_manager_expansion_and_do_not_publish_ports_or_repull() {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/deployment/release.json")).unwrap();
    value["workload"]["services"]["api"]["command"] = json!([
        "/app/server",
        "literal %n $HOST_SECRET",
        "quoted\\\"argument"
    ]);
    value["workload"]["services"]["api"]["health"]["start_interval_seconds"] = json!(2);
    let doc = read_release(&serde_json::to_vec(&value).unwrap()).unwrap();
    let empty = BTreeMap::new();
    let env = BTreeMap::from([(
        "runtime".into(),
        "/var/lib/komizo/secrets/runtime.env".into(),
    )]);
    let networks = BTreeMap::from([(
        "backend".into(),
        ObjectRecord {
            name: "kmz-owned-backend".into(),
            id: "1".repeat(64),
        },
    )]);
    let bindings = units::Bindings {
        application: "mailroom",
        instance: "production",
        release_digest: &doc.digest,
        ownership: &"e".repeat(32),
        networks: &networks,
        volumes: &empty,
        environment_files: &env,
        secrets: &BTreeMap::new(),
        ingress: None,
    };
    let unit = units::quadlet(&doc, "api", &bindings, false).unwrap();
    assert!(unit.contains("%%n $$HOST_SECRET"));
    assert!(unit.contains("--pull=never"));
    assert!(unit.contains("--remote=false"));
    assert!(unit.contains("--health-interval\" \"disable"));
    let (probe, timer) = units::health_units(
        "mailroom",
        "production",
        "api",
        doc.release.workload.services["api"]
            .health
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert!(probe.contains(&format!(
        "Slice={}",
        units::slice("mailroom", "production").unwrap()
    )));
    assert!(timer.contains("OnUnitInactiveSec=2s"));
    assert!(
        !unit.contains("PublishPort")
            && !unit.contains("WantedBy=")
            && !unit.contains("AutoUpdate=")
    );
    assert_ne!(
        units::namespace("mailroom", "production").unwrap(),
        units::namespace("mailroom", "pr-1").unwrap()
    );
}
