use komizo::deployment::{
    data::{self, Evidence, Verification},
    store::{Installed, ObjectRecord, Resources},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn fixture() -> (Installed, Value) {
    let installed = Installed {
        kind: "komizo.installed".into(),
        version: 1,
        application: "mailroom".into(),
        instance: "production".into(),
        release_digest: format!("sha256:{}", "a".repeat(64)),
        operation_id: "b".repeat(32),
        desired_running: false,
        removed: false,
        expires_at: None,
        resources: Resources {
            volumes: BTreeMap::from([(
                "data".into(),
                ObjectRecord {
                    name: "owned-data".into(),
                    id: format!("sha256:{}", "c".repeat(64)),
                },
            )]),
            ..Default::default()
        },
        secret_snapshots: BTreeMap::new(),
    };
    let evidence = json!({"kind":"komizo.data-evidence","version":1,"application":"mailroom","instance":"production","release_digest":installed.release_digest,"volumes":installed.resources.volumes,"created_at":100,"source":{"kind":"empty","confirmation":"initialize-new-empty-application"}});
    (installed, evidence)
}
#[test]
fn initialization_requires_explicit_owner_intent_and_exact_stopped_data_identity() {
    let (installed, evidence) = fixture();
    let check = |value: Value, record: &Installed| {
        data::validate(
            &serde_json::from_value::<Evidence>(value).unwrap(),
            record,
            200,
        )
    };
    check(evidence.clone(), &installed).unwrap();
    for (field, value) in [
        ("application", json!("other")),
        ("instance", json!("pr-1")),
        (
            "release_digest",
            json!(format!("sha256:{}", "d".repeat(64))),
        ),
        ("created_at", json!(-86400)),
    ] {
        let mut changed = evidence.clone();
        changed[field] = value;
        assert!(check(changed, &installed).is_err());
    }
    let mut changed = evidence.clone();
    changed["volumes"]["data"]["id"] = json!(format!("sha256:{}", "e".repeat(64)));
    assert!(check(changed, &installed).is_err());
    let mut changed = evidence.clone();
    changed["source"]["confirmation"] = json!("implicit");
    assert!(check(changed, &installed).is_err());
    let mut running = installed;
    running.desired_running = true;
    assert!(check(evidence, &running).is_err());
}
#[test]
fn transfer_binds_snapshot_volume_fingerprints_and_all_product_verification_classes() {
    let (installed, mut evidence) = fixture();
    let snapshot = format!("sha256:{}", "1".repeat(64));
    evidence["source"] = json!({"kind":"transfer","snapshot_sha256":snapshot,"verification_sha256":format!("sha256:{}","2".repeat(64))});
    let evidence: Evidence = serde_json::from_value(evidence).unwrap();
    data::validate(&evidence, &installed, 200).unwrap();
    let report = json!({"kind":"komizo.data-verification","version":1,"application":"mailroom","instance":"production","release_digest":installed.release_digest,"volumes":installed.resources.volumes,"snapshot_sha256":snapshot,"created_at":100,"checks":{"database":"passed","authorization":"passed","files":"passed"},"observations":{"source_rows":42,"restored_rows":42,"acl_report_sha256":format!("sha256:{}","3".repeat(64))}});
    let check = |value: Value| {
        data::validate_verification(
            &serde_json::from_value::<Verification>(value).unwrap(),
            &evidence,
            200,
        )
    };
    check(report.clone()).unwrap();
    for field in ["database", "authorization", "files"] {
        let mut changed = report.clone();
        changed["checks"][field] = json!("pending");
        assert!(check(changed).is_err());
    }
    let mut changed = report.clone();
    changed["snapshot_sha256"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert!(check(changed).is_err());
    let mut changed = report.clone();
    changed["volumes"]["data"]["name"] = json!("replacement");
    assert!(check(changed).is_err());
    let mut changed = report;
    changed["observations"] = json!({});
    assert!(check(changed).is_err());
}
