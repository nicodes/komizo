use komizo::deployment::{
    native::{self, RecoveryEvidence},
    store::{Installed, Resources},
    *,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn document() -> ReleaseDocument {
    read_release(include_bytes!("fixtures/deployment/release.json")).unwrap()
}

#[test]
fn retained_data_cannot_be_silently_redirected_to_an_empty_volume() {
    let mut previous = document();
    previous
        .release
        .workload
        .volumes
        .insert("data".into(), Volume {});
    previous
        .release
        .workload
        .services
        .get_mut("api")
        .unwrap()
        .volumes
        .push(Mount {
            name: "data".into(),
            target: "/var/lib/app".into(),
            read_only: false,
        });
    let mut next = previous.clone();
    next.release.source.revision = "f".repeat(40);
    native::retained_topology(&previous, &next).unwrap();
    next.release
        .workload
        .volumes
        .insert("empty".into(), Volume {});
    next.release
        .workload
        .services
        .get_mut("api")
        .unwrap()
        .volumes[0]
        .name = "empty".into();
    assert!(native::retained_topology(&previous, &next).is_err());
    next = previous.clone();
    next.release
        .workload
        .services
        .get_mut("api")
        .unwrap()
        .volumes[0]
        .target = "/var/lib/elsewhere".into();
    assert!(native::retained_topology(&previous, &next).is_err());
}

#[test]
fn owner_forward_recovery_is_bound_to_exact_data_credentials_operation_and_schema() {
    let mut document = document();
    document.release.stateful_contract=Some(serde_json::from_value(json!({"version":1,"source_revision":document.release.source.revision,"schema":{"minimum":1,"maximum":2,"write":2},"data_revision":"2","credential_revision":"3","migrations":[],"recovery_action":"forward_only"})).unwrap());
    let installed = Installed {
        kind: "komizo.installed".into(),
        version: 1,
        application: document.release.application.clone(),
        instance: "production".into(),
        release_digest: document.digest.clone(),
        operation_id: "1".repeat(32),
        desired_running: false,
        expires_at: None,
        resources: Resources::default(),
        secret_snapshots: BTreeMap::new(),
    };
    let value = json!({"kind":"komizo.recovery-evidence","version":1,"application":installed.application,"instance":installed.instance,"release_digest":document.digest,"operation_id":installed.operation_id,"action":"forward","schema_version":1,"data_revision":"2","credential_revision":"3","created_at":100});
    let check = |value: Value| {
        let evidence: RecoveryEvidence = serde_json::from_value(value).unwrap();
        native::verify_forward_evidence(
            &evidence,
            &installed,
            &document,
            &installed.operation_id,
            200,
        )
    };
    check(value.clone()).unwrap();
    for (field, replacement) in [
        ("application", json!("other")),
        ("instance", json!("pr-1")),
        (
            "release_digest",
            json!(format!("sha256:{}", "f".repeat(64))),
        ),
        ("operation_id", json!("2".repeat(32))),
        ("data_revision", json!("1")),
        ("credential_revision", json!("1")),
        ("schema_version", json!(3)),
        ("created_at", json!(201)),
        ("action", json!("restore")),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(check(changed).is_err(), "accepted changed {field}");
    }
}

#[test]
fn dependency_order_places_successful_jobs_before_their_consuming_services() {
    let mut document = document();
    let mut job = document.release.workload.services["api"].clone();
    job.needs.clear();
    document.release.workload.jobs.insert("migrate".into(), job);
    document
        .release
        .workload
        .services
        .get_mut("api")
        .unwrap()
        .needs
        .insert("migrate".into(), Condition::Completed);
    assert_eq!(native::order(&document).unwrap(), ["migrate", "api"]);
    document
        .release
        .workload
        .jobs
        .get_mut("migrate")
        .unwrap()
        .needs
        .insert("api".into(), Condition::Started);
    assert!(native::order(&document).is_err());
}

#[test]
fn interrupted_object_adoption_requires_the_exact_protected_token_and_isolated_network() {
    let physical = format!(
        "{}-n-app",
        komizo::deployment::units::namespace("mailroom", "production").unwrap()
    );
    let mut intent = native::ObjectIntent {
        kind: "komizo.object-intent".into(),
        version: 1,
        application: "mailroom".into(),
        instance: "production".into(),
        operation_id: "1".repeat(32),
        release_digest: document().digest,
        object_kind: "network".into(),
        logical: "app".into(),
        name: physical.clone(),
        ownership: "2".repeat(32),
        internal: Some(false),
        identity: None,
    };
    let value = json!({"name":physical,"id":"3".repeat(64),"driver":"bridge","internal":false,"options":{"isolate":"1"},"labels":{"io.komizo.application":"mailroom","io.komizo.instance":"production","io.komizo.object":"network:app","io.komizo.ownership":"2".repeat(32)}});
    let record = native::object_evidence(&intent, &value).unwrap();
    assert_eq!(record.id, "3".repeat(64));
    let mut wrong = value.clone();
    wrong["labels"]["io.komizo.ownership"] = json!("4".repeat(32));
    assert!(native::object_evidence(&intent, &wrong).is_err());
    wrong = value.clone();
    wrong["options"]["isolate"] = json!("0");
    assert!(native::object_evidence(&intent, &wrong).is_err());
    intent.identity = Some("5".repeat(64));
    assert!(native::object_evidence(&intent, &value).is_err());
}
