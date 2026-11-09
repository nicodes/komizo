use anyhow::Result;
use komizo::deployment::{
    document_digest, engine,
    native::ObjectIntent,
    recovery,
    store::{self, Installed, ObjectRecord, Resources, Store},
    system::{self, UnitFiles, UnitIntent, UnitVersion},
    units,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
const APP: &str = "mailroom";
fn installed() -> Installed {
    Installed {
        kind: "komizo.installed".into(),
        version: 1,
        application: APP.into(),
        instance: "production".into(),
        release_digest: format!("sha256:{}", "a".repeat(64)),
        operation_id: "b".repeat(32),
        desired_running: false,
        expires_at: None,
        resources: Resources::default(),
        secret_snapshots: Default::default(),
    }
}
fn creation(kind: &str) -> ObjectIntent {
    ObjectIntent {
        kind: "komizo.object-intent".into(),
        version: 1,
        application: APP.into(),
        instance: "production".into(),
        operation_id: "b".repeat(32),
        release_digest: installed().release_digest,
        object_kind: kind.into(),
        logical: "data".into(),
        name: units::object_name(APP, "production", kind, "data").unwrap(),
        ownership: "c".repeat(32),
        internal: if kind == "network" { Some(true) } else { None },
        identity: None,
    }
}
fn object(intent: &ObjectIntent) -> Value {
    let labels = json!({"io.komizo.application":APP,"io.komizo.instance":"production","io.komizo.object":format!("{}:data",intent.object_kind),"io.komizo.ownership":intent.ownership});
    if intent.object_kind == "network" {
        json!({"name":intent.name,"id":"d".repeat(64),"driver":"bridge","internal":true,"options":{"isolate":"1"},"labels":labels})
    } else {
        json!({"Name":intent.name,"CreatedAt":"2026-11-09T00:00:00Z","Driver":"local","Mountpoint":"/owned/data","Options":null,"Labels":labels})
    }
}
fn store() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let s = Store::new(d.path().join("state")).unwrap();
    (d, s)
}
fn save_creation(s: &Store, i: &ObjectIntent) {
    store::atomic(
        &s.root
            .join("journal")
            .join(&i.operation_id)
            .join(format!("object-{}-{}.json", i.object_kind, i.logical)),
        &serde_json::to_vec(i).unwrap(),
        0o600,
    )
    .unwrap();
}
#[test]
fn actual_owned_object_identity_is_durable_before_installed_advance_without_recreation() {
    for kind in ["volume", "network"] {
        let (_d, s) = store();
        let mut state = installed();
        let i = creation(kind);
        save_creation(&s, &i);
        let actual = object(&i);
        recovery::reconcile_objects_with(&s, &mut state, &i.operation_id, |k, n| {
            assert_eq!(k, kind);
            assert_eq!(n, i.name);
            Ok(Some(actual.clone()))
        })
        .unwrap();
        let record = if kind == "volume" {
            &state.resources.volumes["data"]
        } else {
            &state.resources.networks["data"]
        };
        assert_eq!(record.name, i.name);
        assert!(!record.id.is_empty());
        assert_eq!(
            s.installed(APP, "production")
                .unwrap()
                .unwrap()
                .resources
                .volumes
                .len(),
            usize::from(kind == "volume")
        );
        recovery::reconcile_objects_with(&s, &mut state, &i.operation_id, |_, _| {
            Ok(Some(actual.clone()))
        })
        .unwrap();
    }
}
#[test]
fn foreign_scope_token_topology_replacement_and_missing_proven_data_refuse() {
    for change in ["token", "topology", "identity", "scope", "version"] {
        let (_d, s) = store();
        let mut state = installed();
        let mut i = creation("network");
        let mut actual = object(&i);
        match change {
            "token" => actual["labels"]["io.komizo.ownership"] = json!("f".repeat(32)),
            "topology" => actual["internal"] = json!(false),
            "identity" => i.identity = Some("f".repeat(64)),
            "scope" => i.application = "other".into(),
            _ => i.version = 2,
        };
        save_creation(&s, &i);
        assert!(
            recovery::reconcile_objects_with(&s, &mut state, &i.operation_id, |_, _| Ok(Some(
                actual.clone()
            )))
            .is_err()
        );
        assert!(state.resources.networks.is_empty());
    }
    let (_d, s) = store();
    let mut state = installed();
    let mut i = creation("volume");
    i.identity = Some(engine::volume_identity(&object(&i)).unwrap());
    save_creation(&s, &i);
    assert!(
        recovery::reconcile_objects_with(&s, &mut state, &i.operation_id, |_, _| Ok(None)).is_err()
    );
}
#[test]
fn pre_create_absence_is_observed_without_fabricating_or_recreating_an_object() {
    let (_d, s) = store();
    let mut state = installed();
    let i = creation("volume");
    save_creation(&s, &i);
    recovery::reconcile_objects_with(&s, &mut state, &i.operation_id, |_, _| Ok(None)).unwrap();
    assert!(state.resources.volumes.is_empty());
}
#[test]
fn authorized_removal_clears_only_exact_absent_object_and_preserves_existing_data() {
    for present in [false, true] {
        let (_d, s) = store();
        let mut state = installed();
        let i = creation("volume");
        let actual = object(&i);
        let id = engine::volume_identity(&actual).unwrap();
        state.resources.volumes.insert(
            "data".into(),
            ObjectRecord {
                name: i.name.clone(),
                id: id.clone(),
            },
        );
        let removal = recovery::ObjectRemoval {
            kind: "komizo.object-removal".into(),
            version: 1,
            application: i.application,
            instance: i.instance,
            operation_id: i.operation_id.clone(),
            release_digest: i.release_digest,
            object_kind: "volume".into(),
            logical: "data".into(),
            name: i.name,
            identity: id,
        };
        store::atomic(
            &s.root
                .join("journal")
                .join(&i.operation_id)
                .join("object-removal-volume-data.json"),
            &serde_json::to_vec(&removal).unwrap(),
            0o600,
        )
        .unwrap();
        recovery::reconcile_object_removals_with(&s, &mut state, &i.operation_id, |_, _| {
            Ok(if present { Some(actual.clone()) } else { None })
        })
        .unwrap();
        assert_eq!(state.resources.volumes.contains_key("data"), present);
        if present {
            let mut changed = actual;
            changed["CreatedAt"] = json!("replacement");
            assert!(
                recovery::reconcile_object_removals_with(
                    &s,
                    &mut state,
                    &i.operation_id,
                    |_, _| Ok(Some(changed.clone()))
                )
                .is_err()
            );
            assert!(state.resources.volumes.contains_key("data"));
        }
    }
}
struct Files {
    root: PathBuf,
}
impl Files {
    fn path(&self, path: &Path) -> PathBuf {
        self.root.join(path.file_name().unwrap())
    }
}
impl UnitFiles for Files {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let path = self.path(path);
        Ok(if path.exists() {
            Some(fs::read(path)?)
        } else {
            None
        })
    }
    fn write(&self, path: &Path, body: &[u8]) -> Result<()> {
        fs::write(self.path(path), body)?;
        Ok(())
    }
    fn remove(&self, path: &Path) -> Result<()> {
        fs::remove_file(self.path(path))?;
        Ok(())
    }
}
fn version(body: &str) -> UnitVersion {
    UnitVersion {
        sha256: document_digest(body.as_bytes()),
        body: body.into(),
    }
}
fn unit(old: Option<&str>, new: Option<&str>) -> UnitIntent {
    UnitIntent {
        kind: "komizo.unit-intent".into(),
        version: 1,
        identity: "e".repeat(32),
        application: APP.into(),
        instance: "production".into(),
        operation_id: Some("b".repeat(32)),
        path: "/etc/containers/systemd/owned-api.container".into(),
        old: old.map(version),
        new: new.map(version),
        phase: "pending".into(),
    }
}
fn ledger(s: &Store, i: &UnitIntent, hash: &str) {
    store::atomic(
        &s.root.join("units.json"),
        &serde_json::to_vec(
            &json!({&i.path:{"application":APP,"instance":"production","sha256":hash}}),
        )
        .unwrap(),
        0o600,
    )
    .unwrap();
}
fn save_unit(s: &Store, i: &UnitIntent) {
    store::atomic(
        &s.root
            .join("unit-intents")
            .join(format!("{}.json", i.identity)),
        &serde_json::to_vec(i).unwrap(),
        0o600,
    )
    .unwrap();
}
#[test]
fn unit_creation_and_interrupted_file_before_ledger_update_converge_exact_pairs() {
    for (observed, old) in [
        (None, None),
        (Some("old"), Some("old")),
        (Some("new"), Some("old")),
    ] {
        let (d, s) = store();
        let files = Files {
            root: d.path().to_owned(),
        };
        let i = unit(old, Some("new"));
        let path = Path::new(&i.path);
        if let Some(body) = observed {
            files.write(path, body.as_bytes()).unwrap()
        };
        if let Some(old) = &i.old {
            ledger(&s, &i, &old.sha256)
        }
        system::reconcile_unit_intent_with(&s, &i, &files).unwrap();
        assert_eq!(files.read(path).unwrap().unwrap(), b"new");
        let records: Value =
            serde_json::from_slice(&fs::read(s.root.join("units.json")).unwrap()).unwrap();
        assert_eq!(records[&i.path]["sha256"], i.new.unwrap().sha256);
    }
}
#[test]
fn unit_removal_handles_missing_file_after_effect_and_never_deletes_foreign_bytes() {
    for observed in [None, Some("old"), Some("foreign")] {
        let (d, s) = store();
        let files = Files {
            root: d.path().to_owned(),
        };
        let i = unit(Some("old"), None);
        let path = Path::new(&i.path);
        ledger(&s, &i, &i.old.as_ref().unwrap().sha256);
        if let Some(body) = observed {
            files.write(path, body.as_bytes()).unwrap()
        }
        let result = system::reconcile_unit_intent_with(&s, &i, &files);
        if observed == Some("foreign") {
            assert!(result.is_err());
            assert_eq!(files.read(path).unwrap().unwrap(), b"foreign")
        } else {
            result.unwrap();
            assert!(files.read(path).unwrap().is_none());
            assert_eq!(fs::read(s.root.join("units.json")).unwrap(), b"{}")
        }
    }
}
#[test]
fn scoped_unit_hash_chain_advances_installed_hash_only_through_exact_authorized_intents() {
    let (d, s) = store();
    let files = Files {
        root: d.path().to_owned(),
    };
    let i = unit(Some("old"), Some("new"));
    save_unit(&s, &i);
    ledger(&s, &i, &i.old.as_ref().unwrap().sha256);
    files.write(Path::new(&i.path), b"new").unwrap();
    let actual = system::reconciled_unit_hash_with(
        &s,
        Path::new(&i.path),
        APP,
        "production",
        &"b".repeat(32),
        &document_digest(b"old"),
        &files,
    )
    .unwrap();
    assert_eq!(actual, document_digest(b"new"));
    assert!(
        system::reconciled_unit_hash_with(
            &s,
            Path::new(&i.path),
            APP,
            "production",
            &"b".repeat(32),
            &document_digest(b"unproven"),
            &files
        )
        .is_err()
    );
    assert!(
        system::reconciled_unit_hash_with(
            &s,
            Path::new(&i.path),
            APP,
            "production",
            &"f".repeat(32),
            &document_digest(b"old"),
            &files
        )
        .is_err()
    );
}
#[test]
fn only_exact_private_interrupted_atomic_temporaries_are_ignored() {
    let (d, s) = store();
    let files = Files {
        root: d.path().to_owned(),
    };
    let i = unit(None, Some("new"));
    save_unit(&s, &i);
    let pending = s.root.join("unit-intents/.komizo-pending-Ab12Cd");
    fs::write(&pending, b"{partial").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    system::reconcile_unit_intents_with(&s, APP, "production", &"b".repeat(32), &files).unwrap();
    assert_eq!(files.read(Path::new(&i.path)).unwrap().unwrap(), b"new");
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        system::reconcile_unit_intents_with(&s, APP, "production", &"b".repeat(32), &files)
            .is_err()
    );
    fs::remove_file(pending).unwrap();
    fs::write(s.root.join("unit-intents/unknown"), b"{}").unwrap();
    assert!(
        system::reconcile_unit_intents_with(&s, APP, "production", &"b".repeat(32), &files)
            .is_err()
    );
}

#[test]
fn unit_replacement_refuses_foreign_owner_hash_and_missing_known_ledger_or_file() {
    for change in ["owner", "hash", "ledger", "file"] {
        let (directory, store) = store();
        let files = Files {
            root: directory.path().to_owned(),
        };
        let intent = unit(Some("old"), Some("new"));
        let path = Path::new(&intent.path);
        files.write(path, b"new").unwrap();
        ledger(&store, &intent, &intent.old.as_ref().unwrap().sha256);
        match change {
            "ledger" => fs::remove_file(store.root.join("units.json")).unwrap(),
            "file" => files.remove(path).unwrap(),
            _ => {
                let mut value: Value =
                    serde_json::from_slice(&fs::read(store.root.join("units.json")).unwrap())
                        .unwrap();
                if change == "owner" {
                    value[&intent.path]["application"] = json!("foreign")
                } else {
                    value[&intent.path]["sha256"] = json!(document_digest(b"foreign"))
                }
                store::atomic(
                    &store.root.join("units.json"),
                    &serde_json::to_vec(&value).unwrap(),
                    0o600,
                )
                .unwrap();
            }
        }
        let before = files.read(path).unwrap();
        let result = system::reconcile_unit_intent_with(&store, &intent, &files);
        assert!(result.is_err(), "{change}");
        assert_eq!(files.read(path).unwrap(), before);
    }
}

#[test]
fn framework_reconciliation_consumes_only_exact_scope_and_untagged_intents() {
    let (directory, store) = store();
    let files = Files {
        root: directory.path().to_owned(),
    };
    let mut framework = unit(None, Some("proxy"));
    framework.application = "platform".into();
    framework.instance = "proxy".into();
    framework.operation_id = None;
    framework.path = system::PROXY_CONFIG.into();
    save_unit(&store, &framework);
    let mut tagged = unit(None, Some("tagged"));
    tagged.identity = "d".repeat(32);
    tagged.application = "platform".into();
    tagged.instance = "proxy".into();
    tagged.path = "/etc/systemd/system/tagged.service".into();
    save_unit(&store, &tagged);
    let mut foreign = unit(None, Some("capacity"));
    foreign.identity = "c".repeat(32);
    foreign.application = "platform".into();
    foreign.instance = "capacity".into();
    foreign.operation_id = None;
    foreign.path = "/etc/systemd/system/capacity.slice".into();
    save_unit(&store, &foreign);

    system::reconcile_framework_units_with(&store, APP, "production", &files).unwrap();
    system::reconcile_unit_intents_with(&store, APP, "production", &"b".repeat(32), &files)
        .unwrap();
    assert!(files.read(Path::new(&framework.path)).unwrap().is_none());
    system::reconcile_framework_units_with(&store, "platform", "proxy", &files).unwrap();
    assert_eq!(
        files.read(Path::new(&framework.path)).unwrap().unwrap(),
        b"proxy"
    );
    for untouched in [&tagged, &foreign] {
        assert!(files.read(Path::new(&untouched.path)).unwrap().is_none());
        let raw = fs::read(
            store
                .root
                .join("unit-intents")
                .join(format!("{}.json", untouched.identity)),
        )
        .unwrap();
        let record: UnitIntent = serde_json::from_slice(&raw).unwrap();
        assert_eq!(record.phase, "pending");
    }
}
