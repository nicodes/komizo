use komizo::deployment::{store::*, units, *};
use serde_json::json;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};

fn request() -> Request {
    serde_json::from_value(json!({"kind":"komizo.request","version":1,"authority":"github","application":"mailroom","instance":"production","action":"deploy","release_digest":format!("sha256:{}","a".repeat(64)),"nonce":"b".repeat(32),"issued_at":1000,"expires_at":1120,"proof":"SECRET_TOKEN","registry":{"server":"ghcr.io","username":"private","token":"REGISTRY_TOKEN"}})).unwrap()
}

#[test]
fn interrupted_atomic_writes_do_not_become_operations_and_committed_ids_cannot_be_overwritten() {
    let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
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

#[test]
fn concurrent_atomic_observation_keeps_complete_records_and_refuses_hardlinks() {
    let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = dir.path().join("observed.json");
    let first = b"{\"phase\":\"staging\"}";
    let second = b"{\"phase\":\"needs_reconciliation\"}";
    atomic(&path, first, 0o600).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_path = path.clone();
    let writer_barrier = barrier.clone();
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for i in 0..256 {
            atomic(&writer_path, if i % 2 == 0 { second } else { first }, 0o600).unwrap();
        }
    });
    barrier.wait();
    let mut complete_reads = 0;
    for _ in 0..2048 {
        match read_protected(&path, 4096) {
            Ok(body) => {
                assert!(body == first || body == second);
                complete_reads += 1;
            }
            // Continuous replacement can exhaust the bounded reopen loop.
            // That refusal is safe; incomplete or linked records are not.
            Err(error) => assert_eq!(
                error.to_string(),
                "protected file was repeatedly replaced while opening"
            ),
        }
    }
    writer.join().unwrap();
    assert!(complete_reads > 0);
    assert_eq!(read_protected(&path, 4096).unwrap(), first);
    let linked = dir.path().join("linked");
    fs::hard_link(&path, &linked).unwrap();
    assert!(read_protected(&path, 4096).is_err());
    assert!(read_protected(&linked, 4096).is_err());
    fs::remove_file(linked).unwrap();
    assert_eq!(read_protected(&path, 4096).unwrap(), first);
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
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
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
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
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
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
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
fn native_service_configs_preserve_literal_arguments_without_ports_or_repull() {
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
    let config = units::service_config(&doc, "api", &bindings, false).unwrap();
    assert_eq!(config.command, doc.release.workload.services["api"].command);
    assert!(config.command.contains(&"literal %n $HOST_SECRET".into()));
    assert!(config.options.contains(&"--pull=never".into()));
    assert!(config.options.contains(&"--cgroups=no-conmon".into()));
    assert!(config.options.contains(&"--log-driver=k8s-file".into()));
    assert!(
        config
            .options
            .contains(&"--log-opt=max-size=1048576".into())
    );
    let parent = config
        .options
        .windows(2)
        .find(|pair| pair[0] == "--cgroup-parent")
        .unwrap();
    assert_eq!(
        parent[1],
        komizo::deployment::cgroups::workload_group(
            "mailroom",
            "production",
            komizo::deployment::cgroups::WorkloadKind::Service,
            "api",
            &"e".repeat(32)
        )
        .unwrap()
        .relative()
    );
    assert!(parent[1].starts_with("/komizo/production/"));
    assert_eq!(
        config.health.as_ref().unwrap().start_interval_seconds,
        Some(2)
    );
    assert!(!config.wanted);
    assert!(
        !config
            .options
            .iter()
            .any(|arg| arg.starts_with("--publish") || arg == "-p")
    );
    let encoded = config.bytes().unwrap();
    let decoded = units::ServiceConfig::parse(&encoded).unwrap();
    assert_eq!(decoded.bytes().unwrap(), encoded);
    let mut foreign: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    foreign["unknown"] = true.into();
    assert!(units::ServiceConfig::parse(&serde_json::to_vec(&foreign).unwrap()).is_err());
    assert_ne!(
        units::namespace("mailroom", "production").unwrap(),
        units::namespace("mailroom", "pr-1").unwrap()
    );
}

#[test]
fn removed_preview_state_cannot_retain_data_or_be_confused_with_a_deliberate_stop() {
    let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let store = Store::new(dir.path().join("state")).unwrap();
    let mut installed = Installed {
        kind: "komizo.installed".into(),
        version: 1,
        application: "mailroom".into(),
        instance: "pr-1".into(),
        release_digest: format!("sha256:{}", "a".repeat(64)),
        operation_id: "b".repeat(32),
        desired_running: false,
        removed: false,
        expires_at: None,
        resources: Resources::default(),
        secret_snapshots: BTreeMap::new(),
    };
    installed.resources.volumes.insert(
        "data".into(),
        ObjectRecord {
            name: "owned-data".into(),
            id: format!("sha256:{}", "c".repeat(64)),
        },
    );
    store.save_installed(&installed).unwrap();
    assert!(
        !store
            .installed("mailroom", "pr-1")
            .unwrap()
            .unwrap()
            .removed
    );
    installed.removed = true;
    assert!(store.save_installed(&installed).is_err());
    installed.resources = Resources::default();
    store.save_installed(&installed).unwrap();
    assert!(
        store
            .installed("mailroom", "pr-1")
            .unwrap()
            .unwrap()
            .removed
    );
    assert!(store.view("mailroom", "pr-1").unwrap().1.is_none());
    installed.desired_running = true;
    assert!(installed.validate().is_err());
    installed.desired_running = false;
    installed.instance = "production".into();
    assert!(installed.validate().is_err());
    let pending = store.root.join("instances/.komizo-pending-A1b2C3");
    fs::write(&pending, b"{partial").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        komizo::deployment::proxy::instances(&store).unwrap().len(),
        1
    );
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(komizo::deployment::proxy::instances(&store).is_err());
}

#[test]
fn protected_state_refuses_a_symbolic_ancestor_even_when_its_target_is_private() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let direct = directory.path().join("direct");
    fs::create_dir(&direct).unwrap();
    fs::set_permissions(&direct, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    symlink(&direct, &alias).unwrap();
    assert!(Store::new(alias.join("state")).is_err());
    assert!(!direct.join("state").exists());
    assert!(Store::new(direct.join("state")).is_ok());
}
