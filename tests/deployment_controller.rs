use anyhow::Result;
use komizo::deployment::{
    controller::{self, Backend, Coordinator, Job},
    store::{self, Operation, Store},
    *,
};
use serde_json::{Value, json};
use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

struct Worker {
    calls: Arc<AtomicUsize>,
    gate: Mutex<mpsc::Receiver<()>>,
    fail: bool,
}
impl Backend for Worker {
    fn execute(
        &self,
        store: &Store,
        _: &Policy,
        job: &Job,
        operation: &mut Operation,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        controller::advance(store, operation, "staging")?;
        controller::advance(store, operation, "jobs")?;
        self.gate
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))?;
        anyhow::ensure!(!self.fail, "simulated interrupted migration effect");
        for phase in ["installing", "activating", "readiness", "ready"] {
            controller::advance(store, operation, phase)?;
        }
        assert_eq!(
            operation.operation_id,
            komizo::deployment::store::operation_identity(&job.request)?
        );
        Ok(())
    }
}
fn setup(
    fail: bool,
) -> (
    tempfile::TempDir,
    Arc<Coordinator>,
    mpsc::SyncSender<()>,
    Arc<AtomicUsize>,
    Value,
) {
    let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let policies = dir.path().join("policies");
    fs::create_dir(&policies).unwrap();
    let policy = json!({"kind":"komizo.policy","version":1,"application":"mailroom","authority":{"kind":"owner"},"artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],"limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},"readiness":[{"url":"https://mail.example/","status":200}],"secrets":{"runtime":{"path":"/etc/komizo/runtime.env","services":["api"],"environment_file":true,"generation":"11111111111111111111111111111111"}}});
    komizo::deployment::store::atomic(
        &policies.join("mailroom.json"),
        &serde_json::to_vec(&policy).unwrap(),
        0o600,
    )
    .unwrap();
    let (gate, receiver) = mpsc::sync_channel(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let worker = Worker {
        calls: calls.clone(),
        gate: Mutex::new(receiver),
        fail,
    };
    let coordinator =
        Coordinator::new(dir.path().join("state"), policies, Arc::new(worker)).unwrap();
    let release: Value =
        serde_json::from_str(include_str!("fixtures/deployment/release.json")).unwrap();
    let digest = read_release(&serde_json::to_vec(&release).unwrap())
        .unwrap()
        .digest;
    let request = json!({"kind":"komizo.request","version":1,"authority":"owner","application":"mailroom","instance":"production","action":"deploy","release_digest":digest,"nonce":"b".repeat(32),"issued_at":1000,"expires_at":1120,"timeout_seconds":30,"release":release,"registry":{"server":"ghcr.io","username":"private","token":"PRIVATE_REGISTRY_TOKEN"}});
    (dir, coordinator, gate, calls, request)
}
fn wait(store: &Store, id: &str) -> Operation {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let operation = store.operation(id).unwrap();
        if operation.terminal() {
            return operation;
        }
        assert!(Instant::now() < deadline, "worker did not complete");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn disconnected_submitter_does_not_cancel_or_repeat_an_admitted_effect() {
    let (_dir, c, gate, calls, request) = setup(false);
    let parsed: Request = serde_json::from_value(request.clone()).unwrap();
    let id = komizo::deployment::store::operation_identity(&parsed).unwrap();
    assert_eq!(id, "3a136f1b4cdd49cd0c83b4231129a21f");
    let completion = c
        .admit(serde_json::to_vec(&request).unwrap(), 0, 1000, &mut |_| {
            panic!("owner request fetched remote keys")
        })
        .unwrap();
    drop(completion);
    gate.send(()).unwrap();
    let operation = wait(&c.store, &id);
    assert!(operation.ok);
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert!(
        c.admit(
            serde_json::to_vec(&request).unwrap(),
            0,
            1000,
            &mut |_| panic!()
        )
        .is_err()
    );
    let audit = fs::read_to_string(
        c.store
            .root
            .join("journal")
            .join(&id)
            .join("admission.json"),
    )
    .unwrap();
    assert!(!audit.contains("PRIVATE_REGISTRY_TOKEN"));
    assert!(!audit.contains("\"proof\""));
}

#[test]
fn uncertain_migration_blocks_a_new_deploy_until_explicit_owner_reconciliation() {
    let (_dir, c, gate, calls, mut request) = setup(true);
    let parsed: Request = serde_json::from_value(request.clone()).unwrap();
    let id = komizo::deployment::store::operation_identity(&parsed).unwrap();
    let completion = c
        .admit(
            serde_json::to_vec(&request).unwrap(),
            0,
            1000,
            &mut |_| panic!(),
        )
        .unwrap();
    drop(completion);
    gate.send(()).unwrap();
    let operation = wait(&c.store, &id);
    assert_eq!(operation.phase, "needs_reconciliation");
    assert!(!operation.ok);
    request["nonce"] = json!("c".repeat(32));
    assert!(
        c.admit(
            serde_json::to_vec(&request).unwrap(),
            0,
            1000,
            &mut |_| panic!()
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Acquire), 1);
}

#[test]
fn prepared_start_is_bound_to_the_selected_source_and_stale_installed_target_refuses() {
    use komizo::deployment::store::{Installed, Resources};
    let (_dir, c, gate, calls, request) = setup(false);
    let old = read_release(&serde_json::to_vec(&request["release"]).unwrap()).unwrap();
    let mut next = request["release"].clone();
    next["source"]["revision"] = json!("f".repeat(40));
    let next = read_release(&serde_json::to_vec(&next).unwrap()).unwrap();
    c.store.save_release(&old).unwrap();
    c.store.save_release(&next).unwrap();
    let installed = Installed {
        kind: "komizo.installed".into(),
        version: 1,
        application: "mailroom".into(),
        instance: "production".into(),
        release_digest: old.digest.clone(),
        operation_id: "1".repeat(32),
        desired_running: false,
        removed: false,
        expires_at: None,
        resources: Resources::default(),
        secret_snapshots: Default::default(),
    };
    c.store.save_installed(&installed).unwrap();
    let mut prepared = installed.clone();
    prepared.release_digest = next.digest.clone();
    prepared.operation_id = "2".repeat(32);
    komizo::deployment::store::atomic(
        &c.store.root.join("prepared/mailroom--production.json"),
        &serde_json::to_vec(&prepared).unwrap(),
        0o600,
    )
    .unwrap();
    let mut start = json!({"kind":"komizo.request","version":1,"authority":"owner","application":"mailroom","instance":"production","action":"start","release_digest":old.digest,"nonce":"c".repeat(32),"issued_at":1000,"expires_at":1120,"timeout_seconds":30});
    assert!(
        c.admit(
            serde_json::to_vec(&start).unwrap(),
            0,
            1000,
            &mut |_| panic!()
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Acquire), 0);
    start["release_digest"] = json!(next.digest);
    let id = komizo::deployment::store::operation_identity(
        &serde_json::from_value(start.clone()).unwrap(),
    )
    .unwrap();
    drop(
        c.admit(
            serde_json::to_vec(&start).unwrap(),
            0,
            1000,
            &mut |_| panic!(),
        )
        .unwrap(),
    );
    gate.send(()).unwrap();
    assert!(wait(&c.store, &id).ok);
}

#[test]
fn terminal_acknowledgment_releases_the_instance_before_unrelated_maintenance() {
    struct BlockingMaintenance {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        calls: AtomicUsize,
    }
    impl Backend for BlockingMaintenance {
        fn execute(
            &self,
            store: &Store,
            _: &Policy,
            _: &Job,
            operation: &mut Operation,
        ) -> Result<()> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            for phase in [
                "staging",
                "jobs",
                "installing",
                "activating",
                "readiness",
                "ready",
            ] {
                controller::advance(store, operation, phase)?;
            }
            Ok(())
        }
        fn maintenance(&self, _: &Store) -> Result<()> {
            if self.calls.load(Ordering::Acquire) == 1 {
                let _ = self.entered.send(());
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))?;
            }
            Ok(())
        }
    }
    let (_dir, original, _gate, _calls, mut request) = setup(false);
    let state = original.store.root.clone();
    let policies = original.policies.clone();
    drop(original);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let backend = Arc::new(BlockingMaintenance {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        calls: AtomicUsize::new(0),
    });
    let c = Coordinator::new(state, policies, backend.clone()).unwrap();
    let first =
        store::operation_identity(&serde_json::from_value(request.clone()).unwrap()).unwrap();
    drop(
        c.admit(
            serde_json::to_vec(&request).unwrap(),
            0,
            1000,
            &mut |_| panic!(),
        )
        .unwrap(),
    );
    entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(c.store.operation(&first).unwrap().ok);
    request["nonce"] = json!("e".repeat(32));
    let second =
        store::operation_identity(&serde_json::from_value(request.clone()).unwrap()).unwrap();
    let admitted = c.admit(
        serde_json::to_vec(&request).unwrap(),
        0,
        1000,
        &mut |_| panic!(),
    );
    release_tx.send(()).unwrap();
    drop(admitted.expect("a completed operation must not retain the app lease during maintenance"));
    assert!(wait(&c.store, &second).ok);
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
}
