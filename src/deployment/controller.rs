use super::{
    authority,
    model::*,
    store::{self, Guard, Operation, Store},
    transport::Completion,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub struct Job {
    pub request: Request,
    pub operation_id: String,
    pub deadline: Instant,
    pub admitted_at: i64,
    policy_digest: String,
    _guard: Guard,
    response: mpsc::SyncSender<Operation>,
}

pub trait Backend: Send + Sync + 'static {
    fn execute(
        &self,
        store: &Store,
        policy: &Policy,
        job: &Job,
        operation: &mut Operation,
    ) -> Result<()>;
}

pub struct Coordinator {
    pub store: Store,
    pub policies: PathBuf,
    sender: mpsc::SyncSender<Job>,
}

pub fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

pub fn policy(directory: &Path, application: &str) -> Result<(Policy, String)> {
    ensure!(name(application), "invalid policy application scope");
    let body = store::read_protected(
        &directory.join(format!("{application}.json")),
        MAX_DOCUMENT_BYTES,
    )?;
    let value = crate::strict::value(&body, MAX_DOCUMENT_BYTES)?;
    let policy: Policy = serde_json::from_value(value.clone())?;
    policy.validate()?;
    ensure!(
        policy.application == application,
        "policy file belongs to another application"
    );
    Ok((policy, document_digest(&canonical(&value)?)))
}

fn frame(value: Value) -> Result<Completion> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    Ok(Box::new(move |stream| {
        stream.write_all(&bytes)?;
        Ok(())
    }))
}

impl Coordinator {
    pub fn new(state: PathBuf, policies: PathBuf, backend: Arc<dyn Backend>) -> Result<Arc<Self>> {
        let store = Store::new(state)?;
        store::protected_directory(&policies)?;
        let (sender, receiver) = mpsc::sync_channel::<Job>(32);
        let coordinator = Arc::new(Self {
            store,
            policies,
            sender,
        });
        let worker_store = coordinator.store.clone();
        let worker_policies = coordinator.policies.clone();
        std::thread::spawn(move || {
            // One effect worker preserves the shared startup and disk budget.
            // Authentication and read-only inspection remain independently live.
            for job in receiver {
                let result = (|| -> Result<Operation> {
                    let mut operation = worker_store.operation(&job.operation_id)?;
                    let executed =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                            ensure!(
                                Instant::now() < job.deadline,
                                "operation expired while queued"
                            );
                            let (policy, hash) =
                                policy(&worker_policies, &job.request.application)?;
                            ensure!(
                                hash == job.policy_digest,
                                "host policy changed after admission"
                            );
                            backend.execute(&worker_store, &policy, &job, &mut operation)?;
                            ensure!(
                                operation.terminal() && operation.ok,
                                "worker did not complete its accepted operation"
                            );
                            Ok(())
                        }));
                    if !matches!(executed, Ok(Ok(()))) {
                        if !operation.terminal() {
                            let phase =
                                if ["admitted", "staging"].contains(&operation.phase.as_str()) {
                                    "failed"
                                } else {
                                    "needs_reconciliation"
                                };
                            operation.transition(phase)?;
                        }
                        worker_store.save_operation(&operation)?;
                    }
                    Ok(operation)
                })();
                if let Ok(operation) = result {
                    let _ = job.response.send(operation);
                }
                // The lease and credentials are dropped only after the worker
                // finishes, never when its waiting SSH connection disappears.
            }
        });
        Ok(coordinator)
    }

    pub fn admit(
        &self,
        body: Vec<u8>,
        peer_uid: u32,
        at: i64,
        key: &mut authority::KeyProvider<'_>,
    ) -> Result<Completion> {
        let scope = bounded_value(&body, MAX_DOCUMENT_BYTES)?;
        let application = scope["application"]
            .as_str()
            .ok_or_else(|| anyhow!("request application missing"))?;
        let (policy, policy_digest) = policy(&self.policies, application)?;
        let authority::AdmittedRequest {
            mut request,
            digest: request_digest,
            release,
            evidence,
        } = authority::admit(&body, &policy, peer_uid, at, key)?;
        drop(scope);
        drop(body);
        let id = store::operation_identity(&request)?;
        if request.action == "inspect" {
            self.store.reserve(&request, &request_digest, &id)?;
            return self.inspect(&request, &policy);
        }
        if request.action == "export" {
            self.store.reserve(&request, &request_digest, &id)?;
            return self.export(&request, &policy);
        }
        let guard = self.store.lock(&request.application, &request.instance)?;
        self.blocked(&request)?;
        let installed = self
            .store
            .installed(&request.application, &request.instance)?;
        if request.action != "deploy" && request.action != "recover" {
            ensure!(
                installed
                    .as_ref()
                    .is_some_and(|r| r.release_digest == request.release_digest)
                    || (request.action == "backup"
                        && request.release_digest == "absent"
                        && installed.is_none()),
                "operation target differs from the installed release"
            );
        }
        let work_remaining = request
            .issued_at
            .checked_add(i64::from(request.timeout_seconds))
            .and_then(|n| n.checked_sub(at))
            .ok_or_else(|| anyhow!("operation deadline overflow"))?;
        ensure!(work_remaining > 0, "operation deadline has already elapsed");
        let deadline = Instant::now()
            + Duration::from_secs(
                (work_remaining as u64).min(u64::from(policy.operation_timeout_seconds)),
            );
        self.store.reserve(&request, &request_digest, &id)?;
        if let Some(document) = release {
            self.store.save_release(&document)?;
        }
        let operation = Operation {
            kind: "komizo.operation".into(),
            version: 1,
            operation_id: id.clone(),
            application: request.application.clone(),
            instance: request.instance.clone(),
            release_digest: request.release_digest.clone(),
            phase: "admitted".into(),
            ok: false,
            previous_release_digest: installed.as_ref().map(|r| r.release_digest.clone()),
            reconciliation_required: false,
            backup: None,
        };
        self.store.create_operation(&operation)?;
        let journal = self.store.root.join("journal").join(&id);
        store::atomic(
            &journal.join("admission.json"),
            &serde_json::to_vec(
                &json!({"kind":"komizo.admission","version":1,"operation_id":id,"policy_digest":policy_digest,"evidence":evidence}),
            )?,
            0o600,
        )?;
        if let Some(record) = installed {
            store::atomic(
                &journal.join("previous.json"),
                &serde_json::to_vec(&record)?,
                0o600,
            )?;
        }
        // The canonical release and audit metadata are durable. Neither bearer
        // proof nor raw request is retained in the queue or on disk.
        request.release = None;
        request.release_proof = None;
        request.proof.clear();
        let (response, receiver) = mpsc::sync_channel(1);
        let queued = self
            .sender
            .try_send(Job {
                request,
                operation_id: id.clone(),
                deadline,
                admitted_at: at,
                policy_digest,
                _guard: guard,
                response,
            })
            .map_err(|_| anyhow!("host operation queue is unavailable"));
        if queued.is_err() {
            let mut operation = operation;
            operation.transition("failed")?;
            self.store.save_operation(&operation)?;
            return frame(serde_json::to_value(operation)?);
        }
        Ok(Box::new(move |stream| {
            let operation = receiver
                .recv_timeout(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(30),
                )
                .map_err(|_| {
                    anyhow!("operation acknowledgment is uncertain; inspect its proposed identity")
                })?;
            serde_json::to_writer(&mut *stream, &operation)?;
            stream.write_all(b"\n")?;
            Ok(())
        }))
    }

    fn inspect(&self, request: &Request, policy: &Policy) -> Result<Completion> {
        if let Some(id) = &request.operation {
            let operation = self.store.operation(id)?;
            ensure!(
                operation.application == request.application
                    && operation.instance == request.instance
                    && operation.release_digest == request.release_digest,
                "operation inspection is outside its authenticated scope"
            );
            return frame(serde_json::to_value(operation)?);
        }
        let installed = self
            .store
            .installed(&request.application, &request.instance)?;
        ensure!(
            request.release_digest == "current"
                || installed
                    .as_ref()
                    .is_some_and(|r| r.release_digest == request.release_digest),
            "instance inspection target changed"
        );
        let mut response = json!({"kind":"komizo.instance","version":1,"application":request.application,"instance":request.instance,"installed":installed.map(|r|json!({"release_digest":r.release_digest,"desired_running":r.desired_running,"operation_id":r.operation_id}))});
        if request.instance != "production" {
            let p = policy
                .previews
                .as_ref()
                .ok_or_else(|| anyhow!("preview plan is not admitted"))?;
            let app = format!("https://{}.{}", request.instance, p.hostname_suffix);
            let api = p.api_path.as_ref().map_or_else(
                || format!("https://{}-api.{}", request.instance, p.hostname_suffix),
                |path| format!("{app}{path}"),
            );
            response["plan"] = json!({"app_origin":app,"api_origin":api});
        }
        frame(response)
    }

    fn export(&self, request: &Request, policy: &Policy) -> Result<Completion> {
        let id = request
            .operation
            .as_deref()
            .ok_or_else(|| anyhow!("backup operation missing"))?;
        let operation = self.store.operation(id)?;
        ensure!(
            operation.application == request.application
                && operation.instance == request.instance
                && operation.release_digest == request.release_digest
                && operation.ok,
            "export is outside an accepted backup scope"
        );
        let backup = operation
            .backup
            .as_ref()
            .filter(|b| b.status == "ready")
            .ok_or_else(|| anyhow!("operation has no encrypted backup"))?;
        let name = request.export_name.as_deref().unwrap();
        let metadata = backup
            .files
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| anyhow!("backup export name is not recorded"))?;
        let task = policy
            .backup
            .as_ref()
            .ok_or_else(|| anyhow!("backup export policy is absent"))?;
        ensure!(
            metadata.size_bytes <= task.max_export_bytes && digest(&metadata.sha256),
            "export exceeds its protected bound"
        );
        let path = self.store.root.join("exports").join(id).join(name);
        super::assets::verify_file(&path, &metadata.sha256, metadata.size_bytes)?;
        let mut file = fs::File::open(&path)?;
        let header = json!({"kind":"komizo.export","version":1,"operation_id":id,"application":request.application,"instance":request.instance,"release_digest":request.release_digest,"export_name":name,"size_bytes":metadata.size_bytes,"sha256":metadata.sha256});
        let size = metadata.size_bytes;
        Ok(Box::new(move |stream| {
            serde_json::to_writer(&mut *stream, &header)?;
            stream.write_all(b"\n")?;
            let copied = std::io::copy(&mut file, stream)?;
            ensure!(copied == size, "encrypted export changed during transfer");
            Ok(())
        }))
    }

    fn blocked(&self, request: &Request) -> Result<()> {
        if request.authority == "owner"
            && ["recover", "stop", "secret-set"].contains(&request.action.as_str())
        {
            return Ok(());
        }
        for entry in fs::read_dir(self.store.root.join("operations"))? {
            let entry = entry?;
            let name = entry.file_name();
            let id = name
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .ok_or_else(|| anyhow!("invalid operation record path"))?;
            let operation = self.store.operation(id)?;
            if operation.application == request.application
                && operation.instance == request.instance
                && (operation.reconciliation_required || !operation.terminal())
            {
                let resolution = self
                    .store
                    .root
                    .join("reconciliations")
                    .join(format!("{id}.json"));
                ensure!(
                    resolution.try_exists()?,
                    "instance requires explicit owner reconciliation"
                );
                let value = crate::strict::value(&store::read_protected(&resolution, 4096)?, 4096)?;
                let by = value["resolved_by"]
                    .as_str()
                    .ok_or_else(|| anyhow!("invalid reconciliation record"))?;
                let resolved = self.store.operation(by)?;
                ensure!(
                    resolved.application == operation.application
                        && resolved.instance == operation.instance
                        && resolved.ok,
                    "instance reconciliation has not completed"
                );
            }
        }
        Ok(())
    }
}

pub fn advance(store: &Store, operation: &mut Operation, phase: &str) -> Result<()> {
    let journal = store.root.join("journal").join(&operation.operation_id);
    store::atomic(
        &journal.join("effect-intent.json"),
        &serde_json::to_vec(&json!({"kind":"komizo.effect-intent","version":1,"phase":phase}))?,
        0o600,
    )?;
    operation.transition(phase)?;
    store.save_operation(operation)
}

pub fn write_frame(stream: &mut UnixStream, operation: &Operation) -> Result<()> {
    serde_json::to_writer(&mut *stream, operation)?;
    stream.write_all(b"\n")?;
    Ok(())
}
