//! Serialized native effects. Every retained object has protected ownership.
use super::{
    capacity,
    controller::{self, Backend, Job, advance},
    data,
    engine::{Engine, volume_identity},
    jobs,
    model::*,
    observation, proxy,
    registry::Registry,
    secrets,
    store::{self, Installed, ObjectRecord, Operation, Resources, Store},
    system::{self, System},
    units,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct Native;

#[path = "service_maintenance.rs"]
mod service_maintenance;

#[path = "task_lifetime.rs"]
mod task_lifetime;
#[path = "task_process.rs"]
mod task_process;
#[path = "task_watchdog.rs"]
mod task_watchdog;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskIntent {
    kind: String,
    version: u32,
    application: String,
    instance: String,
    operation_id: String,
    task: String,
    unit: String,
    unit_sha256: String,
    program: String,
    program_sha256: String,
    request_sha256: String,
    request_operation_id: String,
    environment: BTreeMap<String, String>,
    boot_id: String,
    deadline_monotonic_ns: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceIntent {
    kind: String,
    version: u32,
    application: String,
    instance: String,
    operation_id: String,
    release_digest: String,
    service: String,
    record: store::ContainerRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit_body: Option<String>,
}

fn service_intent_path(
    store: &Store,
    operation_id: &str,
    kind: &str,
    service: &str,
) -> Result<PathBuf> {
    ensure!(
        hex(operation_id, 32) && name(service) && ["creation", "removal"].contains(&kind),
        "invalid service intent scope"
    );
    Ok(store
        .root
        .join("journal")
        .join(operation_id)
        .join(format!("service-{kind}-{service}.json")))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIntent {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub operation_id: String,
    pub release_digest: String,
    pub object_kind: String,
    pub logical: String,
    pub name: String,
    pub ownership: String,
    pub internal: Option<bool>,
    pub identity: Option<String>,
}

pub fn object_evidence(intent: &ObjectIntent, value: &serde_json::Value) -> Result<ObjectRecord> {
    ensure!(
        intent.kind == "komizo.object-intent"
            && intent.version == 1
            && name(&intent.application)
            && name(&intent.instance)
            && name(&intent.logical)
            && hex(&intent.operation_id, 32)
            && digest(&intent.release_digest)
            && hex(&intent.ownership, 32),
        "invalid protected object creation intent"
    );
    ensure!(
        intent.name
            == units::object_name(
                &intent.application,
                &intent.instance,
                &intent.object_kind,
                &intent.logical
            )?,
        "object creation intent escaped its namespace"
    );
    let labels = value
        .get("labels")
        .or_else(|| value.get("Labels"))
        .ok_or_else(|| anyhow!("native object ownership labels unavailable"))?;
    ensure!(
        labels["io.komizo.application"] == intent.application
            && labels["io.komizo.instance"] == intent.instance
            && labels["io.komizo.object"] == format!("{}:{}", intent.object_kind, intent.logical)
            && labels["io.komizo.ownership"] == intent.ownership,
        "native object has no matching pre-effect ownership token"
    );
    let id = if intent.object_kind == "network" {
        ensure!(
            value["name"] == intent.name
                && value["driver"] == "bridge"
                && ["1", "true"]
                    .iter()
                    .any(|expected| value["options"]["isolate"] == *expected)
                && intent
                    .internal
                    .is_some_and(|internal| value["internal"] == internal),
            "native network differs from its declared topology"
        );
        let id = value["id"]
            .as_str()
            .ok_or_else(|| anyhow!("network ID missing"))?;
        ensure!(hex(id, 64), "invalid native network ID");
        id.to_owned()
    } else {
        ensure!(
            value["Name"] == intent.name && intent.internal.is_none(),
            "native volume differs from its creation intent"
        );
        volume_identity(value)?
    };
    ensure!(
        intent
            .identity
            .as_ref()
            .is_none_or(|expected| *expected == id),
        "native object was replaced after creation"
    );
    Ok(ObjectRecord {
        name: intent.name.clone(),
        id,
    })
}

fn create_object(
    store: &Store,
    installed: &Installed,
    document: &ReleaseDocument,
    engine: &Engine,
    kind: &str,
    logical: &str,
    internal: Option<bool>,
) -> Result<ObjectRecord> {
    let physical = units::object_name(&installed.application, &installed.instance, kind, logical)?;
    ensure!(
        !engine.exists(kind, &physical)?,
        "unrecorded native object cannot be adopted"
    );
    let mut intent = ObjectIntent {
        kind: "komizo.object-intent".into(),
        version: 1,
        application: installed.application.clone(),
        instance: installed.instance.clone(),
        operation_id: installed.operation_id.clone(),
        release_digest: document.digest.clone(),
        object_kind: kind.into(),
        logical: logical.into(),
        name: physical.clone(),
        ownership: store::identity()?,
        internal,
        identity: None,
    };
    let path = store
        .root
        .join("journal")
        .join(&installed.operation_id)
        .join(format!("object-{kind}-{logical}.json"));
    ensure!(
        !path.try_exists()?,
        "object creation intent already exists; explicit reconciliation is required"
    );
    store::atomic(&path, &serde_json::to_vec(&intent)?, 0o600)?;
    let mut args = vec![
        kind.to_owned(),
        "create".into(),
        format!(
            "--driver={}",
            if kind == "network" { "bridge" } else { "local" }
        ),
    ];
    if kind == "network" {
        args.extend(["--opt".into(), "isolate=1".into()]);
    }
    for (key, value) in [
        ("application", installed.application.as_str()),
        ("instance", installed.instance.as_str()),
        ("ownership", intent.ownership.as_str()),
    ] {
        args.extend(["--label".into(), format!("io.komizo.{key}={value}")]);
    }
    args.extend([
        "--label".into(),
        format!("io.komizo.object={kind}:{logical}"),
    ]);
    if internal == Some(true) {
        args.push("--internal".into());
    }
    args.push(physical);
    engine.run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    let record = object_evidence(&intent, &engine.inspect(kind, &intent.name)?)?;
    intent.identity = Some(record.id.clone());
    store::atomic(&path, &serde_json::to_vec(&intent)?, 0o600)?;
    Ok(record)
}

fn remove_object(
    store: &Store,
    installed: &Installed,
    engine: &Engine,
    operation_id: &str,
    kind: &str,
    logical: &str,
    record: &ObjectRecord,
) -> Result<()> {
    ensure!(
        hex(operation_id, 32)
            && record.name
                == units::object_name(&installed.application, &installed.instance, kind, logical)?,
        "invalid retained object removal scope"
    );
    engine.owned_object(kind, record)?;
    store::atomic(
        &store
            .root
            .join("journal")
            .join(operation_id)
            .join(format!("object-removal-{kind}-{logical}.json")),
        &canonical(
            &json!({"kind":"komizo.object-removal","version":1,"application":installed.application,"instance":installed.instance,"operation_id":operation_id,"release_digest":installed.release_digest,"object_kind":kind,"logical":logical,"name":record.name,"identity":record.id}),
        )?,
        0o600,
    )?;
    engine.run(&[kind, "rm", &record.name])?;
    ensure!(
        !engine.exists(kind, &record.name)?,
        "owned object removal remains uncertain"
    );
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvidence {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub operation_id: String,
    pub release_digest: String,
    pub action: String,
    pub schema_version: u64,
    pub data_revision: String,
    pub credential_revision: String,
    pub created_at: i64,
}

pub fn verify_forward_evidence(
    evidence: &RecoveryEvidence,
    installed: &Installed,
    document: &ReleaseDocument,
    operation_id: &str,
    now: i64,
) -> Result<()> {
    let contract = document
        .release
        .stateful_contract
        .as_ref()
        .ok_or_else(|| anyhow!("forward recovery requires an installed data contract"))?;
    ensure!(
        evidence.kind == "komizo.recovery-evidence"
            && evidence.version == 1
            && evidence.application == installed.application
            && evidence.instance == installed.instance
            && evidence.operation_id == operation_id
            && evidence.release_digest == document.digest
            && evidence.action == "forward"
            && contract.recovery_action == RecoveryAction::ForwardOnly
            && evidence.schema_version >= contract.schema.minimum
            && evidence.schema_version <= contract.schema.maximum
            && evidence.data_revision == contract.data_revision
            && evidence.credential_revision == contract.credential_revision
            && now
                .checked_sub(evidence.created_at)
                .is_some_and(|age| (0..=86400).contains(&age)),
        "owner recovery evidence differs from the installed data and credential authority"
    );
    Ok(())
}
impl Native {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
    pub fn startup(&self, store: &Store) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        super::bootstrap::proxy_guard()?;
        Engine { deadline }.preflight()?;
        super::bootstrap::dns_guard()?;
        super::bootstrap::dns_configuration_guard()?;
        super::bootstrap::apparmor_guard()?;
        let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
        system::reconcile_framework_units(store, "platform", "capacity")?;
        system::host_pools(store, &System { deadline }, &capacity)?;
        store.reconcile_interrupted()?;
        proxy::globals()?;
        for installed in proxy::instances(store)? {
            proxy::verify_assets(store, &store.release(&installed.release_digest)?)?;
        }
        Ok(())
    }
}

fn prepared_path(store: &Store, application: &str, instance: &str) -> Result<PathBuf> {
    Ok(store.root.join("prepared").join(format!(
        "{}.json",
        Store::instance_key(application, instance)?
    )))
}

struct TaskFence {
    kill: std::fs::File,
    group: super::cgroups::Group,
    channel: Option<std::os::unix::net::UnixStream>,
}
impl Drop for TaskFence {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = self.kill.write_all(b"1");
        if matches!(super::cgroups::empty(&self.group), Ok(true)) {
            if let Some(channel) = self.channel.as_mut() {
                let timeout = Some(Duration::from_millis(50));
                let _ = channel.set_read_timeout(timeout);
                let _ = channel.set_write_timeout(timeout);
                let _ = channel.write_all(b"D");
                let mut acknowledgement = [0_u8];
                let _ = channel.read_exact(&mut acknowledgement);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn spawn_task_entry(
    operation_id: &str,
    kind: &str,
    mode: &str,
    group: &super::cgroups::Group,
    channel: Option<std::os::unix::net::UnixStream>,
    output: Option<std::fs::File>,
) -> Result<task_process::Process> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    ensure!(
        hex(operation_id, 32)
            && ["backup", "prepare", "reconcile"].contains(&kind)
            && ["task-run", "task-watch"].contains(&mode),
        "invalid protected child scope"
    );
    let entry = super::cgroups::process_entry(group)?;
    let mut command = std::process::Command::new("/usr/local/bin/komizo-box");
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8")
        .args([mode, "--operation", operation_id, "--task", kind])
        .stdin(std::process::Stdio::null())
        .stdout(
            output
                .map(std::process::Stdio::from)
                .unwrap_or_else(std::process::Stdio::null),
        )
        .stderr(std::process::Stdio::null());
    // Only async-signal-safe syscalls run between fork and exec. The already
    // verified kernel descriptor attaches the child before any task code runs.
    let bound_output = mode == "task-run" && kind == "reconcile";
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0
                || libc::write(entry.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            task_process::child_limits(bound_output)?;
            if let Some(channel) = &channel {
                if libc::dup2(channel.as_raw_fd(), 3) != 3 || libc::fcntl(3, libc::F_SETFD, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    task_process::Process::spawn(&mut command, mode == "task-run")
}

#[cfg(not(target_os = "linux"))]
fn spawn_task_entry(
    _operation_id: &str,
    _kind: &str,
    _mode: &str,
    _group: &super::cgroups::Group,
    _channel: Option<std::os::unix::net::UnixStream>,
    _output: Option<std::fs::File>,
) -> Result<task_process::Process> {
    Err(anyhow!("protected native task execution requires Linux"))
}

fn run_task(
    store: &Store,
    operation_id: &str,
    kind: &str,
    program: &ProtectedTask,
    input: &[u8],
    environment: &BTreeMap<String, String>,
    deadline: Instant,
) -> Result<()> {
    use std::io::Write;
    ensure!(
        hex(operation_id, 32) && ["backup", "prepare", "reconcile"].contains(&kind),
        "invalid protected task scope"
    );
    let (boot_id, deadline_monotonic_ns) =
        task_lifetime::deadline(deadline, program.timeout_seconds)?;
    ensure!(
        document_digest(&store::read_protected(
            Path::new(&program.program),
            32 << 20
        )?) == program.sha256,
        "protected executable bundle bytes changed"
    );
    let scope = bounded_value(input, MAX_DOCUMENT_BYTES)?;
    let application = scope["application"]
        .as_str()
        .ok_or_else(|| anyhow!("protected task application missing"))?;
    let instance = scope["instance"]
        .as_str()
        .ok_or_else(|| anyhow!("protected task instance missing"))?;
    ensure!(
        name(application) && name(instance),
        "invalid protected task identity"
    );
    let unit = format!("komizo-{kind}-{operation_id}.service");
    let mut environment = environment.clone();
    ensure!(
        !environment.contains_key("KOMIZO_TASK_OPERATION_ID"),
        "task identity cannot be supplied by a protected program"
    );
    environment.insert("KOMIZO_TASK_OPERATION_ID".into(), operation_id.into());
    for key in environment.keys() {
        ensure!(
            key.starts_with("KOMIZO_") || ["PATH", "HOME", "LANG"].contains(&key.as_str()),
            "unsupported protected task environment"
        );
    }
    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
    let body = canonical(&json!({"kind":"komizo.task-config","version":1,
        "application":application,"instance":instance,"operation_id":operation_id,
        "task":kind,"program":program.program,"program_sha256":program.sha256,
        "request_sha256":document_digest(input),"environment":environment,
        "boot_id":boot_id,"deadline_monotonic_ns":deadline_monotonic_ns,"limits":capacity.control.limits}))?;
    let hash = document_digest(&body);
    let journal = store.root.join("journal").join(operation_id);
    store::atomic(&journal.join(format!("{kind}-request.json")), input, 0o600)?;
    store::atomic(
        &journal.join(format!("{kind}-task.json")),
        &serde_json::to_vec(&TaskIntent {
            kind: "komizo.task".into(),
            version: 1,
            application: application.into(),
            instance: instance.into(),
            operation_id: operation_id.into(),
            task: kind.into(),
            unit: unit.clone(),
            unit_sha256: hash.clone(),
            program: program.program.clone(),
            program_sha256: program.sha256.clone(),
            request_sha256: document_digest(input),
            request_operation_id: scope["operation_id"]
                .as_str()
                .filter(|id| hex(id, 32))
                .ok_or_else(|| anyhow!("protected task operation scope missing"))?
                .into(),
            environment,
            boot_id,
            deadline_monotonic_ns,
        })?,
        0o600,
    )?;
    ensure!(
        system::install_for_operation(
            store,
            &units::config_path(&unit)?,
            application,
            instance,
            &body,
            operation_id
        )? == hash,
        "protected task configuration changed"
    );
    let system = System { deadline };
    let group = super::cgroups::task_group(kind, operation_id)?;
    let runner = super::cgroups::task_runner(kind, operation_id)?;
    let watchers = super::cgroups::control_leaf(super::cgroups::ControlLeaf::Watchdogs);
    for selected in [&group, &runner] {
        system.prepare_group(selected, &capacity.control.limits, &Default::default())?;
    }
    system.prepare_group(
        &watchers,
        &capacity.control.limits,
        &capacity.control.controls,
    )?;
    ensure!(
        system.group_empty(&group)?,
        "fresh protected task already owns processes"
    );
    let mut _fence = TaskFence {
        kill: system.kill_entry(&group)?,
        group: group.clone(),
        channel: None,
    };
    if kind != "reconcile" {
        super::bootstrap::apparmor_guard()?;
    }
    let (mut owner, watcher) = std::os::unix::net::UnixStream::pair()?;
    _fence.channel = Some(owner.try_clone()?);
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow!("protected task setup expired"))?;
    owner.set_read_timeout(Some(remaining))?;
    owner.set_write_timeout(Some(remaining))?;
    let mut watchdog = spawn_task_entry(
        operation_id,
        kind,
        "task-watch",
        &watchers,
        Some(watcher),
        None,
    )?;
    let mut acknowledgement = [0_u8];
    owner.read_exact(&mut acknowledgement)?;
    ensure!(
        acknowledgement == *b"A"
            && watchdog.try_wait()?.is_none()
            && task_lifetime::monotonic_ns()? < deadline_monotonic_ns,
        "independent task watchdog did not arm before execution"
    );
    let output = if kind == "reconcile" {
        use std::os::unix::fs::OpenOptionsExt;
        Some(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(journal.join("reconcile-output.json"))?,
        )
    } else {
        None
    };
    let mut child = spawn_task_entry(operation_id, kind, "task-run", &runner, None, output)?;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            watchdog.try_wait()?.is_none(),
            "independent task watchdog exited before completion"
        );
        ensure!(
            Instant::now() < deadline && task_lifetime::monotonic_ns()? < deadline_monotonic_ns,
            "protected task absolute deadline expired"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    ensure!(
        status.success(),
        "protected task did not complete successfully"
    );
    system.kill_group(&group)?;
    task_quiescent(kind, operation_id)?;
    owner.write_all(b"D")?;
    owner.read_exact(&mut acknowledgement)?;
    ensure!(
        acknowledgement == *b"D",
        "task watchdog did not verify empty completion"
    );
    loop {
        if let Some(status) = watchdog.try_wait()? {
            ensure!(status.success(), "task watchdog completion failed");
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "task watchdog completion exceeded its deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    system.remove_group(&group)?;
    store::atomic(
        &journal.join(format!("{kind}-completed.json")),
        &canonical(&json!({"unit_sha256":hash,"exit_code":0}))?,
        0o600,
    )
}

fn task_intent(store: &Store, operation_id: &str, kind: &str) -> Result<TaskIntent> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && hex(operation_id, 32)
            && ["backup", "prepare", "reconcile"].contains(&kind),
        "invalid protected task execution scope"
    );
    let journal = store.root.join("journal").join(operation_id);
    let intent: TaskIntent = serde_json::from_value(bounded_value(
        &store::read_protected(&journal.join(format!("{kind}-task.json")), 16384)?,
        16384,
    )?)?;
    ensure!(
        intent.kind == "komizo.task"
            && intent.version == 1
            && intent.operation_id == operation_id
            && intent.task == kind
            && name(&intent.application)
            && name(&intent.instance)
            && intent.unit == format!("komizo-{kind}-{operation_id}.service")
            && absolute(&intent.program)
            && digest(&intent.program_sha256)
            && digest(&intent.request_sha256)
            && digest(&intent.unit_sha256)
            && hex(&intent.request_operation_id, 32),
        "protected task intent is invalid"
    );
    Ok(intent)
}

/// This independent process owns the same absolute deadline when its caller
/// or task runner dies. Its anonymous socket is fixed to descriptor three.
pub fn task_watch(operation_id: &str, kind: &str) -> Result<()> {
    use std::os::fd::FromRawFd;
    let store = Store::new(Path::new(observation::STATE).into())?;
    let intent = task_intent(&store, operation_id, kind)?;
    let operation = store.operation(operation_id)?;
    ensure!(
        operation.application == intent.application
            && operation.instance == intent.instance
            && operation.phase == "jobs"
            && !operation.ok
            && !operation.reconciliation_required,
        "task watchdog no longer belongs to its admitted operation"
    );
    system::verify_unit(
        &store,
        &units::config_path(&intent.unit)?,
        &intent.application,
        &intent.instance,
        &intent.unit_sha256,
    )?;
    let group = super::cgroups::task_group(kind, operation_id)?;
    let mut socket: libc::stat = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstat(3, &mut socket) } == 0
            && socket.st_mode & libc::S_IFMT == libc::S_IFSOCK,
        "task watchdog owner channel is unavailable"
    );
    let channel = unsafe { std::os::unix::net::UnixStream::from_raw_fd(3) };
    task_watchdog::serve(
        &group.path(),
        &intent.boot_id,
        intent.deadline_monotonic_ns,
        channel,
    )
}

/// No caller-selected executable, environment or path crosses this boundary;
/// all are frozen in the protected effect intent.
pub fn task_run(operation_id: &str, kind: &str) -> Result<()> {
    let store = Store::new(Path::new(observation::STATE).into())?;
    let journal = store.root.join("journal").join(operation_id);
    let intent = task_intent(&store, operation_id, kind)?;
    let lifetime =
        task_lifetime::Lifetime::arm(&intent.unit, &intent.boot_id, intent.deadline_monotonic_ns)?;
    ensure!(
        intent
            .environment
            .get("KOMIZO_TASK_OPERATION_ID")
            .map(String::as_str)
            == Some(operation_id),
        "protected task environment changed its supervising operation"
    );
    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
    lifetime.verify_limits(&capacity.control.limits)?;
    let operation = store.operation(operation_id)?;
    ensure!(
        operation.application == intent.application
            && operation.instance == intent.instance
            && operation.phase == "jobs"
            && !operation.ok
            && !operation.reconciliation_required,
        "protected task no longer belongs to its admitted effect phase"
    );
    system::verify_unit(
        &store,
        &units::config_path(&intent.unit)?,
        &intent.application,
        &intent.instance,
        &intent.unit_sha256,
    )?;
    ensure!(
        document_digest(&store::read_protected(
            Path::new(&intent.program),
            32 << 20
        )?) == intent.program_sha256,
        "protected task executable changed before execution"
    );
    let request = store::read_protected(
        &journal.join(format!("{kind}-request.json")),
        MAX_DOCUMENT_BYTES,
    )?;
    let scope = bounded_value(&request, MAX_DOCUMENT_BYTES)?;
    ensure!(
        document_digest(&request) == intent.request_sha256
            && scope["application"] == intent.application
            && scope["instance"] == intent.instance
            && scope["operation_id"] == intent.request_operation_id,
        "protected task input escaped its frozen operation scope"
    );
    for key in intent.environment.keys() {
        ensure!(
            key.starts_with("KOMIZO_") || ["PATH", "HOME", "LANG"].contains(&key.as_str()),
            "protected task environment is not admitted"
        );
    }
    // O_EXCL prevents even an early repeated service start from replaying an
    // uncertain program. Recovery uses a separately admitted task and intent.
    use std::os::unix::fs::OpenOptionsExt;
    let mut started = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(journal.join(format!("{kind}-started.json")))?;
    use std::io::Write;
    started.write_all(&canonical(&json!({"unit_sha256":intent.unit_sha256,"deadline_monotonic_ns":intent.deadline_monotonic_ns}))?)?;
    started.sync_all()?;
    use std::io::{Seek, SeekFrom};
    let mut input = tempfile::tempfile()?;
    input.write_all(&request)?;
    input.seek(SeekFrom::Start(0))?;
    let status = std::process::Command::new(&intent.program)
        .env_clear()
        .envs(&intent.environment)
        .stdin(std::process::Stdio::from(input))
        .status()?;
    ensure!(
        status.success(),
        "protected task program did not complete successfully"
    );
    lifetime.finish()
}

fn task_quiescent(kind: &str, operation_id: &str) -> Result<()> {
    let group = super::cgroups::task_group(kind, operation_id)?;
    ensure!(
        super::cgroups::empty(&group)?,
        "protected task still has live descendants"
    );
    Ok(())
}

fn reconcile_tasks(store: &Store, operation: &Operation, system: &System) -> Result<()> {
    let journal = store.root.join("journal").join(&operation.operation_id);
    for kind in ["backup", "prepare", "reconcile"] {
        let path = journal.join(format!("{kind}-task.json"));
        if !path.try_exists()? {
            continue;
        }
        let intent: TaskIntent =
            serde_json::from_value(bounded_value(&store::read_protected(&path, 16384)?, 16384)?)?;
        ensure!(
            intent.kind == "komizo.task"
                && intent.version == 1
                && intent.application == operation.application
                && intent.instance == operation.instance
                && intent.operation_id == operation.operation_id
                && intent.task == kind
                && intent.unit == format!("komizo-{kind}-{}.service", operation.operation_id)
                && digest(&intent.unit_sha256)
                && digest(&intent.program_sha256)
                && absolute(&intent.program)
                && digest(&intent.request_sha256)
                && hex(&intent.request_operation_id, 32),
            "protected task intent differs from the interrupted operation"
        );
        let request = store::read_protected(
            &journal.join(format!("{kind}-request.json")),
            MAX_DOCUMENT_BYTES,
        )?;
        ensure!(
            document_digest(&request) == intent.request_sha256,
            "protected task input identity changed"
        );
        let scope = bounded_value(&request, MAX_DOCUMENT_BYTES)?;
        ensure!(
            scope["application"] == operation.application
                && scope["instance"] == operation.instance
                && scope["operation_id"] == intent.request_operation_id,
            "protected task input escaped the interrupted scope"
        );
        if kind == "reconcile" {
            let admission = bounded_value(
                &store::read_protected(&journal.join("admission.json"), MAX_DOCUMENT_BYTES)?,
                MAX_DOCUMENT_BYTES,
            )?;
            ensure!(
                admission["action"] == "recover"
                    && admission["target_operation"] == intent.request_operation_id,
                "cleanup task does not select its admitted interrupted operation"
            );
        } else {
            ensure!(
                intent.request_operation_id == operation.operation_id,
                "protected task changed its operation identity"
            );
        }
        let path = units::config_path(&intent.unit)?;
        let group = super::cgroups::task_group(kind, &operation.operation_id)?;
        if path.try_exists()? {
            system::verify_unit(
                store,
                &path,
                &operation.application,
                &operation.instance,
                &intent.unit_sha256,
            )?;
            system.kill_group(&group)?;
        } else {
            ensure!(
                system.group_empty(&group)?,
                "missing task configuration still owns live descendants and requires explicit repair"
            );
        }
        task_quiescent(kind, &operation.operation_id)?;
        system.remove_group(&group)?;
        store::atomic(
            &journal.join(format!("{kind}-reconciled.json")),
            &canonical(
                &json!({"unit_sha256":intent.unit_sha256,"request_sha256":intent.request_sha256,"inactive":true}),
            )?,
            0o600,
        )?;
    }
    Ok(())
}

fn cleanup_captures(
    store: &Store,
    interrupted: &Operation,
    job: &Job,
    operation: &mut Operation,
) -> Result<()> {
    let journal = store.root.join("journal").join(&interrupted.operation_id);
    if !journal.join("capture-helpers").try_exists()?
        && !store
            .root
            .join("exports")
            .join(&interrupted.operation_id)
            .join(".capture-staging.json")
            .try_exists()?
    {
        return Ok(());
    }
    let original: Policy = serde_json::from_value(bounded_value(
        &store::read_protected(&journal.join("policy.json"), MAX_DOCUMENT_BYTES)?,
        MAX_DOCUMENT_BYTES,
    )?)?;
    ensure!(
        original.application == interrupted.application,
        "capture recovery policy belongs to another application"
    );
    let task = original
        .backup
        .as_ref()
        .ok_or_else(|| anyhow!("interrupted capture has no original protected cleanup bundle"))?;
    let deadline = job.deadline.min(Instant::now() + Duration::from_secs(300));
    let unix =
        controller::now()? + deadline.saturating_duration_since(Instant::now()).as_secs() as i64;
    let input = canonical(
        &json!({"kind":"komizo.capture-reconcile","version":1,"application":interrupted.application,"instance":interrupted.instance,"operation_id":interrupted.operation_id,"deadline_unix":unix}),
    )?;
    let environment = BTreeMap::from([
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("HOME".into(), "/root".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("KOMIZO_APPLICATION".into(), interrupted.application.clone()),
        ("KOMIZO_INSTANCE".into(), interrupted.instance.clone()),
        (
            "KOMIZO_OPERATION_ID".into(),
            interrupted.operation_id.clone(),
        ),
        ("KOMIZO_DEADLINE_UNIX".into(), unix.to_string()),
    ]);
    advance(store, operation, "staging")?;
    advance(store, operation, "jobs")?;
    run_task(
        store,
        &operation.operation_id,
        "reconcile",
        task,
        &input,
        &environment,
        deadline,
    )?;
    let receipt = bounded_value(
        &store::read_protected(
            &store
                .root
                .join("journal")
                .join(&operation.operation_id)
                .join("reconcile-output.json"),
            16384,
        )?,
        16384,
    )?;
    let fields = [
        "kind",
        "version",
        "application",
        "instance",
        "operation_id",
        "helpers",
        "helpers_absent",
        "orphan_plaintext_removed",
    ];
    ensure!(
        receipt
            .as_object()
            .is_some_and(|value| value.len() == fields.len()
                && fields.iter().all(|field| value.contains_key(*field)))
            && receipt["kind"] == "komizo.capture-reconciled"
            && receipt["version"] == 1
            && receipt["application"] == interrupted.application
            && receipt["instance"] == interrupted.instance
            && receipt["operation_id"] == interrupted.operation_id
            && receipt["helpers_absent"] == true
            && receipt["helpers"].as_u64().is_some_and(|count| count <= 64)
            && receipt["orphan_plaintext_removed"].is_boolean(),
        "protected capture cleanup did not confirm exact owned absence"
    );
    store::atomic(
        &journal.join("capture-reconciled.json"),
        &canonical(&receipt)?,
        0o600,
    )
}

fn validate_service_intent(
    store: &Store,
    intent: &ServiceIntent,
    operation: &Operation,
    installed: &Installed,
    document: &ReleaseDocument,
) -> Result<()> {
    ensure!(
        intent.version == 1
            && ["komizo.service-creation", "komizo.service-removal"]
                .contains(&intent.kind.as_str())
            && intent.application == installed.application
            && intent.instance == installed.instance
            && intent.operation_id == operation.operation_id
            && intent.release_digest == document.digest
            && document.release.application == installed.application
            && name(&intent.service)
            && intent.record.name
                == format!(
                    "{}-{}",
                    units::namespace(&installed.application, &installed.instance)?,
                    intent.service
                )
            && intent.record.release_digest == document.digest
            && hex(&intent.record.ownership, 32)
            && (intent.record.id.is_empty() || hex(&intent.record.id, 64))
            && digest(&intent.record.unit_sha256),
        "service intent differs from its admitted source and instance"
    );
    let service = document
        .release
        .workload
        .services
        .get(&intent.service)
        .ok_or_else(|| anyhow!("service intent selects an undeclared service"))?;
    let Artifact::Image {
        reference,
        config_digest,
        ..
    } = &document.release.artifacts[&service.artifact]
    else {
        return Err(anyhow!("service intent has no image authority"));
    };
    let volumes = service
        .volumes
        .iter()
        .map(|mount| {
            let expected = units::object_name(
                &installed.application,
                &installed.instance,
                "volume",
                &mount.name,
            )?;
            if let Some(record) = installed.resources.volumes.get(&mount.name) {
                ensure!(
                    record.name == expected,
                    "service intent retained volume changed physical scope"
                );
            }
            Ok((mount.name.clone(), expected))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        intent.record.image == *reference
            && intent.record.config_digest == *config_digest
            && intent.record.volumes == volumes,
        "service creation token does not bind its complete image and volume closure"
    );
    if intent.kind == "komizo.service-creation" {
        let body = intent
            .unit_body
            .as_ref()
            .ok_or_else(|| anyhow!("service creation config missing"))?;
        ensure!(
            intent.record.id.is_empty()
                && body.len() <= 1 << 20
                && document_digest(body.as_bytes()) == intent.record.unit_sha256,
            "service configuration intent bytes are incomplete or changed"
        );
        let actual = units::ServiceConfig::parse(body.as_bytes())?;
        let expected = service_configuration(
            store,
            installed,
            document,
            &intent.service,
            &intent.record.ownership,
            true,
        )?;
        ensure!(
            actual.bytes()? == expected.bytes()?,
            "service creation escaped its complete admitted configuration"
        );
    } else {
        ensure!(
            intent.unit_body.is_none(),
            "service removal cannot add service configuration"
        );
    }
    Ok(())
}
fn reconcile_services(
    store: &Store,
    interrupted: &Operation,
    installed: &mut Installed,
    engine: &Engine,
    system: &System,
) -> Result<()> {
    let journal = store.root.join("journal").join(&interrupted.operation_id);
    // Complete only accepted metadata and removals. Never start containers,
    // run migrations, or infer an outcome for an interrupted service start.
    for kind in ["removal", "creation"] {
        let mut count = 0;
        for entry in fs::read_dir(&journal)? {
            count += 1;
            ensure!(count <= 16384, "service recovery journal exceeds bound");
            let entry = entry?;
            let filename = entry.file_name();
            let Some(filename) = filename.to_str() else {
                continue;
            };
            if !filename.starts_with(&format!("service-{kind}-")) {
                continue;
            }
            let intent: ServiceIntent = serde_json::from_value(bounded_value(
                &store::read_protected(&entry.path(), 2 << 20)?,
                2 << 20,
            )?)?;
            ensure!(
                entry.path()
                    == service_intent_path(
                        store,
                        &interrupted.operation_id,
                        kind,
                        &intent.service
                    )?,
                "service intent path changed"
            );
            let document = store.release(&intent.release_digest)?;
            validate_service_intent(store, &intent, interrupted, installed, &document)?;
            let path = units::config_path(&intent.record.name)?;
            if kind == "removal" {
                let Some(record) = installed.resources.containers.get(&intent.service).cloned()
                else {
                    continue;
                };
                if record.ownership != intent.record.ownership {
                    ensure!(
                        installed.operation_id == interrupted.operation_id
                            && installed.release_digest == interrupted.release_digest
                            && record.release_digest == installed.release_digest,
                        "service removal encountered an unaccepted replacement"
                    );
                    continue;
                }
                ensure!(
                    record.name == intent.record.name
                        && record.config_digest == intent.record.config_digest
                        && record.volumes == intent.record.volumes,
                    "service removal binding changed"
                );
                let mut candidate = record.clone();
                if path.try_exists()? {
                    candidate.unit_sha256 = system::reconciled_unit_hash(
                        store,
                        &path,
                        &installed.application,
                        &installed.instance,
                        &interrupted.operation_id,
                        &candidate.unit_sha256,
                    )?;
                }
                if candidate.id.is_empty() && engine.exists("container", &candidate.name)? {
                    candidate.id = engine.inspect("container", &candidate.name)?["Id"]
                        .as_str()
                        .filter(|id| hex(id, 64))
                        .ok_or_else(|| anyhow!("owned service ID unavailable"))?
                        .into();
                    let value = engine
                        .container_metadata(
                            &candidate,
                            &installed.application,
                            &installed.instance,
                            &intent.service,
                        )?
                        .ok_or_else(|| anyhow!("recorded service disappeared during recovery"))?;
                    super::engine::service_mounts(
                        &value,
                        &candidate,
                        &document.release.workload.services[&intent.service],
                    )?;
                    installed
                        .resources
                        .containers
                        .insert(intent.service.clone(), candidate.clone());
                    store.save_installed(installed)?;
                }
                stop_owned_service(
                    installed,
                    &document,
                    &intent.service,
                    &candidate,
                    engine,
                    system,
                )?;
                if engine.exists("container", &candidate.name)? {
                    engine.run(&["rm", "--", &candidate.id])?;
                }
                if path.try_exists()? {
                    system::remove_for_operation(
                        store,
                        &path,
                        &installed.application,
                        &installed.instance,
                        &interrupted.operation_id,
                    )?;
                }
                installed.resources.containers.remove(&intent.service);
                store.save_installed(installed)?;
            } else {
                ensure!(
                    installed.operation_id == interrupted.operation_id
                        && installed.release_digest == intent.release_digest,
                    "service creation no longer selects the interrupted installed source"
                );
                if let Some(record) = installed.resources.containers.get(&intent.service) {
                    ensure!(
                        record.ownership == intent.record.ownership
                            && record.name == intent.record.name
                            && record.config_digest == intent.record.config_digest
                            && record.volumes == intent.record.volumes,
                        "service creation encountered a foreign protected record"
                    );
                } else {
                    installed
                        .resources
                        .containers
                        .insert(intent.service.clone(), intent.record.clone());
                    store.save_installed(installed)?;
                }
                if !path.try_exists()? {
                    system::install_for_operation(
                        store,
                        &path,
                        &installed.application,
                        &installed.instance,
                        intent.unit_body.as_ref().unwrap().as_bytes(),
                        &interrupted.operation_id,
                    )?;
                } else {
                    system::verify_unit(
                        store,
                        &path,
                        &installed.application,
                        &installed.instance,
                        &intent.record.unit_sha256,
                    )?;
                }
                verified_service_configuration(store, installed, &document, &intent.service)?;
            }
        }
    }
    Ok(())
}

fn reconcile_container_ids(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    engine: &Engine,
    operation_id: &str,
) -> Result<()> {
    let namespace = units::namespace(&installed.application, &installed.instance)?;
    let names = installed
        .resources
        .containers
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        let mut record = installed.resources.containers[&name].clone();
        ensure!(
            document.release.workload.services.contains_key(&name)
                && record.name == format!("{namespace}-{name}"),
            "container recovery escaped its installed service"
        );
        let path = units::config_path(&record.name)?;
        record.unit_sha256 = system::reconciled_unit_hash(
            store,
            &path,
            &installed.application,
            &installed.instance,
            operation_id,
            &record.unit_sha256,
        )?;
        installed
            .resources
            .containers
            .insert(name.clone(), record.clone());
        verified_service_configuration(store, installed, document, &name)?;
        if record.id.is_empty() && engine.exists("container", &record.name)? {
            record.id = engine.inspect("container", &record.name)?["Id"]
                .as_str()
                .filter(|id| hex(id, 64))
                .ok_or_else(|| anyhow!("created service has no native ID"))?
                .into();
        }
        if let Some(value) = engine.container_metadata(
            &record,
            &installed.application,
            &installed.instance,
            &name,
        )? {
            super::engine::service_mounts(
                &value,
                &record,
                &document.release.workload.services[&name],
            )?;
        }
        installed.resources.containers.insert(name, record);
    }
    store.save_installed(installed)
}

/// Ordinary releases cannot silently rename a database mount or bind an empty
/// replacement volume. Data topology changes require an explicit owner transfer.
pub fn retained_topology(previous: &ReleaseDocument, next: &ReleaseDocument) -> Result<()> {
    if let Some(old) = &previous.release.stateful_contract {
        let new = next
            .release
            .stateful_contract
            .as_ref()
            .ok_or_else(|| anyhow!("retained data cannot discard its stateful authority"))?;
        ensure!(
            new.schema.write >= old.schema.write,
            "ordinary deployment cannot downgrade the retained schema; owner data recovery is required"
        );
    }
    let topology = |document: &ReleaseDocument| -> Result<Vec<u8>> {
        let mounts = document
            .release
            .workload
            .services
            .iter()
            .chain(document.release.workload.jobs.iter())
            .map(|(name, c)| {
                let values = c
                    .volumes
                    .iter()
                    .map(|m| (&m.target, &m.name))
                    .collect::<BTreeMap<_, _>>();
                (name, values)
            })
            .filter(|(_, m)| !m.is_empty())
            .collect::<BTreeMap<_, _>>();
        canonical(&json!({"volumes":document.release.workload.volumes,"mounts":mounts}))
    };
    ensure!(
        topology(previous)? == topology(next)?,
        "retained data topology changed; owner transfer is required"
    );
    Ok(())
}

fn stage(store: &Store, policy: &Policy, document: &ReleaseDocument, job: &Job) -> Result<()> {
    let engine = Engine {
        deadline: job.deadline,
    };
    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
    let root = store.root.join("staging").join(&job.operation_id);
    store::protected_directory(&root)?;
    let public = proxy::asset_root(document);
    if !document.release.workload.assets.is_empty() {
        store::protected_directory(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
    }
    for (key, artifact) in &document.release.artifacts {
        ensure!(Instant::now() < job.deadline, "staging deadline exceeded");
        if let Artifact::Image {
            config_digest,
            platform,
            ..
        } = artifact
        {
            ensure!(
                *platform == engine.platform()?,
                "image targets a different native platform"
            );
            if engine.exists("image", config_digest)? {
                engine.image(config_digest, config_digest)?;
                continue;
            }
        }
        if matches!(artifact, Artifact::Archive { .. }) {
            let targets = document
                .release
                .workload
                .assets
                .iter()
                .filter(|(_, asset)| asset.artifact == *key)
                .map(|(name, _)| public.join(name))
                .collect::<Vec<_>>();
            if targets.iter().any(|p| p.exists()) {
                proxy::verify_assets(store, document)?;
                ensure!(
                    targets.iter().all(|p| p.is_dir()),
                    "immutable asset cache is incomplete"
                );
                continue;
            }
        }
        let staging_bytes = match artifact {
            Artifact::Image { .. } => policy.max_image_bytes.checked_mul(3),
            Artifact::Archive { size_bytes, .. } => size_bytes.checked_add(policy.max_asset_bytes),
        }
        .ok_or_else(|| anyhow!("staging bound overflow"))?;
        capacity::disk(&store.root, capacity.disk_reserve_bytes, staging_bytes)?;
        let (mut registry, manifest) = Registry::new(
            artifact.reference(),
            job.request.registry.as_ref(),
            job.deadline.saturating_duration_since(Instant::now()),
        )?;
        let file = root.join(format!("{key}.oci"));
        match artifact {
            Artifact::Image { config_digest, .. } => {
                registry.image_archive(&manifest, artifact, &file, policy)?;
                engine.import(&file, config_digest)?;
            }
            Artifact::Archive {
                digest, size_bytes, ..
            } => {
                registry.static_archive(&manifest, artifact, &file, policy)?;
                super::assets::verify_file(&file, digest, *size_bytes)?;
                for (name, asset) in &document.release.workload.assets {
                    if asset.artifact == *key {
                        let target = public.join(name);
                        if !target.try_exists()? {
                            super::assets::extract(&file, &target, policy)?;
                        }
                    }
                }
            }
        }
        fs::remove_file(file)?;
    }
    proxy::seal_assets(store, document)
}

fn preview_capacity(store: &Store, policy: &Policy, instance: &str) -> Result<()> {
    if instance == "production" {
        return Ok(());
    }
    let preview = policy
        .previews
        .as_ref()
        .ok_or_else(|| anyhow!("preview authority missing"))?;
    let active = proxy::instances(store)?
        .into_iter()
        .filter(|i| {
            i.application == policy.application
                && i.instance != "production"
                && i.instance != instance
                && (i.desired_running || i.expires_at.is_some())
        })
        .count();
    ensure!(
        active < preview.max_instances as usize,
        "application preview capacity refuses another full instance"
    );
    Ok(())
}

fn prepare_preview(
    store: &Store,
    policy: &Policy,
    job: &Job,
    operation: &mut Operation,
) -> Result<()> {
    preview_capacity(store, policy, &job.request.instance)?;
    if job.request.instance == "production" {
        return Ok(());
    }
    let preview = policy
        .previews
        .as_ref()
        .ok_or_else(|| anyhow!("preview authority missing"))?;
    let Some(task) = &preview.prepare else {
        return Ok(());
    };
    let marker = store.root.join("preview-prepared").join(format!(
        "{}.json",
        Store::instance_key(&policy.application, &job.request.instance)?
    ));
    let expected = canonical(
        &json!({"program":task.sha256,"secrets":preview.secrets.iter().map(|(k,v)|(k,&v.generation)).collect::<BTreeMap<_,_>>()}),
    )?;
    if marker.try_exists()? {
        ensure!(
            store::read_protected(&marker, 16384)? == expected,
            "preview credential preparation changed; owner rotation is required"
        );
        return Ok(());
    }
    let program = store::read_protected(Path::new(&task.program), 32 << 20)?;
    ensure!(
        document_digest(&program) == task.sha256,
        "preview preparation bundle bytes changed"
    );
    let deadline = job
        .deadline
        .min(Instant::now() + Duration::from_secs(u64::from(task.timeout_seconds)));
    let input = canonical(
        &json!({"kind":"komizo.preview-request","version":1,"application":policy.application,"instance":job.request.instance,"operation_id":job.operation_id,"app_origin":format!("https://{}.{}",job.request.instance,preview.hostname_suffix),"secrets":preview.secrets,"deadline_unix":controller::now()?+deadline.saturating_duration_since(Instant::now()).as_secs() as i64}),
    )?;
    advance(store, operation, "jobs")?;
    run_task(
        store,
        &job.operation_id,
        "prepare",
        task,
        &input,
        &BTreeMap::from([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), "/root".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ]),
        deadline,
    )?;
    store::atomic(&marker, &expected, 0o600)
}

fn retained(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    engine: &Engine,
) -> Result<()> {
    for (name, network) in &document.release.workload.networks {
        if let Some(record) = installed.resources.networks.get(name) {
            let value = engine.owned_object("network", record)?;
            ensure!(
                value["driver"] == "bridge"
                    && value["internal"] == network.internal
                    && ["1", "true"]
                        .iter()
                        .any(|expected| value["options"]["isolate"] == *expected),
                "retained network topology changed; owner transfer is required"
            );
        } else {
            let record = create_object(
                store,
                installed,
                document,
                engine,
                "network",
                name,
                Some(network.internal),
            )?;
            installed.resources.networks.insert(name.clone(), record);
            store.save_installed(installed)?;
        }
    }
    for name in document.release.workload.volumes.keys() {
        if let Some(record) = installed.resources.volumes.get(name) {
            engine.owned_object("volume", record)?;
        } else {
            let record = create_object(store, installed, document, engine, "volume", name, None)?;
            installed.resources.volumes.insert(name.clone(), record);
            store.save_installed(installed)?;
        }
    }
    Ok(())
}

fn cleanup_service(
    before: Option<&serde_json::Value>,
    group: &super::cgroups::Group,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let native = if let Some(before) = before {
        Engine { deadline }.kill_owned(before)
    } else {
        Ok(())
    };
    // Always attempt the exact kernel kill even if native cleanup failed.
    let kernel = super::cgroups::kill(group, deadline)
        .and_then(|()| super::cgroups::remove(group, deadline));
    native?;
    kernel
}

fn stop_owned_service(
    installed: &Installed,
    document: &ReleaseDocument,
    name: &str,
    record: &store::ContainerRecord,
    engine: &Engine,
    _system: &System,
) -> Result<()> {
    let group = super::cgroups::workload_group(
        &installed.application,
        &installed.instance,
        super::cgroups::WorkloadKind::Service,
        name,
        &record.ownership,
    )?;
    if let Some(before) =
        engine.container_metadata(record, &installed.application, &installed.instance, name)?
    {
        super::engine::service_mounts(&before, record, &document.release.workload.services[name])?;
        if before["State"]["Running"] == true || before["State"]["Paused"] == true {
            let stopped = (|| -> Result<()> {
                super::engine::workload_group(&before, &group)?;
                let timeout = document.release.workload.services[name]
                    .stop_timeout_seconds
                    .to_string();
                engine.run(&["stop", "--time", &timeout, "--", &record.id])?;
                let after = engine
                    .container_metadata(record, &installed.application, &installed.instance, name)?
                    .ok_or_else(|| anyhow!("owned service disappeared during stop"))?;
                ensure!(
                    after["State"]["Running"] == false
                        && after["State"]["Paused"] == false
                        && after["State"]["Pid"] == 0,
                    "owned service remained live after stop"
                );
                Ok(())
            })();
            if let Err(error) = stopped {
                let cleanup = cleanup_service(Some(&before), &group);
                if cleanup.is_err() {
                    return Err(
                        error.context("owned service stop failed and termination remains unproven")
                    );
                }
                return Err(error);
            }
        } else {
            ensure!(
                before["State"]["Paused"] == false && before["State"]["Pid"] == 0,
                "non-running service retains unexplained execution state"
            );
        }
    }
    cleanup_service(None, &group)
}

fn stop_services(
    store: &Store,
    installed: &mut Installed,
    engine: &Engine,
    system: &System,
    remove: bool,
    operation_id: &str,
) -> Result<()> {
    installed.desired_running = false;
    store.save_installed(installed)?;
    proxy::refresh(store, system.deadline)?;
    let document = store.release(&installed.release_digest)?;
    let mut ordered = order(&document)?;
    ordered.reverse();
    for name in ordered {
        let Some(record) = installed.resources.containers.get(&name).cloned() else {
            continue;
        };
        verified_service_configuration(store, installed, &document, &name)?;
        let path = units::config_path(&record.name)?;
        if remove {
            let intent = ServiceIntent {
                kind: "komizo.service-removal".into(),
                version: 1,
                application: installed.application.clone(),
                instance: installed.instance.clone(),
                operation_id: operation_id.into(),
                release_digest: installed.release_digest.clone(),
                service: name.clone(),
                record: record.clone(),
                unit_body: None,
            };
            store::atomic(
                &service_intent_path(store, operation_id, "removal", &name)?,
                &serde_json::to_vec(&intent)?,
                0o600,
            )?;
        }
        stop_owned_service(installed, &document, &name, &record, engine, system)?;
        if remove {
            if engine.exists("container", &record.name)? {
                engine.run(&["rm", "--", &record.id])?;
            }
            system::remove_for_operation(
                store,
                &path,
                &installed.application,
                &installed.instance,
                operation_id,
            )?;
            installed.resources.containers.remove(&name);
            store.save_installed(installed)?;
        }
    }
    if !remove {
        wanted(store, installed, false, system, operation_id)?;
    }
    Ok(())
}

fn wanted(
    store: &Store,
    installed: &mut Installed,
    value: bool,
    _system: &System,
    operation_id: &str,
) -> Result<()> {
    let document = store.release(&installed.release_digest)?;
    let names = installed
        .resources
        .containers
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for name in names {
        let mut config = verified_service_configuration(store, installed, &document, &name)?;
        config.wanted = value;
        let bytes = config.bytes()?;
        let record = installed.resources.containers.get_mut(&name).unwrap();
        record.unit_sha256 = system::install_for_operation(
            store,
            &units::config_path(&record.name)?,
            &installed.application,
            &installed.instance,
            &bytes,
            operation_id,
        )?;
    }
    store.save_installed(installed)?;
    Ok(())
}

pub fn order(document: &ReleaseDocument) -> Result<Vec<String>> {
    fn visit(
        name: &str,
        all: &BTreeMap<&str, &Container>,
        seen: &mut BTreeSet<String>,
        active: &mut BTreeSet<String>,
        result: &mut Vec<String>,
    ) -> Result<()> {
        if seen.contains(name) {
            return Ok(());
        }
        ensure!(active.insert(name.to_owned()), "workload dependency cycle");
        for dependency in all
            .get(name)
            .ok_or_else(|| anyhow!("missing workload dependency"))?
            .needs
            .keys()
        {
            visit(dependency, all, seen, active, result)?;
        }
        active.remove(name);
        seen.insert(name.into());
        result.push(name.into());
        Ok(())
    }
    let all = document
        .release
        .workload
        .services
        .iter()
        .chain(document.release.workload.jobs.iter())
        .map(|(n, c)| (n.as_str(), c))
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut active = BTreeSet::new();
    for name in all.keys() {
        visit(name, &all, &mut seen, &mut active, &mut result)?;
    }
    Ok(result)
}

fn service_configuration(
    store: &Store,
    installed: &Installed,
    document: &ReleaseDocument,
    name: &str,
    ownership: &str,
    wanted: bool,
) -> Result<units::ServiceConfig> {
    let container = document
        .release
        .workload
        .services
        .get(name)
        .ok_or_else(|| anyhow!("service configuration selects an undeclared service"))?;
    let env = container
        .environment_files
        .iter()
        .map(|alias| {
            let snapshot = installed
                .secret_snapshots
                .get(alias)
                .ok_or_else(|| anyhow!("service environment snapshot missing"))?;
            let body = store::read_protected(Path::new(&snapshot.path), 128 << 10)?;
            ensure!(
                document_digest(&body) == snapshot.sha256,
                "service environment snapshot changed"
            );
            secrets::environment_file(&body)?;
            Ok((alias.clone(), snapshot.path.clone()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mounts = container
        .secrets
        .iter()
        .map(|secret| {
            let snapshot = installed
                .secret_snapshots
                .get(&secret.source)
                .ok_or_else(|| anyhow!("service secret snapshot is missing"))?;
            Ok((
                secret.source.clone(),
                secrets::mount_snapshot(&store.root, name, secret, snapshot)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    units::service_config(
        document,
        name,
        &units::Bindings {
            application: &installed.application,
            instance: &installed.instance,
            release_digest: &document.digest,
            ownership,
            networks: &installed.resources.networks,
            volumes: &installed.resources.volumes,
            environment_files: &env,
            secrets: &mounts,
            ingress: None,
        },
        wanted,
    )
}

fn verified_service_configuration(
    store: &Store,
    installed: &Installed,
    document: &ReleaseDocument,
    name: &str,
) -> Result<units::ServiceConfig> {
    let record = installed
        .resources
        .containers
        .get(name)
        .ok_or_else(|| anyhow!("protected service record missing"))?;
    let path = units::config_path(&record.name)?;
    system::verify_unit(
        store,
        &path,
        &installed.application,
        &installed.instance,
        &record.unit_sha256,
    )?;
    let bytes = store::read_protected(&path, 1 << 20)?;
    let actual = units::ServiceConfig::parse(&bytes)?;
    let expected = service_configuration(
        store,
        installed,
        document,
        name,
        &record.ownership,
        actual.wanted,
    )?;
    let declared = &document.release.workload.services[name];
    let Artifact::Image {
        reference,
        config_digest,
        ..
    } = &document.release.artifacts[&declared.artifact]
    else {
        return Err(anyhow!(
            "service configuration lacks immutable image authority"
        ));
    };
    let volumes = declared
        .volumes
        .iter()
        .map(|mount| {
            let binding = installed
                .resources
                .volumes
                .get(&mount.name)
                .ok_or_else(|| anyhow!("service volume authority missing"))?;
            Ok((mount.name.clone(), binding.name.clone()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        actual.bytes()? == expected.bytes()?
            && record.name == expected.container_name
            && record.release_digest == document.digest
            && record.image == *reference
            && record.config_digest == *config_digest
            && record.volumes == volumes,
        "service configuration escaped its admitted release and bindings"
    );
    Ok(actual)
}

fn install_units(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    _system: &System,
) -> Result<()> {
    for (name, container) in &document.release.workload.services {
        let ownership = store::identity()?;
        let config = service_configuration(store, installed, document, name, &ownership, true)?;
        let body = String::from_utf8(config.bytes()?)?;
        let Artifact::Image {
            reference,
            config_digest,
            ..
        } = &document.release.artifacts[&container.artifact]
        else {
            return Err(anyhow!("service image missing"));
        };
        let record = store::ContainerRecord {
            name: config.container_name.clone(),
            id: String::new(),
            image: reference.clone(),
            config_digest: config_digest.clone(),
            release_digest: document.digest.clone(),
            ownership,
            unit_sha256: document_digest(body.as_bytes()),
            volumes: container
                .volumes
                .iter()
                .map(|mount| {
                    (
                        mount.name.clone(),
                        installed.resources.volumes[&mount.name].name.clone(),
                    )
                })
                .collect(),
        };
        let intent = ServiceIntent {
            kind: "komizo.service-creation".into(),
            version: 1,
            application: installed.application.clone(),
            instance: installed.instance.clone(),
            operation_id: installed.operation_id.clone(),
            release_digest: document.digest.clone(),
            service: name.clone(),
            record: record.clone(),
            unit_body: Some(body.clone()),
        };
        store::atomic(
            &service_intent_path(store, &installed.operation_id, "creation", name)?,
            &serde_json::to_vec(&intent)?,
            0o600,
        )?;
        installed.resources.containers.insert(name.clone(), record);
        store.save_installed(installed)?;
        system::install_for_operation(
            store,
            &units::config_path(&config.container_name)?,
            &installed.application,
            &installed.instance,
            body.as_bytes(),
            &installed.operation_id,
        )?;
    }
    Ok(())
}

fn service_group(
    installed: &Installed,
    name: &str,
    ownership: &str,
) -> Result<super::cgroups::Group> {
    super::cgroups::workload_group(
        &installed.application,
        &installed.instance,
        super::cgroups::WorkloadKind::Service,
        name,
        ownership,
    )
}

fn health_interval(health: &Health, started: &str, now: i64) -> Result<u32> {
    let started = chrono::DateTime::parse_from_rfc3339(started)?.timestamp();
    ensure!(started > 0, "service health start time missing");
    Ok(
        if now.saturating_sub(started) < i64::from(health.start_period_seconds) {
            health
                .start_interval_seconds
                .unwrap_or(health.interval_seconds)
        } else {
            health.interval_seconds
        },
    )
}

fn probe_due(
    previous: Option<&serde_json::Value>,
    id: &str,
    now: i64,
    interval: u32,
) -> Result<bool> {
    let Some(previous) = previous else {
        return Ok(true);
    };
    ensure!(
        previous["kind"] == "komizo.probe"
            && previous["version"] == 1
            && previous["container_id"]
                .as_str()
                .is_some_and(|id| hex(id, 64))
            && previous["checked_at"].as_i64().is_some_and(|time| time > 0),
        "service probe metadata is invalid"
    );
    Ok(!(previous["container_id"] == id
        && previous["checked_at"]
            .as_i64()
            .is_some_and(|checked| now >= checked && now - checked < i64::from(interval))))
}

fn service_probe(
    store: &Store,
    policy: &Policy,
    installed: &Installed,
    name: &str,
    record: &store::ContainerRecord,
    value: &serde_json::Value,
    health: &Health,
    engine: &Engine,
) -> Result<()> {
    let (application, instance) = probe_lock_scope(installed, name)?;
    // A background probe never owns the application mutation lease. It drops
    // this separate probe lease when admission wins, so the lock order cannot
    // deadlock and readiness need not fail merely because a probe was running.
    let _guard = loop {
        if let Some(guard) = store.try_lock(&application, &instance)? {
            break guard;
        }
        ensure!(
            Instant::now() < engine.deadline,
            "service probe lease exceeded original readiness deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let now = controller::now()?;
    let interval = health_interval(
        health,
        value["State"]["StartedAt"]
            .as_str()
            .ok_or_else(|| anyhow!("service health start identity missing"))?,
        now,
    )?;
    let previous = probe_record(store, installed, name)?;
    if !probe_due(previous.as_ref(), &record.id, now, interval)? {
        return Ok(());
    }
    let group = super::cgroups::service_probe_group(
        &installed.application,
        &installed.instance,
        name,
        &record.ownership,
    )?;
    super::cgroups::prepare(
        &group,
        instance_limits(policy, &installed.instance)?,
        &Default::default(),
        engine.deadline,
    )?;
    engine.health_in_group(&record.id, &group)?;
    commit_probe(store, installed, name, &record.id, now)
}

fn stopped_service(value: &serde_json::Value) -> Result<()> {
    ensure!(
        value["State"]["Running"] == false
            && value["State"]["Paused"] == false
            && value["State"]["Pid"] == 0
            && ["configured", "created", "exited", "stopped"]
                .contains(&value["State"]["Status"].as_str().unwrap_or("")),
        "service start refuses an unexplained native execution state"
    );
    Ok(())
}

fn unstarted_service(value: &serde_json::Value) -> Result<()> {
    stopped_service(value)?;
    ensure!(
        ["configured", "created"].contains(&value["State"]["Status"].as_str().unwrap_or("")),
        "new service already executed before durable CID registration"
    );
    Ok(())
}

fn start_service(
    store: &Store,
    policy: &Policy,
    installed: &mut Installed,
    document: &ReleaseDocument,
    name: &str,
    engine: &Engine,
    system: &System,
) -> Result<()> {
    let config = verified_service_configuration(store, installed, document, name)?;
    ensure!(
        config.wanted && installed.desired_running,
        "service start is not desired by its protected state"
    );
    let limits = if installed.instance == "production" {
        &policy.limits
    } else {
        &policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview allocation missing"))?
            .limits
    };
    let group = service_group(installed, name, &config.ownership)?;
    system.prepare_group(&group, limits, &Default::default())?;
    let mut record = installed.resources.containers[name].clone();
    if record.id.is_empty() {
        ensure!(
            !engine.exists("container", &record.name)?,
            "unrecorded service requires explicit metadata reconciliation"
        );
        ensure!(
            system.group_empty(&group)?,
            "missing service retains live owned processes"
        );
        let mut arguments = vec![
            "create".to_owned(),
            "--name".into(),
            config.container_name.clone(),
        ];
        arguments.extend(config.options.clone());
        arguments.push(config.image_id.clone());
        arguments.extend(config.command.clone());
        let raw = engine.run(&arguments.iter().map(String::as_str).collect::<Vec<_>>())?;
        let created = std::str::from_utf8(&raw)?.trim();
        ensure!(
            hex(created, 64),
            "native service create did not return its exact container identity"
        );
        record.id = created.into();
        let before = engine
            .container_metadata(&record, &installed.application, &installed.instance, name)?
            .ok_or_else(|| anyhow!("created service disappeared before durable registration"))?;
        unstarted_service(&before)?;
        super::engine::service_mounts(&before, &record, &document.release.workload.services[name])?;
        installed
            .resources
            .containers
            .insert(name.to_owned(), record.clone());
        store.save_installed(installed)?;
    }
    // A missing recorded CID is not authority to replace it or adopt its name.
    let before = engine
        .container_metadata(&record, &installed.application, &installed.instance, name)?
        .ok_or_else(|| {
            anyhow!("recorded service container is missing; owner reconciliation required")
        })?;
    super::engine::service_mounts(&before, &record, &document.release.workload.services[name])?;
    let mut start_attempted = before["State"]["Running"] == true;
    let effect = (|| -> Result<()> {
        if before["State"]["Running"] != true {
            stopped_service(&before)?;
            // Preserve the former pre-start authority, retained data, exact
            // image/snapshot and completed/healthy dependency fences.
            observation::guard(&installed.application, &installed.instance, name)?;
            start_attempted = true;
            engine.run(&["start", &record.id])?;
        }
        loop {
            ensure!(
                Instant::now() < engine.deadline,
                "native service readiness deadline exceeded"
            );
            let value = engine
                .owned_container(&record, &installed.application, &installed.instance, name)?
                .ok_or_else(|| anyhow!("native service disappeared before readiness"))?;
            super::engine::service_mounts(
                &value,
                &record,
                &document.release.workload.services[name],
            )?;
            system.verify_group(&group, limits, &Default::default())?;
            super::engine::workload_limits(
                &value,
                &group,
                &document.release.workload.services[name].limits,
            )?;
            ensure!(
                value["State"]["Running"] == true && value["State"]["Paused"] == false,
                "native service exited before readiness"
            );
            let Some(health) = &config.health else {
                break;
            };
            if value["State"]["Health"]["Status"] == "healthy" {
                break;
            }
            ensure!(
                value["State"]["Health"]["Status"] != "unhealthy",
                "native service healthcheck failed"
            );
            service_probe(
                store, policy, installed, name, &record, &value, health, engine,
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    })();
    if let Err(error) = effect {
        let cleanup = cleanup_service(if start_attempted { Some(&before) } else { None }, &group);
        if cleanup.is_err() {
            return Err(error.context(
                "service activation failed and exact owned termination remains unproven",
            ));
        }
        return Err(error);
    }
    Ok(())
}

fn restart_due(
    previous: Option<&serde_json::Value>,
    record: &store::ContainerRecord,
    now: i64,
) -> Result<bool> {
    let Some(previous) = previous else {
        return Ok(true);
    };
    ensure!(
        previous["kind"] == "komizo.service-backoff"
            && previous["version"] == 1
            && previous["container_id"]
                .as_str()
                .is_some_and(|id| hex(id, 64))
            && previous["unit_sha256"].as_str().is_some_and(digest)
            && previous["attempted_at"]
                .as_i64()
                .is_some_and(|time| time > 0),
        "service restart backoff is invalid"
    );
    Ok(previous["container_id"] != record.id
        || previous["unit_sha256"] != record.unit_sha256
        || previous["attempted_at"]
            .as_i64()
            .is_some_and(|attempt| now >= attempt && now - attempt >= 3))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceEpoch {
    kind: String,
    version: u32,
    application: String,
    instance: String,
    token: String,
}
fn service_epoch_path(store: &Store, installed: &Installed) -> Result<PathBuf> {
    Ok(store.root.join("service-epochs").join(format!(
        "{}.json",
        Store::instance_key(&installed.application, &installed.instance)?
    )))
}
fn service_epoch(store: &Store, installed: &Installed) -> Result<Option<String>> {
    let path = service_epoch_path(store, installed)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let epoch: ServiceEpoch = serde_json::from_value(crate::strict::value(
        &store::read_protected(&path, 4096)?,
        4096,
    )?)?;
    ensure!(
        epoch.kind == "komizo.service-epoch"
            && epoch.version == 1
            && epoch.application == installed.application
            && epoch.instance == installed.instance
            && hex(&epoch.token, 32),
        "service runtime epoch escaped its instance"
    );
    Ok(Some(epoch.token))
}
fn advance_service_epoch(store: &Store, installed: &Installed) -> Result<()> {
    let epoch = ServiceEpoch {
        kind: "komizo.service-epoch".into(),
        version: 1,
        application: installed.application.clone(),
        instance: installed.instance.clone(),
        token: store::identity()?,
    };
    store::atomic(
        &service_epoch_path(store, installed)?,
        &canonical(&serde_json::to_value(epoch)?)?,
        0o600,
    )
}

#[derive(Clone)]
struct ServiceSnapshot {
    installed: Installed,
    document: ReleaseDocument,
    policy: Policy,
    config: units::ServiceConfig,
    record: store::ContainerRecord,
    binding: String,
}

fn instance_limits<'a>(policy: &'a Policy, instance: &str) -> Result<&'a Limits> {
    if instance == "production" {
        Ok(&policy.limits)
    } else {
        Ok(&policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview allocation missing"))?
            .limits)
    }
}

// Caller holds the short, priority-aware maintenance lease. This reads and
// freezes the entire authority closure; it never invokes a native CLI.
fn service_snapshot(
    store: &Store,
    scope: &service_maintenance::Scope,
    prepare: bool,
) -> Result<Option<ServiceSnapshot>> {
    let Some(installed) = store.installed(&scope.application, &scope.instance)? else {
        return Ok(None);
    };
    let operation = store.operation(&installed.operation_id)?;
    if !maintenance_eligible(
        &installed,
        &operation,
        !store
            .unresolved(&scope.application, &scope.instance)?
            .is_empty(),
        controller::now()?,
    ) {
        return Ok(None);
    }
    let document = store.release(&installed.release_digest)?;
    let Some(record) = installed.resources.containers.get(&scope.service).cloned() else {
        return Ok(None);
    };
    ensure!(
        hex(&record.id, 64),
        "automatic restart cannot adopt an unrecorded native identity"
    );
    let (policy, policy_digest) =
        controller::policy(Path::new(observation::POLICIES), &scope.application)?;
    let admission = store::read_protected(
        &store
            .root
            .join("journal")
            .join(&installed.operation_id)
            .join("admission.json"),
        MAX_DOCUMENT_BYTES,
    )?;
    let authority = crate::strict::value(&admission, MAX_DOCUMENT_BYTES)?;
    ensure!(
        authority["kind"] == "komizo.admission"
            && authority["version"] == 1
            && authority["operation_id"] == installed.operation_id
            && authority["policy_digest"] == policy_digest,
        "automatic service maintenance requires its unchanged admitted policy"
    );
    let config = verified_service_configuration(store, &installed, &document, &scope.service)?;
    ensure!(config.wanted, "desired service configuration is disabled");
    let data =
        if installed.instance == "production" && !document.release.workload.volumes.is_empty() {
            Some(document_digest(&store::read_protected(
                &store.root.join("data-admissions").join(format!(
                    "{}.json",
                    Store::instance_key(&scope.application, &scope.instance)?
                )),
                1 << 20,
            )?))
        } else {
            None
        };
    let mut completed = BTreeMap::new();
    for (dependency, condition) in &document.release.workload.services[&scope.service].needs {
        if *condition == Condition::Completed {
            let identity = jobs::identity(&document, dependency, &installed)?;
            let receipt = jobs::read(store, &scope.application, &scope.instance, &identity)?;
            completed.insert(
                dependency.clone(),
                document_digest(&canonical(&serde_json::to_value(receipt)?)?),
            );
        }
    }
    let binding = document_digest(&canonical(
        &json!({"installed":installed,"operation":operation,
        "policy_digest":policy_digest,"admission":document_digest(&admission),
        "configuration":document_digest(&config.bytes()?),"data_admission":data,"completed":completed,
        "runtime_epoch":service_epoch(store,&installed)?}),
    )?);
    if prepare {
        let system = System {
            deadline: Instant::now() + Duration::from_secs(5),
        };
        system::restore_instance_allocation(store, &system, &policy, &scope.instance)?;
        let group = service_group(&installed, &scope.service, &record.ownership)?;
        system.prepare_group(
            &group,
            instance_limits(&policy, &scope.instance)?,
            &Default::default(),
        )?;
        let probe = super::cgroups::service_probe_group(
            &scope.application,
            &scope.instance,
            &scope.service,
            &record.ownership,
        )?;
        system.prepare_group(
            &probe,
            instance_limits(&policy, &scope.instance)?,
            &Default::default(),
        )?;
    }
    Ok(Some(ServiceSnapshot {
        installed,
        document,
        policy,
        config,
        record,
        binding,
    }))
}

fn same_service_generation(observed: &serde_json::Value, current: &serde_json::Value) -> bool {
    observed["Id"] == current["Id"]
        && observed["State"]["StartedAt"].as_str().is_some()
        && observed["State"]["StartedAt"] == current["State"]["StartedAt"]
        && (current["State"]["Running"] != true
            || (observed["State"]["Running"] == true
                && observed["State"]["Pid"] == current["State"]["Pid"]))
}

fn probe_lock_scope(installed: &Installed, service: &str) -> Result<(String, String)> {
    let namespace = units::namespace(&installed.application, &installed.instance)?;
    let key = document_digest(service.as_bytes());
    Ok((
        format!("probe-{}", &namespace[4..]),
        format!("service-{}", &key[7..27]),
    ))
}

fn probe_path(store: &Store, installed: &Installed, service: &str) -> Result<PathBuf> {
    Ok(store
        .root
        .join("probes")
        .join(units::namespace(
            &installed.application,
            &installed.instance,
        )?)
        .join(format!("{service}.json")))
}

fn probe_record(
    store: &Store,
    installed: &Installed,
    service: &str,
) -> Result<Option<serde_json::Value>> {
    let path = probe_path(store, installed, service)?;
    if path.try_exists()? {
        Ok(Some(crate::strict::value(
            &store::read_protected(&path, 4096)?,
            4096,
        )?))
    } else {
        Ok(None)
    }
}

fn commit_probe(
    store: &Store,
    installed: &Installed,
    service: &str,
    id: &str,
    checked_at: i64,
) -> Result<()> {
    store::atomic(
        &probe_path(store, installed, service)?,
        &canonical(&json!({"kind":"komizo.probe",
        "version":1,"container_id":id,"checked_at":checked_at}))?,
        0o600,
    )
}

fn backoff_path(store: &Store, installed: &Installed, service: &str) -> Result<PathBuf> {
    Ok(store
        .root
        .join("service-backoff")
        .join(units::namespace(
            &installed.application,
            &installed.instance,
        )?)
        .join(format!("{service}.json")))
}

fn service_backoff(store: &Store, snapshot: &ServiceSnapshot, service: &str) -> Result<bool> {
    let path = backoff_path(store, &snapshot.installed, service)?;
    let previous = if path.try_exists()? {
        Some(crate::strict::value(
            &store::read_protected(&path, 4096)?,
            4096,
        )?)
    } else {
        None
    };
    restart_due(previous.as_ref(), &snapshot.record, controller::now()?)
}

fn commit_backoff(store: &Store, snapshot: &ServiceSnapshot, service: &str) -> Result<()> {
    store::atomic(
        &backoff_path(store, &snapshot.installed, service)?,
        &canonical(&json!({
        "kind":"komizo.service-backoff","version":1,"container_id":snapshot.record.id,
        "unit_sha256":snapshot.record.unit_sha256,"attempted_at":controller::now()?}))?,
        0o600,
    )
}

// Each queued scope owns its dedupe slot until every observation/commit ends.
// Probe and authority CLIs run outside the application mutation lease.
fn maintain_service(scope: &service_maintenance::Scope) -> Result<()> {
    let store = Store::new(scope.root.clone())?;
    let frozen = {
        let Some(_lease) =
            controller::maintenance_lease(&store, &scope.application, &scope.instance)?
        else {
            return Ok(());
        };
        let Some(snapshot) = service_snapshot(&store, scope, true)? else {
            return Ok(());
        };
        snapshot
    };
    let (probe_application, probe_instance) = probe_lock_scope(&frozen.installed, &scope.service)?;
    let Some(probe_lock) = store.try_lock(&probe_application, &probe_instance)? else {
        return Ok(());
    };
    // If admission acquired the instance while we were taking the probe lock,
    // discard immediately instead of starting a long stale health command.
    {
        let Some(_lease) =
            controller::maintenance_lease(&store, &scope.application, &scope.instance)?
        else {
            return Ok(());
        };
        let Some(current) = service_snapshot(&store, scope, false)? else {
            return Ok(());
        };
        if current.binding != frozen.binding {
            return Ok(());
        }
    }
    let deadline =
        Instant::now() + Duration::from_secs(u64::from(frozen.policy.operation_timeout_seconds));
    let engine = Engine {
        deadline: deadline.min(Instant::now() + Duration::from_secs(20)),
    };
    let group = service_group(&frozen.installed, &scope.service, &frozen.record.ownership)?;
    let before = engine
        .container_metadata(
            &frozen.record,
            &scope.application,
            &scope.instance,
            &scope.service,
        )?
        .ok_or_else(|| {
            anyhow!("desired native CID missing; explicit owner reconciliation required")
        })?;
    super::engine::service_mounts(
        &before,
        &frozen.record,
        &frozen.document.release.workload.services[&scope.service],
    )?;
    let mut checked_at = None;
    let observed = (|| -> Result<bool> {
        super::engine::workload_limits(
            &before,
            &group,
            &frozen.document.release.workload.services[&scope.service].limits,
        )?;
        if before["State"]["Running"] != true {
            stopped_service(&before)?;
            return Ok(false);
        }
        super::cgroups::verify(
            &group,
            instance_limits(&frozen.policy, &scope.instance)?,
            &Default::default(),
        )?;
        if let Some(health) = &frozen.config.health {
            let now = controller::now()?;
            let interval = health_interval(
                health,
                before["State"]["StartedAt"]
                    .as_str()
                    .ok_or_else(|| anyhow!("service health lacks start identity"))?,
                now,
            )?;
            let previous = probe_record(&store, &frozen.installed, &scope.service)?;
            if probe_due(previous.as_ref(), &frozen.record.id, now, interval)? {
                let probe = super::cgroups::service_probe_group(
                    &scope.application,
                    &scope.instance,
                    &scope.service,
                    &frozen.record.ownership,
                )?;
                let command = Engine {
                    deadline: deadline.min(
                        Instant::now()
                            + Duration::from_secs(u64::from(health.timeout_seconds) + 15),
                    ),
                };
                command.health_in_group(&frozen.record.id, &probe)?;
                checked_at = Some(now);
            }
            let after = Engine {
                deadline: deadline.min(Instant::now() + Duration::from_secs(20)),
            }
            .owned_container(
                &frozen.record,
                &scope.application,
                &scope.instance,
                &scope.service,
            )?
            .ok_or_else(|| anyhow!("service disappeared during health observation"))?;
            if after["State"]["Running"] != true {
                stopped_service(&after)?;
                return Ok(false);
            }
            let status = after["State"]["Health"]["Status"].as_str().unwrap_or("");
            ensure!(
                ["healthy", "starting", "unhealthy"].contains(&status),
                "service health state missing"
            );
            Ok(status != "unhealthy")
        } else {
            Ok(true)
        }
    })();
    let restart = matches!(observed, Ok(false));
    let stopped = {
        let Some(_lease) =
            controller::maintenance_lease(&store, &scope.application, &scope.instance)?
        else {
            return Ok(());
        };
        let Some(current) = service_snapshot(&store, scope, false)? else {
            return Ok(());
        };
        if current.binding != frozen.binding {
            return Ok(());
        }
        let live = Engine {
            deadline: deadline.min(Instant::now() + Duration::from_secs(5)),
        }
        .container_metadata(
            &frozen.record,
            &scope.application,
            &scope.instance,
            &scope.service,
        )?
        .ok_or_else(|| anyhow!("service disappeared before observation commit"))?;
        if !same_service_generation(&before, &live) {
            return Ok(());
        }
        if let Some(checked) = checked_at {
            commit_probe(
                &store,
                &current.installed,
                &scope.service,
                &current.record.id,
                checked,
            )?;
        }
        match observed {
            Ok(true) => return Ok(()),
            Err(error) => {
                commit_backoff(&store, &current, &scope.service)?;
                advance_service_epoch(&store, &current.installed)?;
                if cleanup_service(Some(&before), &group).is_err() {
                    return Err(error.context(
                        "service observation failed and exact owned termination remains unproven",
                    ));
                }
                return Err(error);
            }
            Ok(false) => {
                if !service_backoff(&store, &current, &scope.service)? {
                    return Ok(());
                }
                commit_backoff(&store, &current, &scope.service)?;
                let was_running = live["State"]["Running"] == true;
                if was_running {
                    advance_service_epoch(&store, &current.installed)?;
                }
                let stop = Engine {
                    deadline: deadline.min(
                        Instant::now()
                            + Duration::from_secs(
                                u64::from(
                                    current.document.release.workload.services[&scope.service]
                                        .stop_timeout_seconds,
                                ) + 5,
                            ),
                    ),
                };
                stop_owned_service(
                    &current.installed,
                    &current.document,
                    &scope.service,
                    &current.record,
                    &stop,
                    &System {
                        deadline: stop.deadline,
                    },
                )?;
                let stopped = stop
                    .container_metadata(
                        &current.record,
                        &scope.application,
                        &scope.instance,
                        &scope.service,
                    )?
                    .ok_or_else(|| anyhow!("stopped service disappeared"))?;
                stopped_service(&stopped)?;
                // A new source/dependency proof follows the three-second backoff.
                if was_running {
                    return Ok(());
                }
                stopped
            }
        }
    };
    drop(probe_lock);
    if !restart {
        return Ok(());
    }
    // The full pre-start source/data/job/dependency guard observes outside the
    // mutation lease. Its entire frozen authority closure is rechecked below.
    observation::guard(&scope.application, &scope.instance, &scope.service)?;
    let after_start_binding = {
        let Some(_lease) =
            controller::maintenance_lease(&store, &scope.application, &scope.instance)?
        else {
            return Ok(());
        };
        let Some(current) = service_snapshot(&store, scope, false)? else {
            return Ok(());
        };
        if current.binding != frozen.binding {
            return Ok(());
        }
        let command = Engine {
            deadline: deadline.min(Instant::now() + Duration::from_secs(5)),
        };
        let live = command
            .container_metadata(
                &current.record,
                &scope.application,
                &scope.instance,
                &scope.service,
            )?
            .ok_or_else(|| anyhow!("service disappeared before restart"))?;
        if !same_service_generation(&stopped, &live) {
            return Ok(());
        }
        stopped_service(&live)?;
        let system = System {
            deadline: command.deadline,
        };
        system.prepare_group(
            &group,
            instance_limits(&current.policy, &scope.instance)?,
            &Default::default(),
        )?;
        let probe = super::cgroups::service_probe_group(
            &scope.application,
            &scope.instance,
            &scope.service,
            &current.record.ownership,
        )?;
        system.prepare_group(
            &probe,
            instance_limits(&current.policy, &scope.instance)?,
            &Default::default(),
        )?;
        advance_service_epoch(&store, &current.installed)?;
        let started = (|| -> Result<()> {
            command.run(&["start", &current.record.id])?;
            let after = command
                .owned_container(
                    &current.record,
                    &scope.application,
                    &scope.instance,
                    &scope.service,
                )?
                .ok_or_else(|| anyhow!("restarted service disappeared"))?;
            super::engine::workload_limits(
                &after,
                &group,
                &current.document.release.workload.services[&scope.service].limits,
            )?;
            ensure!(
                after["State"]["Running"] == true,
                "service exited during restart"
            );
            Ok(())
        })();
        if let Err(error) = started {
            advance_service_epoch(&store, &current.installed)?;
            if cleanup_service(Some(&live), &group).is_err() {
                return Err(error.context(
                    "service restart failed and exact owned termination remains unproven",
                ));
            }
            return Err(error);
        }
        service_snapshot(&store, scope, false)?
            .ok_or_else(|| anyhow!("restarted service authority disappeared"))?
            .binding
    };
    // Route generation reads current protected state itself. HTTP readiness is
    // pure observation and must not hold the application mutation lease.
    proxy::refresh(
        &store,
        deadline.min(Instant::now() + Duration::from_secs(20)),
    )?;
    readiness(
        &frozen.document,
        &frozen.policy,
        &scope.instance,
        deadline.min(Instant::now() + Duration::from_secs(15)),
    )?;
    // No operational metadata or source acceptance is inferred from this old
    // observation if admission changed the instance while readiness ran.
    let Some(_lease) = controller::maintenance_lease(&store, &scope.application, &scope.instance)?
    else {
        return Ok(());
    };
    let Some(current) = service_snapshot(&store, scope, false)? else {
        return Ok(());
    };
    if current.binding != after_start_binding {
        return Ok(());
    }
    Ok(())
}

fn maintenance_eligible(
    installed: &Installed,
    operation: &Operation,
    unresolved: bool,
    now: i64,
) -> bool {
    !installed.removed
        && installed.desired_running
        && !unresolved
        && installed.expires_at.is_none_or(|expires| expires > now)
        && operation.application == installed.application
        && operation.instance == installed.instance
        && operation.operation_id == installed.operation_id
        && operation.phase == "ready"
        && operation.ok
        && !operation.reconciliation_required
        && operation.release_digest == installed.release_digest
}

fn maintain_services(store: &Store) -> Result<()> {
    for installed in proxy::instances(store)? {
        if installed.removed || !installed.desired_running {
            continue;
        }
        let document = store.release(&installed.release_digest)?;
        for service in order(&document)? {
            if !document.release.workload.services.contains_key(&service) {
                continue;
            }
            service_maintenance::enqueue(service_maintenance::Scope {
                root: store.root.clone(),
                application: installed.application.clone(),
                instance: installed.instance.clone(),
                service,
            })?;
        }
    }
    Ok(())
}

fn activate(
    store: &Store,
    policy: &Policy,
    installed: &mut Installed,
    document: &ReleaseDocument,
    job: &Job,
    operation: &mut Operation,
) -> Result<()> {
    let system = System {
        deadline: job.deadline,
    };
    let engine = Engine {
        deadline: job.deadline,
    };
    if operation.phase == "staging" {
        advance(store, operation, "jobs")?;
    }
    system::instance_allocation(store, &system, policy, &installed.instance)?;
    retained(store, installed, document, &engine)?;
    data::require(store, installed, document, &engine)?;
    install_units(store, installed, document, &system)?;
    installed.desired_running = true;
    store.save_installed(installed)?;
    for name in order(document)? {
        if document.release.workload.jobs.contains_key(&name) {
            jobs::run(
                store,
                policy,
                document,
                installed,
                &name,
                &job.operation_id,
                job.deadline,
            )?;
        } else {
            start_service(store, policy, installed, document, &name, &engine, &system)?;
        }
    }
    advance(store, operation, "installing")?;
    advance(store, operation, "activating")?;
    proxy::refresh(store, job.deadline)?;
    advance(store, operation, "readiness")?;
    readiness(document, policy, &installed.instance, job.deadline)?;
    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
    capacity::reserve(
        store,
        &capacity,
        policy,
        document,
        &installed.instance,
        false,
    )?;
    advance(store, operation, "ready")
}

fn readiness(
    document: &ReleaseDocument,
    policy: &Policy,
    instance: &str,
    deadline: Instant,
) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let protected = if instance == "production" {
        policy.readiness.clone()
    } else {
        policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview readiness authority missing"))?
            .readiness
            .iter()
            .map(|p| {
                let mut p = p.clone();
                p.url = p.url.replace("{instance}", instance);
                p
            })
            .collect()
    };
    for check in document
        .release
        .workload
        .readiness
        .iter()
        .chain(protected.iter())
    {
        let mut last_error = "no response observed".to_owned();
        loop {
            ensure!(
                Instant::now() < deadline,
                "public readiness deadline exceeded for {}: {}",
                check.url,
                last_error
            );
            let result = (|| -> Result<()> {
                let response = client
                    .get(&check.url)
                    .timeout(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(15)),
                    )
                    .header("Cache-Control", "no-cache")
                    .send()?;
                ensure!(
                    response.status().as_u16() == check.status,
                    "readiness HTTP status {} differs from {}",
                    response.status().as_u16(),
                    check.status
                );
                ensure!(
                    response
                        .headers()
                        .get("X-Komizo-Release")
                        .and_then(|v| v.to_str().ok())
                        == Some(&document.digest),
                    "readiness response has no matching accepted release header"
                );
                let mut body = Vec::new();
                response.take((1 << 20) + 1).read_to_end(&mut body)?;
                ensure!(body.len() <= 1 << 20, "readiness body exceeds bound");
                if let Some(text) = &check.contains {
                    ensure!(
                        std::str::from_utf8(&body)?.contains(text),
                        "readiness response content differs"
                    );
                }
                if let Some(field) = &check.revision_field {
                    let value = bounded_value(&body, 1 << 20)?;
                    ensure!(
                        value.get(field).and_then(|v| v.as_str())
                            == Some(&document.release.source.revision),
                        "readiness source revision differs"
                    );
                }
                Ok(())
            })();
            match result {
                Ok(()) => break,
                Err(error) => last_error = format!("{error:#}").chars().take(768).collect(),
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(())
}

fn backup(
    store: &Store,
    policy: &Policy,
    installed: &Installed,
    operation: &mut Operation,
    deadline: Instant,
) -> Result<()> {
    let task = policy
        .backup
        .as_ref()
        .ok_or_else(|| anyhow!("installed state requires a protected backup program"))?;
    let body = store::read_protected(Path::new(&task.program), 32 << 20)?;
    ensure!(
        document_digest(&body) == task.sha256,
        "protected backup bundle bytes changed"
    );
    let directory = store.root.join("exports").join(&operation.operation_id);
    store::protected_directory(&directory)?;
    ensure!(
        fs::read_dir(&directory)?.next().is_none(),
        "backup output directory is not fresh"
    );
    let deadline =
        deadline.min(Instant::now() + Duration::from_secs(u64::from(task.timeout_seconds)));
    let unix =
        controller::now()? + deadline.saturating_duration_since(Instant::now()).as_secs() as i64;
    let environment = BTreeMap::from([
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("HOME".into(), "/root".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("KOMIZO_APPLICATION".into(), installed.application.clone()),
        ("KOMIZO_INSTANCE".into(), installed.instance.clone()),
        (
            "KOMIZO_RELEASE_DIGEST".into(),
            installed.release_digest.clone(),
        ),
        ("KOMIZO_OPERATION_ID".into(), operation.operation_id.clone()),
        (
            "KOMIZO_OUTPUT_DIRECTORY".into(),
            directory.to_str().unwrap().into(),
        ),
        ("KOMIZO_DEADLINE_UNIX".into(), unix.to_string()),
    ]);
    let input = canonical(
        &json!({"kind":"komizo.backup-request","version":1,"application":installed.application,"instance":installed.instance,"release_digest":installed.release_digest,"operation_id":operation.operation_id,"output_directory":directory,"deadline_unix":unix}),
    )?;
    if operation.phase == "admitted" {
        advance(store, operation, "staging")?;
    }
    if operation.phase == "staging" {
        advance(store, operation, "jobs")?;
    }
    run_task(
        store,
        &operation.operation_id,
        "backup",
        task,
        &input,
        &environment,
        deadline,
    )?;
    ensure!(
        fs::read_dir(&directory)?.count() == 2,
        "backup emitted an unrecognized export"
    );
    let mut files = Vec::new();
    for name in ["snapshot.cms", "receipt.json"] {
        let path = directory.join(name);
        let mut file = store::open_protected(&path, task.max_export_bytes)?;
        let size = file.metadata()?.len();
        ensure!(size > 0, "backup export is empty");
        let hash = hash_file(&mut file, Some(deadline))?;
        files.push(store::Export {
            name: name.into(),
            size_bytes: size,
            sha256: hash,
        });
    }
    let receipt = bounded_value(
        &store::read_protected(&directory.join("receipt.json"), 1 << 20)?,
        1 << 20,
    )?;
    ensure!(
        receipt["deployment"]["application"] == installed.application
            && receipt["deployment"]["release_digest"] == installed.release_digest
            && receipt["deployment"]["source"]
                == serde_json::to_value(store.release(&installed.release_digest)?.release.source)?
            && receipt["deployment"]["provider"]
                == serde_json::to_value(
                    store.release(&installed.release_digest)?.release.providers
                )?
            && receipt["ciphertext_sha256"].as_str().is_some_and(|hash| {
                files.iter().any(|file| {
                    file.name == "snapshot.cms" && file.sha256 == format!("sha256:{hash}")
                })
            }),
        "backup receipt differs from installed source authority"
    );
    operation.backup = Some(store::Backup {
        status: "ready".into(),
        release_digest: Some(installed.release_digest.clone()),
        files,
    });
    store.save_operation(operation)?;
    store::atomic(
        &store.root.join("backups").join(format!(
            "{}.json",
            Store::instance_key(&installed.application, &installed.instance)?
        )),
        &canonical(
            &json!({"operation_id":operation.operation_id,"release_digest":installed.release_digest,"installed_operation_id":installed.operation_id,"created_at":controller::now()?}),
        )?,
        0o600,
    )
}

pub fn file_hash(mut file: fs::File) -> Result<String> {
    hash_file(&mut file, None)
}

pub fn hash_file(file: &mut fs::File, deadline: Option<Instant>) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        ensure!(
            deadline.is_none_or(|end| Instant::now() < end),
            "protected file verification deadline expired"
        );
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn require_backup(store: &Store, installed: &Installed) -> Result<()> {
    let path = store.root.join("backups").join(format!(
        "{}.json",
        Store::instance_key(&installed.application, &installed.instance)?
    ));
    let value = bounded_value(&store::read_protected(&path, 4096)?, 4096)?;
    let at = value["created_at"]
        .as_i64()
        .ok_or_else(|| anyhow!("backup time missing"))?;
    let now = controller::now()?;
    ensure!(
        value["release_digest"] == installed.release_digest
            && value["installed_operation_id"] == installed.operation_id
            && at <= now
            && now - at <= 1800,
        "activation requires a recent backup of the actual installed release"
    );
    let operation = store.operation(
        value["operation_id"]
            .as_str()
            .ok_or_else(|| anyhow!("backup operation missing"))?,
    )?;
    ensure!(
        operation.ok
            && operation
                .backup
                .as_ref()
                .is_some_and(|b| b.status == "ready"),
        "backup operation has not completed"
    );
    Ok(())
}

fn needs_backup(_policy: &Policy, instance: &str, document: &ReleaseDocument) -> bool {
    !document.release.workload.volumes.is_empty() && instance == "production"
}

fn finish_remove(
    store: &Store,
    installed: &mut Installed,
    engine: &Engine,
    system: &System,
    operation_id: &str,
) -> Result<()> {
    ensure!(
        installed.instance != "production",
        "only ephemeral data may be removed"
    );
    let pending = store.unresolved(&installed.application, &installed.instance)?;
    for old in pending
        .iter()
        .filter(|old| old.operation_id != operation_id)
    {
        super::recovery::reconcile_units(
            store,
            &installed.application,
            &installed.instance,
            &old.operation_id,
        )?;
        reconcile_tasks(store, old, system)?;
        super::recovery::reconcile_objects(store, installed, &old.operation_id, engine)?;
        reconcile_services(store, old, installed, engine, system)?;
        super::recovery::reconcile_object_removals(store, installed, &old.operation_id, engine)?;
    }
    stop_services(store, installed, engine, system, true, operation_id)?;
    jobs::cleanup_ephemeral(store, installed, operation_id, engine.deadline)?;
    for (logical, record) in installed.resources.volumes.clone() {
        remove_object(
            store,
            installed,
            engine,
            operation_id,
            "volume",
            &logical,
            &record,
        )?;
        installed.resources.volumes.remove(&logical);
        store.save_installed(installed)?;
    }
    for (logical, record) in installed.resources.networks.clone() {
        remove_object(
            store,
            installed,
            engine,
            operation_id,
            "network",
            &logical,
            &record,
        )?;
        installed.resources.networks.remove(&logical);
        store.save_installed(installed)?;
    }
    engine.prove_absent(&units::namespace(
        &installed.application,
        &installed.instance,
    )?)?;
    let prepared = prepared_path(store, &installed.application, &installed.instance)?;
    if prepared.try_exists()? {
        fs::remove_file(prepared)?;
    }
    installed.expires_at = None;
    installed.removed = true;
    installed.operation_id = operation_id.into();
    store.save_installed(installed)?;
    capacity::release(store, &installed.application, &installed.instance)?;
    for old in pending
        .iter()
        .filter(|old| old.operation_id != operation_id)
    {
        store::atomic(
            &store
                .root
                .join("reconciliations")
                .join(format!("{}.json", old.operation_id)),
            &canonical(&json!({"resolved_by":operation_id,"outcome":"ephemeral_removed"}))?,
            0o600,
        )?;
    }
    Ok(())
}

impl Backend for Native {
    fn maintenance(&self, store: &Store) -> Result<()> {
        let services = maintain_services(store);
        let routes = proxy::refresh_background(store, Instant::now() + Duration::from_secs(20));
        services?;
        routes
    }
    fn execute(
        &self,
        store: &Store,
        policy: &Policy,
        job: &Job,
        operation: &mut Operation,
    ) -> Result<()> {
        let application = &job.request.application;
        let instance = &job.request.instance;
        let engine = Engine {
            deadline: job.deadline,
        };
        let system = System {
            deadline: job.deadline,
        };
        let mut previous = store.installed(application, instance)?;
        if job.request.action == "deploy"
            && previous.as_ref().is_some_and(|installed| installed.removed)
        {
            ensure!(
                instance != "production",
                "production cannot be an ephemeral removed instance"
            );
            engine.prove_absent(&units::namespace(application, instance)?)?;
            previous = None;
        }
        match job.request.action.as_str() {
            "data-prepare" => {
                let document = store.release(&job.request.release_digest)?;
                ensure!(
                    !document.release.workload.volumes.is_empty(),
                    "data preparation requires retained volumes"
                );
                policy.admit(&document.release, instance)?;
                advance(store, operation, "staging")?;
                stage(store, policy, &document, job)?;
                let snapshots = secrets::stage(&store.root, &document, policy, instance)?;
                let resources = if let Some(previous) = previous {
                    ensure!(
                        !previous.desired_running
                            && previous.release_digest == document.digest
                            && !data::enrolled(store, &previous)?,
                        "owner data preparation cannot replace accepted or active data"
                    );
                    for record in previous.resources.containers.values() {
                        ensure!(
                            !engine.exists("container", &record.name)?,
                            "owner data preparation refuses an existing service"
                        );
                    }
                    previous.resources
                } else {
                    Resources::default()
                };
                let mut installed = Installed {
                    kind: "komizo.installed".into(),
                    version: 1,
                    application: application.clone(),
                    instance: instance.clone(),
                    release_digest: document.digest.clone(),
                    operation_id: operation.operation_id.clone(),
                    desired_running: false,
                    removed: false,
                    expires_at: None,
                    resources,
                    secret_snapshots: snapshots,
                };
                advance(store, operation, "jobs")?;
                store.save_installed(&installed)?;
                retained(store, &mut installed, &document, &engine)?;
                install_units(store, &mut installed, &document, &system)?;
                advance(store, operation, "installing")?;
                advance(store, operation, "prepared_stopped")
            }
            "data-accept" => {
                let installed = previous.ok_or_else(|| anyhow!("data preparation is required"))?;
                ensure!(
                    store
                        .release(&installed.release_digest)?
                        .release
                        .workload
                        .volumes
                        .keys()
                        .eq(installed.resources.volumes.keys()),
                    "data preparation has not created every declared retained volume"
                );
                data::accept(
                    store,
                    &installed,
                    job.request
                        .data_evidence
                        .as_deref()
                        .ok_or_else(|| anyhow!("owner data evidence missing"))?,
                    &operation.operation_id,
                    controller::now()?,
                    &engine,
                )?;
                advance(store, operation, "ready")
            }
            "deploy" => {
                let document = store.release(&job.request.release_digest)?;
                policy.admit(&document.release, instance)?;
                if instance == "production" && !document.release.workload.volumes.is_empty() {
                    let enrolled = previous.as_ref().ok_or_else(|| {
                        anyhow!(
                            "stateful production requires owner data preparation and acceptance"
                        )
                    })?;
                    data::require(store, enrolled, &document, &engine)?;
                }
                if let Some(previous) = &previous {
                    retained_topology(&store.release(&previous.release_digest)?, &document)?;
                }
                preview_capacity(store, policy, instance)?;
                if previous.as_ref().is_none_or(|p| p.desired_running) {
                    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                    capacity::preflight(store, &capacity, policy, &document, instance, true)?;
                }
                advance(store, operation, "staging")?;
                super::tls::reserve(store, &document, instance, controller::now()?)?;
                stage(store, policy, &document, job)?;
                prepare_preview(store, policy, job, operation)?;
                let snapshots = secrets::stage(&store.root, &document, policy, instance)?;
                if let Some(previous) = &previous
                    && !previous.desired_running
                {
                    let prepared = Installed {
                        kind: "komizo.installed".into(),
                        version: 1,
                        application: application.clone(),
                        instance: instance.clone(),
                        release_digest: document.digest.clone(),
                        operation_id: operation.operation_id.clone(),
                        desired_running: false,
                        removed: false,
                        expires_at: job
                            .request
                            .ttl_seconds
                            .map(|n| job.admitted_at + i64::from(n)),
                        resources: previous.resources.clone(),
                        secret_snapshots: snapshots,
                    };
                    store::atomic(
                        &prepared_path(store, application, instance)?,
                        &serde_json::to_vec(&prepared)?,
                        0o600,
                    )?;
                    let mut stopped = previous.clone();
                    stopped.expires_at = prepared.expires_at;
                    store.save_installed(&stopped)?;
                    advance(store, operation, "installing")?;
                    return advance(store, operation, "prepared_stopped");
                }
                let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                capacity::reserve(store, &capacity, policy, &document, instance, true)?;
                let mut resources = Resources::default();
                if let Some(mut previous) = previous {
                    if needs_backup(policy, instance, &document) {
                        require_backup(store, &previous)?;
                    }
                    if operation.phase == "staging" {
                        advance(store, operation, "jobs")?;
                    }
                    stop_services(
                        store,
                        &mut previous,
                        &engine,
                        &system,
                        true,
                        &job.operation_id,
                    )?;
                    resources = previous.resources;
                    // activation's jobs transition is entered below; the stop
                    // effect is journalled before touching the prior services.
                }
                let mut installed = Installed {
                    kind: "komizo.installed".into(),
                    version: 1,
                    application: application.clone(),
                    instance: instance.clone(),
                    release_digest: document.digest.clone(),
                    operation_id: operation.operation_id.clone(),
                    desired_running: false,
                    removed: false,
                    expires_at: job
                        .request
                        .ttl_seconds
                        .map(|n| job.admitted_at + i64::from(n)),
                    resources,
                    secret_snapshots: snapshots,
                };
                let prepared = prepared_path(store, application, instance)?;
                if prepared.try_exists()? {
                    fs::remove_file(prepared)?;
                }
                store.save_installed(&installed)?;
                activate(store, policy, &mut installed, &document, job, operation)
            }
            "backup" => {
                ensure!(
                    instance == "production",
                    "logical backup requires a production instance"
                );
                if let Some(installed) = previous {
                    ensure!(
                        installed.desired_running,
                        "a deliberately stopped instance cannot produce a logical backup"
                    );
                    backup(store, policy, &installed, operation, job.deadline)?;
                } else {
                    ensure!(
                        !prepared_path(store, application, instance)?.try_exists()?,
                        "prepared state prevents absence assertion"
                    );
                    engine.prove_absent(&units::namespace(application, instance)?)?;
                    operation.backup = Some(store::Backup {
                        status: "absent".into(),
                        release_digest: None,
                        files: Vec::new(),
                    });
                }
                advance(store, operation, "ready")
            }
            "stop" => {
                let mut installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                ensure!(
                    !installed.removed,
                    "removed preview requires a fresh admitted deployment"
                );
                advance(store, operation, "staging")?;
                advance(store, operation, "installing")?;
                stop_services(
                    store,
                    &mut installed,
                    &engine,
                    &system,
                    false,
                    &job.operation_id,
                )?;
                capacity::release(store, application, instance)?;
                advance(store, operation, "prepared_stopped")
            }
            "start" | "restart" => {
                let mut installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                ensure!(
                    !installed.removed,
                    "removed preview requires a fresh admitted deployment"
                );
                advance(store, operation, "staging")?;
                let prepared = prepared_path(store, application, instance)?;
                if prepared.try_exists()?
                    && job.request.action == "start"
                    && !installed.desired_running
                {
                    let mut next: Installed = serde_json::from_slice(&store::read_protected(
                        &prepared,
                        MAX_DOCUMENT_BYTES,
                    )?)?;
                    ensure!(
                        next.release_digest == job.request.release_digest
                            && !installed.desired_running,
                        "prepared start target changed after admission"
                    );
                    let accepted = store.operation(&next.operation_id)?;
                    ensure!(
                        accepted.ok && accepted.phase == "prepared_stopped",
                        "prepared source did not finish accepted staging"
                    );
                    let old_document = store.release(&installed.release_digest)?;
                    let document = store.release(&next.release_digest)?;
                    policy.admit(&document.release, instance)?;
                    retained_topology(&old_document, &document)?;
                    data::require(store, &installed, &document, &engine)?;
                    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                    capacity::reserve(store, &capacity, policy, &document, instance, true)?;
                    if needs_backup(policy, instance, &document)
                        && !data::fresh_empty(store, &installed, &engine)?
                    {
                        // Bring up only the previous release's data services;
                        // its exact installed descriptor remains authoritative
                        // throughout capture, before any new migration runs.
                        advance(store, operation, "jobs")?;
                        installed.desired_running = true;
                        store.save_installed(&installed)?;
                        wanted(store, &mut installed, true, &system, &job.operation_id)?;
                        for name in order(&old_document)? {
                            if policy
                                .backup
                                .as_ref()
                                .is_some_and(|task| task.services.contains(&name))
                            {
                                start_service(
                                    store,
                                    policy,
                                    &mut installed,
                                    &old_document,
                                    &name,
                                    &engine,
                                    &system,
                                )?;
                            }
                        }
                        backup(store, policy, &installed, operation, job.deadline)?;
                    }
                    if operation.phase == "staging" {
                        advance(store, operation, "jobs")?;
                    }
                    stop_services(
                        store,
                        &mut installed,
                        &engine,
                        &system,
                        true,
                        &job.operation_id,
                    )?;
                    next.resources = installed.resources;
                    next.operation_id = job.operation_id.clone();
                    store.save_installed(&next)?;
                    fs::remove_file(prepared)?;
                    activate(store, policy, &mut next, &document, job, operation)
                } else {
                    let document = store.release(&installed.release_digest)?;
                    let admission = bounded_value(
                        &store::read_protected(
                            &store
                                .root
                                .join("journal")
                                .join(&installed.operation_id)
                                .join("admission.json"),
                            MAX_DOCUMENT_BYTES,
                        )?,
                        MAX_DOCUMENT_BYTES,
                    )?;
                    ensure!(
                        admission["action"] != "data-prepare",
                        "owner data preparation cannot activate an unstaged application source"
                    );
                    policy.admit(&document.release, instance)?;
                    data::require(store, &installed, &document, &engine)?;
                    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                    capacity::reserve(store, &capacity, policy, &document, instance, true)?;
                    advance(store, operation, "jobs")?;
                    system::instance_allocation(store, &system, policy, instance)?;
                    if job.request.action == "restart" {
                        stop_services(
                            store,
                            &mut installed,
                            &engine,
                            &system,
                            false,
                            &job.operation_id,
                        )?;
                    }
                    installed.desired_running = true;
                    installed.operation_id = job.operation_id.clone();
                    store.save_installed(&installed)?;
                    wanted(store, &mut installed, true, &system, &job.operation_id)?;
                    for name in order(&document)? {
                        if document.release.workload.services.contains_key(&name) {
                            start_service(
                                store,
                                policy,
                                &mut installed,
                                &document,
                                &name,
                                &engine,
                                &system,
                            )?;
                        } else {
                            ensure!(
                                jobs::completed(store, &document, &name, &installed)?,
                                "start cannot replay a one-shot job"
                            );
                        }
                    }
                    advance(store, operation, "installing")?;
                    advance(store, operation, "activating")?;
                    proxy::refresh(store, job.deadline)?;
                    advance(store, operation, "readiness")?;
                    readiness(&document, policy, instance, job.deadline)?;
                    capacity::reserve(store, &capacity, policy, &document, instance, false)?;
                    advance(store, operation, "ready")
                }
            }
            "remove" => {
                ensure!(
                    instance != "production",
                    "production retained data requires explicit owner transfer"
                );
                let mut installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                advance(store, operation, "staging")?;
                advance(store, operation, "installing")?;
                finish_remove(store, &mut installed, &engine, &system, &job.operation_id)?;
                advance(store, operation, "prepared_stopped")
            }
            "secret-set" => {
                let mut policy = policy.clone();
                secrets::rotate(
                    &Path::new(observation::POLICIES).join(format!("{application}.json")),
                    &mut policy,
                    &job.request.secret_updates,
                    &store.root,
                )?;
                advance(store, operation, "ready")
            }
            "recover" => {
                let target =
                    job.request.operation.as_deref().ok_or_else(|| {
                        anyhow!("recovery requires its exact uncertain operation")
                    })?;
                let uncertain = store.operation(target)?;
                ensure!(
                    uncertain.application == *application
                        && uncertain.instance == *instance
                        && uncertain.reconciliation_required,
                    "recovery target is outside this uncertain instance"
                );
                let admission = bounded_value(
                    &store::read_protected(
                        &store
                            .root
                            .join("journal")
                            .join(target)
                            .join("admission.json"),
                        MAX_DOCUMENT_BYTES,
                    )?,
                    MAX_DOCUMENT_BYTES,
                )?;
                ensure!(
                    admission["kind"] == "komizo.admission"
                        && admission["version"] == 1
                        && admission["operation_id"] == target,
                    "interrupted admission identity differs"
                );
                let action = admission["action"]
                    .as_str()
                    .ok_or_else(|| anyhow!("interrupted action missing"))?;
                ensure!(
                    [
                        "deploy",
                        "start",
                        "restart",
                        "stop",
                        "backup",
                        "remove",
                        "data-prepare",
                        "data-accept",
                        "secret-set",
                        "recover"
                    ]
                    .contains(&action),
                    "interrupted action has no reviewed recovery path"
                );
                super::recovery::reconcile_units(store, application, instance, target)?;
                reconcile_tasks(store, &uncertain, &system)?;
                cleanup_captures(store, &uncertain, job, operation)?;
                if let Some(mut installed) = previous {
                    if action == "remove" {
                        ensure!(
                            job.request.release_digest == installed.release_digest,
                            "ephemeral recovery source changed"
                        );
                        if operation.phase == "admitted" {
                            advance(store, operation, "staging")?;
                        }
                        if operation.phase == "staging" {
                            advance(store, operation, "jobs")?;
                        }
                        finish_remove(store, &mut installed, &engine, &system, &job.operation_id)?;
                        return advance(store, operation, "ready");
                    }
                    let document = store.release(&installed.release_digest)?;
                    ensure!(
                        job.request.release_digest == installed.release_digest,
                        "owner recovery target differs from installed source"
                    );
                    super::recovery::reconcile_objects(store, &mut installed, target, &engine)?;
                    reconcile_services(store, &uncertain, &mut installed, &engine, &system)?;
                    reconcile_container_ids(store, &mut installed, &document, &engine, target)?;
                    super::recovery::reconcile_object_removals(
                        store,
                        &mut installed,
                        target,
                        &engine,
                    )?;
                    let staged_jobs = ["deploy", "start", "restart"].contains(&action)
                        && installed.operation_id == target;
                    let allow_failed = if let Some(expected) = &job.request.recovery_evidence {
                        ensure!(
                            staged_jobs,
                            "owner data evidence does not select a staged job operation"
                        );
                        let body = store::read_protected(
                            &store
                                .root
                                .join("recovery-evidence")
                                .join(format!("{target}.json")),
                            16384,
                        )?;
                        ensure!(
                            document_digest(&body) == *expected,
                            "owner recovery evidence bytes changed"
                        );
                        let evidence: RecoveryEvidence =
                            serde_json::from_value(bounded_value(&body, 16384)?)?;
                        verify_forward_evidence(
                            &evidence,
                            &installed,
                            &document,
                            target,
                            controller::now()?,
                        )?;
                        true
                    } else {
                        false
                    };
                    if staged_jobs {
                        jobs::reconcile_with_evidence(
                            store,
                            &document,
                            &installed,
                            target,
                            job.deadline,
                            allow_failed,
                        )?;
                    }
                    for volume in installed.resources.volumes.values() {
                        engine.owned_object("volume", volume)?;
                    }
                    for network in installed.resources.networks.values() {
                        engine.owned_object("network", network)?;
                    }
                    if action == "stop" {
                        ensure!(
                            !installed.desired_running,
                            "interrupted stop has not persisted stop intent"
                        );
                        stop_services(store, &mut installed, &engine, &system, false, target)?;
                        capacity::release(store, application, instance)?;
                    }
                } else {
                    ensure!(
                        job.request.release_digest == uncertain.release_digest
                            && job.request.recovery_evidence.is_none(),
                        "uninstalled recovery source differs from interrupted admission"
                    );
                    engine.prove_absent(&units::namespace(application, instance)?)?;
                }
                store::atomic(
                    &store
                        .root
                        .join("reconciliations")
                        .join(format!("{target}.json")),
                    &canonical(&json!({"resolved_by":operation.operation_id}))?,
                    0o600,
                )?;
                advance(store, operation, "ready")
            }
            _ => Err(anyhow!("unsupported native effect")),
        }
    }
}

pub fn expire() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "preview expiry requires owner identity"
    );
    let store = Store::new(Path::new(observation::STATE).into())?;
    for installed in proxy::instances(&store)? {
        let now = controller::now()?;
        if installed.instance == "production" || installed.expires_at.is_none_or(|n| n > now) {
            continue;
        }
        let request = json!({"kind":"komizo.request","version":1,"authority":"owner","application":installed.application,"instance":installed.instance,"action":"remove","release_digest":installed.release_digest,"nonce":store::identity()?,"issued_at":now,"expires_at":now+120,"timeout_seconds":1200});
        let mut response = Vec::new();
        super::transport::submit(&mut &canonical(&request)?[..], &mut response)?;
        let value = bounded_value(&response, 16384)?;
        ensure!(
            value["ok"] == true,
            "preview expiry requires reconciliation"
        );
    }
    Ok(())
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn service_observation_discards_replaced_or_restarted_process_generations() {
        let observed = json!({"Id":"a".repeat(64),"State":{"Running":true,"Pid":123,"StartedAt":"2026-11-11T00:00:00Z"}});
        assert!(same_service_generation(&observed, &observed));
        let mut terminal = observed.clone();
        terminal["State"]["Running"] = json!(false);
        terminal["State"]["Pid"] = json!(0);
        assert!(same_service_generation(&observed, &terminal));
        let mut changed = observed.clone();
        changed["Id"] = json!("b".repeat(64));
        assert!(!same_service_generation(&observed, &changed));
        changed = observed.clone();
        changed["State"]["StartedAt"] = json!("2026-11-11T00:00:01Z");
        assert!(!same_service_generation(&observed, &changed));
        changed = observed.clone();
        changed["State"]["Pid"] = json!(124);
        assert!(!same_service_generation(&observed, &changed));
        assert!(!same_service_generation(&terminal, &observed));
    }

    #[test]
    fn health_schedule_honors_start_period_interval_and_exact_native_identity() {
        let health = Health {
            command: vec!["/app/health".into()],
            interval_seconds: 30,
            timeout_seconds: 3,
            retries: 3,
            start_period_seconds: 60,
            start_interval_seconds: Some(2),
        };
        let started = "2026-11-11T00:00:00Z";
        let epoch = chrono::DateTime::parse_from_rfc3339(started)
            .unwrap()
            .timestamp();
        assert_eq!(health_interval(&health, started, epoch + 59).unwrap(), 2);
        assert_eq!(health_interval(&health, started, epoch + 60).unwrap(), 30);
        assert!(health_interval(&health, "missing", epoch).is_err());
        let id = "a".repeat(64);
        let previous =
            json!({"kind":"komizo.probe","version":1,"container_id":id,"checked_at":epoch});
        assert!(!probe_due(Some(&previous), &id, epoch + 29, 30).unwrap());
        assert!(probe_due(Some(&previous), &id, epoch + 30, 30).unwrap());
        assert!(probe_due(Some(&previous), &"b".repeat(64), epoch + 1, 30).unwrap());
        assert!(probe_due(Some(&json!({})), &id, epoch, 30).is_err());
    }

    #[test]
    fn service_restart_backoff_is_finite_and_unknown_native_states_never_start() {
        let record = store::ContainerRecord {
            name: "synthetic".into(),
            id: "a".repeat(64),
            image: "unused".into(),
            config_digest: format!("sha256:{}", "b".repeat(64)),
            release_digest: format!("sha256:{}", "c".repeat(64)),
            ownership: "d".repeat(32),
            unit_sha256: format!("sha256:{}", "e".repeat(64)),
            volumes: BTreeMap::new(),
        };
        let previous = json!({"kind":"komizo.service-backoff","version":1,"container_id":record.id,
            "unit_sha256":record.unit_sha256,"attempted_at":100});
        assert!(!restart_due(Some(&previous), &record, 102).unwrap());
        assert!(restart_due(Some(&previous), &record, 103).unwrap());
        assert!(!restart_due(Some(&previous), &record, 99).unwrap());
        let mut replacement = record.clone();
        replacement.id = "f".repeat(64);
        assert!(restart_due(Some(&previous), &replacement, 101).unwrap());
        assert!(
            unstarted_service(
                &json!({"State":{"Status":"created","Running":false,"Paused":false,"Pid":0}})
            )
            .is_ok()
        );
        assert!(
            unstarted_service(
                &json!({"State":{"Status":"exited","Running":false,"Paused":false,"Pid":0}})
            )
            .is_err()
        );
        for status in ["configured", "created", "exited", "stopped"] {
            stopped_service(
                &json!({"State":{"Status":status,"Running":false,"Paused":false,"Pid":0}}),
            )
            .unwrap();
        }
        for state in [
            json!({}),
            json!({"Status":"unknown","Running":false,"Paused":false,"Pid":0}),
            json!({"Status":"running","Running":true,"Paused":false,"Pid":42}),
            json!({"Status":"exited","Running":false,"Paused":false,"Pid":42}),
        ] {
            assert!(stopped_service(&json!({"State":state})).is_err());
        }
    }

    #[test]
    fn service_creation_and_removal_intents_bind_exact_source_token_unit_and_volume_authority() {
        let document = read_release(include_bytes!(
            "../../tests/fixtures/deployment/release.json"
        ))
        .unwrap();
        let Artifact::Image {
            reference,
            config_digest,
            ..
        } = &document.release.artifacts["api"]
        else {
            panic!()
        };
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let store = Store::new(directory.path().join("state")).unwrap();
        let environment = store.root.join("runtime.env");
        let secret = b"TOKEN=synthetic-only\n";
        store::atomic(&environment, secret, 0o600).unwrap();
        let installed = Installed {
            kind: "komizo.installed".into(),
            version: 1,
            application: "mailroom".into(),
            instance: "production".into(),
            release_digest: document.digest.clone(),
            operation_id: "a".repeat(32),
            desired_running: false,
            removed: false,
            expires_at: None,
            resources: Resources {
                networks: BTreeMap::from([(
                    "backend".into(),
                    ObjectRecord {
                        name: "kmz-owned-network".into(),
                        id: "c".repeat(64),
                    },
                )]),
                ..Default::default()
            },
            secret_snapshots: BTreeMap::from([(
                "runtime".into(),
                secrets::Snapshot {
                    generation: "synthetic-generation".into(),
                    path: environment.to_str().unwrap().into(),
                    sha256: document_digest(secret),
                },
            )]),
        };
        let operation = Operation {
            kind: "komizo.operation".into(),
            version: 1,
            operation_id: installed.operation_id.clone(),
            application: installed.application.clone(),
            instance: installed.instance.clone(),
            release_digest: document.digest.clone(),
            phase: "needs_reconciliation".into(),
            ok: false,
            previous_release_digest: None,
            reconciliation_required: true,
            backup: None,
        };
        let body = String::from_utf8(
            service_configuration(&store, &installed, &document, "api", &"b".repeat(32), true)
                .unwrap()
                .bytes()
                .unwrap(),
        )
        .unwrap();
        let mut intent = ServiceIntent {
            kind: "komizo.service-creation".into(),
            version: 1,
            application: installed.application.clone(),
            instance: installed.instance.clone(),
            operation_id: operation.operation_id.clone(),
            release_digest: document.digest.clone(),
            service: "api".into(),
            record: store::ContainerRecord {
                name: format!(
                    "{}-api",
                    units::namespace("mailroom", "production").unwrap()
                ),
                id: String::new(),
                image: reference.clone(),
                config_digest: config_digest.clone(),
                release_digest: document.digest.clone(),
                ownership: "b".repeat(32),
                unit_sha256: document_digest(body.as_bytes()),
                volumes: BTreeMap::new(),
            },
            unit_body: Some(body),
        };
        validate_service_intent(&store, &intent, &operation, &installed, &document).unwrap();
        assert_eq!(service_epoch(&store, &installed).unwrap(), None);
        advance_service_epoch(&store, &installed).unwrap();
        let first_epoch = service_epoch(&store, &installed).unwrap().unwrap();
        assert!(hex(&first_epoch, 32));
        advance_service_epoch(&store, &installed).unwrap();
        assert_ne!(
            service_epoch(&store, &installed).unwrap().unwrap(),
            first_epoch
        );
        let epoch_path = service_epoch_path(&store, &installed).unwrap();
        let mut foreign: serde_json::Value =
            serde_json::from_slice(&store::read_protected(&epoch_path, 4096).unwrap()).unwrap();
        foreign["instance"] = json!("foreign");
        store::atomic(&epoch_path, &canonical(&foreign).unwrap(), 0o600).unwrap();
        assert!(service_epoch(&store, &installed).is_err());
        advance_service_epoch(&store, &installed).unwrap();
        fs::set_permissions(&epoch_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(service_epoch(&store, &installed).is_err());
        fs::set_permissions(&epoch_path, fs::Permissions::from_mode(0o600)).unwrap();
        let original_body = intent.unit_body.clone().unwrap();
        let mut forged = units::ServiceConfig::parse(original_body.as_bytes()).unwrap();
        forged.command.push("unadmitted".into());
        let forged_body = String::from_utf8(forged.bytes().unwrap()).unwrap();
        intent.record.unit_sha256 = document_digest(forged_body.as_bytes());
        intent.unit_body = Some(forged_body);
        assert!(
            validate_service_intent(&store, &intent, &operation, &installed, &document).is_err()
        );
        intent.record.unit_sha256 = document_digest(original_body.as_bytes());
        intent.unit_body = Some(original_body);
        let mut ready = operation.clone();
        ready.phase = "ready".into();
        ready.ok = true;
        ready.reconciliation_required = false;
        let mut desired = installed.clone();
        desired.desired_running = true;
        assert!(maintenance_eligible(&desired, &ready, false, 100));
        assert!(!maintenance_eligible(&desired, &ready, true, 100));
        assert!(!maintenance_eligible(&desired, &operation, false, 100));
        assert!(!maintenance_eligible(&installed, &ready, false, 100));
        desired.expires_at = Some(100);
        assert!(!maintenance_eligible(&desired, &ready, false, 100));
        desired.expires_at = None;
        ready.application = "foreign".into();
        assert!(!maintenance_eligible(&desired, &ready, false, 100));
        intent.record.ownership = "wrong".into();
        assert!(
            validate_service_intent(&store, &intent, &operation, &installed, &document).is_err()
        );
        intent.record.ownership = "b".repeat(32);
        intent.unit_body = Some("changed".into());
        assert!(
            validate_service_intent(&store, &intent, &operation, &installed, &document).is_err()
        );
        intent.kind = "komizo.service-removal".into();
        intent.unit_body = None;
        validate_service_intent(&store, &intent, &operation, &installed, &document).unwrap();
        intent
            .record
            .volumes
            .insert("foreign".into(), "foreign-data".into());
        assert!(
            validate_service_intent(&store, &intent, &operation, &installed, &document).is_err()
        );
    }
}
