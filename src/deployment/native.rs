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
    program_sha256: String,
    request_sha256: String,
    request_operation_id: String,
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
    health_units: BTreeMap<String, String>,
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

fn run_task(
    store: &Store,
    operation_id: &str,
    kind: &str,
    program: &ProtectedTask,
    input: &[u8],
    environment: &BTreeMap<String, String>,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        hex(operation_id, 32) && ["backup", "prepare", "reconcile"].contains(&kind),
        "invalid protected task scope"
    );
    ensure!(
        document_digest(&store::read_protected(
            Path::new(&program.program),
            32 << 20
        )?) == program.sha256,
        "protected executable bundle bytes changed"
    );
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_secs()
        .min(u64::from(program.timeout_seconds));
    ensure!(remaining > 0, "protected task deadline expired");
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
    let journal = store.root.join("journal").join(operation_id);
    let request_path = journal.join(format!("{kind}-request.json"));
    store::atomic(&request_path, input, 0o600)?;
    let mut body = format!(
        "[Unit]\nDescription=Komizo protected {kind} task\nRequiresMountsFor=/var/lib/komizo\n[Service]\nType=oneshot\nUser=root\nGroup=root\nSlice=komizo-control.slice\nUMask=0077\nNoNewPrivileges=yes\nKillMode=control-group\nTimeoutStartSec={remaining}s\nTimeoutStopSec=5s\nRemainAfterExit=yes\nStandardInput=file:{}\nStandardOutput=null\nStandardError=journal\nExecStart={}\n",
        request_path.display(),
        units::word(&program.program)
    );
    if kind == "reconcile" {
        let output = journal.join("reconcile-output.json");
        ensure!(!output.try_exists()?, "reconciliation output is not fresh");
        store::atomic(&output, b"", 0o600)?;
        body = body.replace(
            "StandardOutput=null\n",
            &format!(
                "StandardOutput=append:{}\nLimitFSIZE=33554432\n",
                output.display()
            ),
        );
    }
    for (key, value) in environment {
        ensure!(
            key.starts_with("KOMIZO_") || ["PATH", "HOME", "LANG"].contains(&key.as_str()),
            "unsupported protected task environment"
        );
        body.push_str(&format!(
            "Environment={}\n",
            units::word(&format!("{key}={value}"))
        ));
    }
    let path = Path::new(system::UNITS).join(&unit);
    let hash = document_digest(body.as_bytes());
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
            program_sha256: program.sha256.clone(),
            request_sha256: document_digest(input),
            request_operation_id: scope["operation_id"]
                .as_str()
                .filter(|id| hex(id, 32))
                .ok_or_else(|| anyhow!("protected task operation scope missing"))?
                .into(),
        })?,
        0o600,
    )?;
    ensure!(
        system::install_for_operation(
            store,
            &path,
            application,
            instance,
            body.as_bytes(),
            operation_id
        )? == hash,
        "protected task unit identity changed"
    );
    let system = System { deadline };
    system.reload()?;
    if kind != "reconcile" {
        super::bootstrap::apparmor_guard()?;
    }
    system.start(&unit)?;
    let status = system.run(&["show", "--property=ExecMainStatus", "--value", &unit])?;
    ensure!(
        std::str::from_utf8(&status)?.trim() == "0",
        "protected task exit evidence differs"
    );
    // Stop the owned group even after a successful leader exit, so background
    // children cannot outlive a supposedly completed capture.
    system.stop(&unit)?;
    task_quiescent(&system, &unit)?;
    store::atomic(
        &journal.join(format!("{kind}-completed.json")),
        &canonical(&json!({"unit_sha256":hash,"exit_code":0}))?,
        0o600,
    )
}

fn task_quiescent(system: &System, unit: &str) -> Result<()> {
    let state = system.run(&["show", "--property=ActiveState", "--value", unit])?;
    ensure!(
        ["inactive", "failed"].contains(&std::str::from_utf8(&state)?.trim()),
        "protected task group is not inactive"
    );
    let group = system.run(&["show", "--property=ControlGroup", "--value", unit])?;
    let group = std::str::from_utf8(&group)?.trim();
    if !group.is_empty() {
        ensure!(
            absolute(group) && group != "/",
            "protected task cgroup is ambiguous"
        );
        let events = Path::new("/sys/fs/cgroup")
            .join(group.trim_start_matches('/'))
            .join("cgroup.events");
        if events.try_exists()? {
            ensure!(
                fs::read_to_string(events)?
                    .lines()
                    .any(|line| line == "populated 0"),
                "protected task still has live descendants"
            );
        }
    }
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
        let unit = Path::new(system::UNITS).join(&intent.unit);
        if unit.try_exists()? {
            system::verify_unit(
                store,
                &unit,
                &operation.application,
                &operation.instance,
                &intent.unit_sha256,
            )?;
            system.stop(&intent.unit)?;
        } else {
            let state = system.run(&["show", "--property=LoadState", "--value", &intent.unit])?;
            ensure!(
                std::str::from_utf8(&state)?.trim() == "not-found",
                "missing task unit remains loaded and requires explicit repair"
            );
        }
        task_quiescent(system, &intent.unit)?;
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
            installed
                .resources
                .volumes
                .get(&mount.name)
                .map(|record| (mount.name.clone(), record.name.clone()))
                .ok_or_else(|| anyhow!("service intent retained volume is missing"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        intent.record.image == *reference
            && intent.record.config_digest == *config_digest
            && intent.record.volumes == volumes,
        "service creation token does not bind its complete image and volume closure"
    );
    if intent.kind == "komizo.service-creation" {
        ensure!(
            intent.record.id.is_empty()
                && intent
                    .unit_body
                    .as_ref()
                    .is_some_and(|body| body.len() <= 1 << 20
                        && document_digest(body.as_bytes()) == intent.record.unit_sha256)
                && ((service.health.is_some()
                    && intent.health_units.len() == 2
                    && ["service", "timer"]
                        .iter()
                        .all(|name| intent.health_units.contains_key(*name)))
                    || (service.health.is_none() && intent.health_units.is_empty()))
                && intent
                    .health_units
                    .values()
                    .all(|body| !body.is_empty() && body.len() <= 1 << 20),
            "service unit intent bytes are incomplete or changed"
        );
    } else {
        ensure!(
            intent.unit_body.is_none() && intent.health_units.is_empty(),
            "service removal cannot add native units"
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
    // Complete only accepted offline unit metadata and accepted removals. This
    // path never starts a service or executes a migration.
    for kind in ["removal", "creation"] {
        for entry in fs::read_dir(&journal)? {
            let entry = entry?;
            let filename = entry.file_name();
            let Some(filename) = filename.to_str() else {
                continue;
            };
            if !filename.starts_with(&format!("service-{kind}-")) {
                continue;
            }
            let intent: ServiceIntent = serde_json::from_value(bounded_value(
                &store::read_protected(&entry.path(), 4 << 20)?,
                4 << 20,
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
            if kind == "removal" && !installed.resources.containers.contains_key(&intent.service) {
                ensure!(
                    intent.application == installed.application
                        && intent.instance == installed.instance
                        && intent.operation_id == interrupted.operation_id,
                    "completed service removal intent escaped its operation"
                );
                continue;
            }
            validate_service_intent(&intent, interrupted, installed, &document)?;
            let path =
                Path::new(system::QUADLETS).join(format!("{}.container", intent.record.name));
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
                if engine.exists("container", &candidate.name)? {
                    if candidate.id.is_empty() {
                        candidate.id = engine.inspect("container", &candidate.name)?["Id"]
                            .as_str()
                            .filter(|id| hex(id, 64))
                            .ok_or_else(|| anyhow!("owned service ID unavailable"))?
                            .into();
                    }
                    engine.owned_container(
                        &candidate,
                        &installed.application,
                        &installed.instance,
                        &intent.service,
                    )?;
                }
                if path.try_exists()? {
                    system::verify_unit(
                        store,
                        &path,
                        &installed.application,
                        &installed.instance,
                        &candidate.unit_sha256,
                    )?;
                    if document.release.workload.services[&intent.service]
                        .health
                        .is_some()
                    {
                        let timer =
                            Path::new(system::UNITS).join(format!("{}-health.timer", record.name));
                        if timer.try_exists()? {
                            let bytes = store::read_protected(&timer, 1 << 20)?;
                            system::verify_unit(
                                store,
                                &timer,
                                &installed.application,
                                &installed.instance,
                                &document_digest(&bytes),
                            )?;
                            system.stop(&format!("{}-health.timer", record.name))?;
                        }
                    }
                    system.stop(&format!("{}.service", record.name))?;
                } else {
                    task_quiescent(system, &format!("{}.service", record.name))?;
                }
                if let Some(value) = engine.owned_container(
                    &candidate,
                    &installed.application,
                    &installed.instance,
                    &intent.service,
                )? {
                    ensure!(
                        value["State"]["Running"] == false,
                        "owned service still runs during removal reconciliation"
                    );
                    engine.run(&["rm", value["Id"].as_str().unwrap()])?;
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
                if document.release.workload.services[&intent.service]
                    .health
                    .is_some()
                {
                    for suffix in ["service", "timer"] {
                        let path = Path::new(system::UNITS)
                            .join(format!("{}-health.{suffix}", record.name));
                        if path.try_exists()? {
                            system::remove_for_operation(
                                store,
                                &path,
                                &installed.application,
                                &installed.instance,
                                &interrupted.operation_id,
                            )?;
                        }
                    }
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
                }
                for (suffix, body) in &intent.health_units {
                    let path = Path::new(system::UNITS)
                        .join(format!("{}-health.{suffix}", intent.record.name));
                    if !path.try_exists()? {
                        system::install_for_operation(
                            store,
                            &path,
                            &installed.application,
                            &installed.instance,
                            body.as_bytes(),
                            &interrupted.operation_id,
                        )?;
                    } else {
                        system::verify_unit(
                            store,
                            &path,
                            &installed.application,
                            &installed.instance,
                            &document_digest(body.as_bytes()),
                        )?;
                    }
                }
            }
        }
    }
    system.reload()
}

fn reconcile_container_ids(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    engine: &Engine,
    operation_id: &str,
) -> Result<()> {
    let namespace = units::namespace(&installed.application, &installed.instance)?;
    for (name, record) in &mut installed.resources.containers {
        ensure!(
            document.release.workload.services.contains_key(name)
                && record.name == format!("{namespace}-{name}"),
            "container recovery escaped its installed service"
        );
        let path = Path::new(system::QUADLETS).join(format!("{namespace}-{name}.container"));
        record.unit_sha256 = system::reconciled_unit_hash(
            store,
            &path,
            &installed.application,
            &installed.instance,
            operation_id,
            &record.unit_sha256,
        )?;
        system::verify_unit(
            store,
            &path,
            &installed.application,
            &installed.instance,
            &record.unit_sha256,
        )?;
        if record.id.is_empty() && engine.exists("container", &record.name)? {
            let value = engine.inspect("container", &record.name)?;
            let mut candidate = record.clone();
            candidate.id = value["Id"]
                .as_str()
                .filter(|id| hex(id, 64))
                .ok_or_else(|| anyhow!("created service has no native ID"))?
                .into();
            engine.owned_container(
                &candidate,
                &installed.application,
                &installed.instance,
                name,
            )?;
            super::engine::service_mounts(
                &value,
                &candidate,
                &document.release.workload.services[name],
            )?;
            *record = candidate;
        } else {
            engine.owned_container(record, &installed.application, &installed.instance, name)?;
        }
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

fn prepare_preview(
    store: &Store,
    policy: &Policy,
    job: &Job,
    operation: &mut Operation,
) -> Result<()> {
    if job.request.instance == "production" {
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
                && i.instance != job.request.instance
                && (i.desired_running || i.expires_at.is_some())
        })
        .count();
    ensure!(
        active < preview.max_instances as usize,
        "application preview capacity refuses another full instance"
    );
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
    let ns = units::namespace(&installed.application, &installed.instance)?;
    let mut ordered = order(&document)?;
    ordered.reverse();
    for name in ordered {
        let Some(container) = document.release.workload.services.get(&name) else {
            continue;
        };
        let Some(record) = installed.resources.containers.get(&name) else {
            continue;
        };
        let path = Path::new(system::QUADLETS).join(format!("{ns}-{name}.container"));
        system::verify_unit(
            store,
            &path,
            &installed.application,
            &installed.instance,
            &record.unit_sha256,
        )?;
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
                health_units: BTreeMap::new(),
            };
            store::atomic(
                &service_intent_path(store, operation_id, "removal", &name)?,
                &serde_json::to_vec(&intent)?,
                0o600,
            )?;
        }
        if container.health.is_some() {
            system.stop(&format!("{ns}-{name}-health.timer"))?;
        }
        if engine.exists("container", &record.name)? {
            engine.owned_container(record, &installed.application, &installed.instance, &name)?;
        }
        system.stop(&format!("{ns}-{name}.service"))?;
        if let Some(value) =
            engine.owned_container(record, &installed.application, &installed.instance, &name)?
        {
            ensure!(
                value["State"]["Running"] == false,
                "service remained running after stop"
            );
            if remove {
                engine.run(&["rm", value["Id"].as_str().unwrap()])?;
            }
        }
        if remove {
            system::remove_for_operation(
                store,
                &path,
                &installed.application,
                &installed.instance,
                operation_id,
            )?;
            if container.health.is_some() {
                for suffix in ["service", "timer"] {
                    system::remove_for_operation(
                        store,
                        &Path::new(system::UNITS).join(format!("{ns}-{name}-health.{suffix}")),
                        &installed.application,
                        &installed.instance,
                        operation_id,
                    )?;
                }
            }
            installed.resources.containers.remove(&name);
            store.save_installed(installed)?;
        }
    }
    if remove {
        installed.resources.containers.clear();
        store.save_installed(installed)?;
        system.reload()?;
    } else {
        wanted(store, installed, false, system, operation_id)?;
    }
    Ok(())
}

fn wanted(
    store: &Store,
    installed: &mut Installed,
    value: bool,
    system: &System,
    operation_id: &str,
) -> Result<()> {
    let ns = units::namespace(&installed.application, &installed.instance)?;
    for (name, record) in &mut installed.resources.containers {
        let path = Path::new(system::QUADLETS).join(format!("{ns}-{name}.container"));
        system::verify_unit(
            store,
            &path,
            &installed.application,
            &installed.instance,
            &record.unit_sha256,
        )?;
        let old = String::from_utf8(store::read_protected(&path, 1 << 20)?)?;
        let mut body = old
            .strip_suffix("WantedBy=multi-user.target\n")
            .unwrap_or(&old)
            .to_owned();
        ensure!(
            body.ends_with("[Install]\n"),
            "managed Quadlet install section changed"
        );
        if value {
            body.push_str("WantedBy=multi-user.target\n");
        }
        record.unit_sha256 = system::install_for_operation(
            store,
            &path,
            &installed.application,
            &installed.instance,
            body.as_bytes(),
            operation_id,
        )?;
    }
    store.save_installed(installed)?;
    system.reload()
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

fn install_units(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    system: &System,
) -> Result<()> {
    let ns = units::namespace(&installed.application, &installed.instance)?;
    for (name, container) in &document.release.workload.services {
        let ownership = store::identity()?;
        let env = installed
            .secret_snapshots
            .iter()
            .map(|(a, s)| (a.clone(), s.path.clone()))
            .collect();
        let mounts = container
            .secrets
            .iter()
            .map(|s| {
                Ok((
                    s.source.clone(),
                    secrets::mount_snapshot(
                        &store.root,
                        name,
                        s,
                        &installed.secret_snapshots[&s.source],
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let bindings = units::Bindings {
            application: &installed.application,
            instance: &installed.instance,
            release_digest: &document.digest,
            ownership: &ownership,
            networks: &installed.resources.networks,
            volumes: &installed.resources.volumes,
            environment_files: &env,
            secrets: &mounts,
            ingress: None,
        };
        let body = units::quadlet(document, name, &bindings, true)?;
        let health_units = if let Some(health) = &container.health {
            let (service, timer) =
                units::health_units(&installed.application, &installed.instance, name, health)?;
            BTreeMap::from([("service".into(), service), ("timer".into(), timer)])
        } else {
            BTreeMap::new()
        };
        let Artifact::Image {
            reference,
            config_digest,
            ..
        } = &document.release.artifacts[&container.artifact]
        else {
            return Err(anyhow!("service image missing"));
        };
        let record = store::ContainerRecord {
            name: format!("{ns}-{name}"),
            id: String::new(),
            image: reference.clone(),
            config_digest: config_digest.clone(),
            release_digest: document.digest.clone(),
            ownership,
            unit_sha256: document_digest(body.as_bytes()),
            volumes: container
                .volumes
                .iter()
                .map(|m| {
                    (
                        m.name.clone(),
                        installed.resources.volumes[&m.name].name.clone(),
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
            health_units: health_units.clone(),
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
            &Path::new(system::QUADLETS).join(format!("{ns}-{name}.container")),
            &installed.application,
            &installed.instance,
            body.as_bytes(),
            &installed.operation_id,
        )?;
        for (suffix, body) in health_units {
            system::install_for_operation(
                store,
                &Path::new(system::UNITS).join(format!("{ns}-{name}-health.{suffix}")),
                &installed.application,
                &installed.instance,
                body.as_bytes(),
                &installed.operation_id,
            )?;
        }
    }
    system.reload()
}

fn start_service(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    name: &str,
    engine: &Engine,
    system: &System,
) -> Result<()> {
    let record = &installed.resources.containers[name];
    if engine.exists("container", &record.name)? {
        engine.owned_container(record, &installed.application, &installed.instance, name)?;
    }
    system.start(&format!("{}.service", record.name))?;
    let value = engine.inspect("container", &record.name)?;
    let mut candidate = record.clone();
    candidate.id = value["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("started container ID missing"))?
        .to_owned();
    engine.owned_container(
        &candidate,
        &installed.application,
        &installed.instance,
        name,
    )?;
    installed
        .resources
        .containers
        .insert(name.to_owned(), candidate);
    store.save_installed(installed)?;
    let container = &document.release.workload.services[name];
    if container.health.is_some() {
        system.start(&format!(
            "{}-health.timer",
            installed.resources.containers[name].name
        ))?;
    }
    engine.wait_healthy(
        &installed.resources.containers[name].name,
        container.health.is_some(),
    )?;
    let observed = system.group(&format!(
        "{}.service",
        installed.resources.containers[name].name
    ))?;
    ensure!(
        observed
            .starts_with(Path::new("/sys/fs/cgroup").join(
                units::slice(&installed.application, &installed.instance)?.replace('-', "/")
            ))
            || observed
                .to_str()
                .is_some_and(|p| p
                    .contains(&units::slice(&installed.application, &installed.instance).unwrap())),
        "service escaped its instance slice"
    );
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
    system::instance_slice(store, &system, policy, &installed.instance)?;
    retained(store, installed, document, &engine)?;
    data::require(store, installed, document, &engine)?;
    install_units(store, installed, document, &system)?;
    installed.desired_running = true;
    store.save_installed(installed)?;
    for name in order(document)? {
        if document.release.workload.jobs.contains_key(&name) {
            jobs::run(
                store,
                document,
                installed,
                &name,
                &job.operation_id,
                job.deadline,
            )?;
        } else {
            start_service(store, installed, document, &name, &engine, &system)?;
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
        proxy::refresh(store, Instant::now() + Duration::from_secs(20))
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
                advance(store, operation, "staging")?;
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
                        for name in order(&old_document)? {
                            if policy
                                .backup
                                .as_ref()
                                .is_some_and(|task| task.services.contains(&name))
                            {
                                start_service(
                                    store,
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
                    system::instance_slice(store, &system, policy, instance)?;
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
            resources: Resources::default(),
            secret_snapshots: BTreeMap::new(),
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
        let body = "[Container]\nImage=accepted\n".to_owned();
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
            health_units: if document.release.workload.services["api"].health.is_some() {
                BTreeMap::from([
                    ("service".into(), "accepted service".into()),
                    ("timer".into(), "accepted timer".into()),
                ])
            } else {
                BTreeMap::new()
            },
        };
        validate_service_intent(&intent, &operation, &installed, &document).unwrap();
        intent.record.ownership = "wrong".into();
        assert!(validate_service_intent(&intent, &operation, &installed, &document).is_err());
        intent.record.ownership = "b".repeat(32);
        intent.unit_body = Some("changed".into());
        assert!(validate_service_intent(&intent, &operation, &installed, &document).is_err());
        intent.kind = "komizo.service-removal".into();
        intent.unit_body = None;
        intent.health_units.clear();
        validate_service_intent(&intent, &operation, &installed, &document).unwrap();
        intent
            .record
            .volumes
            .insert("foreign".into(), "foreign-data".into());
        assert!(validate_service_intent(&intent, &operation, &installed, &document).is_err());
    }
}
