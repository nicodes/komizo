use super::{
    model::*,
    store::{self, Installed, Store},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub identity: String,
    pub job: String,
    pub operation_id: String,
    pub release_digest: String,
    pub container_name: String,
    pub container_id: String,
    pub ownership: String,
    pub native_timeout_seconds: u32,
    pub phase: String,
    pub exit_code: Option<i32>,
}

pub fn identity(document: &ReleaseDocument, job: &str, installed: &Installed) -> Result<String> {
    let container = document
        .release
        .workload
        .jobs
        .get(job)
        .ok_or_else(|| anyhow!("unknown one-shot job"))?;
    let secrets = container
        .environment_files
        .iter()
        .chain(container.secrets.iter().map(|s| &s.source))
        .map(|a| {
            installed
                .secret_snapshots
                .get(a)
                .map(|s| (a, json!({"generation":s.generation,"sha256":s.sha256})))
                .ok_or_else(|| anyhow!("job secret generation is missing"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let volumes = container
        .volumes
        .iter()
        .map(|v| {
            installed
                .resources
                .volumes
                .get(&v.name)
                .map(|record| (&v.name, record))
                .ok_or_else(|| anyhow!("job retained volume binding is missing"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let networks = container
        .networks
        .iter()
        .map(|key| {
            installed
                .resources
                .networks
                .get(key)
                .map(|record| (key, record))
                .ok_or_else(|| anyhow!("job network binding is missing"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(document_digest(&canonical(
        &json!({"application":installed.application,"instance":installed.instance,"job":job,
                "container":container,"artifact":document.release.artifacts[&container.artifact],
                "secrets":secrets,"volumes":volumes,"networks":networks}),
    )?))
}
pub fn read(
    store: &Store,
    application: &str,
    instance: &str,
    identity: &str,
) -> Result<Option<Receipt>> {
    ensure!(
        name(application) && name(instance) && digest(identity),
        "invalid job receipt scope"
    );
    let namespace = super::units::namespace(application, instance)?;
    let path = store
        .root
        .join("jobs")
        .join(namespace)
        .join(format!("{}.json", &identity[7..]));
    if !path.try_exists()? {
        return Ok(None);
    }
    let receipt: Receipt = serde_json::from_value(crate::strict::value(
        &store::read_protected(&path, 64 << 10)?,
        64 << 10,
    )?)?;
    validate(&receipt)?;
    ensure!(
        receipt.application == application
            && receipt.instance == instance
            && receipt.identity == identity,
        "durable job receipt scope changed"
    );
    Ok(Some(receipt))
}
fn validate(receipt: &Receipt) -> Result<()> {
    let namespace = super::units::namespace(&receipt.application, &receipt.instance)?;
    ensure!(
        receipt.kind == "komizo.job"
            && receipt.version == 1
            && digest(&receipt.identity)
            && name(&receipt.job)
            && hex(&receipt.operation_id, 32)
            && digest(&receipt.release_digest)
            && hex(&receipt.ownership, 32)
            && (1..=1500).contains(&receipt.native_timeout_seconds)
            && receipt.container_name == format!("{namespace}-job-{}", &receipt.identity[7..27])
            && (receipt.container_id.is_empty() || hex(&receipt.container_id, 64))
            && match receipt.phase.as_str() {
                "starting" | "uncertain" => receipt.exit_code.is_none(),
                "running" => hex(&receipt.container_id, 64) && receipt.exit_code.is_none(),
                "completed" => hex(&receipt.container_id, 64) && receipt.exit_code == Some(0),
                "failed" =>
                    hex(&receipt.container_id, 64)
                        && receipt.exit_code.is_some_and(|n| (1..=255).contains(&n)),
                _ => false,
            },
        "invalid durable job receipt"
    );
    Ok(())
}
pub fn save(store: &Store, receipt: &Receipt) -> Result<()> {
    validate(receipt)?;
    let namespace = super::units::namespace(&receipt.application, &receipt.instance)?;
    store::atomic(
        &store
            .root
            .join("jobs")
            .join(namespace)
            .join(format!("{}.json", &receipt.identity[7..])),
        &serde_json::to_vec(receipt)?,
        0o600,
    )
}
pub fn completed(
    store: &Store,
    document: &ReleaseDocument,
    job: &str,
    installed: &Installed,
) -> Result<bool> {
    Ok(read(
        store,
        &installed.application,
        &installed.instance,
        &identity(document, job, installed)?,
    )?
    .is_some_and(|r| r.job == job && r.phase == "completed" && r.exit_code == Some(0)))
}

trait Runtime {
    fn prepare_group(&self, group: &super::cgroups::Group, limits: &Limits) -> Result<()>;
    fn workload_limits(
        &self,
        actual: &serde_json::Value,
        group: &super::cgroups::Group,
        limits: &Limits,
    ) -> Result<Option<serde_json::Value>>;
    fn kill_owned(
        &self,
        expected: &serde_json::Value,
        cleanup_deadline: std::time::Instant,
    ) -> Result<()>;
    fn retire_group(
        &self,
        group: &super::cgroups::Group,
        cleanup_deadline: std::time::Instant,
    ) -> Result<()>;
    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>>;
    fn start(&self, id: &str, deadline: std::time::Instant) -> Result<()>;
    fn exists(&self, kind: &str, name: &str) -> Result<bool>;
    fn inspect(&self, kind: &str, name: &str) -> Result<serde_json::Value>;
    fn retained(&self, kind: &str, record: &store::ObjectRecord) -> Result<()>;
}
impl Runtime for super::engine::Engine {
    fn prepare_group(&self, group: &super::cgroups::Group, limits: &Limits) -> Result<()> {
        super::cgroups::prepare(group, limits, &ResourceControls::default(), self.deadline)
    }
    fn workload_limits(
        &self,
        actual: &serde_json::Value,
        group: &super::cgroups::Group,
        limits: &Limits,
    ) -> Result<Option<serde_json::Value>> {
        self.workload_limits(actual, group, limits)
    }
    fn kill_owned(
        &self,
        expected: &serde_json::Value,
        cleanup_deadline: std::time::Instant,
    ) -> Result<()> {
        // Cleanup can outlive an expired execution budget only to terminate the
        // already-proven native identity. This helper cannot start or replay it.
        Self {
            deadline: cleanup_deadline,
        }
        .kill_owned(expected)
    }
    fn retire_group(
        &self,
        group: &super::cgroups::Group,
        cleanup_deadline: std::time::Instant,
    ) -> Result<()> {
        super::cgroups::kill(group, cleanup_deadline)?;
        super::cgroups::remove(group, cleanup_deadline)
    }
    fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        self.run(arguments)
    }
    fn start(&self, id: &str, deadline: std::time::Instant) -> Result<()> {
        Self {
            deadline: deadline.min(self.deadline),
        }
        .run(&["start", id])?;
        Ok(())
    }
    fn exists(&self, kind: &str, name: &str) -> Result<bool> {
        self.exists(kind, name)
    }
    fn inspect(&self, kind: &str, name: &str) -> Result<serde_json::Value> {
        self.inspect(kind, name)
    }
    fn retained(&self, kind: &str, record: &store::ObjectRecord) -> Result<()> {
        self.owned_object(kind, record).map(|_| ())
    }
}

fn cleanup_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(5)
}

fn job_group(receipt: &Receipt) -> Result<super::cgroups::Group> {
    super::cgroups::workload_group(
        &receipt.application,
        &receipt.instance,
        super::cgroups::WorkloadKind::Job,
        &receipt.job,
        &receipt.ownership,
    )
}

fn owned(
    runtime: &impl Runtime,
    receipt: &Receipt,
    value: &Container,
    installed: &Installed,
    config: &str,
) -> Result<serde_json::Value> {
    let actual = runtime.inspect("container", &receipt.container_name)?;
    super::engine::workload_profile(&actual)?;
    let labels = &actual["Config"]["Labels"];
    ensure!(
        hex(&receipt.container_id, 64)
            && actual["Id"] == receipt.container_id
            && actual["Name"]
                .as_str()
                .is_some_and(|n| n.trim_start_matches('/') == receipt.container_name)
            && super::engine::normalize_id(actual["Image"].as_str().unwrap_or("")) == config
            && labels["io.komizo.application"] == receipt.application
            && labels["io.komizo.instance"] == receipt.instance
            && labels["io.komizo.service"] == receipt.job
            && labels["io.komizo.release"] == receipt.release_digest
            && labels["io.komizo.ownership"] == receipt.ownership
            && labels["io.komizo.job.identity"] == receipt.identity
            && actual["Config"]["Timeout"] == receipt.native_timeout_seconds,
        "one-shot container differs from its durable ownership"
    );
    let mounts = actual["Mounts"]
        .as_array()
        .ok_or_else(|| anyhow!("job mount evidence missing"))?;
    let observed = mounts
        .iter()
        .filter(|m| m["Type"] == "volume")
        .map(|m| {
            (
                m["Name"].as_str().unwrap_or(""),
                m["Destination"].as_str().unwrap_or(""),
                m["RW"].as_bool(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let expected = value
        .volumes
        .iter()
        .map(|m| {
            Ok((
                installed
                    .resources
                    .volumes
                    .get(&m.name)
                    .ok_or_else(|| anyhow!("retained job volume binding missing"))?
                    .name
                    .as_str(),
                m.target.as_str(),
                Some(!m.read_only),
            ))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        observed == expected,
        "one-shot retained-volume mounts changed"
    );
    Ok(runtime
        .workload_limits(&actual, &job_group(receipt)?, &value.limits)?
        .unwrap_or(actual))
}

fn snapshots(value: &Container, installed: &Installed) -> Result<()> {
    for alias in value
        .environment_files
        .iter()
        .chain(value.secrets.iter().map(|s| &s.source))
    {
        let snapshot = installed
            .secret_snapshots
            .get(alias)
            .ok_or_else(|| anyhow!("job secret snapshot missing"))?;
        ensure!(
            digest(&snapshot.sha256) && !snapshot.generation.is_empty(),
            "job secret generation is incomplete"
        );
        let body = store::read_protected(std::path::Path::new(&snapshot.path), 128 << 10)?;
        ensure!(
            document_digest(&body) == snapshot.sha256,
            "job secret snapshot changed"
        );
        if value.environment_files.contains(alias) {
            super::secrets::environment_file(&body)?;
        }
    }
    Ok(())
}

fn retained(runtime: &impl Runtime, value: &Container, installed: &Installed) -> Result<()> {
    for key in &value.networks {
        runtime.retained(
            "network",
            installed
                .resources
                .networks
                .get(key)
                .ok_or_else(|| anyhow!("job network missing"))?,
        )?;
    }
    for mount in &value.volumes {
        runtime.retained(
            "volume",
            installed
                .resources
                .volumes
                .get(&mount.name)
                .ok_or_else(|| anyhow!("job volume missing"))?,
        )?;
    }
    Ok(())
}

fn environment(
    store: &Store,
    job: &str,
    value: &Container,
    installed: &Installed,
) -> Result<(BTreeMap<String, String>, BTreeMap<String, String>)> {
    let mut environment = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    for alias in &value.environment_files {
        let snapshot = installed
            .secret_snapshots
            .get(alias)
            .ok_or_else(|| anyhow!("job environment snapshot missing"))?;
        let body = store::read_protected(std::path::Path::new(&snapshot.path), 128 << 10)?;
        ensure!(
            document_digest(&body) == snapshot.sha256,
            "job environment snapshot changed"
        );
        super::secrets::environment_file(&body)?;
        environment.insert(alias.clone(), snapshot.path.clone());
    }
    for secret in &value.secrets {
        let snapshot = installed
            .secret_snapshots
            .get(&secret.source)
            .ok_or_else(|| anyhow!("job mounted snapshot missing"))?;
        secrets.insert(
            secret.source.clone(),
            super::secrets::mount_snapshot(&store.root, job, secret, snapshot)?,
        );
    }
    Ok((environment, secrets))
}

/// Run under the caller's instance lock. The durable intent precedes creation;
/// any interrupted or unproven attempt requires owner reconciliation, never replay.
pub fn run(
    store: &Store,
    policy: &Policy,
    document: &ReleaseDocument,
    installed: &Installed,
    job: &str,
    operation_id: &str,
    deadline: std::time::Instant,
) -> Result<Receipt> {
    document.release.validate()?;
    policy.validate()?;
    let value = document
        .release
        .workload
        .jobs
        .get(job)
        .ok_or_else(|| anyhow!("unknown one-shot job"))?;
    let timeout = value
        .timeout_seconds
        .ok_or_else(|| anyhow!("job timeout missing"))?;
    let deadline = deadline
        .min(std::time::Instant::now() + std::time::Duration::from_secs(u64::from(timeout)));
    run_with(
        store,
        policy,
        document,
        installed,
        job,
        JobExecution {
            operation_id,
            deadline,
        },
        &super::engine::Engine { deadline },
    )
}

struct JobExecution<'a> {
    operation_id: &'a str,
    deadline: std::time::Instant,
}

fn run_with(
    store: &Store,
    policy: &Policy,
    document: &ReleaseDocument,
    installed: &Installed,
    job: &str,
    execution: JobExecution<'_>,
    runtime: &impl Runtime,
) -> Result<Receipt> {
    let JobExecution {
        operation_id,
        deadline,
    } = execution;
    ensure!(
        std::time::Instant::now() < deadline
            && installed.kind == "komizo.installed"
            && installed.version == 1
            && installed.application == document.release.application
            && policy.kind == "komizo.policy"
            && policy.version == 1
            && policy.application == installed.application
            && installed.release_digest == document.digest
            && installed.operation_id == operation_id
            && hex(operation_id, 32),
        "job does not belong to this staged operation or its deadline expired"
    );
    let value = document
        .release
        .workload
        .jobs
        .get(job)
        .ok_or_else(|| anyhow!("unknown one-shot job"))?;
    let Artifact::Image { config_digest, .. } = &document.release.artifacts[&value.artifact] else {
        return Err(anyhow!("job artifact is not an image"));
    };
    let group_limits = if installed.instance == "production" {
        &policy.limits
    } else {
        &policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview job allocation missing"))?
            .limits
    };
    group_limits.validate()?;
    snapshots(value, installed)?;
    retained(runtime, value, installed)?;
    let identity = identity(document, job, installed)?;
    if let Some(mut receipt) = read(
        store,
        &installed.application,
        &installed.instance,
        &identity,
    )? {
        ensure!(
            receipt.job == job,
            "job receipt selects a different declaration"
        );
        if receipt.phase == "completed" && receipt.exit_code == Some(0) {
            if runtime.exists("container", &receipt.container_name)? {
                let actual = owned(runtime, &receipt, value, installed, config_digest)?;
                ensure!(
                    actual["State"]["Running"] == false && actual["State"]["ExitCode"] == 0,
                    "completed job no longer has its proven native exit state"
                );
            }
            runtime.retire_group(&job_group(&receipt)?, cleanup_deadline())?;
            return Ok(receipt);
        }
        if ["starting", "running"].contains(&receipt.phase.as_str()) {
            receipt.phase = "uncertain".into();
            save(store, &receipt)?;
        }
        return Err(anyhow!(
            "one-shot outcome requires owner reconciliation; automatic replay refused"
        ));
    }
    let (environment_files, secrets) = environment(store, job, value, installed)?;
    // conmon enforces this lifetime even when the controller dies. Reserve
    // time for native creation/start and its second-rounded timer, then refuse
    // a delayed start rather than allowing effects beyond the admitted budget.
    let timeout = native_timeout(
        deadline,
        std::time::Instant::now(),
        value.timeout_seconds.unwrap(),
    )?;
    let mut receipt = Receipt {
        kind: "komizo.job".into(),
        version: 1,
        application: installed.application.clone(),
        instance: installed.instance.clone(),
        identity: identity.clone(),
        job: job.to_owned(),
        operation_id: operation_id.to_owned(),
        release_digest: document.digest.clone(),
        container_name: format!(
            "{}-job-{}",
            super::units::namespace(&installed.application, &installed.instance)?,
            &identity[7..27]
        ),
        container_id: String::new(),
        ownership: store::identity()?,
        native_timeout_seconds: timeout,
        phase: "starting".into(),
        exit_code: None,
    };
    ensure!(
        !runtime.exists("container", &receipt.container_name)?,
        "unrecorded job container prevents creation"
    );
    let bindings = super::units::Bindings {
        application: &receipt.application,
        instance: &receipt.instance,
        release_digest: &receipt.release_digest,
        ownership: &receipt.ownership,
        networks: &installed.resources.networks,
        volumes: &installed.resources.volumes,
        environment_files: &environment_files,
        secrets: &secrets,
        ingress: None,
    };
    let mut arguments = vec![
        "create".to_owned(),
        "--name".into(),
        receipt.container_name.clone(),
        "--timeout".into(),
        timeout.to_string(),
        "--label".into(),
        format!("io.komizo.job.identity={identity}"),
    ];
    arguments.extend(super::units::options(
        super::cgroups::WorkloadKind::Job,
        job,
        value,
        &bindings,
    )?);
    arguments.push(config_digest.clone());
    arguments.extend(value.command.iter().cloned());
    save(store, &receipt)?;
    let group = job_group(&receipt)?;
    runtime.prepare_group(&group, group_limits)?;
    let mut before_start = None;
    let mut start_attempted = false;
    let effect = (|| -> Result<()> {
        let output = runtime.run(&arguments.iter().map(String::as_str).collect::<Vec<_>>())?;
        let id = std::str::from_utf8(&output)?.trim();
        ensure!(
            hex(id, 64),
            "job creation returned no complete native identity"
        );
        receipt.container_id = id.to_owned();
        save(store, &receipt)?;
        let created = owned(runtime, &receipt, value, installed, config_digest)?;
        ensure!(
            created["State"]["Running"] == false
                && created["State"]["Paused"] == false
                && created["State"]["Pid"] == 0
                && ["configured", "created"]
                    .contains(&created["State"]["Status"].as_str().unwrap_or("")),
            "new job already executed before its proven native start"
        );
        before_start = Some(created);
        let start_deadline = deadline - std::time::Duration::from_secs(u64::from(timeout) + 2);
        ensure!(
            std::time::Instant::now() < start_deadline,
            "job preparation exhausted its native lifetime reservation; start refused"
        );
        start_attempted = true;
        runtime.start(&receipt.container_id, start_deadline)?;
        owned(runtime, &receipt, value, installed, config_digest)?;
        receipt.phase = "running".into();
        save(store, &receipt)?;
        let output = runtime.run(&[
            "wait",
            "--condition=stopped",
            "--interval=100ms",
            &receipt.container_id,
        ])?;
        let exit: i32 = std::str::from_utf8(&output)?.trim().parse()?;
        ensure!(
            (0..=255).contains(&exit),
            "job wait returned an invalid exit code"
        );
        let actual = owned(runtime, &receipt, value, installed, config_digest)?;
        ensure!(
            actual["State"]["Running"] == false
                && actual["State"]["ExitCode"] == exit
                && actual["State"]["FinishedAt"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && !s.starts_with("0001-")),
            "job exit was not independently proven by the native engine"
        );
        receipt.exit_code = Some(exit);
        receipt.phase = if exit == 0 { "completed" } else { "failed" }.into();
        save(store, &receipt)?;
        ensure!(exit == 0, "one-shot job exited unsuccessfully");
        Ok(())
    })();
    // Every return after successful allocation retires the exact owned payload
    // and monitor subtree. Keep the native container and durable result for
    // owner reconciliation; a failed operation never creates a new attempt.
    // The immutable pre-start inspection was already proven against the
    // durable receipt. Native KILL also reaches a monitor/payload that failed
    // attachment to its expected kernel group; never select a replacement ID.
    let cleanup_deadline = cleanup_deadline();
    let termination = if effect.is_err() && start_attempted {
        runtime.kill_owned(
            before_start
                .as_ref()
                .expect("verified inspection precedes start"),
            cleanup_deadline,
        )
    } else {
        Ok(())
    };
    let retirement = runtime.retire_group(&group, cleanup_deadline);
    if let Err(error) = effect {
        if !["completed", "failed"].contains(&receipt.phase.as_str()) {
            receipt.phase = "uncertain".into();
            save(store, &receipt)?;
        }
        if termination.is_err() {
            return Err(
                error.context("job failed and exact owned native termination remains unproven")
            );
        }
        if retirement.is_err() {
            return Err(error.context("job failed and owned cgroup retirement remains unproven"));
        }
        return Err(error);
    }
    retirement?;
    Ok(receipt)
}

fn native_timeout(
    deadline: std::time::Instant,
    now: std::time::Instant,
    declared: u32,
) -> Result<u32> {
    let remaining = deadline.saturating_duration_since(now).as_secs();
    let timeout = remaining.saturating_sub(4).min(u64::from(declared));
    ensure!(
        timeout > 0,
        "job deadline cannot contain native startup and lifetime bounds"
    );
    Ok(timeout as u32)
}

/// Explicit owner recovery may prove an interrupted exit, but never starts,
/// recreates or removes a job. A missing or still-running result remains blocked.
pub fn reconcile(
    store: &Store,
    document: &ReleaseDocument,
    installed: &Installed,
    operation_id: &str,
    deadline: std::time::Instant,
) -> Result<()> {
    reconcile_with_evidence(store, document, installed, operation_id, deadline, false)
}

/// A separately admitted ephemeral instance removal may cancel and remove its
/// exact jobs. Their durable completed/failed/uncertain receipts remain intact.
pub fn cleanup_ephemeral(
    store: &Store,
    installed: &Installed,
    operation_id: &str,
    deadline: std::time::Instant,
) -> Result<()> {
    cleanup_ephemeral_with(
        store,
        installed,
        operation_id,
        &super::engine::Engine { deadline },
    )
}
fn cleanup_ephemeral_with(
    store: &Store,
    installed: &Installed,
    operation_id: &str,
    runtime: &impl Runtime,
) -> Result<()> {
    ensure!(
        installed.instance != "production" && hex(operation_id, 32),
        "job removal requires an admitted ephemeral instance"
    );
    let directory = store.root.join("jobs").join(super::units::namespace(
        &installed.application,
        &installed.instance,
    )?);
    if !directory.try_exists()? {
        return Ok(());
    }
    let mut count = 0;
    for entry in std::fs::read_dir(directory)? {
        count += 1;
        ensure!(
            count <= 16384,
            "job cleanup exceeds its bounded receipt inventory"
        );
        let path = entry?.path();
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("invalid job receipt member"))?;
        if store::pending(&path, 64 << 10)? {
            continue;
        }
        let id = filename
            .strip_suffix(".json")
            .filter(|id| hex(id, 64))
            .ok_or_else(|| anyhow!("unexpected job receipt member"))?;
        let mut receipt = read(
            store,
            &installed.application,
            &installed.instance,
            &format!("sha256:{id}"),
        )?
        .ok_or_else(|| anyhow!("job receipt disappeared during cleanup"))?;
        if !runtime.exists("container", &receipt.container_name)? {
            runtime.retire_group(&job_group(&receipt)?, cleanup_deadline())?;
            continue;
        }
        let document = store.release(&receipt.release_digest)?;
        ensure!(
            document.release.application == installed.application,
            "job removal source belongs to another application"
        );
        let value = document
            .release
            .workload
            .jobs
            .get(&receipt.job)
            .ok_or_else(|| anyhow!("job removal source declaration missing"))?;
        let Artifact::Image { config_digest, .. } = &document.release.artifacts[&value.artifact]
        else {
            return Err(anyhow!("job removal has no immutable image authority"));
        };
        retained(runtime, value, installed)?;
        if receipt.container_id.is_empty() {
            let actual = runtime.inspect("container", &receipt.container_name)?;
            receipt.container_id = actual["Id"]
                .as_str()
                .filter(|id| hex(id, 64))
                .ok_or_else(|| anyhow!("job removal has no actual native ID"))?
                .into();
            owned(runtime, &receipt, value, installed, config_digest)?;
            receipt.phase = "uncertain".into();
            save(store, &receipt)?;
        }
        owned(runtime, &receipt, value, installed, config_digest)?;
        let intent = store
            .root
            .join("journal")
            .join(operation_id)
            .join(format!("job-removal-{id}.json"));
        store::atomic(
            &intent,
            &canonical(
                &json!({"kind":"komizo.job-removal","version":1,"operation_id":operation_id,"application":installed.application,"instance":installed.instance,"receipt":receipt,"config_digest":config_digest}),
            )?,
            0o600,
        )?;
        runtime.retire_group(&job_group(&receipt)?, cleanup_deadline())?;
        runtime.run(&["rm", "--force", "--", &receipt.container_id])?;
        ensure!(
            !runtime.exists("container", &receipt.container_name)?,
            "ephemeral job removal remains uncertain"
        );
    }
    Ok(())
}

pub fn log_id(
    store: &Store,
    document: &ReleaseDocument,
    installed: &Installed,
    job: &str,
    deadline: std::time::Instant,
) -> Result<String> {
    let value = document
        .release
        .workload
        .jobs
        .get(job)
        .ok_or_else(|| anyhow!("job is not installed"))?;
    let receipt = read(
        store,
        &installed.application,
        &installed.instance,
        &identity(document, job, installed)?,
    )?
    .ok_or_else(|| anyhow!("job has no recorded execution"))?;
    let engine = super::engine::Engine { deadline };
    if engine.exists("container", &receipt.container_name)? {
        let Artifact::Image { config_digest, .. } = &document.release.artifacts[&value.artifact]
        else {
            return Err(anyhow!("job image identity missing"));
        };
        owned(&engine, &receipt, value, installed, config_digest)?;
    }
    ensure!(
        hex(&receipt.container_id, 64),
        "job has no recorded native ID"
    );
    Ok(receipt.container_id)
}

/// The caller must independently authenticate root-owned data recovery evidence
/// before setting allow_failed. This resolves the operation, never the job cache.
pub fn reconcile_with_evidence(
    store: &Store,
    document: &ReleaseDocument,
    installed: &Installed,
    operation_id: &str,
    deadline: std::time::Instant,
    allow_failed: bool,
) -> Result<()> {
    reconcile_with(
        store,
        document,
        installed,
        operation_id,
        &super::engine::Engine { deadline },
        allow_failed,
    )
}
fn reconcile_with(
    store: &Store,
    document: &ReleaseDocument,
    installed: &Installed,
    operation_id: &str,
    runtime: &impl Runtime,
    allow_failed: bool,
) -> Result<()> {
    ensure!(
        hex(operation_id, 32)
            && installed.operation_id == operation_id
            && installed.application == document.release.application
            && installed.release_digest == document.digest,
        "job recovery does not select the staged operation"
    );
    for (job, value) in &document.release.workload.jobs {
        let Some(mut receipt) = read(
            store,
            &installed.application,
            &installed.instance,
            &identity(document, job, installed)?,
        )?
        else {
            continue;
        };
        if receipt.operation_id != operation_id {
            continue;
        }
        ensure!(
            receipt.job == *job && receipt.release_digest == document.digest,
            "job recovery receipt differs from the interrupted release"
        );
        let Artifact::Image { config_digest, .. } = &document.release.artifacts[&value.artifact]
        else {
            return Err(anyhow!("job recovery artifact is not an image"));
        };
        retained(runtime, value, installed)?;
        if receipt.phase == "completed" {
            if runtime.exists("container", &receipt.container_name)? {
                let actual = owned(runtime, &receipt, value, installed, config_digest)?;
                ensure!(
                    actual["State"]["Running"] == false
                        && actual["State"]["Paused"] == false
                        && actual["State"]["Pid"] == 0
                        && actual["State"]["ExitCode"] == 0
                        && ["exited", "stopped"]
                            .contains(&actual["State"]["Status"].as_str().unwrap_or(""))
                        && actual["State"]["FinishedAt"]
                            .as_str()
                            .is_some_and(|time| !time.is_empty() && !time.starts_with("0001-")),
                    "completed job no longer has its proven terminal native state"
                );
            }
            // Exit proof does not imply the later cleanup barrier succeeded.
            // Reconcile the exact group without starting or replaying the job.
            runtime.retire_group(&job_group(&receipt)?, cleanup_deadline())?;
            continue;
        }
        ensure!(
            (receipt.phase != "failed" || allow_failed),
            "failed job requires a corrected job identity before deployment"
        );
        let actual = owned(runtime, &receipt, value, installed, config_digest)?;
        let exit = actual["State"]["ExitCode"]
            .as_i64()
            .filter(|n| (0..=255).contains(n));
        ensure!(
            actual["State"]["Running"] == false
                && ["exited", "stopped"]
                    .contains(&actual["State"]["Status"].as_str().unwrap_or(""))
                && actual["State"]["FinishedAt"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && !s.starts_with("0001-"))
                && exit.is_some(),
            "interrupted job has no independently proven native exit"
        );
        runtime.retire_group(&job_group(&receipt)?, cleanup_deadline())?;
        receipt.exit_code = exit.map(|n| n as i32);
        receipt.phase = if exit == Some(0) {
            "completed"
        } else {
            "failed"
        }
        .into();
        save(store, &receipt)?;
        ensure!(
            exit == Some(0) || allow_failed,
            "interrupted job exited unsuccessfully; replay refused"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::{
        cell::RefCell,
        time::{Duration, Instant},
    };

    struct Fixture {
        _directory: tempfile::TempDir,
        store: Store,
        document: ReleaseDocument,
        policy: Policy,
        installed: Installed,
    }
    impl Fixture {
        fn new() -> Self {
            let directory =
                tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
            let store = Store::new(directory.path().join("state")).unwrap();
            let mut release: Value =
                serde_json::from_str(include_str!("../../tests/fixtures/deployment/release.json"))
                    .unwrap();
            let mut job = release["workload"]["services"]["api"].clone();
            job.as_object_mut().unwrap().remove("health");
            job["command"] = json!(["/app/server", "migrate"]);
            job["timeout_seconds"] = json!(30);
            job["volumes"] = json!([{"name":"data","target":"/var/lib/app"}]);
            release["workload"]["jobs"]["migrate"] = job;
            release["workload"]["volumes"]["data"] = json!({});
            let document = read_release(&serde_json::to_vec(&release).unwrap()).unwrap();
            store.save_release(&document).unwrap();
            let path = store.root.join("runtime.env");
            store::atomic(&path, b"PRIVATE_TOKEN=do-not-log-this\n", 0o600).unwrap();
            let installed = Installed {
                kind: "komizo.installed".into(),
                version: 1,
                application: "mailroom".into(),
                instance: "production".into(),
                release_digest: document.digest.clone(),
                operation_id: "a".repeat(32),
                desired_running: true,
                removed: false,
                expires_at: None,
                resources: store::Resources {
                    networks: BTreeMap::from([(
                        "backend".into(),
                        store::ObjectRecord {
                            name: "kmz-owned-network".into(),
                            id: "b".repeat(64),
                        },
                    )]),
                    volumes: BTreeMap::from([(
                        "data".into(),
                        store::ObjectRecord {
                            name: "kmz-owned-data".into(),
                            id: format!("sha256:{}", "c".repeat(64)),
                        },
                    )]),
                    ..Default::default()
                },
                secret_snapshots: BTreeMap::from([(
                    "runtime".into(),
                    super::super::secrets::Snapshot {
                        generation: "generation-one".into(),
                        path: path.to_str().unwrap().into(),
                        sha256: document_digest(b"PRIVATE_TOKEN=do-not-log-this\n"),
                    },
                )]),
            };
            let policy = serde_json::from_value(json!({
                "kind":"komizo.policy","version":1,"application":"mailroom",
                "authority":{"kind":"owner"},"artifact_prefixes":["ghcr.io/example/mailroom"],
                "hostnames":["api.mail.example"],
                "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},
                "readiness":[{"url":"https://api.mail.example/readyz","status":200}],
                "previews":{"hostname_suffix":"preview.mail.example","max_instances":4,"max_ttl_seconds":3600,
                    "limits":{"memory_bytes":134217728,"memory_swap_bytes":134217728,"milli_cpus":250,"pids":128}}
            })).unwrap();
            Self {
                _directory: directory,
                store,
                document,
                policy,
                installed,
            }
        }
        fn receipt(&self) -> Option<Receipt> {
            read(
                &self.store,
                "mailroom",
                &self.installed.instance,
                &identity(&self.document, "migrate", &self.installed).unwrap(),
            )
            .unwrap()
        }
        fn run(&self, runtime: &Fake<'_>) -> Result<Receipt> {
            run_with(
                &self.store,
                &self.policy,
                &self.document,
                &self.installed,
                "migrate",
                JobExecution {
                    operation_id: &self.installed.operation_id,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
                runtime,
            )
        }
    }
    struct Fake<'a> {
        fixture: &'a Fixture,
        calls: RefCell<Vec<Vec<String>>>,
        container: RefCell<Option<Value>>,
        fail: Option<&'static str>,
        exit: i32,
        corrupt_owner: bool,
        corrupt_mount: bool,
        corrupt_timeout: bool,
        corrupt_parent: bool,
        fail_group: Option<&'static str>,
        fresh_terminal: Option<i32>,
        escaped_process: Option<&'static str>,
        fail_kill: bool,
        cleanup_operation: Option<String>,
        groups: RefCell<Vec<(String, String)>>,
        cleanup_deadlines: RefCell<Vec<Instant>>,
    }
    impl<'a> Fake<'a> {
        fn new(fixture: &'a Fixture) -> Self {
            Self {
                fixture,
                calls: RefCell::new(vec![]),
                container: RefCell::new(None),
                fail: None,
                exit: 0,
                corrupt_owner: false,
                corrupt_mount: false,
                corrupt_timeout: false,
                corrupt_parent: false,
                fail_group: None,
                fresh_terminal: None,
                escaped_process: None,
                fail_kill: false,
                cleanup_operation: None,
                groups: RefCell::new(Vec::new()),
                cleanup_deadlines: RefCell::new(Vec::new()),
            }
        }
    }
    impl Runtime for Fake<'_> {
        fn prepare_group(
            &self,
            group: &super::super::cgroups::Group,
            limits: &Limits,
        ) -> Result<()> {
            let receipt = self
                .fixture
                .receipt()
                .expect("intent precedes cgroup allocation");
            assert_eq!(group, &job_group(&receipt)?);
            let expected = if self.fixture.installed.instance == "production" {
                &self.fixture.policy.limits
            } else {
                &self.fixture.policy.previews.as_ref().unwrap().limits
            };
            assert_eq!(limits.memory_bytes, expected.memory_bytes);
            assert_eq!(limits.milli_cpus, expected.milli_cpus);
            self.groups
                .borrow_mut()
                .push(("prepare".into(), group.relative().into()));
            ensure!(
                self.fail_group != Some("prepare"),
                "synthetic cgroup allocation failure"
            );
            Ok(())
        }
        fn workload_limits(
            &self,
            actual: &Value,
            group: &super::super::cgroups::Group,
            limits: &Limits,
        ) -> Result<Option<Value>> {
            assert_eq!(
                limits.memory_bytes,
                self.fixture.document.release.workload.jobs["migrate"]
                    .limits
                    .memory_bytes
            );
            ensure!(
                actual["HostConfig"]["CgroupParent"] == group.relative(),
                "job cgroup parent differs"
            );
            self.groups
                .borrow_mut()
                .push(("verify".into(), group.relative().into()));
            ensure!(
                actual["State"]["Running"] != true || self.escaped_process.is_none(),
                "synthetic payload or monitor escaped its cgroup"
            );
            if let Some(exit) = self.fresh_terminal
                && actual["State"]["Running"] == true
            {
                let mut terminal = actual.clone();
                terminal["State"] = json!({"Running":false,"Paused":false,"Pid":0,"Status":"exited",
                    "ExitCode":exit,"FinishedAt":"2026-01-01T00:00:00Z"});
                return Ok(Some(terminal));
            }
            Ok(None)
        }
        fn kill_owned(&self, expected: &Value, cleanup_deadline: Instant) -> Result<()> {
            self.cleanup_deadlines.borrow_mut().push(cleanup_deadline);
            let receipt = self.fixture.receipt().unwrap();
            let mut current = self.container.borrow_mut();
            let actual = current
                .as_mut()
                .ok_or_else(|| anyhow!("owned job disappeared"))?;
            assert_eq!(expected["Id"], receipt.container_id);
            assert_eq!(actual["Id"], expected["Id"]);
            for key in [
                "Config",
                "HostConfig",
                "Mounts",
                "Image",
                "Name",
                "AppArmorProfile",
            ] {
                ensure!(
                    actual[key] == expected[key],
                    "native termination refused changed ownership"
                );
            }
            self.groups
                .borrow_mut()
                .push(("kill".into(), job_group(&receipt)?.relative().into()));
            ensure!(!self.fail_kill, "synthetic native termination failure");
            actual["State"]["Running"] = json!(false);
            actual["State"]["Status"] = json!("exited");
            // Killing an unproven attempt does not authenticate a job outcome.
            Ok(())
        }
        fn retire_group(
            &self,
            group: &super::super::cgroups::Group,
            cleanup_deadline: Instant,
        ) -> Result<()> {
            self.cleanup_deadlines.borrow_mut().push(cleanup_deadline);
            self.groups
                .borrow_mut()
                .push(("retire".into(), group.relative().into()));
            ensure!(
                self.fail_group != Some("retire"),
                "synthetic cgroup retirement failure"
            );
            Ok(())
        }
        fn start(&self, id: &str, deadline: Instant) -> Result<()> {
            ensure!(
                Instant::now() < deadline,
                "synthetic start deadline expired"
            );
            self.run(&["start", id])?;
            Ok(())
        }
        fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).into()).collect());
            let receipt = self
                .fixture
                .receipt()
                .expect("durable intent must precede every native effect");
            ensure!(
                self.fail != Some(args[0]),
                "synthetic interrupted native operation"
            );
            match args[0] {
                "create" => {
                    assert_eq!(receipt.phase, "starting");
                    assert!(receipt.container_id.is_empty());
                    assert!(args.contains(&"--pull=never"));
                    assert!(args.contains(&"--read-only"));
                    assert!(args.contains(&"--timeout"));
                    assert!(args.contains(&"--cgroup-parent"));
                    assert!(args.contains(&"--env-file"));
                    assert!(!args.join(" ").contains("do-not-log-this"));
                    let mut labels = serde_json::Map::new();
                    for pair in args.windows(2).filter(|pair| pair[0] == "--label") {
                        let (key, value) = pair[1].split_once('=').unwrap();
                        labels.insert(key.into(), json!(value));
                    }
                    if self.corrupt_owner {
                        labels.insert("io.komizo.ownership".into(), json!("f".repeat(32)));
                    }
                    let mut value = json!({"Id":"d".repeat(64),"Name":receipt.container_name,
                        "Image":format!("sha256:{}","c".repeat(64)),"Config":{"Labels":labels,"Timeout":receipt.native_timeout_seconds},
                        "AppArmorProfile":super::super::bootstrap::WORKLOAD_PROFILE,
                        "HostConfig":{"CgroupParent":args.windows(2).find(|pair| pair[0] == "--cgroup-parent").unwrap()[1]},
                        "State":{"Running":false,"Paused":false,"Pid":0,"Status":"configured","ExitCode":0,"FinishedAt":"0001-01-01T00:00:00Z"},
                        "Mounts":[{"Type":"volume","Name":"kmz-owned-data","Destination":"/var/lib/app","RW":true}]});
                    if self.corrupt_mount {
                        value["Mounts"][0]["Name"] = json!("foreign-data");
                    }
                    if self.corrupt_parent {
                        value["HostConfig"]["CgroupParent"] = json!("/komizo/production/foreign");
                    }
                    if self.corrupt_timeout {
                        value["Config"]["Timeout"] = json!(1500);
                    }
                    *self.container.borrow_mut() = Some(value);
                    Ok(format!("{}\n", "d".repeat(64)).into_bytes())
                }
                "start" => {
                    assert_eq!(receipt.container_id, "d".repeat(64));
                    assert_eq!(receipt.phase, "starting");
                    let mut container = self.container.borrow_mut();
                    let state = &mut container.as_mut().unwrap()["State"];
                    state["Running"] = json!(true);
                    state["Status"] = json!("running");
                    Ok(vec![])
                }
                "wait" => {
                    assert_eq!(receipt.phase, "running");
                    let mut container = self.container.borrow_mut();
                    let state = &mut container.as_mut().unwrap()["State"];
                    state["Running"] = json!(false);
                    state["Status"] = json!("exited");
                    state["ExitCode"] = json!(self.exit);
                    state["FinishedAt"] = json!("2026-01-01T00:00:00Z");
                    Ok(format!("{}\n", self.exit).into_bytes())
                }
                "rm" => {
                    let operation = self
                        .cleanup_operation
                        .as_ref()
                        .expect("only explicitly authorized ephemeral cleanup may remove jobs");
                    assert_eq!(args, ["rm", "--force", "--", receipt.container_id.as_str()]);
                    let path = self
                        .fixture
                        .store
                        .root
                        .join("journal")
                        .join(operation)
                        .join(format!("job-removal-{}.json", &receipt.identity[7..]));
                    let intent: Value =
                        serde_json::from_slice(&store::read_protected(&path, 64 << 10)?).unwrap();
                    assert_eq!(intent["receipt"]["ownership"], receipt.ownership);
                    assert_eq!(intent["receipt"]["container_id"], receipt.container_id);
                    *self.container.borrow_mut() = None;
                    Ok(vec![])
                }
                _ => panic!("unowned or destructive native operation"),
            }
        }
        fn exists(&self, _kind: &str, _name: &str) -> Result<bool> {
            Ok(self.container.borrow().is_some())
        }
        fn inspect(&self, _kind: &str, _name: &str) -> Result<Value> {
            self.container
                .borrow()
                .clone()
                .ok_or_else(|| anyhow!("container missing"))
        }
        fn retained(&self, _kind: &str, _record: &store::ObjectRecord) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_payload_or_monitor_attachment_terminates_only_the_previously_owned_native_id() {
        for escaped in ["payload", "monitor"] {
            for fail_kill in [false, true] {
                let fixture = Fixture::new();
                let mut runtime = Fake::new(&fixture);
                runtime.escaped_process = Some(escaped);
                runtime.fail_kill = fail_kill;
                let error = fixture.run(&runtime).unwrap_err();
                let receipt = fixture.receipt().unwrap();
                assert_eq!(receipt.phase, "uncertain");
                assert_eq!(receipt.exit_code, None);
                assert_eq!(
                    runtime
                        .calls
                        .borrow()
                        .iter()
                        .map(|a| a[0].as_str())
                        .collect::<Vec<_>>(),
                    ["create", "start"]
                );
                let events = runtime.groups.borrow();
                assert_eq!(events[events.len() - 2].0, "kill");
                assert_eq!(events.last().unwrap().0, "retire");
                let deadlines = runtime.cleanup_deadlines.borrow();
                assert_eq!(deadlines.len(), 2);
                assert_eq!(deadlines[0], deadlines[1]);
                assert!(deadlines[0] <= Instant::now() + Duration::from_secs(5));
                assert!(format!("{error:#}").contains("escaped its cgroup"));
                if fail_kill {
                    assert!(error.to_string().contains("termination remains unproven"));
                }
                assert_eq!(
                    runtime.container.borrow().as_ref().unwrap()["State"]["Running"],
                    fail_kill
                );
                let count = runtime.calls.borrow().len();
                assert!(fixture.run(&runtime).is_err());
                assert_eq!(runtime.calls.borrow().len(), count);
            }
        }
    }

    #[test]
    fn finite_job_owned_evidence_returns_fresh_terminal_exit_without_reclassifying_it() {
        let fixture = Fixture::new();
        let mut runtime = Fake::new(&fixture);
        runtime.fail = Some("wait");
        assert!(fixture.run(&runtime).is_err());
        runtime.container.borrow_mut().as_mut().unwrap()["State"]["Running"] = json!(true);
        runtime.fresh_terminal = Some(19);
        let receipt = fixture.receipt().unwrap();
        let value = &fixture.document.release.workload.jobs["migrate"];
        let Artifact::Image { config_digest, .. } =
            &fixture.document.release.artifacts[&value.artifact]
        else {
            panic!()
        };
        let actual = owned(&runtime, &receipt, value, &fixture.installed, config_digest).unwrap();
        assert_eq!(actual["State"]["Running"], false);
        assert_eq!(actual["State"]["ExitCode"], 19);
        assert_eq!(
            runtime.container.borrow().as_ref().unwrap()["State"]["Running"],
            true
        );
        reconcile_with(
            &fixture.store,
            &fixture.document,
            &fixture.installed,
            &fixture.installed.operation_id,
            &runtime,
            true,
        )
        .unwrap();
        assert_eq!(fixture.receipt().unwrap().phase, "failed");
        assert_eq!(fixture.receipt().unwrap().exit_code, Some(19));
        assert!(fixture.run(&runtime).is_err());
    }

    #[test]
    fn job_workloads_have_distinct_owned_parents_and_retire_after_each_attempt() {
        for instance in ["production", "pr-1"] {
            let mut fixture = Fixture::new();
            fixture.installed.instance = instance.into();
            let runtime = Fake::new(&fixture);
            let receipt = fixture.run(&runtime).unwrap();
            let group = job_group(&receipt).unwrap();
            let service = super::super::cgroups::workload_group(
                "mailroom",
                instance,
                super::super::cgroups::WorkloadKind::Service,
                "migrate",
                &receipt.ownership,
            )
            .unwrap();
            assert_ne!(group, service);
            let events = runtime.groups.borrow();
            assert_eq!(events.first().unwrap().0, "prepare");
            assert_eq!(events.last().unwrap().0, "retire");
            assert!(events.iter().all(|(_, parent)| parent == group.relative()));
            assert_eq!(
                events.iter().filter(|(kind, _)| kind == "verify").count(),
                3
            );
        }
        for command in ["create", "start", "wait"] {
            let fixture = Fixture::new();
            let mut runtime = Fake::new(&fixture);
            runtime.fail = Some(command);
            assert!(fixture.run(&runtime).is_err());
            assert_eq!(runtime.groups.borrow().last().unwrap().0, "retire");
            assert_eq!(fixture.receipt().unwrap().phase, "uncertain");
        }
    }
    #[test]
    fn unprepared_or_foreign_job_parent_refuses_execution_and_cleanup_failure_blocks_success() {
        for phase in ["prepare", "retire", "foreign"] {
            let fixture = Fixture::new();
            let mut runtime = Fake::new(&fixture);
            if phase == "foreign" {
                runtime.corrupt_parent = true;
            } else {
                runtime.fail_group = Some(phase);
            }
            assert!(fixture.run(&runtime).is_err());
            let calls = runtime.calls.borrow();
            if phase == "prepare" {
                assert!(calls.is_empty());
            }
            if phase == "foreign" {
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0][0], "create");
            }
            if phase == "retire" {
                assert_eq!(fixture.receipt().unwrap().phase, "completed");
                assert_eq!(fixture.receipt().unwrap().exit_code, Some(0));
                // A durable outcome remains final even when post-exit cleanup failed.
                assert_eq!(calls.iter().filter(|args| args[0] == "create").count(), 1);
            }
        }
        let mut fixture = Fixture::new();
        fixture.policy.application = "foreign".into();
        let runtime = Fake::new(&fixture);
        assert!(fixture.run(&runtime).is_err());
        assert!(runtime.calls.borrow().is_empty());
        assert!(fixture.receipt().is_none());
    }

    #[test]
    fn completed_job_recovery_still_requires_exact_owned_terminal_state_and_retirement() {
        let fixture = Fixture::new();
        let mut runtime = Fake::new(&fixture);
        runtime.fail_group = Some("retire");
        assert!(fixture.run(&runtime).is_err());
        let before = canonical(&serde_json::to_value(fixture.receipt().unwrap()).unwrap()).unwrap();
        assert_eq!(fixture.receipt().unwrap().phase, "completed");
        let effects = runtime.calls.borrow().len();
        let recover = |runtime: &Fake<'_>| {
            reconcile_with(
                &fixture.store,
                &fixture.document,
                &fixture.installed,
                &fixture.installed.operation_id,
                runtime,
                false,
            )
        };
        assert!(recover(&runtime).is_err());
        assert_eq!(runtime.calls.borrow().len(), effects);
        runtime.fail_group = None;
        let owned = runtime.container.borrow().as_ref().unwrap().clone();
        runtime.container.borrow_mut().as_mut().unwrap()["Config"]["Labels"]["io.komizo.ownership"] =
            json!("f".repeat(32));
        assert!(recover(&runtime).is_err());
        *runtime.container.borrow_mut() = Some(owned.clone());
        runtime.container.borrow_mut().as_mut().unwrap()["State"]["Running"] = json!(true);
        assert!(recover(&runtime).is_err());
        *runtime.container.borrow_mut() = Some(owned);
        recover(&runtime).unwrap();
        assert_eq!(
            canonical(&serde_json::to_value(fixture.receipt().unwrap()).unwrap()).unwrap(),
            before
        );
        assert_eq!(runtime.calls.borrow().len(), effects);
        assert_eq!(runtime.groups.borrow().last().unwrap().0, "retire");
        *runtime.container.borrow_mut() = None;
        recover(&runtime).unwrap();
        assert_eq!(runtime.calls.borrow().len(), effects);
    }

    #[test]
    fn ephemeral_cleanup_preserves_receipts_and_requires_actual_owned_job_identity() {
        let mut fixture = Fixture::new();
        fixture.installed.instance = "pr-1".into();
        let mut runtime = Fake::new(&fixture);
        runtime.cleanup_operation = Some("e".repeat(32));
        fixture.run(&runtime).unwrap();
        cleanup_ephemeral_with(
            &fixture.store,
            &fixture.installed,
            &"e".repeat(32),
            &runtime,
        )
        .unwrap();
        assert!(runtime.container.borrow().is_none());
        assert_eq!(fixture.receipt().unwrap().phase, "completed");
        assert_eq!(fixture.receipt().unwrap().exit_code, Some(0));
        fixture.run(&runtime).unwrap();
        assert_eq!(
            runtime
                .calls
                .borrow()
                .iter()
                .filter(|args| args[0] == "create")
                .count(),
            1
        );

        let mut foreign = Fixture::new();
        foreign.installed.instance = "pr-2".into();
        let mut runtime = Fake::new(&foreign);
        runtime.cleanup_operation = Some("e".repeat(32));
        foreign.run(&runtime).unwrap();
        runtime.container.borrow_mut().as_mut().unwrap()["Config"]["Labels"]["io.komizo.ownership"] =
            json!("f".repeat(32));
        assert!(
            cleanup_ephemeral_with(
                &foreign.store,
                &foreign.installed,
                &"e".repeat(32),
                &runtime
            )
            .is_err()
        );
        assert!(runtime.container.borrow().is_some());
        assert!(!runtime.calls.borrow().iter().any(|args| args[0] == "rm"));
    }

    #[test]
    fn removing_an_uncertain_preview_job_does_not_invent_an_exit_or_allow_replay() {
        let mut fixture = Fixture::new();
        fixture.installed.instance = "pr-1".into();
        let mut runtime = Fake::new(&fixture);
        runtime.fail = Some("wait");
        runtime.cleanup_operation = Some("e".repeat(32));
        assert!(fixture.run(&runtime).is_err());
        assert_eq!(fixture.receipt().unwrap().phase, "uncertain");
        cleanup_ephemeral_with(
            &fixture.store,
            &fixture.installed,
            &"e".repeat(32),
            &runtime,
        )
        .unwrap();
        assert!(runtime.container.borrow().is_none());
        assert_eq!(fixture.receipt().unwrap().phase, "uncertain");
        assert_eq!(fixture.receipt().unwrap().exit_code, None);
        assert!(fixture.run(&runtime).is_err());
        let production = Fixture::new();
        let runtime = Fake::new(&production);
        assert!(
            cleanup_ephemeral_with(
                &production.store,
                &production.installed,
                &"e".repeat(32),
                &runtime
            )
            .is_err()
        );
        assert!(runtime.calls.borrow().is_empty());
    }

    #[test]
    fn durable_intent_and_actual_id_precede_effects_and_completed_jobs_are_cached() {
        let fixture = Fixture::new();
        let runtime = Fake::new(&fixture);
        let receipt = fixture.run(&runtime).unwrap();
        assert_eq!(receipt.phase, "completed");
        assert_eq!(receipt.exit_code, Some(0));
        assert_eq!(
            runtime
                .calls
                .borrow()
                .iter()
                .map(|a| a[0].as_str())
                .collect::<Vec<_>>(),
            ["create", "start", "wait"]
        );
        fixture.run(&runtime).unwrap();
        assert_eq!(runtime.calls.borrow().len(), 3);
        assert!(
            !serde_json::to_string(&receipt)
                .unwrap()
                .contains("do-not-log-this")
        );
        assert!(
            completed(
                &fixture.store,
                &fixture.document,
                "migrate",
                &fixture.installed
            )
            .unwrap()
        );
    }
    #[test]
    fn interruption_at_each_effect_is_durable_and_never_replayed() {
        for command in ["create", "start", "wait"] {
            let fixture = Fixture::new();
            let mut runtime = Fake::new(&fixture);
            runtime.fail = Some(command);
            assert!(fixture.run(&runtime).is_err());
            assert_eq!(fixture.receipt().unwrap().phase, "uncertain");
            let count = runtime.calls.borrow().len();
            runtime.fail = None;
            assert!(fixture.run(&runtime).is_err());
            assert_eq!(runtime.calls.borrow().len(), count);
        }
    }
    #[test]
    fn nonzero_exit_is_final_and_does_not_replay() {
        let fixture = Fixture::new();
        let mut runtime = Fake::new(&fixture);
        runtime.exit = 23;
        assert!(fixture.run(&runtime).is_err());
        let receipt = fixture.receipt().unwrap();
        assert_eq!(receipt.phase, "failed");
        assert_eq!(receipt.exit_code, Some(23));
        assert!(fixture.run(&runtime).is_err());
        assert_eq!(runtime.calls.borrow().len(), 3);
    }
    #[test]
    fn forged_owner_or_volume_prevents_start_after_actual_id_is_recorded() {
        for mount in [false, true] {
            let fixture = Fixture::new();
            let mut runtime = Fake::new(&fixture);
            runtime.corrupt_owner = !mount;
            runtime.corrupt_mount = mount;
            assert!(fixture.run(&runtime).is_err());
            let receipt = fixture.receipt().unwrap();
            assert_eq!(receipt.phase, "uncertain");
            assert_eq!(receipt.container_id, "d".repeat(64));
            assert_eq!(runtime.calls.borrow().len(), 1);
        }
    }
    #[test]
    fn native_lifetime_is_bounded_by_remaining_budget_and_verified_before_start() {
        let now = Instant::now();
        assert_eq!(
            native_timeout(now + Duration::from_secs(8), now, 90).unwrap(),
            4
        );
        assert_eq!(
            native_timeout(now + Duration::from_secs(100), now, 30).unwrap(),
            30
        );
        for seconds in 0..=4 {
            assert!(native_timeout(now + Duration::from_secs(seconds), now, 90).is_err());
        }
        let fixture = Fixture::new();
        let mut runtime = Fake::new(&fixture);
        runtime.corrupt_timeout = true;
        assert!(fixture.run(&runtime).is_err());
        assert_eq!(fixture.receipt().unwrap().phase, "uncertain");
        assert_eq!(runtime.calls.borrow().len(), 1);
        assert_eq!(runtime.calls.borrow()[0][0], "create");
        assert!(fixture.receipt().unwrap().native_timeout_seconds < 30);
    }
    #[test]
    fn cache_identity_binds_job_code_scope_secret_bytes_generation_and_retained_objects() {
        let mut fixture = Fixture::new();
        let original = identity(&fixture.document, "migrate", &fixture.installed).unwrap();
        fixture.installed.operation_id = "9".repeat(32);
        fixture.installed.release_digest = format!("sha256:{}", "9".repeat(64));
        assert_eq!(
            identity(&fixture.document, "migrate", &fixture.installed).unwrap(),
            original
        );
        let snapshot = fixture.installed.clone();
        for change in ["generation", "bytes", "volume", "network", "instance"] {
            fixture.installed = snapshot.clone();
            match change {
                "generation" => {
                    fixture
                        .installed
                        .secret_snapshots
                        .get_mut("runtime")
                        .unwrap()
                        .generation = "generation-two".into()
                }
                "bytes" => {
                    fixture
                        .installed
                        .secret_snapshots
                        .get_mut("runtime")
                        .unwrap()
                        .sha256 = format!("sha256:{}", "e".repeat(64))
                }
                "volume" => {
                    fixture
                        .installed
                        .resources
                        .volumes
                        .get_mut("data")
                        .unwrap()
                        .id = format!("sha256:{}", "e".repeat(64))
                }
                "network" => {
                    fixture
                        .installed
                        .resources
                        .networks
                        .get_mut("backend")
                        .unwrap()
                        .id = "e".repeat(64)
                }
                _ => fixture.installed.instance = "pr-1".into(),
            }
            assert_ne!(
                identity(&fixture.document, "migrate", &fixture.installed).unwrap(),
                original,
                "{change}"
            );
        }
        fixture.installed = snapshot;
        fixture
            .document
            .release
            .workload
            .jobs
            .get_mut("migrate")
            .unwrap()
            .command
            .push("new-argument".into());
        assert_ne!(
            identity(&fixture.document, "migrate", &fixture.installed).unwrap(),
            original
        );
    }
    #[test]
    fn changed_secret_and_expired_deadline_refuse_before_any_job_effect() {
        let fixture = Fixture::new();
        let runtime = Fake::new(&fixture);
        store::atomic(
            std::path::Path::new(&fixture.installed.secret_snapshots["runtime"].path),
            b"PRIVATE_TOKEN=changed\n",
            0o600,
        )
        .unwrap();
        assert!(fixture.run(&runtime).is_err());
        assert!(runtime.calls.borrow().is_empty());
        assert!(fixture.receipt().is_none());
        assert!(
            run_with(
                &fixture.store,
                &fixture.policy,
                &fixture.document,
                &fixture.installed,
                "migrate",
                JobExecution {
                    operation_id: &fixture.installed.operation_id,
                    deadline: Instant::now() - Duration::from_secs(1)
                },
                &runtime
            )
            .is_err()
        );
        assert!(runtime.calls.borrow().is_empty());
    }
    #[test]
    fn owner_reconciliation_requires_actual_exact_exit_and_never_executes_the_job() {
        for status in ["running", "absent", "foreign", "success", "failed"] {
            let fixture = Fixture::new();
            let mut runtime = Fake::new(&fixture);
            runtime.fail = Some("wait");
            assert!(fixture.run(&runtime).is_err());
            let count = runtime.calls.borrow().len();
            if status == "absent" {
                *runtime.container.borrow_mut() = None;
            } else {
                let mut container = runtime.container.borrow_mut();
                let value = container.as_mut().unwrap();
                if status == "foreign" {
                    value["Config"]["Labels"]["io.komizo.ownership"] = json!("e".repeat(32));
                }
                if ["success", "failed"].contains(&status) {
                    value["State"] = json!({"Running":false,"Status":"exited","ExitCode":if status=="success" {0}else{19},
                                           "FinishedAt":"2026-01-01T00:00:00Z"});
                }
            }
            let result = reconcile_with(
                &fixture.store,
                &fixture.document,
                &fixture.installed,
                &fixture.installed.operation_id,
                &runtime,
                false,
            );
            assert_eq!(result.is_ok(), status == "success", "{status}");
            assert_eq!(runtime.calls.borrow().len(), count);
            if status == "failed" {
                reconcile_with(
                    &fixture.store,
                    &fixture.document,
                    &fixture.installed,
                    &fixture.installed.operation_id,
                    &runtime,
                    true,
                )
                .unwrap();
                assert_eq!(runtime.calls.borrow().len(), count);
                assert!(fixture.run(&runtime).is_err());
                assert_eq!(runtime.calls.borrow().len(), count);
            }
            assert_eq!(
                fixture.receipt().unwrap().phase,
                match status {
                    "success" => "completed",
                    "failed" => "failed",
                    _ => "uncertain",
                }
            );
        }
    }
}
