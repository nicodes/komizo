use super::{
    capacity::Capacity,
    cgroups::{self, Group, Pool},
    model::*,
    store::{self, Store},
    units,
    validation::*,
};
use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

pub const SERVICE_CONFIGS: &str = "/var/lib/komizo/service-configs";
pub const ASSETS: &str = "/var/lib/komizo-assets";
pub const PROXY_CONFIG: &str = "/etc/komizo-proxy/Caddyfile";
pub const PROXY_SOCKET: &str = "unix//run/komizo-proxy/admin.sock";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitRecord {
    application: String,
    instance: String,
    sha256: String,
}

pub struct System {
    pub deadline: Instant,
}
impl System {
    pub fn prepare_group(
        &self,
        group: &Group,
        limits: &Limits,
        controls: &ResourceControls,
    ) -> Result<()> {
        cgroups::prepare(group, limits, controls, self.deadline)
    }
    pub fn verify_group(
        &self,
        group: &Group,
        limits: &Limits,
        controls: &ResourceControls,
    ) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "resource verification deadline expired"
        );
        cgroups::verify(group, limits, controls)
    }
    pub fn group_empty(&self, group: &Group) -> Result<bool> {
        ensure!(
            Instant::now() < self.deadline,
            "resource observation deadline expired"
        );
        cgroups::empty(group)
    }
    pub fn kill_group(&self, group: &Group) -> Result<()> {
        cgroups::kill(group, self.deadline)
    }
    pub fn kill_entry(&self, group: &Group) -> Result<fs::File> {
        cgroups::kill_entry(group)
    }
    pub fn process_entry(&self, group: &Group) -> Result<fs::File> {
        ensure!(
            Instant::now() < self.deadline,
            "process entry deadline expired"
        );
        cgroups::process_entry(group)
    }
    pub fn enter(&self, group: &Group, pid: u32) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "process entry deadline expired"
        );
        cgroups::enter(group, pid)
    }
    pub fn remove_group(&self, group: &Group) -> Result<()> {
        cgroups::remove(group, self.deadline)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitVersion {
    pub sha256: String,
    pub body: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitIntent {
    pub kind: String,
    pub version: u32,
    pub identity: String,
    pub application: String,
    pub instance: String,
    pub operation_id: Option<String>,
    pub path: String,
    pub old: Option<UnitVersion>,
    pub new: Option<UnitVersion>,
    pub phase: String,
}
fn destination(path: &Path) -> bool {
    path == Path::new(PROXY_CONFIG)
        || path
            .file_stem()
            .and_then(|value| value.to_str())
            .and_then(|value| units::config_path(value).ok())
            .is_some_and(|expected| expected == path)
}
impl UnitIntent {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.unit-intent"
                && self.version == 1
                && hex(&self.identity, 32)
                && name(&self.application)
                && name(&self.instance)
                && self.operation_id.as_deref().is_none_or(|id| hex(id, 32))
                && destination(Path::new(&self.path))
                && ["pending", "committed"].contains(&self.phase.as_str())
                && (self.old.is_some() || self.new.is_some()),
            "invalid protected unit intent"
        );
        for version in [&self.old, &self.new].into_iter().flatten() {
            ensure!(
                version.body.len() <= 1 << 20
                    && document_digest(version.body.as_bytes()) == version.sha256,
                "unit intent bytes differ from their exact hash"
            );
        }
        Ok(())
    }
}
pub trait UnitFiles {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>>;
    fn write(&self, path: &Path, body: &[u8]) -> Result<()>;
    fn remove(&self, path: &Path) -> Result<()>;
}
struct ProtectedUnits;
impl UnitFiles for ProtectedUnits {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        if !path.try_exists()? {
            return Ok(None);
        }
        Ok(Some(store::read_protected(path, 1 << 20)?))
    }
    fn write(&self, path: &Path, body: &[u8]) -> Result<()> {
        store::atomic(
            path,
            body,
            if path == Path::new(PROXY_CONFIG) {
                0o644
            } else {
                0o600
            },
        )
    }
    fn remove(&self, path: &Path) -> Result<()> {
        fs::remove_file(path)?;
        std::fs::File::open(path.parent().unwrap())?.sync_all()?;
        Ok(())
    }
}
fn unit_records(store: &Store) -> Result<BTreeMap<String, UnitRecord>> {
    let path = store.root.join("units.json");
    if !path.try_exists()? {
        return Ok(BTreeMap::new());
    }
    Ok(serde_json::from_value(crate::strict::value(
        &store::read_protected(&path, 4 << 20)?,
        4 << 20,
    )?)?)
}
fn pending_temporary(path: &Path) -> Result<bool> {
    store::pending(path, 4 << 20)
}
fn intent_records(store: &Store) -> Result<Vec<(PathBuf, UnitIntent)>> {
    let directory = store.root.join("unit-intents");
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    store::protected_directory(&directory)?;
    let mut result = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        count += 1;
        ensure!(count <= 16384, "unit intent inventory exceeds bound");
        let path = entry?.path();
        if pending_temporary(&path)? {
            continue;
        }
        let intent: UnitIntent = serde_json::from_value(crate::strict::value(
            &store::read_protected(&path, 4 << 20)?,
            4 << 20,
        )?)?;
        intent.validate()?;
        ensure!(
            path.file_name().and_then(|n| n.to_str()) == Some(&format!("{}.json", intent.identity)),
            "unit intent path identity changed"
        );
        result.push((path, intent));
    }
    Ok(result)
}
fn scoped(
    intent: &UnitIntent,
    application: &str,
    instance: &str,
    operation_id: Option<&str>,
) -> bool {
    intent.application == application
        && intent.instance == instance
        && (intent.operation_id.as_deref() == operation_id || intent.operation_id.is_none())
}
/// Complete only the exact known old/new file and ledger pair. No manager action runs.
pub fn reconcile_unit_intent_with(
    store: &Store,
    intent: &UnitIntent,
    files: &impl UnitFiles,
) -> Result<()> {
    intent.validate()?;
    let _guard = metadata_lease(store)?;
    reconcile_one(store, intent, files)
}
fn reconcile_one(store: &Store, intent: &UnitIntent, files: &impl UnitFiles) -> Result<()> {
    let mut records = unit_records(store)?;
    let observed = files.read(Path::new(&intent.path))?;
    let observed_hash = observed.as_ref().map(|b| document_digest(b));
    let old = intent.old.as_ref().map(|v| v.sha256.as_str());
    let new = intent.new.as_ref().map(|v| v.sha256.as_str());
    ensure!(
        observed_hash.as_deref() == old || observed_hash.as_deref() == new,
        "unit bytes are outside the preauthorized old/new intent"
    );
    if let Some(record) = records.get(&intent.path) {
        ensure!(
            record.application == intent.application
                && record.instance == intent.instance
                && (Some(record.sha256.as_str()) == old || Some(record.sha256.as_str()) == new),
            "unit ledger is outside its preauthorized owner/hash pair"
        );
    } else {
        ensure!(
            old.is_none() || new.is_none(),
            "existing unit ownership ledger disappeared"
        )
    }
    if let Some(next) = &intent.new {
        if observed_hash.as_deref() != Some(&next.sha256) {
            files.write(Path::new(&intent.path), next.body.as_bytes())?;
        }
        records.insert(
            intent.path.clone(),
            UnitRecord {
                application: intent.application.clone(),
                instance: intent.instance.clone(),
                sha256: next.sha256.clone(),
            },
        );
    } else {
        if observed.is_some() {
            files.remove(Path::new(&intent.path))?;
        }
        records.remove(&intent.path);
    }
    store::atomic(
        &store.root.join("units.json"),
        &serde_json::to_vec(&records)?,
        0o600,
    )?;
    Ok(())
}
fn metadata_lease(store: &Store) -> Result<store::Guard> {
    // Only protected filesystem/ledger operations use this bounded wait; no
    // native execution or service lifetime is renewed by metadata contention.
    super::controller::resource_lease(
        store,
        "platform",
        "units",
        Instant::now() + std::time::Duration::from_secs(5),
    )
}

fn transaction(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    body: Option<&[u8]>,
    operation_id: Option<&str>,
) -> Result<String> {
    ensure!(
        name(application)
            && name(instance)
            && destination(path)
            && operation_id.is_none_or(|id| hex(id, 32)),
        "invalid protected unit transaction scope"
    );
    let _guard = metadata_lease(store)?;
    ensure!(
        !intent_records(store)?
            .iter()
            .any(|(_, i)| i.path == path.to_string_lossy() && i.phase == "pending"),
        "unit requires explicit intent reconciliation"
    );
    let records = unit_records(store)?;
    let old_body = ProtectedUnits.read(path)?;
    let key = path.to_str().ok_or_else(|| anyhow!("invalid unit path"))?;
    let old = if let Some(bytes) = old_body {
        let record = records
            .get(key)
            .ok_or_else(|| anyhow!("unrecorded unit cannot be changed"))?;
        ensure!(
            record.application == application
                && record.instance == instance
                && document_digest(&bytes) == record.sha256,
            "unit ownership or protected bytes changed"
        );
        Some(UnitVersion {
            sha256: record.sha256.clone(),
            body: String::from_utf8(bytes)?,
        })
    } else {
        ensure!(
            !records.contains_key(key),
            "recorded unit is missing and requires reconciliation"
        );
        None
    };
    let new = body
        .map(|bytes| -> Result<UnitVersion> {
            ensure!(bytes.len() <= 1 << 20, "unit exceeds its byte bound");
            Ok(UnitVersion {
                sha256: document_digest(bytes),
                body: String::from_utf8(bytes.to_vec())?,
            })
        })
        .transpose()?;
    ensure!(
        old.is_some() || new.is_some(),
        "unrecorded unit cannot be removed"
    );
    if old == new {
        return Ok(new.as_ref().map(|v| v.sha256.clone()).unwrap_or_default());
    }
    let mut intent = UnitIntent {
        kind: "komizo.unit-intent".into(),
        version: 1,
        identity: store::identity()?,
        application: application.into(),
        instance: instance.into(),
        operation_id: operation_id.map(str::to_owned),
        path: key.into(),
        old,
        new,
        phase: "pending".into(),
    };
    intent.validate()?;
    let journal = store
        .root
        .join("unit-intents")
        .join(format!("{}.json", intent.identity));
    store::atomic(&journal, &serde_json::to_vec(&intent)?, 0o600)?;
    reconcile_one(store, &intent, &ProtectedUnits)?;
    intent.phase = "committed".into();
    store::atomic(&journal, &serde_json::to_vec(&intent)?, 0o600)?;
    Ok(intent
        .new
        .as_ref()
        .map(|v| v.sha256.clone())
        .unwrap_or_default())
}
pub fn install(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    body: &[u8],
) -> Result<String> {
    transaction(store, path, application, instance, Some(body), None)
}
pub fn install_for_operation(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    body: &[u8],
    operation_id: &str,
) -> Result<String> {
    transaction(
        store,
        path,
        application,
        instance,
        Some(body),
        Some(operation_id),
    )
}
pub fn remove(store: &Store, path: &Path, application: &str, instance: &str) -> Result<()> {
    transaction(store, path, application, instance, None, None)?;
    Ok(())
}
pub fn remove_for_operation(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    operation_id: &str,
) -> Result<()> {
    transaction(store, path, application, instance, None, Some(operation_id))?;
    Ok(())
}
pub fn reconcile_unit_intents(
    store: &Store,
    application: &str,
    instance: &str,
    operation_id: &str,
) -> Result<()> {
    reconcile_unit_intents_with(store, application, instance, operation_id, &ProtectedUnits)
}
pub fn reconcile_unit_intents_with(
    store: &Store,
    application: &str,
    instance: &str,
    operation_id: &str,
    files: &impl UnitFiles,
) -> Result<()> {
    ensure!(
        name(application) && name(instance) && hex(operation_id, 32),
        "invalid unit reconciliation scope"
    );
    reconcile_selected_unit_intents(store, application, instance, Some(operation_id), files)
}
/// Complete only framework-owned intents in the selected protected scope.
/// This never consumes an operation-tagged application effect or invokes a manager.
pub fn reconcile_framework_units(store: &Store, application: &str, instance: &str) -> Result<()> {
    reconcile_framework_units_with(store, application, instance, &ProtectedUnits)
}
pub fn reconcile_framework_units_with(
    store: &Store,
    application: &str,
    instance: &str,
    files: &impl UnitFiles,
) -> Result<()> {
    ensure!(
        name(application) && name(instance),
        "invalid framework unit reconciliation scope"
    );
    reconcile_selected_unit_intents(store, application, instance, None, files)
}
fn reconcile_selected_unit_intents(
    store: &Store,
    application: &str,
    instance: &str,
    operation_id: Option<&str>,
    files: &impl UnitFiles,
) -> Result<()> {
    let _guard = metadata_lease(store)?;
    for (path, mut intent) in intent_records(store)? {
        if scoped(&intent, application, instance, operation_id) && intent.phase == "pending" {
            reconcile_one(store, &intent, files)?;
            intent.phase = "committed".into();
            store::atomic(&path, &serde_json::to_vec(&intent)?, 0o600)?;
        }
    }
    Ok(())
}
pub fn reconciled_unit_hash(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    operation_id: &str,
    old_hash: &str,
) -> Result<String> {
    reconciled_unit_hash_with(
        store,
        path,
        application,
        instance,
        operation_id,
        old_hash,
        &ProtectedUnits,
    )
}
pub fn reconciled_unit_hash_with(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    operation_id: &str,
    old_hash: &str,
    files: &impl UnitFiles,
) -> Result<String> {
    reconcile_unit_intents_with(store, application, instance, operation_id, files)?;
    let records = unit_records(store)?;
    let key = path.to_str().ok_or_else(|| anyhow!("invalid unit path"))?;
    let actual = records
        .get(key)
        .ok_or_else(|| anyhow!("reconciled unit is absent"))?;
    ensure!(
        actual.application == application
            && actual.instance == instance
            && files
                .read(path)?
                .is_some_and(|body| document_digest(&body) == actual.sha256),
        "reconciled unit differs from actual protected bytes/owner"
    );
    let mut known = std::collections::BTreeSet::from([old_hash.to_owned()]);
    let intents = intent_records(store)?;
    loop {
        let size = known.len();
        for (_, intent) in &intents {
            if !scoped(intent, application, instance, Some(operation_id)) || intent.path != key {
                continue;
            }
            if let (Some(old), Some(new)) = (&intent.old, &intent.new)
                && known.contains(&old.sha256)
            {
                known.insert(new.sha256.clone());
            }
        }
        if known.len() == size {
            break;
        }
    }
    ensure!(
        known.contains(&actual.sha256),
        "installed unit hash has no exact scoped intent chain"
    );
    Ok(actual.sha256.clone())
}

pub fn verify_unit(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    hash: &str,
) -> Result<()> {
    let records: BTreeMap<String, UnitRecord> = serde_json::from_value(crate::strict::value(
        &store::read_protected(&store.root.join("units.json"), 4 << 20)?,
        4 << 20,
    )?)?;
    let record = records
        .get(path.to_str().ok_or_else(|| anyhow!("invalid unit path"))?)
        .ok_or_else(|| anyhow!("unit has no protected ownership record"))?;
    ensure!(
        record.application == application
            && record.instance == instance
            && record.sha256 == hash
            && document_digest(&store::read_protected(path, 1 << 20)?) == hash,
        "unit differs from its recorded accepted identity"
    );
    Ok(())
}

fn resource_config(
    store: &Store,
    group: &Group,
    identity: &str,
    application: &str,
    instance: &str,
    limits: &Limits,
    controls: &ResourceControls,
) -> Result<()> {
    limits.validate()?;
    controls.validate(limits)?;
    let body = canonical(
        &serde_json::json!({"kind":"komizo.cgroup-allocation", "version":1,
        "group":group.relative(), "limits":limits, "controls":controls}),
    )?;
    install(
        store,
        &units::config_path(identity)?,
        application,
        instance,
        &body,
    )?;
    Ok(())
}

pub fn host_pools(store: &Store, system: &System, capacity: &Capacity) -> Result<()> {
    capacity.measured()?;
    let root = cgroups::root_group();
    let pools = vec![
        (
            root,
            "cgroup-root",
            &capacity.limits,
            ResourceControls {
                memory_low_bytes: capacity.limits.memory_bytes,
                ..Default::default()
            },
        ),
        (
            cgroups::pool_group(Pool::Production),
            "cgroup-production",
            &capacity.production,
            ResourceControls {
                memory_low_bytes: capacity.production.memory_bytes,
                ..Default::default()
            },
        ),
        (
            cgroups::pool_group(Pool::Previews),
            "cgroup-previews",
            &capacity.previews,
            ResourceControls {
                memory_low_bytes: capacity.previews.memory_bytes,
                ..Default::default()
            },
        ),
        (
            cgroups::pool_group(Pool::Control),
            "cgroup-control",
            &capacity.control.limits,
            capacity.control.controls.clone(),
        ),
        (
            cgroups::pool_group(Pool::Proxy),
            "cgroup-proxy",
            &capacity.proxy.limits,
            capacity.proxy.controls.clone(),
        ),
    ];
    for (group, identity, limits, controls) in pools {
        resource_config(
            store, &group, identity, "platform", "capacity", limits, &controls,
        )?;
        system.prepare_group(&group, limits, &controls)?;
    }
    Ok(())
}

pub fn instance_allocation(
    store: &Store,
    system: &System,
    policy: &Policy,
    instance: &str,
) -> Result<()> {
    let (limits, controls) = if instance == "production" {
        (&policy.limits, &policy.controls)
    } else {
        let preview = policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview allocation missing"))?;
        (&preview.limits, &preview.controls)
    };
    let group = cgroups::instance_group(&policy.application, instance)?;
    resource_config(
        store,
        &group,
        &format!(
            "cgroup-{}",
            units::namespace(&policy.application, instance)?
        ),
        &policy.application,
        instance,
        limits,
        controls,
    )?;
    system.prepare_group(&group, limits, controls)
}

/// Restore an admitted allocation after boot without entering or modifying the
/// shared configuration ledger from a background actor.
pub fn restore_instance_allocation(
    store: &Store,
    system: &System,
    policy: &Policy,
    instance: &str,
) -> Result<()> {
    let (limits, controls) = if instance == "production" {
        (&policy.limits, &policy.controls)
    } else {
        let preview = policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview allocation missing"))?;
        (&preview.limits, &preview.controls)
    };
    let group = cgroups::instance_group(&policy.application, instance)?;
    let path = units::config_path(&format!(
        "cgroup-{}",
        units::namespace(&policy.application, instance)?
    ))?;
    let body = canonical(
        &serde_json::json!({"kind":"komizo.cgroup-allocation", "version":1,
        "group":group.relative(), "limits":limits, "controls":controls}),
    )?;
    verify_unit(
        store,
        &path,
        &policy.application,
        instance,
        &document_digest(&body),
    )?;
    system.prepare_group(&group, limits, controls)
}

pub fn caddy_validate(config: &Path, deadline: Instant) -> Result<()> {
    let entered = Instant::now();
    let entry_remaining_ms = deadline.saturating_duration_since(entered).as_millis();
    super::bootstrap::proxy_guard()?;
    let guard_elapsed_ms = entered.elapsed().as_millis();
    let after_guard_remaining_ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis();
    let mut command = Command::new("/usr/local/bin/caddy");
    command.env_clear().env("PATH", "/usr/bin:/bin").args([
        "adapt",
        "--adapter",
        "caddyfile",
        "--config",
        config
            .to_str()
            .ok_or_else(|| anyhow!("invalid proxy staging path"))?,
    ]);
    let capture_started = Instant::now();
    let output = crate::process::capture(&mut command, None, 256 << 10, deadline, || false)
        .with_context(|| format!(
            "native proxy configuration adaptation process (entry_remaining_ms={entry_remaining_ms}, guard_elapsed_ms={guard_elapsed_ms}, after_guard_remaining_ms={after_guard_remaining_ms}, capture_elapsed_ms={})",
            capture_started.elapsed().as_millis()
        ))?;
    ensure!(
        output.status.success(),
        "proxy rejected staged serving configuration: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(2048)
            .collect::<String>()
    );
    Ok(())
}

pub fn caddy_reload(deadline: Instant) -> Result<()> {
    let entered = Instant::now();
    let entry_remaining_ms = deadline.saturating_duration_since(entered).as_millis();
    super::bootstrap::proxy_guard()?;
    let guard_elapsed_ms = entered.elapsed().as_millis();
    let after_guard_remaining_ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis();
    let mut command = Command::new("/usr/local/bin/caddy");
    command.env_clear().env("PATH", "/usr/bin:/bin").args([
        "reload",
        "--adapter",
        "caddyfile",
        "--config",
        PROXY_CONFIG,
        "--address",
        PROXY_SOCKET,
    ]);
    let capture_started = Instant::now();
    let output = crate::process::capture(&mut command, None, 256 << 10, deadline, || false)
        .with_context(|| format!(
            "native proxy reload acknowledgment process (entry_remaining_ms={entry_remaining_ms}, guard_elapsed_ms={guard_elapsed_ms}, after_guard_remaining_ms={after_guard_remaining_ms}, capture_elapsed_ms={})",
            capture_started.elapsed().as_millis()
        ))?;
    ensure!(
        output.status.success(),
        "proxy refused the staged serving configuration"
    );
    Ok(())
}

#[cfg(test)]
mod metadata_lease_tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, sync::mpsc, time::Duration};

    #[test]
    fn ledger_lease_waits_for_real_contention_and_keeps_file_ownership_checks() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let store = Store::new(directory.path().join("state")).unwrap();
        let prior = store.lock("platform", "units").unwrap();
        let (ready, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let other = store.clone();
        let worker = std::thread::spawn(move || {
            let _guard = metadata_lease(&other).unwrap();
            ready.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(20)).is_err());
        drop(prior);
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(store.try_lock("platform", "units").unwrap().is_none());
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(store.try_lock("platform", "units").unwrap().is_some());
        fs::set_permissions(
            store.root.join("locks/platform--units"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(metadata_lease(&store).is_err());
    }
}
