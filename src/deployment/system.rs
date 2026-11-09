use super::{
    capacity::{self, Capacity},
    model::*,
    store::{self, Store},
    units,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

pub const QUADLETS: &str = "/etc/containers/systemd";
pub const UNITS: &str = "/etc/systemd/system";
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
    pub fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut command = Command::new("/usr/bin/systemctl");
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8")
            .args(args);
        let output = crate::process::capture(&mut command, None, 1 << 20, self.deadline, || false)
            .map_err(|_| anyhow!("service manager process failed or exceeded its deadline"))?;
        ensure!(
            output.status.success(),
            "service manager refused the protected operation"
        );
        Ok(output.stdout)
    }
    pub fn reload(&self) -> Result<()> {
        self.run(&["daemon-reload"])?;
        Ok(())
    }
    pub fn start(&self, name: &str) -> Result<()> {
        self.run(&["start", name])?;
        Ok(())
    }
    pub fn stop(&self, name: &str) -> Result<()> {
        self.run(&["stop", name])?;
        Ok(())
    }
    pub fn active(&self, name: &str) -> Result<bool> {
        let value = self.run(&["show", "--property=ActiveState", "--value", name])?;
        let value = std::str::from_utf8(&value)?.trim();
        ensure!(
            ["active", "inactive", "failed", "activating", "deactivating"].contains(&value),
            "service manager state is ambiguous"
        );
        Ok(value == "active")
    }
    pub fn group(&self, name: &str) -> Result<PathBuf> {
        let value = self.run(&["show", "--property=ControlGroup", "--value", name])?;
        let path = std::str::from_utf8(&value)?.trim();
        ensure!(
            absolute(path) && path != "/",
            "service manager omitted its protected cgroup"
        );
        Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
    }
    pub fn verify_slice(
        &self,
        name: &str,
        limits: &Limits,
        controls: &ResourceControls,
    ) -> Result<()> {
        capacity::verify_cgroup(&self.group(name)?, limits, controls)
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
    path.parent() == Some(Path::new(QUADLETS))
        || path.parent() == Some(Path::new(UNITS))
        || path == Path::new(PROXY_CONFIG)
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
    let _guard = store.lock("platform", "units")?;
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
    let _guard = store.lock("platform", "units")?;
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
    let _guard = store.lock("platform", "units")?;
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

pub fn host_pools(store: &Store, system: &System, capacity: &Capacity) -> Result<()> {
    capacity.measured()?;
    let pools = vec![
        (
            "komizo.slice",
            &capacity.limits,
            ResourceControls {
                memory_low_bytes: capacity.limits.memory_bytes,
                ..Default::default()
            },
        ),
        (
            "komizo-production.slice",
            &capacity.production,
            ResourceControls {
                memory_low_bytes: capacity.production.memory_bytes,
                ..Default::default()
            },
        ),
        (
            "komizo-previews.slice",
            &capacity.previews,
            ResourceControls {
                memory_low_bytes: capacity.previews.memory_bytes,
                ..Default::default()
            },
        ),
        (
            "komizo-control.slice",
            &capacity.control.limits,
            capacity.control.controls.clone(),
        ),
        (
            "komizo-proxy.slice",
            &capacity.proxy.limits,
            capacity.proxy.controls.clone(),
        ),
    ];
    for (unit, limits, controls) in &pools {
        install(
            store,
            &Path::new(UNITS).join(unit),
            "platform",
            "capacity",
            units::controlled_slice(limits, controls)?.as_bytes(),
        )?;
    }
    system.reload()?;
    for (unit, limits, controls) in &pools {
        system.start(unit)?;
        system.verify_slice(unit, limits, controls)?;
    }
    Ok(())
}

pub fn instance_slice(
    store: &Store,
    system: &System,
    policy: &Policy,
    instance: &str,
) -> Result<()> {
    let (limits, controls) = if instance == "production" {
        (&policy.limits, &policy.controls)
    } else {
        let p = policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview allocation missing"))?;
        (&p.limits, &p.controls)
    };
    let name = units::slice(&policy.application, instance)?;
    install(
        store,
        &Path::new(UNITS).join(&name),
        &policy.application,
        instance,
        units::controlled_slice(limits, controls)?.as_bytes(),
    )?;
    system.reload()?;
    system.start(&name)?;
    system.verify_slice(&name, limits, controls)
}

pub fn caddy_validate(config: &Path, deadline: Instant) -> Result<()> {
    super::bootstrap::proxy_guard()?;
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
    let output = crate::process::capture(&mut command, None, 256 << 10, deadline, || false)?;
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
    super::bootstrap::proxy_guard()?;
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
    let output = crate::process::capture(&mut command, None, 256 << 10, deadline, || false)?;
    ensure!(
        output.status.success(),
        "proxy refused the staged serving configuration"
    );
    Ok(())
}
