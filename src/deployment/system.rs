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

pub fn install(
    store: &Store,
    path: &Path,
    application: &str,
    instance: &str,
    body: &[u8],
) -> Result<String> {
    ensure!(
        name(application) && name(instance) && body.len() <= 1 << 20 && path.is_absolute(),
        "invalid protected unit installation"
    );
    let allowed = path.parent() == Some(Path::new(QUADLETS))
        || path.parent() == Some(Path::new(UNITS))
        || path == Path::new(PROXY_CONFIG);
    ensure!(
        allowed,
        "unit destination is outside protected managed directories"
    );
    let _guard = store.lock("platform", "units")?;
    let ledger = store.root.join("units.json");
    let mut records: BTreeMap<String, UnitRecord> = if ledger.try_exists()? {
        serde_json::from_value(crate::strict::value(
            &store::read_protected(&ledger, 4 << 20)?,
            4 << 20,
        )?)?
    } else {
        BTreeMap::new()
    };
    let key = path
        .to_str()
        .ok_or_else(|| anyhow!("invalid managed path"))?
        .to_owned();
    if path.try_exists()? {
        let old = records
            .get(&key)
            .ok_or_else(|| anyhow!("unrecorded unit cannot be replaced"))?;
        ensure!(
            old.application == application
                && old.instance == instance
                && document_digest(&store::read_protected(path, 1 << 20)?) == old.sha256,
            "unit ownership or protected bytes changed"
        );
    } else {
        ensure!(
            !records.contains_key(&key),
            "recorded unit is missing and requires reconciliation"
        );
    }
    let hash = document_digest(body);
    store::atomic(
        path,
        body,
        if path == Path::new(PROXY_CONFIG) {
            0o644
        } else {
            0o600
        },
    )?;
    records.insert(
        key,
        UnitRecord {
            application: application.to_owned(),
            instance: instance.to_owned(),
            sha256: hash.clone(),
        },
    );
    store::atomic(&ledger, &serde_json::to_vec(&records)?, 0o600)?;
    Ok(hash)
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

pub fn remove(store: &Store, path: &Path, application: &str, instance: &str) -> Result<()> {
    let _guard = store.lock("platform", "units")?;
    let ledger = store.root.join("units.json");
    let mut records: BTreeMap<String, UnitRecord> = serde_json::from_value(crate::strict::value(
        &store::read_protected(&ledger, 4 << 20)?,
        4 << 20,
    )?)?;
    let key = path
        .to_str()
        .ok_or_else(|| anyhow!("invalid managed unit path"))?;
    let record = records
        .get(key)
        .ok_or_else(|| anyhow!("unrecorded unit cannot be removed"))?;
    ensure!(
        record.application == application
            && record.instance == instance
            && document_digest(&store::read_protected(path, 1 << 20)?) == record.sha256,
        "unit ownership changed before removal"
    );
    fs::remove_file(path)?;
    records.remove(key);
    store::atomic(&ledger, &serde_json::to_vec(&records)?, 0o600)
}
