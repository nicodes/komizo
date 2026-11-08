use super::{
    model::*,
    store::{Store, atomic, read_protected},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    pub kind: String,
    pub version: u32,
    pub physical_memory_bytes: u64,
    pub os_reserve_bytes: u64,
    pub physical_milli_cpus: u32,
    pub os_reserve_milli_cpus: u32,
    pub limits: Limits,
    pub production: Limits,
    pub previews: Limits,
    pub control: Infrastructure,
    pub proxy: Infrastructure,
    pub infrastructure_reserve_bytes: u64,
    pub startup_memory_bytes: u64,
    pub disk_reserve_bytes: u64,
    pub max_instances: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Infrastructure {
    pub limits: Limits,
    pub controls: ResourceControls,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub application: String,
    pub instance: String,
    pub release_digest: String,
    pub limits: Limits,
    pub memory_reservation_bytes: u64,
    pub startup_memory_bytes: u64,
    pub is_static: bool,
}

impl Capacity {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        self.production.validate()?;
        self.previews.validate()?;
        self.control.limits.validate()?;
        self.control.controls.validate(&self.control.limits)?;
        self.proxy.limits.validate()?;
        self.proxy.controls.validate(&self.proxy.limits)?;
        ensure!(
            self.kind == "komizo.capacity"
                && self.version == 1
                && self.os_reserve_bytes > 0
                && self.os_reserve_bytes < self.physical_memory_bytes
                && self.limits.memory_bytes <= self.physical_memory_bytes - self.os_reserve_bytes
                && self.os_reserve_milli_cpus > 0
                && self.os_reserve_milli_cpus < self.physical_milli_cpus
                && self.limits.milli_cpus <= self.physical_milli_cpus - self.os_reserve_milli_cpus
                && self.production.fits(&self.limits)
                && self.previews.fits(&self.limits)
                && self.control.limits.fits(&self.limits)
                && self.proxy.limits.fits(&self.limits)
                && self
                    .control
                    .controls
                    .memory_low_bytes
                    .checked_add(self.proxy.controls.memory_low_bytes)
                    .is_some_and(|n| n <= self.infrastructure_reserve_bytes)
                && self.infrastructure_reserve_bytes > 0
                && self.infrastructure_reserve_bytes < self.limits.memory_bytes
                && self.startup_memory_bytes < self.production.memory_bytes
                && self.disk_reserve_bytes >= 256 << 20
                && (1..=256).contains(&self.max_instances),
            "invalid protected host capacity"
        );
        Ok(())
    }
    pub fn measured(&self) -> Result<()> {
        self.validate()?;
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        let memory = meminfo
            .lines()
            .find_map(|l| l.strip_prefix("MemTotal:"))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|v| v.checked_mul(1024))
            .ok_or_else(|| anyhow!("physical memory measurement unavailable"))?;
        let cpus = std::thread::available_parallelism()?.get() as u32 * 1000;
        ensure!(
            self.physical_memory_bytes <= memory && self.physical_milli_cpus <= cpus,
            "protected allocation exceeds actual host capacity"
        );
        Ok(())
    }
    pub fn admit(
        &self,
        allocations: &BTreeMap<String, Allocation>,
        candidate: &Allocation,
    ) -> Result<()> {
        self.validate()?;
        let key = Store::instance_key(&candidate.application, &candidate.instance)?;
        ensure!(
            digest(&candidate.release_digest)
                && (candidate.memory_reservation_bytes > 0 || candidate.is_static)
                && candidate.memory_reservation_bytes <= candidate.limits.memory_bytes
                && candidate.startup_memory_bytes <= self.startup_memory_bytes,
            "candidate lacks a bounded protected reservation"
        );
        let mut production = 0u64;
        let mut previews = 0u64;
        let mut startup = 0u64;
        let mut count = 0u32;
        for (record_key, value) in allocations
            .iter()
            .filter(|(k, _)| *k != &key)
            .chain(std::iter::once((&key, candidate)))
        {
            ensure!(
                Store::instance_key(&value.application, &value.instance)? == *record_key
                    && digest(&value.release_digest),
                "invalid retained capacity ownership"
            );
            let pool = if value.instance == "production" {
                &self.production
            } else {
                &self.previews
            };
            ensure!(
                value.limits.fits(pool)
                    && value.memory_reservation_bytes <= value.limits.memory_bytes,
                "instance exceeds its protected parent pool"
            );
            if value.instance == "production" {
                production = production
                    .checked_add(value.memory_reservation_bytes)
                    .ok_or_else(|| anyhow!("production reservation overflow"))?;
            } else {
                previews = previews
                    .checked_add(value.memory_reservation_bytes)
                    .ok_or_else(|| anyhow!("preview reservation overflow"))?;
            }
            startup = startup
                .checked_add(value.startup_memory_bytes)
                .ok_or_else(|| anyhow!("startup reservation overflow"))?;
            count += 1;
        }
        ensure!(
            count <= self.max_instances
                && production
                    .checked_add(self.startup_memory_bytes)
                    .is_some_and(|n| n <= self.production.memory_bytes)
                && previews <= self.previews.memory_bytes
                && startup <= self.startup_memory_bytes
                && production
                    .checked_add(previews)
                    .and_then(|n| n.checked_add(self.infrastructure_reserve_bytes))
                    .and_then(|n| n.checked_add(self.startup_memory_bytes))
                    .is_some_and(|n| n <= self.limits.memory_bytes),
            "host capacity refuses the complete reserved workload"
        );
        Ok(())
    }
}

pub fn read(path: &Path) -> Result<Capacity> {
    let capacity: Capacity = serde_json::from_value(crate::strict::value(
        &read_protected(path, 64 << 10)?,
        64 << 10,
    )?)?;
    capacity.validate()?;
    Ok(capacity)
}

pub fn reserve(
    store: &Store,
    capacity: &Capacity,
    policy: &Policy,
    document: &ReleaseDocument,
    instance: &str,
    startup: bool,
) -> Result<()> {
    let is_static = document.release.workload.services.is_empty();
    let _lock = store.lock("platform", "capacity")?;
    let path = store.root.join("allocations.json");
    let mut records: BTreeMap<String, Allocation> = if path.try_exists()? {
        serde_json::from_value(crate::strict::value(
            &read_protected(&path, 1 << 20)?,
            1 << 20,
        )?)?
    } else {
        BTreeMap::new()
    };
    let (limits, controls) = if instance == "production" {
        (&policy.limits, &policy.controls)
    } else {
        let p = policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview allocation missing"))?;
        (&p.limits, &p.controls)
    };
    let reservation = if is_static {
        0
    } else if policy.aggregate_mode == AggregateMode::Sum {
        limits.memory_bytes
    } else {
        controls.memory_low_bytes
    };
    let candidate = Allocation {
        application: policy.application.clone(),
        instance: instance.to_owned(),
        release_digest: document.digest.clone(),
        limits: limits.clone(),
        memory_reservation_bytes: reservation,
        startup_memory_bytes: if startup && !is_static {
            policy.startup_memory_bytes
        } else {
            0
        },
        is_static,
    };
    capacity.admit(&records, &candidate)?;
    records.insert(
        Store::instance_key(&policy.application, instance)?,
        candidate,
    );
    atomic(&path, &serde_json::to_vec(&records)?, 0o600)
}

pub fn disk(path: &Path, reserve: u64, staging: u64) -> Result<()> {
    let encoded = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(encoded.as_ptr(), stat.as_mut_ptr()) } == 0,
        "disk capacity measurement unavailable"
    );
    let stat = unsafe { stat.assume_init() };
    let free = u128::from(stat.f_bavail) * u128::from(stat.f_frsize);
    ensure!(
        reserve
            .checked_add(staging)
            .is_some_and(|n| u128::from(n) <= free),
        "disk reserve refuses artifact staging"
    );
    Ok(())
}

pub fn verify_cgroup(root: &Path, limits: &Limits, controls: &ResourceControls) -> Result<()> {
    let number =
        |file: &str| -> Result<u64> { Ok(fs::read_to_string(root.join(file))?.trim().parse()?) };
    ensure!(
        number("memory.max")? == limits.memory_bytes
            && number("memory.swap.max")? == limits.memory_swap_bytes - limits.memory_bytes
            && number("pids.max")? == u64::from(limits.pids)
            && number("memory.low")? == controls.memory_low_bytes,
        "kernel memory, swap, reservation or PID enforcement differs from protected allocation"
    );
    if controls.memory_high_bytes > 0 {
        ensure!(
            number("memory.high")? == controls.memory_high_bytes,
            "kernel memory pressure control differs from policy"
        );
    }
    let cpu = fs::read_to_string(root.join("cpu.max"))?;
    let words = cpu.split_whitespace().collect::<Vec<_>>();
    ensure!(
        words.len() == 2,
        "kernel CPU enforcement evidence is ambiguous"
    );
    let quota = words[0].parse::<u64>()?;
    let period = words[1].parse::<u64>()?;
    ensure!(
        quota > 0
            && period > 0
            && u128::from(quota) * 1000 == u128::from(period) * u128::from(limits.milli_cpus),
        "kernel CPU enforcement exceeds protected quota"
    );
    if let Some(weight) = controls.cpu_weight {
        ensure!(
            number("cpu.weight")? == u64::from(weight),
            "kernel CPU weight differs from policy"
        );
    }
    if !controls.io_max.is_empty() {
        let text = fs::read_to_string(root.join("io.max"))?;
        for rate in &controls.io_max {
            let fields = text
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{} ", rate.device)))
                .ok_or_else(|| anyhow!("kernel IO device limit missing"))?
                .split_whitespace()
                .collect::<Vec<_>>();
            ensure!(
                fields.contains(&format!("rbps={}", rate.read_bytes_per_second).as_str())
                    && fields.contains(&format!("wbps={}", rate.write_bytes_per_second).as_str()),
                "kernel IO rate differs from protected policy"
            );
        }
    }
    Ok(())
}
