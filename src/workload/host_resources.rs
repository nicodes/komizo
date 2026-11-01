//! Operator-owned aggregate capacity and admission preserve every serving allocation.
mod controllers;
use super::resources::ResourcePolicy;
use crate::{
    wire::{self, Slice},
    wire_struct,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
wire_struct!(HostGroup {memory_bytes:"memory_bytes":i64=>required,swap_bytes:"swap_bytes":i64=>required,milli_cpus:"milli_cpus":i64=>required,pids:"pids":i64=>required});
wire_struct!(DeviceIOBudget {device:"device":String=>required,read_bytes_per_second:"read_bytes_per_second":i64=>required,write_bytes_per_second:"write_bytes_per_second":i64=>required,read_iops:"read_iops":i64=>optional,write_iops:"write_iops":i64=>optional});
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlGroup {
    #[serde(flatten)]
    pub group: HostGroup,
    #[serde(deserialize_with = "wire::null_default")]
    pub memory_low_bytes: i64,
    #[serde(deserialize_with = "wire::null_default")]
    pub memory_high_bytes: i64,
    #[serde(deserialize_with = "wire::null_default")]
    pub cpu_weight: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApplicationGroup {
    #[serde(flatten)]
    pub group: HostGroup,
    #[serde(deserialize_with = "wire::null_default")]
    pub baseline_memory_bytes: i64,
    #[serde(deserialize_with = "wire::null_default")]
    pub memory_low_bytes: i64,
    #[serde(deserialize_with = "wire::null_default")]
    pub memory_high_bytes: i64,
    #[serde(deserialize_with = "wire::null_default")]
    pub cpu_weight: i64,
    #[serde(
        deserialize_with = "wire::null_default",
        skip_serializing_if = "wire::Empty::empty"
    )]
    pub io_weight: i64,
    #[serde(skip_serializing_if = "wire::Empty::empty")]
    pub io_max: Slice<DeviceIOBudget>,
}
wire_struct!(HostResources {version:"version":i64=>required,physical_memory_bytes:"physical_memory_bytes":i64=>required,os_reserve_bytes:"os_reserve_bytes":i64=>required,physical_milli_cpus:"physical_milli_cpus":i64=>required,os_reserve_milli_cpus:"os_reserve_milli_cpus":i64=>required,production:"production":HostGroup=>required,proxy:"proxy":HostGroup=>required,previews:"previews":HostGroup=>required,preview_database:"preview_database":HostGroup=>required,apps:"apps":BTreeMap<String,ApplicationGroup> =>optional,controls:"controls":BTreeMap<String,ControlGroup> =>optional});
pub fn block_device(value: &str) -> bool {
    let Some((major, minor)) = value.split_once(':') else {
        return false;
    };
    [major, minor].iter().all(|part| {
        *part == "0"
            || !part.is_empty()
                && part.len() <= 7
                && !part.starts_with('0')
                && part.bytes().all(|byte| byte.is_ascii_digit())
    })
}
impl HostResources {
    pub fn groups(&self) -> [(&'static str, &HostGroup); 4] {
        [
            ("komizo-production", &self.production),
            ("komizo-proxy", &self.proxy),
            ("komizo-previews", &self.previews),
            ("komizo-preview-database", &self.preview_database),
        ]
    }
    pub fn check(&self, measured_memory: i64, measured_cpu: i64) -> Result<()> {
        ensure!(
            self.version == 1
                && self.physical_memory_bytes > 0
                && self.physical_memory_bytes <= measured_memory
                && self.os_reserve_bytes >= 64 << 20
                && self.os_reserve_bytes <= self.physical_memory_bytes,
            "host resources require measured RAM and an OS reserve"
        );
        ensure!(
            self.physical_milli_cpus > 0
                && self.physical_milli_cpus <= measured_cpu
                && self.os_reserve_milli_cpus >= 100
                && self.os_reserve_milli_cpus <= self.physical_milli_cpus,
            "host resources require measured CPU and an OS CPU reserve"
        );
        let mut reserved = i128::from(self.os_reserve_bytes);
        let mut cpu = i128::from(self.os_reserve_milli_cpus);
        for (_, group) in self.groups() {
            ensure!(
                group.memory_bytes >= 4 << 20
                    && group.memory_bytes <= self.physical_memory_bytes
                    && group.swap_bytes >= 0
                    && group.swap_bytes <= self.physical_memory_bytes
                    && (1..=64000).contains(&group.milli_cpus)
                    && (16..=8192).contains(&group.pids),
                "host group requires finite memory, swap, CPU and PID limits"
            );
            reserved += i128::from(group.memory_bytes);
            cpu += i128::from(group.milli_cpus);
        }
        ensure!(
            reserved <= i128::from(self.physical_memory_bytes)
                && cpu <= i128::from(self.physical_milli_cpus),
            "aggregate host ceilings consume the OS reserve"
        );
        ensure!(
            self.previews.swap_bytes == 0 && self.preview_database.swap_bytes == 0,
            "preview groups may not grow swap"
        );
        self.check_apps()?;
        self.check_controls()
    }
    fn check_apps(&self) -> Result<()> {
        ensure!(
            self.apps.len() <= 32,
            "host application inventory exceeds its bound"
        );
        let mut reserved = 0_i128;
        for (name, app) in &self.apps {
            ensure!(
                app.io_max.len() <= 16,
                "application disk device inventory exceeds its bound"
            );
            let mut devices = BTreeSet::new();
            for limit in app.io_max.iter() {
                ensure!(
                    block_device(&limit.device)
                        && devices.insert(&limit.device)
                        && (4096..=1 << 30).contains(&limit.read_bytes_per_second)
                        && (4096..=1 << 30).contains(&limit.write_bytes_per_second)
                        && (0..=1_000_000).contains(&limit.read_iops)
                        && (0..=1_000_000).contains(&limit.write_iops),
                    "disk limits require unique block devices and finite read/write rates"
                );
            }
            let group = &app.group;
            ensure!(
                super::identifier(name)
                    && app.baseline_memory_bytes >= 4 << 20
                    && app.memory_low_bytes >= app.baseline_memory_bytes
                    && app.memory_high_bytes >= app.memory_low_bytes
                    && group.memory_bytes >= app.memory_high_bytes
                    && group.memory_bytes <= self.production.memory_bytes
                    && group.swap_bytes >= 0
                    && group.swap_bytes <= self.production.swap_bytes
                    && group.milli_cpus >= 1
                    && group.milli_cpus <= self.production.milli_cpus
                    && group.pids >= 16
                    && group.pids <= self.production.pids
                    && (1..=10000).contains(&app.cpu_weight)
                    && (0..=10000).contains(&app.io_weight)
                    && (app.io_weight != 0 || !app.io_max.is_empty()),
                "application group requires measured baseline, pressure threshold and finite host-owned limits"
            );
            reserved += i128::from(app.memory_low_bytes);
        }
        for app in self.apps.values() {
            ensure!(
                reserved - i128::from(app.memory_low_bytes) + i128::from(app.group.memory_bytes)
                    <= i128::from(self.production.memory_bytes),
                "one app's hard memory ceiling consumes another app's serving reserve"
            );
        }
        Ok(())
    }
    fn check_controls(&self) -> Result<()> {
        if self.controls.is_empty() {
            return Ok(());
        }
        ensure!(
            (3..=4).contains(&self.controls.len())
                && ["openrc.komizo-rootd", "openrc.komizo-api", "openrc.docker"]
                    .iter()
                    .all(|name| self.controls.contains_key(*name)),
            "control resources require rootd, API and Docker together"
        );
        let mut protected = 0_i128;
        for (name, control) in &self.controls {
            let group = &control.group;
            ensure!(
                matches!(
                    name.as_str(),
                    "openrc.komizo-rootd" | "openrc.komizo-api" | "openrc.docker" | "openrc.sshd"
                ) && control.memory_low_bytes >= 4 << 20
                    && control.memory_high_bytes >= control.memory_low_bytes
                    && group.memory_bytes >= control.memory_high_bytes
                    && group.memory_bytes <= self.physical_memory_bytes
                    && group.swap_bytes >= 0
                    && group.swap_bytes <= self.physical_memory_bytes
                    && group.milli_cpus == 0
                    && (16..=8192).contains(&group.pids)
                    && (1..=10000).contains(&control.cpu_weight),
                "control resources require finite measured memory, swap, PID and CPU weight limits"
            );
            protected += i128::from(control.memory_low_bytes);
        }
        ensure!(
            protected + (64 << 20) <= i128::from(self.os_reserve_bytes),
            "control reserves consume the base OS reserve"
        );
        let serving = if self.apps.is_empty() {
            i128::from(self.production.memory_bytes)
        } else {
            self.apps
                .values()
                .map(|app| i128::from(app.memory_low_bytes))
                .sum()
        };
        let other = (64_i128 << 20)
            + serving
            + i128::from(self.proxy.memory_bytes)
            + i128::from(self.previews.memory_bytes)
            + i128::from(self.preview_database.memory_bytes);
        for control in self.controls.values() {
            ensure!(
                other + protected - i128::from(control.memory_low_bytes)
                    + i128::from(control.group.memory_bytes)
                    <= i128::from(self.physical_memory_bytes),
                "one controller ceiling consumes another serving reserve"
            );
        }
        Ok(())
    }
    pub fn check_serving_budget(
        &self,
        app: &str,
        resources: Option<&ResourcePolicy>,
    ) -> Result<()> {
        let resources = resources.ok_or_else(|| anyhow!("serving budget is missing"))?;
        resources.check()?;
        if !resources.cgroup_parent.starts_with("/komizo-production/") {
            return Ok(());
        }
        ensure!(
            resources.cgroup_parent == format!("/komizo-production/{app}"),
            "serving budget uses another application's cgroup"
        );
        self.check(self.physical_memory_bytes, self.physical_milli_cpus)?;
        let group = self
            .apps
            .get(app)
            .filter(|group| group.memory_low_bytes == resources.max_memory_reserve_bytes)
            .ok_or_else(|| {
                anyhow!(
                    "serving budget does not fit the installed application reserve and ceilings"
                )
            })?;
        if resources.aggregate_mode == "cgroup" {
            ensure!(
                resources.startup_allowance_bytes > 0
                    && resources.startup_allowance_bytes
                        <= group.memory_high_bytes - group.memory_low_bytes,
                "startup allowance consumes the application's serving reserve"
            );
            return Ok(());
        }
        ensure!(
            resources.max_memory_bytes <= group.group.memory_bytes
                && i128::from(resources.max_memory_swap_bytes)
                    <= i128::from(group.group.memory_bytes) + i128::from(group.group.swap_bytes)
                && resources.max_milli_cpus <= group.group.milli_cpus,
            "serving budget does not fit the installed application reserve and ceilings"
        );
        Ok(())
    }
    pub fn check_startup(
        &self,
        app: &str,
        resources: Option<&ResourcePolicy>,
        parent_usage: i64,
        usage: &BTreeMap<String, i64>,
    ) -> Result<()> {
        let resources = resources
            .filter(|resources| resources.cgroup_parent == format!("/komizo-production/{app}"))
            .ok_or_else(|| anyhow!("startup requires the installed application allocation"))?;
        self.check_serving_budget(app, Some(resources))?;
        let group = self.apps.get(app).ok_or_else(|| {
            anyhow!("startup requires measured application usage and a positive startup allowance")
        })?;
        let current = *usage
            .get(app)
            .filter(|current| {
                **current >= 0
                    && parent_usage >= **current
                    && parent_usage <= self.production.memory_bytes
                    && resources.startup_allowance_bytes > 0
            })
            .ok_or_else(|| {
                anyhow!(
                    "startup requires measured application usage and a positive startup allowance"
                )
            })?;
        ensure!(
            i128::from(current)
                <= i128::from(group.memory_high_bytes)
                    - i128::from(resources.startup_allowance_bytes),
            "application serving pressure refuses startup"
        );
        let mut available = i128::from(self.production.memory_bytes)
            - i128::from(parent_usage)
            - i128::from(resources.startup_allowance_bytes);
        let mut children = 0_i128;
        for (name, other) in &self.apps {
            let observed = *usage
                .get(name)
                .filter(|value| **value >= 0 && **value <= other.group.memory_bytes)
                .ok_or_else(|| {
                    anyhow!("application usage is missing or exceeds its installed ceiling")
                })?;
            children += i128::from(observed);
            if name != app && observed < other.memory_low_bytes {
                available -= i128::from(other.memory_low_bytes - observed);
            }
        }
        ensure!(
            children <= i128::from(parent_usage),
            "startup usage changed while measuring the application inventory"
        );
        ensure!(
            available >= 0,
            "startup would consume another application's serving reserve"
        );
        Ok(())
    }
}
