use super::*;
use crate::cgroupfs::Directory;
use anyhow::Context;
use std::path::Path;
fn required(directory: &Directory, name: &str, limit: usize, message: &str) -> Result<Vec<u8>> {
    directory
        .read(name, limit)
        .map_err(|_| anyhow!("{message}"))?
        .ok_or_else(|| anyhow!("{message}"))
}
fn usage(
    directory: &Directory,
    limits: [(&str, i64); 3],
    unavailable: &str,
    refusal: &str,
) -> Result<()> {
    for (name, limit) in limits {
        let body = required(directory, name, 128, unavailable)?;
        let value = std::str::from_utf8(&body)
            .ok()
            .and_then(|body| body.trim().parse::<i64>().ok());
        ensure!(
            value.is_some_and(|value| value >= 0 && value <= limit),
            "{refusal}"
        );
    }
    Ok(())
}
fn settings(
    directory: &Directory,
    values: impl IntoIterator<Item = (&'static str, String)>,
    context: &str,
) -> Result<()> {
    for (name, value) in values {
        directory
            .write(name, &value)
            .with_context(|| format!("{context}/{name}"))?;
    }
    Ok(())
}
fn io_devices(directory: &Directory) -> Result<Vec<String>> {
    let Some(body) = directory
        .read("io.max", 64 << 10)
        .map_err(|_| anyhow!("disk limit inventory is unavailable or oversized"))?
    else {
        return Ok(vec![]);
    };
    let body =
        std::str::from_utf8(&body).map_err(|_| anyhow!("disk limit inventory is ambiguous"))?;
    let mut seen = BTreeSet::new();
    let mut devices = vec![];
    for line in body.trim().lines() {
        if line.trim().is_empty() {
            continue;
        }
        let device = line.split_whitespace().next().unwrap();
        ensure!(
            block_device(device) && seen.insert(device) && devices.len() < 16,
            "disk limit inventory is ambiguous"
        );
        devices.push(device.into());
    }
    Ok(devices)
}
impl HostResources {
    pub fn preflight(&self, root: &Path, measured_memory: i64, measured_cpu: i64) -> Result<()> {
        self.check(measured_memory, measured_cpu)?;
        let directory = Directory::open(root)
            .map_err(|_| anyhow!("cgroup v2 controller inventory unavailable"))?;
        let controllers = required(
            &directory,
            "cgroup.controllers",
            64 << 10,
            "cgroup v2 controller inventory unavailable",
        )?;
        let controllers = std::str::from_utf8(&controllers)
            .map_err(|_| anyhow!("cgroup v2 controller inventory unavailable"))?;
        let available = controllers.split_whitespace().collect::<BTreeSet<_>>();
        for name in ["cpu", "memory", "pids"]
            .into_iter()
            .chain(if self.apps.is_empty() {
                None
            } else {
                Some("io")
            })
        {
            ensure!(
                available.contains(name),
                "required cgroup v2 controller unavailable"
            );
        }
        for (name, control) in &self.controls {
            if let Some(group) = directory
                .directory(name, false)
                .map_err(|_| anyhow!("required OpenRC control group unavailable"))?
            {
                usage(
                    &group,
                    [
                        ("memory.current", control.group.memory_bytes),
                        ("memory.swap.current", control.group.swap_bytes),
                        ("pids.current", control.group.pids),
                    ],
                    "control usage unavailable",
                    "control reduction requires measurement and drain",
                )?;
            }
        }
        if !self.controls.is_empty() && !self.controls.contains_key("openrc.sshd") {
            directory
                .directory("openrc.sshd", false)
                .map_err(|_| anyhow!("SSH control group is not a real directory"))?;
        }
        let production = directory
            .directory("komizo-production", false)
            .map_err(|_| anyhow!("host cgroup path is not a real directory"))?;
        for (name, app) in &self.apps {
            if app.io_weight > 0 {
                ensure!(
                    production.as_ref().is_some_and(|production| production
                        .read("io.weight", 64 << 10)
                        .ok()
                        .flatten()
                        .is_some()),
                    "requested I/O weighting controller unavailable; select explicit device rate limits or a supported weighting backend"
                );
            }
            if root == Path::new("/sys/fs/cgroup") {
                for limit in app.io_max.iter() {
                    ensure!(
                        std::fs::metadata(Path::new("/sys/dev/block").join(&limit.device)).is_ok(),
                        "reviewed disk device is unavailable"
                    );
                }
            }
            if let Some(production) = &production
                && let Some(group) = production
                    .directory(name, false)
                    .map_err(|_| anyhow!("application cgroup path is not a real directory"))?
            {
                io_devices(&group)?;
                usage(
                    &group,
                    [
                        ("memory.current", app.group.memory_bytes),
                        ("memory.swap.current", app.group.swap_bytes),
                        ("pids.current", app.group.pids),
                    ],
                    "application usage is unavailable",
                    "application resource reduction requires measurement and drain",
                )?;
            }
        }
        for (name, group) in self.groups() {
            if let Some(directory) = directory
                .directory(name, false)
                .map_err(|_| anyhow!("host cgroup path is not a real directory"))?
            {
                for (file, limit) in [
                    ("memory.current", group.memory_bytes),
                    ("memory.swap.current", group.swap_bytes),
                    ("pids.current", group.pids),
                ] {
                    let body = required(
                        &directory,
                        file,
                        128,
                        &format!("host usage unavailable for {name}/{file}"),
                    )?;
                    let current = std::str::from_utf8(&body)
                        .ok()
                        .and_then(|body| body.trim().parse::<i64>().ok());
                    ensure!(
                        current.is_some_and(|current| current >= 0 && current <= limit),
                        "host resource change would reduce {name}/{file} below current usage; measure and drain first"
                    );
                }
            }
        }
        Ok(())
    }
    pub fn apply(&self, root: &Path, measured_memory: i64, measured_cpu: i64) -> Result<()> {
        self.preflight(root, measured_memory, measured_cpu)?;
        let directory = Directory::open(root)?;
        let control = if self.apps.is_empty() {
            "+cpu +memory +pids"
        } else {
            "+cpu +memory +pids +io"
        };
        directory.write("cgroup.subtree_control", control)?;
        for (name, group) in &self.controls {
            let target = directory.directory(name, true)?.unwrap();
            settings(
                &target,
                [
                    ("memory.low", group.memory_low_bytes.to_string()),
                    ("memory.high", group.memory_high_bytes.to_string()),
                    ("memory.max", group.group.memory_bytes.to_string()),
                    ("memory.swap.max", group.group.swap_bytes.to_string()),
                    ("pids.max", group.group.pids.to_string()),
                    ("cpu.weight", group.cpu_weight.to_string()),
                    ("cpu.max", "max 100000".into()),
                ],
                &format!("apply control {name}"),
            )?;
        }
        if !self.controls.is_empty()
            && !self.controls.contains_key("openrc.sshd")
            && let Some(target) = directory.directory("openrc.sshd", false)?
        {
            settings(
                &target,
                [
                    ("memory.low", "0".into()),
                    ("memory.high", "max".into()),
                    ("memory.max", "max".into()),
                    ("memory.swap.max", "max".into()),
                    ("pids.max", "max".into()),
                    ("cpu.weight", "100".into()),
                    ("cpu.max", "max 100000".into()),
                ],
                "restore SSH control",
            )?;
        }
        for (name, group) in self.groups() {
            let target = directory.directory(name, true)?.unwrap();
            settings(
                &target,
                [
                    ("memory.max", group.memory_bytes.to_string()),
                    ("memory.swap.max", group.swap_bytes.to_string()),
                    ("cpu.max", format!("{} 100000", group.milli_cpus * 100)),
                    ("pids.max", group.pids.to_string()),
                    ("cgroup.subtree_control", "+cpu +memory +pids".into()),
                ],
                &format!("apply {name}"),
            )?;
            if name == "komizo-proxy" {
                target.write("memory.low", &group.memory_bytes.to_string())?;
            }
        }
        let production = directory.directory("komizo-production", false)?.unwrap();
        let mut reserve = 0_i64;
        if !self.apps.is_empty() {
            production.write("cgroup.subtree_control", control)?;
            for (name, app) in &self.apps {
                reserve = reserve
                    .checked_add(app.memory_low_bytes)
                    .ok_or_else(|| anyhow!("application reserve overflow"))?;
                let target = production.directory(name, true)?.unwrap();
                settings(
                    &target,
                    [
                        ("memory.low", app.memory_low_bytes.to_string()),
                        ("memory.high", app.memory_high_bytes.to_string()),
                        ("memory.max", app.group.memory_bytes.to_string()),
                        ("memory.swap.max", app.group.swap_bytes.to_string()),
                        ("cpu.max", format!("{} 100000", app.group.milli_cpus * 100)),
                        ("cpu.weight", app.cpu_weight.to_string()),
                        ("pids.max", app.group.pids.to_string()),
                        ("cgroup.subtree_control", control.into()),
                    ],
                    &format!("apply application group {name}"),
                )?;
                if app.io_weight > 0 {
                    target.write("io.weight", &format!("default {}", app.io_weight))?;
                }
                for device in io_devices(&target)? {
                    target.write(
                        "io.max",
                        &format!("{device} rbps=max wbps=max riops=max wiops=max"),
                    )?;
                }
                for limit in app.io_max.iter() {
                    let mut value = format!(
                        "{} rbps={} wbps={}",
                        limit.device, limit.read_bytes_per_second, limit.write_bytes_per_second
                    );
                    if limit.read_iops > 0 {
                        value.push_str(&format!(" riops={}", limit.read_iops));
                    }
                    if limit.write_iops > 0 {
                        value.push_str(&format!(" wiops={}", limit.write_iops));
                    }
                    target
                        .write("io.max", &value)
                        .with_context(|| format!("apply application disk limit {name}"))?;
                }
            }
        }
        production.write("memory.low", &reserve.to_string())?;
        Ok(())
    }
}
