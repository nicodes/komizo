//! Protected resource JSON and measured controller adapters share the declared envelope.
use super::{
    Probe,
    workload::{
        files::{self, Document},
        transaction::hash,
    },
};
use crate::{
    statefile, wire_struct,
    workload::{host_resources::HostResources, policy::Policy},
};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
const GROUP: &[&str] = &["memory_bytes", "swap_bytes", "milli_cpus", "pids"];
impl Document for HostResources {
    fn fields() -> &'static [&'static str] {
        &[
            "version",
            "physical_memory_bytes",
            "os_reserve_bytes",
            "physical_milli_cpus",
            "os_reserve_milli_cpus",
            "production",
            "proxy",
            "previews",
            "preview_database",
            "apps",
            "controls",
        ]
    }
    fn normalize(value: Value) -> Result<Value> {
        let mut value = crate::strict::fields(value, Self::fields())?;
        for name in ["production", "proxy", "previews", "preview_database"] {
            if let Some(group) = value.get_mut(name) {
                *group = crate::strict::fields(group.take(), GROUP)?
            }
        }
        for name in ["apps", "controls"] {
            if let Some(Value::Object(groups)) = value.get_mut(name) {
                for group in groups.values_mut() {
                    let mut fields = GROUP.to_vec();
                    fields.extend(["memory_low_bytes", "memory_high_bytes", "cpu_weight"]);
                    if name == "apps" {
                        fields.extend(["baseline_memory_bytes", "io_weight", "io_max"])
                    }
                    *group = crate::strict::fields(group.take(), &fields)?;
                    if let Some(Value::Array(devices)) = group.get_mut("io_max") {
                        for device in devices {
                            *device = crate::strict::fields(
                                device.take(),
                                &[
                                    "device",
                                    "read_bytes_per_second",
                                    "write_bytes_per_second",
                                    "read_iops",
                                    "write_iops",
                                ],
                            )?
                        }
                    }
                }
            }
        }
        Ok(value)
    }
}
pub fn read_resources(body: &[u8]) -> Result<HostResources> {
    files::decode(body, 1 << 20)
}
pub fn host_memory(probe: &Probe) -> Result<i64> {
    let body = statefile::read(&probe.path("/proc/meminfo"), 1 << 20)?
        .ok_or_else(|| anyhow!("measured host memory unavailable"))?;
    for line in String::from_utf8_lossy(&body).split('\n') {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
            let n = fields[1]
                .parse::<i64>()
                .ok()
                .filter(|n| *n > 0 && *n <= 1 << 50)
                .ok_or_else(|| anyhow!("measured host memory unavailable"))?;
            return Ok(n * 1024);
        }
    }
    anyhow::bail!("measured host memory unavailable")
}
pub fn measured_cpu() -> i64 {
    // NumCPU measures scheduling affinity; a service quota is not the host's
    // physical admission capacity. available_parallelism also applies quotas.
    #[cfg(target_os = "linux")]
    {
        let mut bytes = 128;
        while bytes <= 1 << 20 {
            let mut mask = vec![0_u8; bytes];
            if unsafe { libc::sched_getaffinity(0, bytes, mask.as_mut_ptr().cast()) } == 0 {
                let count: u64 = mask.iter().map(|b| u64::from(b.count_ones())).sum();
                if count > 0 {
                    return count as i64 * 1000;
                }
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
                break;
            }
            bytes *= 2;
        }
    }
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 { count as i64 * 1000 } else { 1000 }
}
pub fn installed_serving_budget(root: &Path, p: &Policy) -> Result<()> {
    if !p
        .resources
        .as_ref()
        .is_some_and(|r| r.cgroup_parent.starts_with("/komizo-production/"))
    {
        return Ok(());
    }
    let probe = Probe { root: root.into() };
    let host: HostResources = files::read_json(&probe.path("/etc/komizo/resources.json"))
        .map_err(|_| anyhow!("installed host serving allocation is unavailable"))?;
    host.check(host_memory(&probe)?, measured_cpu())?;
    host.check_serving_budget(&p.app, p.resources.as_ref())
}
wire_struct!(ProxyBudget{version:"version":i64=>required,memory_bytes:"memory_bytes":i64=>required,total_swap_bytes:"total_memory_swap_bytes":i64=>required,milli_cpus:"milli_cpus":i64=>required,pids:"pids":i64=>required,cgroup_parent:"cgroup_parent":String=>required,policy_sha256:"policy_sha256":Option<String> =>required});
impl ProxyBudget {
    pub fn compose(&self) -> String {
        let mut body = format!(
            "    mem_limit: {}\n    memswap_limit: {}\n    cpus: \"{}.{:03}\"\n    pids_limit: {}\n",
            self.memory_bytes,
            self.total_swap_bytes,
            self.milli_cpus / 1000,
            self.milli_cpus % 1000,
            self.pids
        );
        body.push_str(&format!(
            "    environment:\n      GOMEMLIMIT: \"{}\"\n      GODEBUG: disablethp=1\n",
            (self.memory_bytes * 2 / 5).max(8 << 20)
        ));
        if !self.cgroup_parent.is_empty() {
            body.push_str(&format!("    cgroup_parent: {}\n", self.cgroup_parent))
        }
        body
    }
}
pub fn proxy_budget(
    root: &Path,
    owner: &dyn Fn(&fs::Metadata) -> bool,
    measured_memory: i64,
    measured_cpu: i64,
) -> Result<ProxyBudget> {
    let mut budget = ProxyBudget {
        version: 1,
        memory_bytes: 96 << 20,
        total_swap_bytes: 128 << 20,
        milli_cpus: 100,
        pids: 128,
        ..Default::default()
    };
    ensure!(
        root.is_absolute()
            && super::inventory::clean_path(&root.to_string_lossy()) == root.to_string_lossy(),
        "proxy budget root is not canonical"
    );
    let path = root.join("etc/komizo/resources.json");
    for parent in path.parent().unwrap().ancestors() {
        let info = fs::symlink_metadata(parent)
            .map_err(|_| anyhow!("proxy resources require protected ancestry"))?;
        ensure!(
            info.is_dir() && info.mode() & 0o022 == 0 && owner(&info),
            "proxy resources require protected ancestry"
        );
        if parent == root {
            break;
        }
    }
    let info = match fs::symlink_metadata(&path) {
        Ok(info) => info,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(budget),
        Err(_) => anyhow::bail!("proxy resource policy is not private and bounded"),
    };
    ensure!(
        info.is_file() && info.mode() & 0o077 == 0 && owner(&info) && info.len() <= 1 << 20,
        "proxy resource policy is not private and bounded"
    );
    let body = statefile::read(&path, 1 << 20)?
        .ok_or_else(|| anyhow!("proxy resource policy unavailable"))?;
    let host = read_resources(&body).map_err(|_| anyhow!("invalid proxy resource policy"))?;
    host.check(measured_memory, measured_cpu)?;
    let group = host.proxy;
    for (name, wanted) in [
        ("memory.max", group.memory_bytes.to_string()),
        ("memory.swap.max", group.swap_bytes.to_string()),
        ("cpu.max", format!("{} 100000", group.milli_cpus * 100)),
        ("pids.max", group.pids.to_string()),
    ] {
        let path = root.join("sys/fs/cgroup/komizo-proxy").join(name);
        let body = statefile::read(&path, 64).ok().flatten();
        ensure!(
            body.is_some_and(|body| String::from_utf8_lossy(&body)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                == wanted),
            "proxy resource controllers drifted; apply reviewed host resources first"
        );
    }
    budget.memory_bytes = group.memory_bytes;
    budget.total_swap_bytes = group.memory_bytes + group.swap_bytes;
    budget.milli_cpus = group.milli_cpus;
    budget.pids = group.pids;
    budget.cgroup_parent = "/komizo-proxy".into();
    budget.policy_sha256 = Some(hash(&body));
    Ok(budget)
}
fn protected(info: &fs::Metadata, owner: u32) -> bool {
    info.is_file() && info.mode() & 0o022 == 0 && info.uid() == owner
}
fn write_existing(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "control is not regular");
    file.write_all(body)?;
    Ok(())
}
pub fn enter_read_budget(policy: &Path, cgroup: &Path, pid: i32, owner: u32) -> Result<()> {
    let info = match fs::symlink_metadata(policy) {
        Ok(info) => info,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => anyhow::bail!("read resource authority unavailable"),
    };
    ensure!(
        protected(&info, owner) && info.mode() & 0o077 == 0 && info.len() <= 65536,
        "read resource authority unavailable"
    );
    let body = statefile::read(policy, 65536)?
        .ok_or_else(|| anyhow!("read resource authority unavailable"))?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| anyhow!("read resource authority invalid"))?;
    ensure!(
        value.is_null() || value.is_object(),
        "read resource authority invalid"
    );
    let field = |value: &Value, name: &str| -> Option<Value> {
        value.as_object().and_then(|fields| {
            fields
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
                .next_back()
        })
    };
    let controls_value = field(&value, "controls");
    let controls = controls_value
        .as_ref()
        .filter(|v| !v.is_null())
        .and_then(Value::as_object);
    if controls_value
        .as_ref()
        .is_some_and(|v| !v.is_null() && !v.is_object())
    {
        anyhow::bail!("read resource authority invalid")
    }
    let Some(controls) = controls.filter(|c| !c.is_empty()) else {
        return Ok(());
    };
    let mut memory = None;
    for (name, group) in controls {
        ensure!(
            group.is_null() || group.is_object(),
            "read resource authority invalid"
        );
        let value = field(group, "memory_bytes").unwrap_or(Value::Null);
        ensure!(
            value.is_null() || value.as_i64().is_some(),
            "read resource authority invalid"
        );
        if name == "openrc.komizo-rootd" {
            memory = Some(value.as_i64().unwrap_or_default())
        }
    }
    ensure!(
        memory.is_some_and(|n| n >= 4 << 20) && pid > 0,
        "declared read envelope unavailable"
    );
    let memory = memory.unwrap();
    let dir = cgroup.join("openrc.komizo-rootd");
    for path in [cgroup, &dir] {
        let info = fs::symlink_metadata(path)
            .map_err(|_| anyhow!("protected read control group unavailable"))?;
        ensure!(
            info.is_dir() && info.mode() & 0o022 == 0 && info.uid() == owner,
            "protected read control group unavailable"
        )
    }
    for name in ["memory.max", "cgroup.procs"] {
        let info = fs::symlink_metadata(dir.join(name))
            .map_err(|_| anyhow!("read control interface unavailable"))?;
        ensure!(
            protected(&info, owner),
            "read control interface unavailable"
        )
    }
    let body = statefile::read(&dir.join("memory.max"), 64).ok().flatten();
    ensure!(
        body.is_some_and(|body| String::from_utf8_lossy(&body).trim() == memory.to_string()),
        "read control limit differs from authority"
    );
    write_existing(&dir.join("cgroup.procs"), pid.to_string().as_bytes())
}
pub fn kernel_memory(root: &Path, total: i64, owner: u32) -> Result<()> {
    if !cfg!(target_os = "linux") || total > 2 << 30 {
        return Ok(());
    }
    let base = root.join("sys/kernel/mm/transparent_hugepage");
    let path = base.join("enabled");
    let info = match fs::symlink_metadata(&path) {
        Ok(info) => info,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => anyhow::bail!("kernel memory control unavailable"),
    };
    ensure!(protected(&info, owner), "kernel memory control unavailable");
    let enabled = statefile::read(&path, 65536)?
        .ok_or_else(|| anyhow!("kernel memory control unavailable"))?;
    let enabled = String::from_utf8_lossy(&enabled);
    if enabled.contains("[never]") {
        return Ok(());
    }
    ensure!(
        enabled.contains("[always]") || enabled.contains("[madvise]"),
        "unknown kernel memory mode"
    );
    for parent in base.ancestors() {
        if parent == root || parent == Path::new("/") {
            break;
        }
        let info = fs::symlink_metadata(parent)
            .map_err(|_| anyhow!("protected kernel memory ancestry unavailable"))?;
        ensure!(
            info.is_dir() && info.mode() & 0o022 == 0 && info.uid() == owner,
            "protected kernel memory ancestry unavailable"
        )
    }
    let knobs = [
        ("enabled", "madvise"),
        ("defrag", "defer+madvise"),
        ("khugepaged/max_ptes_none", "0"),
    ];
    for (name, _) in knobs {
        let info = fs::symlink_metadata(base.join(name))
            .map_err(|_| anyhow!("protected kernel memory control unavailable"))?;
        ensure!(
            protected(&info, owner),
            "protected kernel memory control unavailable"
        )
    }
    let defrag = statefile::read(&base.join("defrag"), 65536)?
        .ok_or_else(|| anyhow!("deferred kernel memory control unavailable"))?;
    ensure!(
        String::from_utf8_lossy(&defrag).contains("defer+madvise"),
        "deferred kernel memory control unavailable"
    );
    for (name, value) in knobs {
        write_existing(&base.join(name), value.as_bytes())?
    }
    Ok(())
}
