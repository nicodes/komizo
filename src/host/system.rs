//! Kernel observations retain absent counters rather than inventing measurements.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Default)]
pub struct Probe {
    pub root: PathBuf,
}
impl Probe {
    pub fn path(&self, path: impl AsRef<Path>) -> PathBuf {
        if self.root.as_os_str().is_empty() {
            return path.as_ref().to_owned();
        }
        self.root
            .join(path.as_ref().strip_prefix("/").unwrap_or(path.as_ref()))
    }
    pub fn cpu(&self) -> Option<Cpu> {
        for line in lines(self.path("/proc/stat")) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 || fields[0] != "cpu" {
                continue;
            }
            let values: Vec<u64> = fields[1..]
                .iter()
                .map(|v| unsigned(v))
                .collect::<Option<_>>()?;
            return Some(Cpu {
                total: values.iter().fold(0u64, |sum, n| sum.wrapping_add(*n)),
                idle: values[3].wrapping_add(values[4]),
            });
        }
        None
    }
    pub fn cores(&self) -> i64 {
        lines(self.path("/proc/cpuinfo"))
            .iter()
            .filter(|l| l.starts_with("processor"))
            .count() as i64
    }
    pub fn mem(&self) -> Option<Mem> {
        let mut values = BTreeMap::new();
        for line in lines(self.path("/proc/meminfo")) {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let Some(value) = value.split_whitespace().next().and_then(unsigned) else {
                continue;
            };
            values.insert(key.to_owned(), value.wrapping_mul(1024));
        }
        let total = *values.get("MemTotal")?;
        let available = *values.get("MemAvailable")?;
        if total == 0 {
            return None;
        }
        let swap = match (values.get("SwapTotal"), values.get("SwapFree")) {
            (Some(&total), Some(&free)) if total > 0 => Some(Swap {
                total,
                used: total.saturating_sub(free),
            }),
            _ => None,
        };
        Some(Mem {
            total,
            used: total.wrapping_sub(available),
            available,
            swap,
        })
    }
    pub fn uptime(&self) -> i64 {
        lines(self.path("/proc/uptime"))
            .first()
            .and_then(|l| l.split_whitespace().next())
            .and_then(crate::workload::resources::parse_cpu)
            .filter(|v| v.is_finite())
            .unwrap_or(0.0) as i64
    }
    pub fn listening_ports(&self, pid: i64) -> Vec<i64> {
        if pid <= 0 {
            return vec![];
        }
        let mut seen = BTreeSet::new();
        for name in ["tcp", "tcp6"] {
            for line in lines(self.path(format!("/proc/{pid}/net/{name}"))) {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 4 || fields[3] != "0A" {
                    continue;
                }
                let Some((_, port)) = fields[1].split_once(':') else {
                    continue;
                };
                if let Ok(port) = u32::from_str_radix(port, 16)
                    && !(32768..=60999).contains(&port)
                {
                    seen.insert(i64::from(port));
                }
            }
        }
        seen.into_iter().collect()
    }
    pub fn cgroup_stat(&self, pid: i64) -> ContainerStat {
        let mut stat = ContainerStat::default();
        if pid <= 0 {
            return stat;
        }
        let entries = lines(self.path(format!("/proc/{pid}/cgroup")));
        for line in &entries {
            let fields: Vec<_> = line.splitn(3, ':').collect();
            if fields.len() != 3 || fields[0] != "0" {
                continue;
            }
            let Some(dir) = self.cgroup_path("", fields[2]) else {
                break;
            };
            if !dir.is_dir() {
                break;
            }
            stat.cpu_usec = field_from(dir.join("cpu.stat"), "usage_usec");
            cgroup_pressure_stats(&dir, &mut stat);
            stat.mem = num_from(dir.join("memory.current")).map(|current| {
                current.saturating_sub(
                    field_from(dir.join("memory.stat"), "inactive_file").unwrap_or(0),
                )
            });
            stat.limit = num_from(dir.join("memory.max"));
            return stat;
        }
        for line in &entries {
            let fields: Vec<_> = line.splitn(3, ':').collect();
            if fields.len() != 3 {
                continue;
            }
            for controller in fields[1].split(',') {
                let Some(dir) = self.cgroup_path(controller, fields[2]) else {
                    continue;
                };
                match controller {
                    "cpuacct" => {
                        stat.cpu_usec = num_from(dir.join("cpuacct.usage")).map(|n| n / 1000)
                    }
                    "memory" => {
                        stat.mem = num_from(dir.join("memory.usage_in_bytes")).map(|current| {
                            current.saturating_sub(
                                field_from(dir.join("memory.stat"), "total_inactive_file")
                                    .unwrap_or(0),
                            )
                        });
                        stat.limit = num_from(dir.join("memory.limit_in_bytes"));
                    }
                    _ => {}
                }
            }
        }
        stat
    }
    fn cgroup_path(&self, controller: &str, name: &str) -> Option<PathBuf> {
        if Path::new(name)
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            return None;
        }
        Some(
            self.path(
                Path::new("/sys/fs/cgroup")
                    .join(controller)
                    .join(name.trim_start_matches('/')),
            ),
        )
    }
    pub fn group_stats(&self) -> Vec<GroupStat> {
        let mut result = vec![];
        for name in [
            "komizo-production",
            "komizo-proxy",
            "komizo-previews",
            "komizo-preview-database",
            "openrc.komizo-rootd",
            "openrc.komizo-api",
            "openrc.docker",
        ] {
            let dir = self.path(Path::new("/sys/fs/cgroup").join(name));
            if !dir.is_dir() {
                continue;
            }
            let mut stat = ContainerStat::default();
            cgroup_pressure_stats(&dir, &mut stat);
            stat.cpu_usec = field_from(dir.join("cpu.stat"), "usage_usec");
            stat.limit = num_from(dir.join("memory.max"));
            result.push(GroupStat {
                name: name.into(),
                stat,
            });
        }
        result
    }
    pub fn disks(&self) -> Vec<Disk> {
        let mut seen = BTreeSet::new();
        let mut result = vec![];
        for mount in ["/", "/var/lib/docker"] {
            let Some(mut disk) = statfs(&self.path(mount)) else {
                continue;
            };
            if disk.size == 0 || !disk.dev.is_empty() && !seen.insert(disk.dev.clone()) {
                continue;
            }
            disk.mount = mount.into();
            result.push(disk);
        }
        result
    }
    pub fn system_counters(&self) -> System {
        System {
            cores: self.cores(),
            cpu: self.cpu(),
            mem: self.mem(),
            pressure: read_pressure(&self.path("/proc/pressure"), ""),
            groups: self.group_stats().into(),
            disks: self.disks().into(),
            ..Default::default()
        }
    }
}
pub(crate) fn lines(path: impl AsRef<Path>) -> Vec<String> {
    crate::statefile::read(path.as_ref(), 4 << 20)
        .ok()
        .flatten()
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .replace("\r\n", "\n")
                .split('\n')
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
pub(crate) fn unsigned(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}
pub fn num_from(path: impl AsRef<Path>) -> Option<u64> {
    let bytes = crate::statefile::read(path.as_ref(), 4096).ok()??;
    unsigned(std::str::from_utf8(&bytes).ok()?.trim())
}
pub fn field_from(path: impl AsRef<Path>, key: &str) -> Option<u64> {
    for line in lines(path) {
        let mut fields = line.split_whitespace();
        if fields.next() == Some(key) {
            return fields.next().and_then(unsigned);
        }
    }
    None
}
pub fn read_pressure(dir: &Path, suffix: &str) -> Option<Pressure> {
    let p = Pressure {
        cpu: pressure_file(&dir.join(format!("cpu{suffix}"))),
        memory: pressure_file(&dir.join(format!("memory{suffix}"))),
        io: pressure_file(&dir.join(format!("io{suffix}"))),
    };
    (p.cpu.is_some() || p.memory.is_some() || p.io.is_some()).then_some(p)
}
pub fn pressure_file(path: &Path) -> Option<PressureResource> {
    let bytes = crate::statefile::read(path, 4096).ok()??;
    parse_pressure(std::str::from_utf8(&bytes).ok()?)
}
pub fn parse_pressure(body: &str) -> Option<PressureResource> {
    if body.len() > 4096 {
        return None;
    }
    let mut result = PressureResource::default();
    for line in body.split('\n') {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 5 {
            continue;
        }
        let values: BTreeMap<_, _> = fields[1..]
            .iter()
            .filter_map(|f| f.split_once('='))
            .collect();
        let Some(avgs) = ["avg10", "avg60", "avg300"]
            .iter()
            .map(|key| {
                crate::workload::resources::parse_cpu(values.get(key)?)
                    .filter(|v| v.is_finite() && (0.0..=100.0).contains(v))
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let Some(total_usec) = values.get("total").and_then(|v| unsigned(v)) else {
            continue;
        };
        let value = Some(PressureLine {
            avg10: avgs[0],
            avg60: avgs[1],
            avg300: avgs[2],
            total_usec,
        });
        match fields[0] {
            "some" => result.some = value,
            "full" => result.full = value,
            _ => {}
        }
    }
    (result.some.is_some() || result.full.is_some()).then_some(result)
}
fn cgroup_pressure_stats(dir: &Path, stat: &mut ContainerStat) {
    stat.pressure = read_pressure(dir, ".pressure");
    stat.cpu_periods = field_from(dir.join("cpu.stat"), "nr_periods");
    stat.cpu_throttled_periods = field_from(dir.join("cpu.stat"), "nr_throttled");
    stat.cpu_throttled_usec = field_from(dir.join("cpu.stat"), "throttled_usec");
    stat.memory_max_events = field_from(dir.join("memory.events"), "max");
    stat.oom_kills = field_from(dir.join("memory.events"), "oom_kill");
    stat.memory_anon = field_from(dir.join("memory.stat"), "anon");
    stat.memory_kernel = field_from(dir.join("memory.stat"), "kernel");
    stat.memory_inactive_file = field_from(dir.join("memory.stat"), "inactive_file");
    stat.memory_current = num_from(dir.join("memory.current"));
    stat.swap = num_from(dir.join("memory.swap.current"));
}
pub fn disk_accounting(bsize: u64, blocks: u64, bfree: u64, bavail: u64) -> (u64, u64, u64) {
    if bsize == 0 {
        return (0, 0, 0);
    }
    let used = blocks.wrapping_sub(bfree).wrapping_mul(bsize);
    let available = bavail.wrapping_mul(bsize);
    (used, used.wrapping_add(available), available)
}
pub fn inode_accounting(files: u64, free: u64) -> Option<Inodes> {
    (files > 0).then(|| Inodes {
        used: files.saturating_sub(free),
        free,
    })
}
#[cfg(target_os = "linux")]
pub fn statfs(path: &Path) -> Option<Disk> {
    use std::{ffi::CString, mem::MaybeUninit, os::unix::ffi::OsStrExt};
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the C path is terminated and statfs initializes the output on success.
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    let bsize = stat.f_bsize as u64;
    if bsize == 0 {
        return None;
    }
    let (used, size, available) =
        disk_accounting(bsize, stat.f_blocks, stat.f_bfree, stat.f_bavail);
    // Linux fsid_t consists of two native 32-bit integers on supported targets.
    let ids: [u32; 2] = unsafe { std::mem::transmute(stat.f_fsid) };
    Some(Disk {
        dev: format!("{:x}-{:x}", ids[0], ids[1]),
        used,
        size,
        available,
        inodes: inode_accounting(stat.f_files, stat.f_ffree),
        ..Default::default()
    })
}
#[cfg(not(target_os = "linux"))]
pub fn statfs(_path: &Path) -> Option<Disk> {
    None
}
