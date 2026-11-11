//! Fixed owned cgroup-v2 scopes; names are independent of any init system.
use super::{capacity, model::*, units, validation::*};
use anyhow::{Result, anyhow, ensure};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::OpenOptionsExt,
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

const ROOT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const CGROUP2: u64 = 0x6367_7270;

#[derive(Clone, Copy, Debug)]
pub enum Pool {
    Control,
    Proxy,
    Production,
    Previews,
}
#[derive(Clone, Copy, Debug)]
pub enum ControlLeaf {
    Controller,
    Dns,
    Expiry,
    Watchdogs,
}
#[derive(Clone, Copy, Debug)]
pub enum WorkloadKind {
    Service,
    Job,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    relative: String,
    branch: bool,
    disposable: bool,
}
impl Group {
    pub fn relative(&self) -> &str {
        &self.relative
    }
    pub fn path(&self) -> PathBuf {
        Path::new(ROOT).join(self.relative.trim_start_matches('/'))
    }
}
pub fn root_group() -> Group {
    Group {
        relative: "/komizo".into(),
        branch: true,
        disposable: false,
    }
}
pub fn pool_group(pool: Pool) -> Group {
    let name = match pool {
        Pool::Control => "control",
        Pool::Proxy => "proxy",
        Pool::Production => "production",
        Pool::Previews => "previews",
    };
    Group {
        relative: format!("/komizo/{name}"),
        branch: true,
        disposable: false,
    }
}
pub fn control_leaf(leaf: ControlLeaf) -> Group {
    let name = match leaf {
        ControlLeaf::Controller => "controller",
        ControlLeaf::Dns => "dns",
        ControlLeaf::Expiry => "expiry",
        ControlLeaf::Watchdogs => "watchdogs",
    };
    Group {
        relative: format!("/komizo/control/{name}"),
        branch: false,
        disposable: false,
    }
}
pub fn proxy_leaf() -> Group {
    Group {
        relative: "/komizo/proxy/server".into(),
        branch: false,
        disposable: false,
    }
}
pub fn instance_group(application: &str, instance: &str) -> Result<Group> {
    let pool = if instance == "production" {
        "production"
    } else {
        "previews"
    };
    Ok(Group {
        relative: format!(
            "/komizo/{pool}/{}",
            units::namespace(application, instance)?
        ),
        branch: true,
        disposable: true,
    })
}
pub fn workload_group(
    application: &str,
    instance: &str,
    kind: WorkloadKind,
    logical: &str,
    ownership: &str,
) -> Result<Group> {
    ensure!(
        name(logical) && hex(ownership, 32),
        "invalid owned workload group identity"
    );
    let parent = instance_group(application, instance)?;
    let kind = match kind {
        WorkloadKind::Service => "service",
        WorkloadKind::Job => "job",
    };
    Ok(Group {
        relative: format!("{}/{kind}-{logical}-{ownership}", parent.relative),
        branch: true,
        disposable: true,
    })
}
pub fn service_probe_group(
    application: &str,
    instance: &str,
    service: &str,
    ownership: &str,
) -> Result<Group> {
    let mut group = workload_group(
        application,
        instance,
        WorkloadKind::Service,
        service,
        ownership,
    )?;
    group.relative.push_str("/probe");
    group.branch = false;
    Ok(group)
}

pub fn workload_monitor_group(
    application: &str,
    instance: &str,
    kind: WorkloadKind,
    logical: &str,
    ownership: &str,
) -> Result<Group> {
    let mut group = workload_group(application, instance, kind, logical, ownership)?;
    group.relative.push_str("/conmon");
    group.branch = false;
    Ok(group)
}

pub fn task_group(kind: &str, operation: &str) -> Result<Group> {
    ensure!(
        ["backup", "prepare", "reconcile"].contains(&kind) && hex(operation, 32),
        "invalid protected task group identity"
    );
    Ok(Group {
        relative: format!("/komizo/control/komizo-{kind}-{operation}.service"),
        branch: true,
        disposable: true,
    })
}
pub fn task_runner(kind: &str, operation: &str) -> Result<Group> {
    let mut group = task_group(kind, operation)?;
    group.relative.push_str("/runner");
    group.branch = false;
    Ok(group)
}

#[cfg(target_os = "linux")]
fn check(file: &File, directory: bool) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "cgroup object is not protected root-owned kernel state"
    );
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } == 0
            && filesystem.f_type as u64 == CGROUP2,
        "resource boundary is not unified cgroupfs"
    );
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn check(_file: &File, _directory: bool) -> Result<()> {
    Err(anyhow!("native resource groups require Linux"))
}

fn root() -> Result<File> {
    ensure!(
        cfg!(target_os = "linux"),
        "native resource groups require Linux"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOT)?;
    check(&file, true)?;
    Ok(file)
}
fn directory(group: &Group, create: bool) -> Result<Option<File>> {
    let mut current = root()?;
    let names = group
        .relative
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    for (index, component) in names.iter().enumerate() {
        let name = CString::new(*component)?;
        let mut descriptor = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error.into());
            }
            if !create {
                return Ok(None);
            }
            ensure!(
                index + 1 == names.len(),
                "resource parent must be prepared before its child"
            );
            if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
                // A concurrent owner probe may prepare the same exact leaf.
                // Reopen without following links and retain every kernel/owner check.
            }
            descriptor = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        current = unsafe { File::from_raw_fd(descriptor) };
        check(&current, true)?;
    }
    Ok(Some(current))
}
fn control(directory: &File, name: &str, writable: bool) -> Result<File> {
    ensure!(
        !name.contains('/') && !name.contains('\0'),
        "invalid kernel resource filename"
    );
    let name = CString::new(name)?;
    let mode = if writable {
        libc::O_WRONLY
    } else {
        libc::O_RDONLY
    };
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            mode | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    check(&file, false)?;
    Ok(file)
}
fn text(directory: &File, name: &str) -> Result<String> {
    let mut raw = Vec::new();
    control(directory, name, false)?
        .take((1 << 20) + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= 1 << 20,
        "kernel resource evidence exceeds bound"
    );
    Ok(String::from_utf8(raw)?)
}
fn write(directory: &File, name: &str, value: &str) -> Result<()> {
    ensure!(value.len() <= 65536, "kernel resource write exceeds bound");
    control(directory, name, true)?.write_all(value.as_bytes())?;
    Ok(())
}
fn enable(directory: &File) -> Result<()> {
    let available = text(directory, "cgroup.controllers")?;
    let available = available.split_whitespace().collect::<Vec<_>>();
    ensure!(
        ["cpu", "memory", "pids"]
            .iter()
            .all(|name| available.contains(name)),
        "resource parent lacks required controllers"
    );
    let selected = ["cpu", "memory", "pids", "io"]
        .into_iter()
        .filter(|name| available.contains(name))
        .collect::<Vec<_>>();
    let enabled = text(directory, "cgroup.subtree_control")?;
    let missing = selected
        .iter()
        .filter(|name| !enabled.split_whitespace().any(|value| value == **name))
        .map(|name| format!("+{name}"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        write(directory, "cgroup.subtree_control", &missing.join(" "))?;
    }
    let observed = text(directory, "cgroup.subtree_control")?;
    ensure!(
        selected
            .iter()
            .all(|name| observed.split_whitespace().any(|value| value == *name)),
        "kernel refused child resource delegation"
    );
    Ok(())
}

pub fn values(limits: &Limits, controls: &ResourceControls) -> Result<Vec<(&'static str, String)>> {
    limits.validate()?;
    controls.validate(limits)?;
    let mut result = vec![
        ("memory.max", limits.memory_bytes.to_string()),
        (
            "memory.swap.max",
            (limits.memory_swap_bytes - limits.memory_bytes).to_string(),
        ),
        ("memory.low", controls.memory_low_bytes.to_string()),
        (
            "memory.high",
            if controls.memory_high_bytes == 0 {
                "max".into()
            } else {
                controls.memory_high_bytes.to_string()
            },
        ),
        ("pids.max", limits.pids.to_string()),
        (
            "cpu.max",
            format!("{} 1000000", u64::from(limits.milli_cpus) * 1000),
        ),
        ("cpu.weight", controls.cpu_weight.unwrap_or(100).to_string()),
    ];
    if let Some(weight) = controls.io_weight {
        result.push(("io.weight", format!("default {weight}")));
    }
    for rate in &controls.io_max {
        result.push((
            "io.max",
            format!(
                "{} rbps={} wbps={}",
                rate.device, rate.read_bytes_per_second, rate.write_bytes_per_second
            ),
        ));
    }
    Ok(result)
}
pub fn prepare(
    group: &Group,
    limits: &Limits,
    controls: &ResourceControls,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "resource preparation deadline expired"
    );
    limits.validate()?;
    controls.validate(limits)?;
    if group.relative == "/komizo" {
        enable(&root()?)?;
    }
    let directory =
        directory(group, true)?.ok_or_else(|| anyhow!("prepared cgroup disappeared"))?;
    if !empty_with(&directory)? {
        // Never change the allocation of an unexplained live group. Matching
        // live groups are read back; policy changes require prior quiescence.
        capacity::verify_cgroup(&group.path(), limits, controls)?;
    } else {
        for (name, value) in values(limits, controls)? {
            write(&directory, name, &value)?;
        }
    }
    if group.branch {
        ensure!(
            text(&directory, "cgroup.procs")?.trim().is_empty(),
            "resource branch contains an internal process"
        );
        enable(&directory)?;
    }
    verify(group, limits, controls)
}
pub fn verify(group: &Group, limits: &Limits, controls: &ResourceControls) -> Result<()> {
    limits.validate()?;
    controls.validate(limits)?;
    let directory =
        directory(group, false)?.ok_or_else(|| anyhow!("protected resource group is missing"))?;
    capacity::verify_cgroup(&group.path(), limits, controls)?;
    if controls.memory_high_bytes == 0 {
        ensure!(
            text(&directory, "memory.high")?.trim() == "max",
            "undeclared memory pressure limit remains"
        );
    }
    if controls.cpu_weight.is_none() {
        ensure!(
            text(&directory, "cpu.weight")?.trim() == "100",
            "undeclared CPU weight remains"
        );
    }
    Ok(())
}
fn empty_with(directory: &File) -> Result<bool> {
    let value = text(directory, "cgroup.events")?;
    let rows = value
        .lines()
        .filter_map(|line| line.strip_prefix("populated "))
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1 && ["0", "1"].contains(&rows[0]),
        "kernel resource population is ambiguous"
    );
    Ok(rows[0] == "0")
}
pub fn empty(group: &Group) -> Result<bool> {
    match directory(group, false)? {
        Some(directory) => empty_with(&directory),
        None => Ok(true),
    }
}
pub fn kill(group: &Group, deadline: Instant) -> Result<()> {
    ensure!(
        group.disposable,
        "fixed infrastructure is not a task/container kill scope"
    );
    kill_selected(group, deadline)
}

fn infrastructure_kill_scope(group: &Group) -> bool {
    [
        control_leaf(ControlLeaf::Controller),
        control_leaf(ControlLeaf::Dns),
        proxy_leaf(),
    ]
    .contains(group)
}

/// Only an independently proven exited fixed monitor authorizes this cleanup.
/// Shared watchdog/expiry leaves and every delegated branch are excluded.
pub fn kill_infrastructure(group: &Group, deadline: Instant) -> Result<()> {
    ensure!(
        infrastructure_kill_scope(group),
        "infrastructure cleanup requires an exact controller, DNS or proxy leaf"
    );
    kill_selected(group, deadline)
}

fn kill_selected(group: &Group, deadline: Instant) -> Result<()> {
    let Some(directory) = directory(group, false)? else {
        return Ok(());
    };
    write(&directory, "cgroup.kill", "1")?;
    while !empty_with(&directory)? {
        ensure!(
            Instant::now() < deadline,
            "owned resource group did not become empty"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}
pub fn kill_entry(group: &Group) -> Result<File> {
    ensure!(
        group.disposable,
        "fixed infrastructure is not a task/container kill scope"
    );
    let directory =
        directory(group, false)?.ok_or_else(|| anyhow!("protected kill group is missing"))?;
    control(&directory, "cgroup.kill", true)
}
pub fn process_entry(group: &Group) -> Result<File> {
    ensure!(
        !group.branch,
        "process cannot enter a delegated resource branch"
    );
    let directory =
        directory(group, false)?.ok_or_else(|| anyhow!("protected process group is missing"))?;
    ensure!(
        text(&directory, "cgroup.subtree_control")?
            .trim()
            .is_empty(),
        "process leaf unexpectedly delegates resources"
    );
    control(&directory, "cgroup.procs", true)
}
pub fn enter(group: &Group, pid: u32) -> Result<()> {
    process_entry(group)?.write_all(pid.to_string().as_bytes())?;
    Ok(())
}

pub fn remove(group: &Group, deadline: Instant) -> Result<()> {
    ensure!(
        group.disposable,
        "fixed infrastructure cannot be retired as a task/instance"
    );
    let Some(directory) = directory(group, false)? else {
        return Ok(());
    };
    let (parent, name) = group
        .relative
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("invalid disposable group"))?;
    let parent = Group {
        relative: parent.into(),
        branch: true,
        disposable: false,
    };
    let parent = directory_file(&parent)?;
    let name = CString::new(name)?;
    let mut budget = 4096;
    remove_owned_directory(&parent, &name, directory, &mut budget, 0, deadline)
}

fn directory_file(group: &Group) -> Result<File> {
    directory(group, false)?.ok_or_else(|| anyhow!("owned cgroup parent is missing"))
}

fn remove_owned_directory(
    parent: &File,
    name: &CStr,
    directory: File,
    budget: &mut usize,
    depth: usize,
    deadline: Instant,
) -> Result<()> {
    ensure!(
        Instant::now() < deadline && *budget > 0 && depth <= 64,
        "cgroup retirement exceeds bound"
    );
    *budget -= 1;
    check(&directory, true)?;
    ensure!(
        empty_with(&directory)?,
        "populated cgroup cannot be retired"
    );
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe {
            libc::close(duplicate);
        }
        return Err(std::io::Error::last_os_error().into());
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Stream(stream);
    loop {
        ensure!(
            Instant::now() < deadline,
            "cgroup retirement deadline expired"
        );
        let item = unsafe { libc::readdir(stream.0) };
        if item.is_null() {
            break;
        }
        let item = unsafe { &*item };
        let child_name = unsafe { CStr::from_ptr(item.d_name.as_ptr()) };
        if [b".".as_slice(), b"..".as_slice()].contains(&child_name.to_bytes()) {
            continue;
        }
        ensure!(
            !child_name.to_bytes().contains(&b'/'),
            "cgroup member path is invalid"
        );
        if item.d_type == libc::DT_REG {
            continue;
        }
        ensure!(
            item.d_type == libc::DT_DIR,
            "cgroup member is linked, special or ambiguous"
        );
        let child_name = child_name.to_owned();
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                child_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let child = unsafe { File::from_raw_fd(descriptor) };
        remove_owned_directory(&directory, &child_name, child, budget, depth + 1, deadline)?;
    }
    ensure!(
        empty_with(&directory)?,
        "cgroup became populated during retirement"
    );
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            memory_bytes: 64 << 20,
            memory_swap_bytes: 80 << 20,
            milli_cpus: 125,
            pids: 23,
        }
    }

    #[test]
    fn scopes_are_closed_and_keep_task_contract_without_an_init_manager() {
        assert_eq!(pool_group(Pool::Control).relative(), "/komizo/control");
        assert_eq!(proxy_leaf().relative(), "/komizo/proxy/server");
        assert_eq!(
            control_leaf(ControlLeaf::Watchdogs).relative(),
            "/komizo/control/watchdogs"
        );
        let task = task_group("backup", &"a".repeat(32)).unwrap();
        assert_eq!(
            task.relative(),
            format!("/komizo/control/komizo-backup-{}.service", "a".repeat(32))
        );
        assert_eq!(
            task_runner("backup", &"a".repeat(32)).unwrap().relative(),
            format!("{}/runner", task.relative())
        );
        assert!(
            instance_group("mailroom", "production")
                .unwrap()
                .relative()
                .starts_with("/komizo/production/kmz-")
        );
        assert!(
            instance_group("mailroom", "pr-1")
                .unwrap()
                .relative()
                .starts_with("/komizo/previews/kmz-")
        );
        for kind in ["foreign", "../backup", "backup/runner"] {
            assert!(task_group(kind, &"a".repeat(32)).is_err());
        }
        assert!(task_group("backup", "short").is_err());
        assert!(instance_group("../foreign", "production").is_err());
    }

    #[test]
    fn delegated_branches_refuse_process_entry_before_any_kernel_access() {
        assert!(process_entry(&root_group()).is_err());
        assert!(process_entry(&pool_group(Pool::Control)).is_err());
        assert!(process_entry(&task_group("prepare", &"a".repeat(32)).unwrap()).is_err());
        assert!(kill_entry(&root_group()).is_err());
        assert!(kill_entry(&pool_group(Pool::Control)).is_err());
        assert!(kill_entry(&control_leaf(ControlLeaf::Watchdogs)).is_err());
    }

    #[test]
    fn workload_monitor_leaves_bind_the_complete_workload_identity() {
        for kind in [WorkloadKind::Service, WorkloadKind::Job] {
            for instance in ["production", "pr-7"] {
                let ownership = "a".repeat(32);
                let parent = workload_group("mailroom", instance, kind, "api", &ownership).unwrap();
                let monitor =
                    workload_monitor_group("mailroom", instance, kind, "api", &ownership).unwrap();
                assert_eq!(monitor.relative(), format!("{}/conmon", parent.relative()));
                assert!(!monitor.branch);
                assert!(monitor.disposable);
                assert_ne!(monitor, control_leaf(ControlLeaf::Controller));
            }
        }
        assert!(
            workload_monitor_group(
                "mailroom",
                "production",
                WorkloadKind::Service,
                "../foreign",
                &"a".repeat(32)
            )
            .is_err()
        );
        assert!(
            workload_monitor_group(
                "mailroom",
                "production",
                WorkloadKind::Job,
                "api",
                "foreign"
            )
            .is_err()
        );
    }

    #[test]
    fn workload_groups_separate_kind_logical_name_and_ownership() {
        let service = workload_group(
            "mailroom",
            "production",
            WorkloadKind::Service,
            "api",
            &"a".repeat(32),
        )
        .unwrap();
        assert!(
            service
                .relative()
                .ends_with(&format!("/service-api-{}", "a".repeat(32)))
        );
        for other in [
            workload_group(
                "mailroom",
                "production",
                WorkloadKind::Job,
                "api",
                &"a".repeat(32),
            )
            .unwrap(),
            workload_group(
                "mailroom",
                "production",
                WorkloadKind::Service,
                "worker",
                &"a".repeat(32),
            )
            .unwrap(),
            workload_group(
                "mailroom",
                "production",
                WorkloadKind::Service,
                "api",
                &"b".repeat(32),
            )
            .unwrap(),
            workload_group(
                "mailroom",
                "pr-1",
                WorkloadKind::Service,
                "api",
                &"a".repeat(32),
            )
            .unwrap(),
        ] {
            assert_ne!(service, other);
        }
        for logical in ["../api", "api/child", ""] {
            assert!(
                workload_group(
                    "mailroom",
                    "production",
                    WorkloadKind::Service,
                    logical,
                    &"a".repeat(32)
                )
                .is_err()
            );
        }
        assert!(
            workload_group(
                "mailroom",
                "production",
                WorkloadKind::Service,
                "api",
                "short"
            )
            .is_err()
        );
        assert!(remove(&root_group(), Instant::now()).is_err());
        assert!(remove(&control_leaf(ControlLeaf::Watchdogs), Instant::now()).is_err());
    }

    #[test]
    fn infrastructure_cleanup_authority_is_exact_and_excludes_shared_watchers() {
        let probe = service_probe_group("mailroom", "production", "api", &"a".repeat(32)).unwrap();
        assert!(!probe.branch && probe.disposable);
        assert!(
            probe
                .relative()
                .ends_with(&format!("/service-api-{}/probe", "a".repeat(32)))
        );
        assert!(service_probe_group("mailroom", "production", "../api", &"a".repeat(32)).is_err());
        for group in [
            control_leaf(ControlLeaf::Controller),
            control_leaf(ControlLeaf::Dns),
            proxy_leaf(),
        ] {
            assert!(infrastructure_kill_scope(&group));
        }
        for group in [
            root_group(),
            pool_group(Pool::Control),
            control_leaf(ControlLeaf::Watchdogs),
            control_leaf(ControlLeaf::Expiry),
            task_group("backup", &"a".repeat(32)).unwrap(),
        ] {
            assert!(!infrastructure_kill_scope(&group));
            assert!(kill_infrastructure(&group, Instant::now()).is_err());
        }
    }

    #[test]
    fn resource_writes_preserve_kernel_units_and_explicit_defaults() {
        let values = values(&limits(), &ResourceControls::default()).unwrap();
        assert!(values.contains(&("memory.max", (64u64 << 20).to_string())));
        assert!(values.contains(&("memory.swap.max", (16u64 << 20).to_string())));
        assert!(values.contains(&("memory.low", "0".into())));
        assert!(values.contains(&("memory.high", "max".into())));
        assert!(values.contains(&("cpu.max", "125000 1000000".into())));
        assert!(values.contains(&("cpu.weight", "100".into())));
        assert!(values.contains(&("pids.max", "23".into())));
    }

    #[test]
    fn invalid_limits_refuse_before_swap_arithmetic_or_writes() {
        let mut invalid = limits();
        invalid.memory_swap_bytes = 1;
        assert!(values(&invalid, &ResourceControls::default()).is_err());
        invalid = limits();
        invalid.pids = 0;
        assert!(values(&invalid, &ResourceControls::default()).is_err());
        assert!(
            values(
                &limits(),
                &ResourceControls {
                    memory_low_bytes: 65 << 20,
                    ..Default::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn io_and_pressure_controls_are_exact_bounded_kernel_assignments() {
        let controls = ResourceControls {
            memory_low_bytes: 8 << 20,
            memory_high_bytes: 48 << 20,
            cpu_weight: Some(77),
            io_weight: Some(99),
            io_max: vec![IoRate {
                device: "8:0".into(),
                read_bytes_per_second: 1234,
                write_bytes_per_second: 5678,
            }],
        };
        let values = values(&limits(), &controls).unwrap();
        assert!(values.contains(&("memory.high", (48u64 << 20).to_string())));
        assert!(values.contains(&("memory.low", (8u64 << 20).to_string())));
        assert!(values.contains(&("cpu.weight", "77".into())));
        assert!(values.contains(&("io.weight", "default 99".into())));
        assert!(values.contains(&("io.max", "8:0 rbps=1234 wbps=5678".into())));
    }
}
