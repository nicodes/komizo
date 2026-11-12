//! Bind Podman's resource claims to the live kernel processes.
use super::{cgroups::Group, model::Limits, validation::hex};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

#[cfg(any(target_os = "linux", test))]
const CONMON: &str = "/usr/bin/conmon";
#[cfg(any(target_os = "linux", test))]
const CRUN: &str = "/usr/bin/crun";

#[derive(Debug)]
struct ProcessEnded;
impl std::fmt::Display for ProcessEnded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("workload process finished during kernel observation")
    }
}
impl std::error::Error for ProcessEnded {}
pub(crate) fn process_ended(error: &anyhow::Error) -> bool {
    error.downcast_ref::<ProcessEnded>().is_some()
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStatus {
    Unknown,
    Created,
    Initialized,
    Running,
    Stopped,
    Paused,
    Exited,
    Removing,
    Stopping,
    Unrecognized,
}
pub(crate) fn native_status(value: &Value) -> NativeStatus {
    match value["State"]["Status"].as_str() {
        Some("unknown") => NativeStatus::Unknown,
        Some("created" | "configured") => NativeStatus::Created,
        Some("initialized") => NativeStatus::Initialized,
        Some("running") => NativeStatus::Running,
        Some("stopped") => NativeStatus::Stopped,
        Some("paused") => NativeStatus::Paused,
        Some("exited") => NativeStatus::Exited,
        Some("removing") => NativeStatus::Removing,
        Some("stopping") => NativeStatus::Stopping,
        _ => NativeStatus::Unrecognized,
    }
}
fn execution_time(value: &Value) -> bool {
    value.as_str().is_some_and(|time| {
        time.len() <= 64
            && chrono::DateTime::parse_from_rfc3339(time).is_ok_and(|at| at.timestamp() > 0)
    })
}
fn unpublished_time(value: &Value) -> bool {
    value.is_null()
        || value.as_str().is_some_and(|time| {
            time.is_empty()
                || (time.len() <= 64
                    && time.starts_with("0001-")
                    && chrono::DateTime::parse_from_rfc3339(time).is_ok())
        })
}
#[derive(Debug, PartialEq, Eq)]
enum TerminalMismatch {
    Id,
    Config,
    HostConfig,
    Mounts,
    Image,
    Name,
    AppArmorProfile,
    Status,
    Running,
    Paused,
    Pid,
    ExitCode,
    StartedAt,
    FinishedAt,
    RestartCount,
}
fn terminal_mismatches(value: &Value, original: &Value) -> Vec<TerminalMismatch> {
    // Fixed names only: never format an inspection, Env, mount or unknown value.
    [
        (TerminalMismatch::Id, value["Id"] == original["Id"]),
        (
            TerminalMismatch::Config,
            value["Config"] == original["Config"],
        ),
        (
            TerminalMismatch::HostConfig,
            value["HostConfig"] == original["HostConfig"],
        ),
        (
            TerminalMismatch::Mounts,
            value["Mounts"] == original["Mounts"],
        ),
        (TerminalMismatch::Image, value["Image"] == original["Image"]),
        (TerminalMismatch::Name, value["Name"] == original["Name"]),
        (
            TerminalMismatch::AppArmorProfile,
            value["AppArmorProfile"] == original["AppArmorProfile"],
        ),
        (
            TerminalMismatch::Status,
            matches!(
                native_status(value),
                NativeStatus::Stopped | NativeStatus::Exited
            ),
        ),
        (
            TerminalMismatch::Running,
            value["State"]["Running"] == false,
        ),
        (TerminalMismatch::Paused, value["State"]["Paused"] == false),
        (TerminalMismatch::Pid, value["State"]["Pid"] == 0),
        (
            TerminalMismatch::ExitCode,
            value["State"]["ExitCode"]
                .as_u64()
                .is_some_and(|code| code <= 255),
        ),
        (
            TerminalMismatch::StartedAt,
            execution_time(&original["State"]["StartedAt"])
                && value["State"]["StartedAt"] == original["State"]["StartedAt"],
        ),
        (
            TerminalMismatch::FinishedAt,
            execution_time(&value["State"]["FinishedAt"]),
        ),
        (
            TerminalMismatch::RestartCount,
            original["RestartCount"].as_u64().is_some()
                && value["RestartCount"] == original["RestartCount"],
        ),
    ]
    .into_iter()
    .filter_map(|(field, matches)| (!matches).then_some(field))
    .collect()
}
pub(crate) fn same_execution(value: &Value, original: &Value) -> Result<()> {
    ensure!(
        execution_time(&original["State"]["StartedAt"])
            && value["State"]["StartedAt"] == original["State"]["StartedAt"]
            && original["RestartCount"].as_u64().is_some()
            && value["RestartCount"] == original["RestartCount"],
        "workload terminal execution changed; mismatch_fields={:?}; status={:?}",
        terminal_mismatches(value, original),
        native_status(value)
    );
    Ok(())
}
fn terminal_identity(value: &Value, original: &Value, group: &Group) -> Result<()> {
    ensure!(
        value["Id"] == original["Id"]
            && [
                "Config",
                "HostConfig",
                "Mounts",
                "Image",
                "Name",
                "AppArmorProfile"
            ]
            .iter()
            .all(|key| value[key] == original[key]),
        "workload terminal reinspection changed immutable ownership; mismatch_fields={:?}; status={:?}",
        terminal_mismatches(value, original),
        native_status(value)
    );
    configuration(value, group)?;
    same_execution(value, original)?;
    Ok(())
}
/// Native payload-exit evidence only. Kernel quiescence is separately mandatory
/// at the caller's existing exact-group retirement barrier, before job success.
pub(crate) fn native_exit(value: &Value) -> Result<Option<i32>> {
    if !matches!(
        native_status(value),
        NativeStatus::Stopped | NativeStatus::Exited
    ) {
        return Ok(None);
    }
    ensure!(
        value["State"]["Running"] == false
            && value["State"]["Paused"] == false
            && value["State"]["Pid"] == 0
            && execution_time(&value["State"]["StartedAt"]),
        "native terminal execution evidence refused; status={:?}",
        native_status(value)
    );
    let exit = &value["State"]["ExitCode"];
    ensure!(
        exit.is_null() || exit.as_u64().is_some_and(|code| code <= 255),
        "native terminal exit code refused; status={:?}",
        native_status(value)
    );
    let finished = &value["State"]["FinishedAt"];
    ensure!(
        execution_time(finished) || unpublished_time(finished),
        "native terminal finish evidence refused; status={:?}",
        native_status(value)
    );
    if exit.is_null() || !execution_time(finished) {
        return Ok(None);
    }
    Ok(Some(exit.as_u64().expect("validated terminal exit") as i32))
}
pub(crate) fn verify_terminal(value: &Value, original: &Value, group: &Group) -> Result<()> {
    terminal_identity(value, original, group)?;
    let exit = native_exit(value).map_err(|error| {
        error.context(format!(
            "workload terminal exit evidence refused; mismatch_fields={:?}; status={:?}",
            terminal_mismatches(value, original),
            native_status(value)
        ))
    })?;
    ensure!(
        exit.is_some(),
        "workload terminal exit evidence is incomplete; mismatch_fields={:?}; status={:?}",
        terminal_mismatches(value, original),
        native_status(value)
    );
    ensure!(
        processes(value, group)?.is_none(),
        "terminal workload retained a live process"
    );
    Ok(())
}
/// Eligible only after typed ProcessEnded. A still-publishing same execution can
/// be read again; an identity change, restart, pause or unknown state cannot.
pub(crate) fn terminal_observation(value: &Value, original: &Value, group: &Group) -> Result<bool> {
    terminal_identity(value, original, group)?;
    match native_status(value) {
        NativeStatus::Stopped | NativeStatus::Exited => {
            if native_exit(value)?.is_none() {
                return Ok(false);
            }
            verify_terminal(value, original, group)?;
            Ok(true)
        }
        NativeStatus::Running | NativeStatus::Stopping => {
            let status = native_status(value);
            ensure!(
                value["State"]["Paused"] == false
                    && value["State"]["Pid"].as_u64().is_some()
                    && (value["State"]["Pid"] == original["State"]["Pid"]
                        || (status == NativeStatus::Stopping && value["State"]["Pid"] == 0))
                    && ((status == NativeStatus::Running && value["State"]["Running"] == true)
                        || (status == NativeStatus::Stopping
                            && value["State"]["Running"] == false)),
                "ending workload changed its observed execution; status={status:?}"
            );
            Ok(false)
        }
        status => Err(anyhow!(
            "ending workload has an ineligible native state; status={status:?}"
        )),
    }
}

pub(crate) fn configuration(value: &Value, group: &Group) -> Result<String> {
    let id = value["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("workload lacks an exact native ID"))?;
    ensure!(
        hex(id, 64)
            && value["HostConfig"]["CgroupParent"] == group.relative()
            && value["HostConfig"]["CgroupManager"] == "cgroupfs"
            && value["OCIRuntime"] == "crun"
            && value["HostConfig"]["LogConfig"]["Type"] == "k8s-file",
        "workload configuration escaped its owned cgroupfs runtime"
    );
    Ok(id.to_owned())
}
pub(crate) fn configuration_limits(value: &Value, limits: &Limits) -> Result<()> {
    limits.validate()?;
    let host = &value["HostConfig"];
    ensure!(
        host["Memory"].as_u64() == Some(limits.memory_bytes)
            && host["MemorySwap"].as_u64() == Some(limits.memory_swap_bytes)
            && host["PidsLimit"].as_u64() == Some(u64::from(limits.pids))
            && host["CpuPeriod"].as_u64() == Some(1_000_000)
            && host["CpuQuota"].as_u64() == Some(u64::from(limits.milli_cpus) * 1000),
        "workload runtime limits differ from its admitted declaration"
    );
    Ok(())
}
fn processes(value: &Value, group: &Group) -> Result<Option<(u32, u32, String)>> {
    let id = configuration(value, group)?;
    let pid = value["State"]["Pid"]
        .as_u64()
        .filter(|pid| *pid <= i32::MAX as u64)
        .ok_or_else(|| anyhow!("workload payload identity is unavailable"))? as u32;
    let running = value["State"]["Running"]
        .as_bool()
        .ok_or_else(|| anyhow!("workload running state is unavailable"))?;
    let paused = value["State"]["Paused"]
        .as_bool()
        .ok_or_else(|| anyhow!("workload paused state is unavailable"))?;
    if !running && !paused {
        ensure!(
            pid == 0,
            "non-running workload retains an unexplained payload PID"
        );
        return Ok(None);
    }
    let conmon = value["State"]["ConmonPid"]
        .as_u64()
        .filter(|pid| *pid > 1 && *pid <= i32::MAX as u64)
        .ok_or_else(|| anyhow!("live workload monitor identity is unavailable"))?
        as u32;
    ensure!(
        pid > 1 && pid != conmon,
        "live workload process identities are invalid"
    );
    Ok(Some((pid, conmon, id)))
}

#[cfg(any(target_os = "linux", test))]
fn start_ticks(stat: &str, pid: u32) -> Result<u64> {
    ensure!(
        stat.starts_with(&format!("{pid} (")),
        "kernel process identity differs"
    );
    let (_, tail) = stat
        .rsplit_once(") ")
        .ok_or_else(|| anyhow!("kernel process stat is incomplete"))?;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() >= 20 && fields[0].len() == 1,
        "kernel process stat is ambiguous"
    );
    if ["Z", "X", "x"].contains(&fields[0]) {
        return Err(ProcessEnded.into());
    }
    ensure!(
        b"RSDTtIWPK".contains(&fields[0].as_bytes()[0]),
        "kernel process stat is ambiguous"
    );
    let ticks = fields[19].parse::<u64>()?;
    ensure!(ticks > 0, "kernel process start identity is missing");
    Ok(ticks)
}
#[cfg(any(target_os = "linux", test))]
fn group_text(body: &str, expected: &str, role: &'static str) -> Result<()> {
    let observed = body.strip_suffix('\n').unwrap_or(body);
    // Error context describes only bounded kernel cgroup paths already read
    // for this check. Malformed or arbitrary proc contents are never echoed.
    let path = |value: &str| {
        value.len() <= 1024
            && value.starts_with('/')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_.-".contains(&byte))
            && (value == "/"
                || value[1..].split('/').all(|part| {
                    !part.is_empty() && part.len() <= 255 && ![".", ".."].contains(&part)
                }))
    };
    let actual_path = observed
        .strip_prefix("0::")
        .filter(|value| path(value))
        .unwrap_or("<unavailable>");
    let expected_path = if path(expected) {
        expected
    } else {
        "<unavailable>"
    };
    ensure!(
        observed == format!("0::{expected}"),
        "workload {role} process is outside its exact owned cgroup (expected {expected_path}; observed {actual_path})"
    );
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn conmon_argv(raw: &[u8], id: &str) -> Result<()> {
    ensure!(
        raw.len() <= 32768 && raw.last() == Some(&0),
        "workload monitor argv exceeds bounds"
    );
    let fields = raw[..raw.len() - 1]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    ensure!(
        fields.len() <= 256 && fields.first() == Some(&CONMON.as_bytes()),
        "workload monitor argv is foreign"
    );
    let option = |key: &[u8]| -> Result<&[u8]> {
        let positions = fields
            .iter()
            .enumerate()
            .filter(|(_, value)| **value == key)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        ensure!(
            positions.len() == 1 && positions[0] + 1 < fields.len(),
            "workload monitor option is missing or ambiguous"
        );
        Ok(fields[positions[0] + 1])
    };
    ensure!(
        option(b"-c")? == id.as_bytes()
            && option(b"-u")? == id.as_bytes()
            && option(b"-r")? == CRUN.as_bytes()
            && option(b"--api-version")? == b"1"
            && option(b"--log-size-max")? == b"1048576"
            && option(b"-l")?.starts_with(b"k8s-file:")
            && !fields.iter().any(|value| [
                b"--cid".as_slice(),
                b"--cuuid",
                b"--systemd-cgroup",
                b"-s",
                b"--exec",
                b"-e"
            ]
            .contains(value)),
        "workload monitor differs from the exact native container and bounded log contract"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::Path,
    };
    struct Process {
        pid: u32,
        directory: File,
        pidfd: File,
        start: u64,
    }
    fn process_io<T>(result: std::io::Result<T>) -> Result<T> {
        match result {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                Err(ProcessEnded.into())
            }
            Err(error) => Err(error.into()),
            Ok(value) => Ok(value),
        }
    }
    impl Process {
        fn open(pid: u32) -> Result<Self> {
            let directory = process_io(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(format!("/proc/{pid}")),
            )?;
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if descriptor < 0 {
                process_io::<()>(Err(std::io::Error::last_os_error()))?;
            }
            let pidfd = unsafe { File::from_raw_fd(descriptor) };
            let mut result = Self {
                pid,
                directory,
                pidfd,
                start: 0,
            };
            result.start = start_ticks(&String::from_utf8(result.read("stat", 65536)?)?, pid)?;
            result.verify()?;
            Ok(result)
        }
        fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>> {
            let name = CString::new(name)?;
            let descriptor = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                process_io::<()>(Err(std::io::Error::last_os_error()))?;
            }
            let input = unsafe { File::from_raw_fd(descriptor) };
            let mut body = Vec::new();
            process_io(input.take((maximum + 1) as u64).read_to_end(&mut body))?;
            ensure!(
                body.len() <= maximum,
                "workload process metadata exceeds bounds"
            );
            Ok(body)
        }
        fn verify(&self) -> Result<()> {
            ensure!(
                start_ticks(&String::from_utf8(self.read("stat", 65536)?)?, self.pid)?
                    == self.start,
                "workload process lifetime changed during observation"
            );
            let mut poll = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll, 1, 0) };
            ensure!(result >= 0, "workload pidfd observation failed");
            if result > 0 && poll.revents & libc::POLLIN != 0 {
                return Err(ProcessEnded.into());
            }
            ensure!(result == 0, "workload pidfd returned an invalid event");
            Ok(())
        }
        fn conmon(&self, id: &str) -> Result<()> {
            ensure!(
                self.directory.metadata()?.uid() == 0,
                "workload monitor is not rootful"
            );
            let expected =
                super::super::bootstrap::public_root_file(Path::new(CONMON), 32 << 20, 0o755)?
                    .metadata()?;
            // Follow only this kernel-provided executable link from the pinned
            // proc directory. Caller paths and environment are never read.
            let descriptor = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    c"exe".as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                process_io::<()>(Err(std::io::Error::last_os_error()))?;
            }
            let actual = unsafe { File::from_raw_fd(descriptor) }.metadata()?;
            ensure!(
                actual.dev() == expected.dev() && actual.ino() == expected.ino(),
                "workload monitor differs from the installed protected conmon"
            );
            let mut path = [0u8; 4096];
            let count = unsafe {
                libc::readlinkat(
                    self.directory.as_raw_fd(),
                    c"exe".as_ptr(),
                    path.as_mut_ptr().cast(),
                    path.len(),
                )
            };
            if count < 0 {
                process_io::<()>(Err(std::io::Error::last_os_error()))?;
            }
            ensure!(
                count > 0
                    && count < path.len() as isize
                    && &path[..count as usize] == CONMON.as_bytes(),
                "workload monitor executable path changed"
            );
            conmon_argv(&self.read("cmdline", 32768)?, id)
        }
    }
    fn payload_limits(group: &Group, id: &str, limits: &Limits) -> Result<()> {
        let directory = process_io(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(group.path().join(format!("libpod-{id}"))),
        )?;
        let metadata = directory.metadata()?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } == 0
                && filesystem.f_type as u64 == 0x6367_7270,
            "workload resource files are not protected unified kernel state"
        );
        let read = |name: &str| -> Result<String> {
            let name = CString::new(name)?;
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if descriptor < 0 {
                process_io::<()>(Err(std::io::Error::last_os_error()))?;
            }
            let input = unsafe { File::from_raw_fd(descriptor) };
            let metadata = input.metadata()?;
            ensure!(
                metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "workload resource control is not protected kernel state"
            );
            let mut text = String::new();
            process_io(input.take(129).read_to_string(&mut text))?;
            ensure!(
                text.len() <= 128,
                "workload resource control exceeds its finite bound"
            );
            Ok(text)
        };
        let memory = read("memory.max")?;
        let swap = read("memory.swap.max")?;
        let pids = read("pids.max")?;
        let cpu = read("cpu.max")?;
        kernel_limits(&memory, &swap, &pids, &cpu, limits)
    }
    pub(super) fn verify(value: &Value, group: &Group, limits: Option<&Limits>) -> Result<()> {
        if let Some(limits) = limits {
            configuration_limits(value, limits)?;
        }
        let Some((pid, conmon, id)) = processes(value, group)? else {
            return Ok(());
        };
        let payload = Process::open(pid)?;
        let monitor = Process::open(conmon)?;
        super::super::engine::workload_label(
            String::from_utf8(payload.read("attr/apparmor/current", 65536)?)?.trim(),
        )?;
        group_text(
            &String::from_utf8(payload.read("cgroup", 4096)?)?,
            &format!("{}/libpod-{id}", group.relative()),
            "payload",
        )?;
        group_text(
            &String::from_utf8(monitor.read("cgroup", 4096)?)?,
            &format!("{}/conmon", group.relative()),
            "monitor",
        )?;
        monitor.conmon(&id)?;
        if let Some(limits) = limits {
            payload_limits(group, &id, limits)?;
        }
        payload.verify()?;
        monitor.verify()?;
        Ok(())
    }
}
pub fn verify(value: &Value, group: &Group) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::verify(value, group, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (value, group);
        Err(anyhow!(
            "live resource verification requires the supported Alpine host"
        ))
    }
}
#[cfg(any(target_os = "linux", test))]
fn kernel_limits(memory: &str, swap: &str, pids: &str, cpu: &str, limits: &Limits) -> Result<()> {
    limits.validate()?;
    ensure!(
        memory.trim().parse::<u64>()? == limits.memory_bytes
            && swap.trim().parse::<u64>()? == limits.memory_swap_bytes - limits.memory_bytes
            && pids.trim().parse::<u64>()? == u64::from(limits.pids)
            && cpu.split_whitespace().collect::<Vec<_>>()
                == [
                    (u64::from(limits.milli_cpus) * 1000).to_string(),
                    "1000000".into()
                ],
        "workload kernel hard limits differ from its admitted declaration"
    );
    Ok(())
}
pub fn verify_limits(value: &Value, group: &Group, limits: &Limits) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::verify(value, group, Some(limits))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (value, group, limits);
        Err(anyhow!(
            "live resource verification requires the supported Alpine host"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::cgroups::{self, WorkloadKind};
    use super::*;
    use serde_json::json;
    #[test]
    fn inspection_never_accepts_warn_only_monitor_or_another_parent() {
        let group = cgroups::workload_group(
            "alpha",
            "production",
            WorkloadKind::Service,
            "api",
            &"a".repeat(32),
        )
        .unwrap();
        let mut value = json!({"Id":"b".repeat(64),"OCIRuntime":"crun","HostConfig":{"CgroupParent":group.relative(),"CgroupManager":"cgroupfs","LogConfig":{"Type":"k8s-file"}},"State":{"Pid":0,"ConmonPid":0,"Running":false,"Paused":false}});
        assert!(processes(&value, &group).unwrap().is_none());
        value["State"]["Running"] = json!(true);
        assert!(processes(&value, &group).is_err());
        value["State"]["Pid"] = json!(101);
        value["State"]["ConmonPid"] = json!(102);
        assert!(processes(&value, &group).unwrap().is_some());
        for (key, replacement) in [
            ("CgroupParent", json!("/foreign")),
            ("CgroupManager", json!("systemd")),
        ] {
            let mut bad = value.clone();
            bad["HostConfig"][key] = replacement;
            assert!(processes(&bad, &group).is_err());
        }
        assert!(
            group_text(
                &format!("0::{}/conmon\n", group.relative()),
                &format!("{}/conmon", group.relative()),
                "monitor"
            )
            .is_ok()
        );
        for bad in [
            "0::/\n",
            "0::/foreign/conmon\n",
            "0::/expected\n0::/expected\n",
        ] {
            assert!(group_text(bad, "/expected", "payload").is_err());
        }
    }
    #[test]
    fn cgroup_failure_context_keeps_roles_and_only_bounded_kernel_paths() {
        for role in ["payload", "monitor"] {
            let error = group_text("0::/komizo/control/controller\n", "/expected", role)
                .unwrap_err()
                .to_string();
            assert!(error.contains(&format!("workload {role} process")));
            assert!(error.contains("expected /expected; observed /komizo/control/controller"));
        }
        for body in [
            "0::/foreign\n0::/private-marker\n".to_owned(),
            "0::/private marker\n".to_owned(),
            "0::/../private-marker\n".to_owned(),
            format!("0::/{}private-marker\n", "x".repeat(1024)),
        ] {
            let error = group_text(&body, "/expected", "payload")
                .unwrap_err()
                .to_string();
            assert!(error.contains("observed <unavailable>"));
            assert!(!error.contains("private-marker"));
            assert!(error.len() < 256);
        }
        assert!(group_text("0::/expected\n", "/expected", "payload").is_ok());
    }
    #[test]
    fn monitor_argv_binds_cid_runtime_and_finite_log_size() {
        let id = "b".repeat(64);
        let args = [
            CONMON,
            "--api-version",
            "1",
            "-c",
            &id,
            "-u",
            &id,
            "-r",
            CRUN,
            "-l",
            "k8s-file:/protected/log",
            "--log-size-max",
            "1048576",
        ];
        let encode = |args: &[&str]| {
            args.iter()
                .flat_map(|v| v.bytes().chain([0]))
                .collect::<Vec<_>>()
        };
        assert!(conmon_argv(&encode(&args), &id).is_ok());
        for index in [0, 2, 4, 6, 8, 10, 12] {
            let mut bad = args;
            bad[index] = "foreign-private-sentinel";
            assert!(conmon_argv(&encode(&bad), &id).is_err());
        }
        let mut duplicate = args.to_vec();
        duplicate.extend(["-c", &id]);
        assert!(conmon_argv(&encode(&duplicate), &id).is_err());
    }
    #[test]
    fn process_stat_uses_kernel_field_after_the_complete_comm() {
        let fields = ["S".to_owned()]
            .into_iter()
            .chain((1..=18).map(|v| v.to_string()))
            .chain(["987654".into()])
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            start_ticks(&format!("101 (comm with ) spaces) {fields}"), 101).unwrap(),
            987654
        );
        assert!(start_ticks(&format!("102 (comm) {fields}"), 101).is_err());
        assert!(start_ticks(&format!("101 (comm) {}", fields.replacen('S', "Z", 1)), 101).is_err());
    }
    #[test]
    fn finite_job_terminal_reinspection_preserves_identity_and_nonzero_exit() {
        let group = cgroups::workload_group(
            "alpha",
            "production",
            WorkloadKind::Job,
            "migrate",
            &"a".repeat(32),
        )
        .unwrap();
        let live = json!({"Id":"b".repeat(64),"Image":"sha256:fixed","OCIRuntime":"crun","RestartCount":0,"Config":{"Labels":{"ownership":"same"}},"Mounts":[],"HostConfig":{"CgroupParent":group.relative(),"CgroupManager":"cgroupfs","LogConfig":{"Type":"k8s-file"}},"State":{"Pid":101,"ConmonPid":102,"Status":"running","Running":true,"Paused":false,"ExitCode":0,"StartedAt":"2026-11-12T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}});
        let mut stopped = live.clone();
        stopped["State"] = json!({"Pid":0,"ConmonPid":0,"Status":"exited","Running":false,"Paused":false,"ExitCode":17,"StartedAt":"2026-11-12T00:00:00Z","FinishedAt":"2026-11-12T00:00:01Z"});
        verify_terminal(&stopped, &live, &group).unwrap();
        assert_eq!(stopped["State"]["ExitCode"], 17);
        for (section, key, value) in [
            ("State", "Status", json!("unknown")),
            ("State", "Pid", json!(101)),
            ("State", "ExitCode", json!(-1)),
            ("State", "ExitCode", json!(256)),
            ("State", "Paused", json!(true)),
            ("State", "Running", json!(true)),
            ("HostConfig", "CgroupParent", json!("/foreign")),
            ("Config", "Labels", json!({"ownership":"foreign"})),
        ] {
            let mut bad = stopped.clone();
            bad[section][key] = value;
            assert!(verify_terminal(&bad, &live, &group).is_err());
        }
        for key in ["Id", "Image", "Mounts", "Name", "AppArmorProfile"] {
            let mut bad = stopped.clone();
            bad[key] = json!("foreign-private-sentinel");
            let error = verify_terminal(&bad, &live, &group).unwrap_err();
            assert!(!error.to_string().contains("foreign-private-sentinel"));
        }
        assert!(process_ended(&anyhow::Error::new(ProcessEnded)));
        assert!(!process_ended(&anyhow!("foreign cgroup")));
        assert!(!process_ended(
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied).into()
        ));
    }
    #[test]
    fn terminal_mismatch_diagnostics_never_emit_inspection_values() {
        let group = cgroups::workload_group(
            "fixture",
            "production",
            WorkloadKind::Job,
            "migrate",
            &"a".repeat(32),
        )
        .unwrap();
        let original = json!({"Id":"b".repeat(64),"Image":"sha256:fixed","OCIRuntime":"crun","RestartCount":0,
            "Config":{"Env":["SYNTHETIC_PRIVATE_ENV=unobserved"]},"Mounts":[],
            "Name":"synthetic-job","AppArmorProfile":"komizo-workload",
            "HostConfig":{"CgroupParent":group.relative(),"CgroupManager":"cgroupfs","LogConfig":{"Type":"k8s-file"}},
            "State":{"Pid":0,"ConmonPid":0,"Status":"exited","Running":false,"Paused":false,"ExitCode":17,"StartedAt":"2026-11-12T00:00:00Z","FinishedAt":"2026-11-12T00:00:01Z"}});
        assert!(terminal_mismatches(&original, &original).is_empty());
        verify_terminal(&original, &original, &group).unwrap();
        let sentinel = "SYNTHETIC_PRIVATE_VALUE\npassword=must-never-appear";
        let cases = [
            (None, "Id", TerminalMismatch::Id),
            (None, "Config", TerminalMismatch::Config),
            (None, "HostConfig", TerminalMismatch::HostConfig),
            (None, "Mounts", TerminalMismatch::Mounts),
            (None, "Image", TerminalMismatch::Image),
            (None, "Name", TerminalMismatch::Name),
            (None, "AppArmorProfile", TerminalMismatch::AppArmorProfile),
            (Some("State"), "Status", TerminalMismatch::Status),
            (Some("State"), "Running", TerminalMismatch::Running),
            (Some("State"), "Paused", TerminalMismatch::Paused),
            (Some("State"), "Pid", TerminalMismatch::Pid),
            (Some("State"), "ExitCode", TerminalMismatch::ExitCode),
            (Some("State"), "StartedAt", TerminalMismatch::StartedAt),
            (Some("State"), "FinishedAt", TerminalMismatch::FinishedAt),
            (None, "RestartCount", TerminalMismatch::RestartCount),
        ];
        let mut all_changed = original.clone();
        let mut expected_all = Vec::new();
        for (section, key, expected) in cases {
            let mut changed = original.clone();
            if let Some(section) = section {
                changed[section][key] = json!(sentinel);
                all_changed[section][key] = json!(sentinel);
            } else {
                changed[key] = json!(sentinel);
                all_changed[key] = json!(sentinel);
            }
            let expected_fields = format!("[{expected:?}]");
            let error = verify_terminal(&changed, &original, &group)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(&format!("mismatch_fields={expected_fields}")),
                "{error}"
            );
            assert!(!error.contains(sentinel));
            assert!(!error.contains("SYNTHETIC_PRIVATE_ENV"));
            expected_all.push(expected);
        }
        assert_eq!(terminal_mismatches(&all_changed, &original), expected_all);
        let error = verify_terminal(&all_changed, &original, &group)
            .unwrap_err()
            .to_string();
        assert!(error.len() < 384);
        assert!(!error.contains(sentinel));
        assert!(!error.contains("SYNTHETIC_PRIVATE_ENV"));
    }
    fn ending_fixture() -> (cgroups::Group, Value, Value) {
        let group = cgroups::workload_group(
            "fixture",
            "production",
            WorkloadKind::Job,
            "migrate",
            &"a".repeat(32),
        )
        .unwrap();
        let live = json!({"Id":"b".repeat(64),"Image":"sha256:fixed","Name":"synthetic-job","AppArmorProfile":"komizo-workload","OCIRuntime":"crun","RestartCount":0,
            "Config":{"Labels":{"ownership":"same"}},"Mounts":[],
            "HostConfig":{"CgroupParent":group.relative(),"CgroupManager":"cgroupfs","LogConfig":{"Type":"k8s-file"}},
            "State":{"Pid":101,"ConmonPid":102,"Status":"running","Running":true,"Paused":false,"ExitCode":0,
                "StartedAt":"2026-11-12T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}});
        let mut stopped = live.clone();
        stopped["State"]["Status"] = json!("stopped");
        stopped["State"]["Running"] = json!(false);
        stopped["State"]["Pid"] = json!(0);
        stopped["State"]["ConmonPid"] = json!(0);
        stopped["State"]["FinishedAt"] = json!("2026-11-12T00:00:01Z");
        (group, live, stopped)
    }
    #[test]
    fn stopped_and_exited_prove_the_same_owned_execution_without_reclassifying_exit() {
        let (group, live, stopped) = ending_fixture();
        for status in ["stopped", "exited"] {
            for exit in [0, 17, 137, 255] {
                let mut value = stopped.clone();
                value["State"]["Status"] = json!(status);
                value["State"]["ExitCode"] = json!(exit);
                assert!(terminal_observation(&value, &live, &group).unwrap());
                verify_terminal(&value, &live, &group).unwrap();
                assert_eq!(native_exit(&value).unwrap(), Some(exit));
            }
        }
    }
    #[test]
    fn only_same_execution_exit_publication_can_remain_pending() {
        let (group, live, stopped) = ending_fixture();
        assert!(!terminal_observation(&live, &live, &group).unwrap());
        for finished in [json!(null), json!(""), json!("0001-01-01T00:00:00Z")] {
            let mut incomplete = stopped.clone();
            incomplete["State"]["FinishedAt"] = finished;
            assert!(!terminal_observation(&incomplete, &live, &group).unwrap());
            assert!(verify_terminal(&incomplete, &live, &group).is_err());
        }
        let mut incomplete = stopped.clone();
        incomplete["State"]["ExitCode"] = Value::Null;
        assert!(!terminal_observation(&incomplete, &live, &group).unwrap());
        for status in [
            "created",
            "initialized",
            "paused",
            "removing",
            "unknown",
            "SYNTHETIC_PRIVATE_STATE",
        ] {
            let mut value = stopped.clone();
            value["State"]["Status"] = json!(status);
            let error = terminal_observation(&value, &live, &group)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("SYNTHETIC_PRIVATE_STATE"));
        }
        for (section, key, value) in [
            ("State", "StartedAt", json!("2026-11-12T00:00:02Z")),
            ("State", "Paused", json!(true)),
            ("State", "Pid", json!(103)),
            ("State", "ExitCode", json!(-1)),
            ("State", "ExitCode", json!(256)),
            ("State", "ExitCode", json!("0")),
            ("State", "FinishedAt", json!(7)),
        ] {
            let mut changed = stopped.clone();
            changed[section][key] = value;
            assert!(terminal_observation(&changed, &live, &group).is_err());
        }
        let mut restarted = stopped.clone();
        restarted["RestartCount"] = json!(1);
        assert!(terminal_observation(&restarted, &live, &group).is_err());
        for key in [
            "Config",
            "HostConfig",
            "Mounts",
            "Image",
            "Name",
            "AppArmorProfile",
            "Id",
        ] {
            let mut changed = live.clone();
            changed[key] = json!("SYNTHETIC_PRIVATE_IDENTITY");
            let error = terminal_observation(&changed, &live, &group)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("SYNTHETIC_PRIVATE_IDENTITY"));
        }
    }
    #[test]
    fn declared_runtime_limits_and_actual_kernel_limits_are_both_required() {
        let limits = Limits {
            memory_bytes: 64 << 20,
            memory_swap_bytes: 96 << 20,
            milli_cpus: 250,
            pids: 32,
        };
        let actual = json!({"HostConfig":{"Memory":64<<20,"MemorySwap":96<<20,"CpuPeriod":1000000,"CpuQuota":250000,"PidsLimit":32}});
        configuration_limits(&actual, &limits).unwrap();
        for key in ["Memory", "MemorySwap", "CpuPeriod", "CpuQuota", "PidsLimit"] {
            let mut bad = actual.clone();
            bad["HostConfig"][key] = json!(0);
            assert!(configuration_limits(&bad, &limits).is_err());
        }
        kernel_limits(
            "67108864\n",
            "33554432\n",
            "32\n",
            "250000 1000000\n",
            &limits,
        )
        .unwrap();
        for (memory, swap, pids, cpu) in [
            ("max", "33554432", "32", "250000 1000000"),
            ("67108864", "max", "32", "250000 1000000"),
            ("67108864", "33554432", "max", "250000 1000000"),
            ("67108864", "33554432", "32", "max 1000000"),
            ("67108864", "33554432", "32", "250001 1000000"),
            ("67108864", "33554432", "32", "250000 999999"),
        ] {
            assert!(kernel_limits(memory, swap, pids, cpu, &limits).is_err());
        }
    }
}
