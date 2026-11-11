//! Four fixed OpenRC services. No caller can choose a program, path or cgroup.
use super::{
    bootstrap,
    capacity::Capacity,
    cgroups::{self, ControlLeaf, Group},
    store,
    system::System,
};
use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixDatagram,
        process::CommandExt,
    },
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd},
    process::Stdio,
};

const CLI: &str = "/usr/local/bin/komizo-box";
const SUPERVISOR: &str = "/sbin/supervise-daemon";
pub const DIRECTORY: &str = "/run/komizo-infrastructure";
const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Controller,
    Proxy,
    Dns,
    Expiry,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StartupStage {
    Files,
    Leaf,
    Monitor,
    Parent,
    Notification,
    NotificationEnvironment,
    NotificationAddress,
    NotificationSocket,
    NotificationParent,
    NotificationIdentity,
    ProxyGuard,
    Confinement,
    Exec,
    Runner,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StartupError {
    Io,
    Guard,
    Pending,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupDiagnostic {
    kind: String,
    version: u32,
    diagnostic_only: bool,
    role: Role,
    boot_id: String,
    pid: u32,
    stage: StartupStage,
    errno: Option<i32>,
    error: StartupError,
}
impl StartupDiagnostic {
    fn new(
        role: Role,
        stage: StartupStage,
        boot_id: String,
        pid: u32,
        error: &anyhow::Error,
    ) -> Self {
        let io = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>());
        Self {
            kind: "komizo.infrastructure-startup-diagnostic".into(),
            version: 1,
            diagnostic_only: true,
            role,
            boot_id,
            pid,
            stage,
            errno: io.and_then(std::io::Error::raw_os_error),
            // Never serialize an arbitrary error Display: it can contain an
            // environment selector or configuration value. Only closed facts
            // from this exact failed entry are retained.
            error: if io.is_some() {
                StartupError::Io
            } else {
                StartupError::Guard
            },
        }
    }
    fn validate(&self, role: Role) -> Result<()> {
        ensure!(
            self.kind == "komizo.infrastructure-startup-diagnostic"
                && self.version == 1
                && self.diagnostic_only
                && self.role == role
                && self.pid > 1
                && self.boot_id.len() == 36
                && self.boot_id.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                }),
            "startup diagnostic scope is invalid"
        );
        ensure!(
            !matches!(self.error, StartupError::Pending)
                || (matches!(self.stage, StartupStage::Exec) && self.errno.is_none()),
            "pending startup diagnostic has an invalid outcome"
        );
        Ok(())
    }
}
fn startup_path(role: Role) -> std::path::PathBuf {
    Path::new(DIRECTORY).join(format!("{}.startup.json", role.name()))
}
fn startup_root() -> Result<()> {
    for name in ["/", "/run", DIRECTORY] {
        let metadata = fs::symlink_metadata(name)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o022 == 0
                && (name != DIRECTORY || metadata.mode() & 0o7777 == 0o700),
            "startup diagnostic directory is not protected"
        );
    }
    Ok(())
}
fn startup_file(path: &Path, role: Role) -> Result<fs::Metadata> {
    ensure!(
        path == startup_path(role),
        "startup diagnostic escaped its fixed role path"
    );
    startup_root()?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() > 0
            && metadata.len() <= 4096,
        "startup diagnostic is not an owned bounded file"
    );
    Ok(metadata)
}
fn clear_startup(role: Role) -> Result<()> {
    let path = startup_path(role);
    if !path.try_exists()? {
        return Ok(());
    }
    let metadata = startup_file(&path, role)?;
    let diagnostic: StartupDiagnostic =
        serde_json::from_slice(&bootstrap::protected_file(&path, 4096)?)?;
    diagnostic.validate(role)?;
    let current = startup_file(&path, role)?;
    ensure!(
        metadata.dev() == current.dev() && metadata.ino() == current.ino(),
        "startup diagnostic changed before owned retirement"
    );
    fs::remove_file(path)?;
    Ok(())
}
fn startup_boot() -> Result<String> {
    let mut boot_id = String::new();
    fs::File::open("/proc/sys/kernel/random/boot_id")?
        .take(38)
        .read_to_string(&mut boot_id)?;
    Ok(boot_id.trim_end().into())
}
fn startup_slot(role: Role) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    startup_root()?;
    let mut diagnostic = StartupDiagnostic::new(
        role,
        StartupStage::Exec,
        startup_boot()?,
        std::process::id(),
        &anyhow!("pending fixed execution"),
    );
    diagnostic.error = StartupError::Pending;
    diagnostic.validate(role)?;
    let body = serde_json::to_vec(&diagnostic)?;
    ensure!(
        body.len() <= 4096,
        "startup diagnostic exceeds its finite bound"
    );
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(startup_path(role))?;
    file.write_all(&body)?;
    Ok(file)
}
fn record_startup(
    role: Role,
    stage: StartupStage,
    error: &anyhow::Error,
    slot: Option<&mut fs::File>,
) -> Result<()> {
    let mut fallback;
    let file = if let Some(file) = slot {
        file
    } else {
        fallback = startup_slot(role)?;
        &mut fallback
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.len() <= 4096,
        "startup diagnostic descriptor is not protected"
    );
    let diagnostic =
        StartupDiagnostic::new(role, stage, startup_boot()?, std::process::id(), error);
    diagnostic.validate(role)?;
    let body = serde_json::to_vec(&diagnostic)?;
    ensure!(
        body.len() <= 4096,
        "startup diagnostic exceeds its finite bound"
    );
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(&body)?;
    Ok(())
}
impl Role {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "controller" => Ok(Self::Controller),
            "proxy" => Ok(Self::Proxy),
            "dns" => Ok(Self::Dns),
            "expiry" => Ok(Self::Expiry),
            _ => Err(anyhow!("unknown fixed infrastructure role")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Proxy => "proxy",
            Self::Dns => "dns",
            Self::Expiry => "expiry",
        }
    }
    pub fn service(self) -> &'static str {
        match self {
            Self::Controller => "komizo-controller",
            Self::Proxy => "komizo-proxy",
            Self::Dns => "komizo-dns",
            Self::Expiry => "komizo-expiry",
        }
    }
    pub fn group(self) -> Group {
        match self {
            Self::Controller => cgroups::control_leaf(ControlLeaf::Controller),
            Self::Proxy => cgroups::proxy_leaf(),
            Self::Dns => cgroups::control_leaf(ControlLeaf::Dns),
            Self::Expiry => cgroups::control_leaf(ControlLeaf::Watchdogs),
        }
    }
    fn pidfile(self) -> String {
        format!("{DIRECTORY}/{}.pid", self.service())
    }
    fn notification(self) -> String {
        format!("/run/openrc/supervise-{}.sock", self.service())
    }
}

pub fn service_script(role: Role) -> String {
    // Do not use OpenRC's supervisor= here: that would start the monitor
    // outside our budget and only move its child into the resource leaf.
    let dependencies = match role {
        Role::Controller => "need localmount apparmor\n    use net komizo-proxy",
        Role::Proxy | Role::Dns => "need localmount apparmor\n    use net",
        Role::Expiry => "need localmount apparmor",
    };
    let timeout = match role {
        Role::Controller => "120s",
        Role::Proxy => "30s",
        Role::Dns => "25s",
        Role::Expiry => "10s",
    };
    format!(
        "#!/sbin/openrc-run\n\ndescription=\"Komizo {}\"\ndepend() {{\n    {}\n}}\nstart() {{\n    /usr/bin/timeout --signal=KILL {} /usr/local/bin/komizo-box infrastructure-supervise {}\n}}\nstop() {{\n    /usr/local/bin/komizo-box infrastructure-stop {}\n}}\n",
        role.name(),
        dependencies,
        timeout,
        role.name(),
        role.name()
    )
}

fn command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", PATH)
        .env("LANG", "C.UTF-8")
        .env("HOME", "/root");
    command
}
fn invoke(role: Role, action: &str, deadline: Instant) -> Result<()> {
    bootstrap::infrastructure_files_guard()?;
    let mut command = command("/sbin/rc-service");
    command.args([role.service(), action]);
    let result = crate::process::capture(&mut command, None, 65536, deadline, || false)?;
    ensure!(
        result.status.success(),
        "fixed infrastructure {} {action} failed ({}): {}",
        role.name(),
        result.status,
        String::from_utf8_lossy(&result.stderr)
            .chars()
            .take(2048)
            .collect::<String>()
    );
    Ok(())
}
pub fn start(role: Role, deadline: Instant) -> Result<()> {
    invoke(role, "start", deadline)
}
pub fn stop(role: Role, deadline: Instant) -> Result<()> {
    invoke(role, "stop", deadline)
}

#[cfg(target_os = "linux")]
pub fn stop_owned(role: Role) -> Result<()> {
    bootstrap::infrastructure_files_guard()?;
    let Some(pid) = supervisor_pid(role)? else {
        if role != Role::Expiry {
            ensure!(
                cgroups::empty(&role.group())?,
                "missing infrastructure monitor left an unsupervised process"
            );
        }
        return Ok(());
    };
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    ensure!(
        descriptor >= 0,
        "cannot bind owned infrastructure supervisor"
    );
    let pidfd = unsafe { File::from_raw_fd(descriptor) };
    ensure!(
        supervisor_pid(role)? == Some(pid),
        "infrastructure supervisor changed before stop"
    );
    ensure!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGTERM,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } == 0,
        "cannot stop owned infrastructure supervisor"
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut poll, 1, 20) };
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(result >= 0, "owned infrastructure stop observation failed");
        if result > 0 {
            ensure!(
                poll.revents & libc::POLLIN != 0,
                "owned supervisor pidfd returned an invalid event"
            );
            if role != Role::Expiry {
                cgroups::kill_infrastructure(&role.group(), deadline)?;
            }
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "owned infrastructure supervisor did not stop"
        );
    }
}
#[cfg(not(target_os = "linux"))]
pub fn stop_owned(_: Role) -> Result<()> {
    Err(anyhow!(
        "fixed infrastructure requires the supported Alpine host"
    ))
}

fn process_group(pid: u32, group: &Group) -> Result<()> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    ensure!(
        text.trim() == format!("0::{}", group.relative()),
        "infrastructure process escaped its fixed resource leaf"
    );
    Ok(())
}
pub fn supervisor_pid(role: Role) -> Result<Option<u32>> {
    let path = role.pidfile();
    if !Path::new(&path).try_exists()? {
        return Ok(None);
    }
    let body = bootstrap::protected_file(Path::new(&path), 32)?;
    let text = std::str::from_utf8(&body)?.trim_end_matches('\n');
    // supervise-daemon opens its pidfile before fork and fills it in the
    // monitor. Its child can reach this point during that bounded handoff.
    if text.is_empty() {
        return Ok(None);
    }
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "invalid infrastructure supervisor identity"
    );
    let pid = text.parse::<u32>()?;
    ensure!(pid > 1, "invalid infrastructure supervisor PID");
    let proc = format!("/proc/{pid}");
    if !Path::new(&proc).try_exists()? {
        return Ok(None);
    }
    let binary = bootstrap::public_root_file(Path::new(SUPERVISOR), 32 << 20, 0o755)?.metadata()?;
    let actual = fs::metadata(format!("{proc}/exe"))?;
    ensure!(
        fs::read_link(format!("{proc}/exe"))? == Path::new(SUPERVISOR)
            && binary.dev() == actual.dev()
            && binary.ino() == actual.ino()
            && fs::metadata(&proc)?.uid() == 0,
        "infrastructure supervisor is foreign"
    );
    process_group(pid, &role.group())?;
    let argv = fs::read(format!("{proc}/cmdline"))?;
    let expected = supervisor_arguments(role);
    let expected = std::iter::once(SUPERVISOR.to_owned())
        .chain(expected)
        .flat_map(|s| s.into_bytes().into_iter().chain([0]))
        .collect::<Vec<_>>();
    ensure!(argv == expected, "infrastructure supervisor argv changed");
    Ok(Some(pid))
}
pub fn active(role: Role) -> Result<bool> {
    Ok(supervisor_pid(role)?.is_some())
}

fn parent(pid: u32) -> Result<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let rows = status
        .lines()
        .filter_map(|line| line.strip_prefix("PPid:"))
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "ambiguous infrastructure parent identity");
    Ok(rows[0].trim().parse::<u32>()?)
}
pub fn dns_supervision(pid: u32) -> Result<()> {
    let runner = parent(pid)?;
    ensure!(runner > 1, "fixed DNS has no owned lifetime runner");
    process_group(runner, &Role::Dns.group())?;
    let expected = bootstrap::public_root_file(Path::new(CLI), 128 << 20, 0o755)?.metadata()?;
    let actual = fs::metadata(format!("/proc/{runner}/exe"))?;
    ensure!(
        fs::read_link(format!("/proc/{runner}/exe"))? == Path::new(CLI)
            && actual.ino() == expected.ino()
            && actual.dev() == expected.dev()
            && fs::metadata(format!("/proc/{runner}"))?.uid() == 0,
        "fixed DNS lifetime runner executable is foreign"
    );
    ensure!(
        fs::read(format!("/proc/{runner}/cmdline"))?
            == format!("{CLI}\0infrastructure-run\0dns\0").as_bytes(),
        "fixed DNS lifetime runner argv changed"
    );
    ensure!(
        supervisor_pid(Role::Dns)? == Some(parent(runner)?),
        "fixed DNS is not owned by its recorded monitor"
    );
    Ok(())
}

fn supervisor_arguments(role: Role) -> Vec<String> {
    [
        role.service(),
        "--start",
        "--pidfile",
        &role.pidfile(),
        "--respawn-delay",
        "2",
        "--respawn-max",
        "5",
        "--respawn-period",
        "60",
        "--retry",
        "TERM/10/KILL/5",
        "--umask",
        "0077",
        "--notify",
        "socket:ready",
        "--stdin",
        "/dev/null",
        "--stdout",
        "/dev/null",
        "--stderr",
        "/dev/null",
        CLI,
        "--",
        "infrastructure-run",
        role.name(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
pub fn supervise(value: &str) -> Result<()> {
    let role = Role::parse(value)?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "infrastructure supervision requires the owner identity"
    );
    bootstrap::infrastructure_files_guard()?;
    ensure!(
        !active(role)?,
        "fixed infrastructure supervisor is already active"
    );
    // A diagnostic is never execution authority. Foreign/malformed records are
    // preserved and never alter this original startup result or deadline.
    let _ = clear_startup(role);
    bootstrap::public_root_file(Path::new(SUPERVISOR), 32 << 20, 0o755)?;
    let capacity: Capacity = serde_json::from_slice(&bootstrap::protected_file(
        Path::new("/etc/komizo/capacity.json"),
        65536,
    )?)?;
    capacity.measured()?;
    let state = store::Store::new(Path::new("/var/lib/komizo").into())?;
    let system = System {
        deadline: Instant::now() + Duration::from_secs(20),
    };
    super::system::host_pools(&state, &system, &capacity)?;
    let allocation = if role == Role::Proxy {
        &capacity.proxy
    } else {
        &capacity.control
    };
    system.prepare_group(&role.group(), &allocation.limits, &allocation.controls)?;
    if role != Role::Expiry {
        ensure!(
            system.group_empty(&role.group())?,
            "fixed infrastructure leaf still contains an unsupervised process"
        );
    }
    bootstrap::runtime_directories()?;
    system.enter(&role.group(), std::process::id())?;
    process_group(std::process::id(), &role.group())?;
    unsafe {
        libc::umask(0o077);
    }
    let mut process = command(SUPERVISOR);
    process
        .env("RC_SVCNAME", role.service())
        .env("RC_SVCDIR", "/run/openrc")
        .args(supervisor_arguments(role));
    Err(process.exec().into())
}

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stopping(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn signals() -> Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = stopping as *const () as usize;
        ensure!(
            unsafe { libc::sigemptyset(&mut action.sa_mask) } == 0
                && unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0,
            "cannot install fixed service shutdown handler"
        );
    }
    Ok(())
}

struct OpenRcParent {
    uid: u32,
    gid: u32,
    mode: u32,
}
struct NotificationSocket {
    uid: u32,
    gid: u32,
    mode: u32,
}
impl NotificationSocket {
    fn owned(self, proxy: Option<(u32, u32)>) -> bool {
        self.mode & 0o170000 == 0o140000
            && self.mode & 0o077 == 0
            && (self.uid == 0
                || proxy.is_some_and(|(uid, gid)| {
                    self.uid == uid && self.gid == gid && self.mode & 0o7777 == 0o600
                }))
    }
}
impl OpenRcParent {
    fn protected(self) -> bool {
        // OpenRC's fixed administrative state directory is root:root 0775 on
        // Alpine. Only this parent trusts root-group writes; the notification
        // socket and every Komizo-owned path retain their stricter modes.
        self.uid == 0 && self.gid == 0 && self.mode & 0o170000 == 0o040000 && self.mode & 0o002 == 0
    }
}
#[cfg(target_os = "linux")]
fn openrc_parent_acl_absent(parent: &fs::File) -> Result<()> {
    let result = unsafe {
        libc::fgetxattr(
            parent.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    ensure!(result < 0, "OpenRC notification parent has an access ACL");
    let error = std::io::Error::last_os_error();
    if error.raw_os_error().is_some_and(|code| {
        code == libc::ENODATA || code == libc::EOPNOTSUPP || code == libc::ENOTSUP
    }) {
        return Ok(());
    }
    Err(error).context("cannot verify the fixed OpenRC parent ACL")
}
#[cfg(not(target_os = "linux"))]
fn openrc_parent_acl_absent(_: &fs::File) -> Result<()> {
    Err(anyhow!(
        "OpenRC parent verification requires the supported Alpine host"
    ))
}
fn notification(role: Role, stage: &mut StartupStage) -> Result<Option<String>> {
    use std::os::unix::fs::OpenOptionsExt;
    *stage = StartupStage::NotificationEnvironment;
    let address =
        std::env::var("NOTIFY_SOCKET").context("fixed infrastructure notification environment")?;
    *stage = StartupStage::NotificationAddress;
    ensure!(
        address == role.notification(),
        "infrastructure notification escaped its fixed socket"
    );
    *stage = StartupStage::NotificationSocket;
    let socket_metadata = match fs::symlink_metadata(&address) {
        Ok(metadata) => metadata,
        // OpenRC removes the startup socket after accepting READY=1. A later
        // supervised restart must not mint another startup admission.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        socket_metadata.file_type().is_socket() && socket_metadata.mode() & 0o077 == 0,
        "infrastructure notification socket is not protected"
    );
    *stage = StartupStage::NotificationParent;
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/run/openrc")?;
    let parent_metadata = parent.metadata()?;
    ensure!(
        OpenRcParent {
            uid: parent_metadata.uid(),
            gid: parent_metadata.gid(),
            mode: parent_metadata.mode(),
        }
        .protected(),
        "infrastructure notification parent is not protected"
    );
    openrc_parent_acl_absent(&parent)?;
    *stage = StartupStage::NotificationIdentity;
    let proxy = if role == Role::Proxy {
        Some(bootstrap::proxy_identity()?)
    } else {
        None
    };
    ensure!(
        NotificationSocket {
            uid: socket_metadata.uid(),
            gid: socket_metadata.gid(),
            mode: socket_metadata.mode(),
        }
        .owned(proxy),
        "infrastructure notification is not a protected supervisor socket"
    );
    if let Some((uid, gid)) = proxy {
        fs::set_permissions(&address, fs::Permissions::from_mode(0o600))?;
        let name = std::ffi::CString::new(address.as_bytes())?;
        ensure!(
            unsafe { libc::chown(name.as_ptr(), uid, gid) } == 0,
            "cannot grant the fixed proxy its startup notification"
        );
    }
    Ok(Some(address))
}
fn notify(address: Option<&str>) -> Result<()> {
    if let Some(address) = address {
        let socket = UnixDatagram::unbound()?;
        ensure!(
            socket.send_to(b"READY=1", address)? == 7,
            "fixed infrastructure readiness was incomplete"
        );
    }
    Ok(())
}

pub fn run(value: &str) -> Result<()> {
    let role = Role::parse(value)?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "fixed infrastructure requires the owner identity"
    );
    let mut stage = StartupStage::Files;
    let mut slot = None;
    let result = run_fixed(role, &mut stage, &mut slot);
    if let Err(error) = &result {
        let _ = record_startup(role, stage, error, slot.as_mut());
    }
    result
}
fn run_fixed(role: Role, stage: &mut StartupStage, slot: &mut Option<fs::File>) -> Result<()> {
    bootstrap::infrastructure_files_guard().context("fixed infrastructure startup files")?;
    *stage = StartupStage::Leaf;
    process_group(std::process::id(), &role.group())
        .context("fixed infrastructure startup leaf")?;
    *stage = StartupStage::Monitor;
    let deadline = Instant::now() + Duration::from_secs(2);
    let monitor = loop {
        if let Some(monitor) =
            supervisor_pid(role).context("fixed infrastructure startup monitor")?
        {
            break monitor;
        }
        ensure!(
            Instant::now() < deadline,
            "fixed service has no owned supervisor"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    *stage = StartupStage::Parent;
    ensure!(
        unsafe { libc::getppid() } as u32 == monitor,
        "fixed service was not started by its owned supervisor"
    );
    unsafe {
        libc::umask(0o077);
    }
    let notification =
        notification(role, stage).context("fixed infrastructure startup notification")?;
    match role {
        Role::Controller => {
            let mut process = command(CLI);
            process.current_dir("/var/lib/komizo").arg("daemon");
            if let Some(address) = notification {
                process.env("NOTIFY_SOCKET", address);
            }
            *stage = StartupStage::Exec;
            Err(process.exec()).context("fixed infrastructure controller execution")
        }
        Role::Proxy => {
            *stage = StartupStage::ProxyGuard;
            bootstrap::proxy_guard().context("fixed infrastructure startup proxy provenance")?;
            let mut process = command("/usr/local/bin/caddy");
            process
                .current_dir("/var/lib/komizo-proxy")
                .env("HOME", "/var/lib/komizo-proxy")
                .env("XDG_DATA_HOME", "/var/lib/komizo-proxy/data")
                .env("XDG_CONFIG_HOME", "/var/lib/komizo-proxy/config")
                .env("TMPDIR", "/run/komizo-proxy")
                .args([
                    "run",
                    "--config",
                    "/etc/komizo-proxy/Caddyfile",
                    "--adapter",
                    "caddyfile",
                ]);
            // exec() runs pre_exec in this same worker. Retain one root-owned
            // CLOEXEC descriptor before any credential change so even a later
            // failed syscall can report only its closed facts. Successful exec
            // closes the capability; a pending record never proves success.
            *slot = startup_slot(role).ok();
            *stage = StartupStage::Confinement;
            bootstrap::confine(&mut process, true)
                .context("fixed infrastructure startup confinement")?;
            if let Some(address) = notification {
                process.env("NOTIFY_SOCKET", address);
            }
            *stage = StartupStage::Exec;
            Err(process.exec()).context("fixed infrastructure proxy execution")
        }
        Role::Dns => {
            *stage = StartupStage::Runner;
            dns_runner(notification.as_deref()).context("fixed infrastructure DNS runner")
        }
        Role::Expiry => {
            *stage = StartupStage::Runner;
            expiry_runner(notification.as_deref()).context("fixed infrastructure expiry runner")
        }
    }
}

fn expiry_runner(notification: Option<&str>) -> Result<()> {
    signals()?;
    notify(notification)?;
    while !STOP.load(Ordering::Relaxed) {
        // Independent from the controller's lifetime. Each pass retains the
        // same 1500s deadline as the old fixed expiry service.
        let mut child = command("/usr/bin/timeout");
        child.args(["--signal=KILL", "1500s", CLI, "expire"]);
        let _ = crate::process::capture(
            &mut child,
            None,
            65536,
            Instant::now() + Duration::from_secs(1501),
            || STOP.load(Ordering::Relaxed),
        );
        for _ in 0..600 {
            if STOP.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}

/// Aardvark always forks. Adopt its exact child and wait on a pidfd, rather
/// than treating the successful launcher exit as the lifetime of the server.
#[cfg(target_os = "linux")]
fn dns_runner(notification: Option<&str>) -> Result<()> {
    signals()?;
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0,
        "cannot own the fixed DNS child lifetime"
    );
    let mut notification = notification;
    loop {
        if STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        if !fs::read_dir(bootstrap::DNS_CONFIG)?
            .any(|entry| entry.ok().is_some_and(|e| e.file_name() != "aardvark.pid"))
        {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        bootstrap::dns_guard()?;
        let mut launch = command(bootstrap::DNS_BINARY);
        launch.args(["--config", bootstrap::DNS_CONFIG, "-p", "53", "run"]);
        bootstrap::confine(&mut launch, false)?;
        launch
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        struct Launch(Option<std::process::Child>);
        impl Drop for Launch {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    // Leader stays unreaped until the exact daemon pidfd is bound.
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                    let _ = child.wait();
                }
            }
        }
        let mut launcher = Launch(Some(launch.spawn()?));
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    launcher.0.as_ref().unwrap().id(),
                    &mut status,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            ensure!(result == 0, "cannot observe fixed DNS launcher");
            if unsafe { status.si_pid() } != 0 {
                break;
            }
            ensure!(
                Instant::now() < deadline && !STOP.load(Ordering::Relaxed),
                "fixed DNS launcher deadline expired"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = bootstrap::dns_pid()?
            .ok_or_else(|| anyhow!("fixed DNS did not publish its identity"))?;
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        ensure!(descriptor >= 0, "cannot bind the fixed DNS lifetime");
        struct Daemon(File);
        impl Drop for Daemon {
            fn drop(&mut self) {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.0.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
            }
        }
        let daemon = Daemon(unsafe { File::from_raw_fd(descriptor) });
        bootstrap::dns_guard()?;
        ensure!(
            launcher.0.take().unwrap().wait()?.success(),
            "fixed DNS launcher failed"
        );
        notify(notification.take())?;
        let mut poll = libc::pollfd {
            fd: daemon.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let mut stopping = None;
        loop {
            if STOP.load(Ordering::Relaxed) && stopping.is_none() {
                stopping = Some(Instant::now());
                ensure!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            daemon.0.as_raw_fd(),
                            libc::SIGTERM,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        )
                    } == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
                    "cannot stop the owned DNS process"
                );
            }
            if stopping.is_some_and(|start: Instant| start.elapsed() >= Duration::from_secs(5)) {
                ensure!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            daemon.0.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        )
                    } == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
                    "cannot kill the owned DNS process"
                );
            }
            let result = unsafe { libc::poll(&mut poll, 1, 100) };
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            ensure!(result >= 0, "fixed DNS lifetime observation failed");
            if result > 0 {
                ensure!(
                    poll.revents & libc::POLLIN != 0,
                    "owned DNS pidfd returned an invalid event"
                );
                break;
            }
        }
        let mut status = 0;
        ensure!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) } == pid as i32,
            "fixed DNS child was not adopted"
        );
        if STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        ensure!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "fixed DNS daemon failed"
        );
    }
}
#[cfg(not(target_os = "linux"))]
fn dns_runner(_: Option<&str>) -> Result<()> {
    Err(anyhow!("fixed DNS requires the supported Alpine host"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_diagnostics_serialize_only_closed_facts_and_preserve_no_private_error_text() {
        let sentinel = "PRIVATE_ENV_AND_CONFIGURATION_SENTINEL";
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            sentinel,
        ))
        .context(sentinel);
        let diagnostic = StartupDiagnostic::new(
            Role::Proxy,
            StartupStage::Exec,
            "11111111-1111-1111-1111-111111111111".into(),
            u32::MAX,
            &error,
        );
        diagnostic.validate(Role::Proxy).unwrap();
        let body = serde_json::to_vec(&diagnostic).unwrap();
        assert!(body.len() < 4096);
        assert!(!String::from_utf8_lossy(&body).contains(sentinel));
        let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 9);
        assert_eq!(value["error"], "io");
        assert_eq!(value["diagnostic_only"], true);
        assert!(diagnostic.validate(Role::Controller).is_err());
        value["environment"] = serde_json::json!(sentinel);
        assert!(serde_json::from_value::<StartupDiagnostic>(value).is_err());
        let diagnostic = StartupDiagnostic::new(
            Role::Proxy,
            StartupStage::Exec,
            "11111111-1111-1111-1111-111111111111".into(),
            123,
            &std::io::Error::from_raw_os_error(libc::EACCES).into(),
        );
        assert_eq!(diagnostic.errno, Some(libc::EACCES));
    }
    #[test]
    fn startup_diagnostic_paths_refuse_foreign_roles_before_any_filesystem_access() {
        for path in [
            Path::new("/tmp/foreign-startup.json").to_path_buf(),
            startup_path(Role::Dns),
        ] {
            let error = startup_file(&path, Role::Proxy).unwrap_err();
            assert!(error.to_string().contains("fixed role path"));
        }
    }
    #[test]
    fn pending_exec_diagnostic_is_explicit_unknown_outcome_and_never_has_an_errno() {
        let mut diagnostic = StartupDiagnostic::new(
            Role::Proxy,
            StartupStage::Exec,
            "11111111-1111-1111-1111-111111111111".into(),
            123,
            &anyhow!("not serialized"),
        );
        diagnostic.error = StartupError::Pending;
        diagnostic.validate(Role::Proxy).unwrap();
        diagnostic.errno = Some(libc::EACCES);
        assert!(diagnostic.validate(Role::Proxy).is_err());
        diagnostic.errno = None;
        diagnostic.stage = StartupStage::Files;
        assert!(diagnostic.validate(Role::Proxy).is_err());
    }
    #[test]
    fn openrc_parent_trusts_only_the_fixed_root_administrative_group() {
        for mode in [0o755, 0o775] {
            assert!(
                OpenRcParent {
                    uid: 0,
                    gid: 0,
                    mode: 0o040000 | mode,
                }
                .protected()
            );
        }
        for parent in [
            OpenRcParent {
                uid: 1,
                gid: 0,
                mode: 0o040775,
            },
            OpenRcParent {
                uid: 0,
                gid: 1,
                mode: 0o040775,
            },
            OpenRcParent {
                uid: 0,
                gid: 0,
                mode: 0o040777,
            },
            OpenRcParent {
                uid: 0,
                gid: 0,
                mode: 0o120775,
            },
            OpenRcParent {
                uid: 0,
                gid: 0,
                mode: 0o100775,
            },
        ] {
            assert!(!parent.protected());
        }
    }
    #[test]
    fn root_owned_openrc_parent_never_substitutes_for_notification_socket_ownership() {
        assert!(
            OpenRcParent {
                uid: 0,
                gid: 0,
                mode: 0o040775
            }
            .protected()
        );
        let socket = |uid, gid, mode| NotificationSocket { uid, gid, mode };
        assert!(!socket(0, 0, 0o040775).owned(None));
        assert!(!socket(0, 0, 0o040700).owned(None));
        assert!(!socket(0, 0, 0o140777).owned(None));
        assert!(socket(0, 0, 0o140700).owned(None));
        assert!(!socket(1002, 1002, 0o140700).owned(None));
        assert!(!socket(1002, 1002, 0o140700).owned(Some((1001, 1001))));
        assert!(socket(1001, 1001, 0o140600).owned(Some((1001, 1001))));
        assert!(!socket(1001, 1002, 0o140600).owned(Some((1001, 1001))));
        assert!(!socket(1002, 1001, 0o140600).owned(Some((1001, 1001))));
        assert!(!socket(1001, 1001, 0o140700).owned(Some((1001, 1001))));
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn openrc_parent_fd_refuses_a_real_access_acl() {
        let root = tempfile::tempdir().unwrap();
        let parent = fs::File::open(root.path()).unwrap();
        openrc_parent_acl_absent(&parent).unwrap();
        // Linux UAPI posix_acl_xattr: version 2 and little-endian tag/perm/id.
        // A named entry for our own mapped UID needs no foreign UID mapping.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, identity) in [
            (0x01_u16, 7_u16, u32::MAX),
            (0x02, 7, unsafe { libc::getuid() }),
            (0x04, 7, u32::MAX),
            (0x10, 7, u32::MAX),
            (0x20, 5, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permissions.to_le_bytes());
            acl.extend(identity.to_le_bytes());
        }
        let result = unsafe {
            libc::fsetxattr(
                parent.as_raw_fd(),
                c"system.posix_acl_access".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error
                .raw_os_error()
                .is_some_and(|code| code == libc::EOPNOTSUPP || code == libc::ENOTSUP)
            {
                eprintln!("test filesystem does not support POSIX access ACLs");
                return;
            }
            panic!("cannot prepare the owned access ACL control: {error}");
        }
        assert_eq!(parent.metadata().unwrap().mode() & 0o777, 0o775);
        assert!(openrc_parent_acl_absent(&parent).is_err());
    }
    #[test]
    fn infrastructure_roles_close_program_paths_and_monitor_scopes() {
        for bad in [
            "",
            "task",
            "dns --port 5353",
            "../controller",
            "/bin/sh",
            "proxy.service",
        ] {
            assert!(Role::parse(bad).is_err());
        }
        for role in [Role::Controller, Role::Proxy, Role::Dns, Role::Expiry] {
            assert_eq!(Role::parse(role.name()).unwrap(), role);
            let args = supervisor_arguments(role);
            assert_eq!(args[0], role.service());
            assert!(args.ends_with(&[
                CLI.to_owned(),
                "--".into(),
                "infrastructure-run".into(),
                role.name().into()
            ]));
            assert_eq!(args.iter().filter(|v| v.as_str() == "/dev/null").count(), 3);
            let script = service_script(role);
            assert!(!script.contains("supervisor="));
            assert!(script.contains(&format!("infrastructure-supervise {}", role.name())));
        }
        assert_ne!(Role::Controller.group(), Role::Expiry.group());
        assert_ne!(Role::Controller.group(), Role::Dns.group());
        assert!(!service_script(Role::Expiry).contains("need komizo-controller"));
        assert!(!service_script(Role::Proxy).contains("need komizo-controller"));
    }
}
