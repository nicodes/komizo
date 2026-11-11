//! Install the native host boundary from explicit owner-provided keys and capacity.
use super::{
    capacity::Capacity,
    engine::Engine,
    store::{self, Store},
    system::{self, System},
    validation::document_digest,
};
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub const CONTROLLER: &str = "komizo-controller";
pub const PROXY: &str = "komizo-proxy";
const SHELL: &str = "/usr/local/libexec/komizo-submit-shell";
const CONFIG: &str = "/etc/komizo";
const LEDGER: &str = "/etc/komizo/bootstrap.json";
const KEYS: &str = "/etc/ssh/komizo-submit/authorized_keys";
const CLI: &str = "/usr/local/bin/komizo-box";
pub(crate) const DNS_BINARY: &str = "/usr/libexec/podman/aardvark-dns";
pub(crate) const DNS_CONFIG: &str = "/run/containers/networks/aardvark-dns";
const DNS_SERVICE: &str = "komizo-dns";
const DNS_HELPER: &str = "/usr/local/libexec/komizo-network/aardvark-dns";
const ENGINE_CONFIG: &str = "/etc/containers/containers.conf.d/80-komizo-network.conf";
const DNS_WRAPPER: &str = "#!/bin/sh\nexec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/local/bin/komizo-box dns \"$@\"\n";
const ENGINE_NETWORK: &str = "[containers]\napparmor_profile=\"komizo-workload\"\n[engine]\ncgroup_manager=\"cgroupfs\"\nhelper_binaries_dir=[\"/usr/local/libexec/komizo-network\",\"/usr/libexec/podman\"]\n[network]\nnetwork_backend=\"netavark\"\nfirewall_driver=\"nftables\"\ndns_bind_port=53\n";

pub const WORKLOAD_PROFILE: &str = "komizo-workload";
const APPARMOR_FILE: &str = "/etc/apparmor.d/komizo-workload";
const APPARMOR_PARSER: &str = "/sbin/apparmor_parser";
const APPARMOR_POLICY: &[u8] = include_bytes!("apparmor-workload");
const APPARMOR_LICENSE: &[u8] = include_bytes!("apparmor-workload.LICENSE");
const INFRASTRUCTURE_PROFILE: &str = "/etc/apparmor.d/komizo-infrastructure";
const INFRASTRUCTURE_POLICY: &[u8] = include_bytes!("apparmor-infrastructure");

fn kernel_text(path: &Path, maximum: u64) -> Result<String> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?
        .take(maximum + 1);
    let mut body = String::new();
    input.read_to_string(&mut body)?;
    ensure!(
        body.len() as u64 <= maximum,
        "kernel confinement metadata exceeds bounds"
    );
    Ok(body)
}

fn enforcing_profile(enabled: &str, profiles: &str) -> Result<()> {
    ensure!(enabled.trim() == "Y", "AppArmor confinement is unavailable");
    ensure!(
        profiles
            .lines()
            .filter(|line| *line == "komizo-workload (enforce)")
            .count()
            == 1,
        "the reviewed workload AppArmor profile is not enforcing"
    );
    Ok(())
}

fn configured_profile(body: &[u8]) -> Result<Option<String>> {
    let text = std::str::from_utf8(body)
        .map_err(|_| anyhow!("root container configuration is not UTF-8"))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(|_| anyhow!("root container configuration is invalid TOML"))?;
    let tables = value
        .as_table()
        .ok_or_else(|| anyhow!("invalid root container configuration table"))?;
    let matches = tables
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("containers"))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() <= 1,
        "ambiguous root container configuration table"
    );
    let Some((_, containers)) = matches.first() else {
        return Ok(None);
    };
    let fields = containers
        .as_table()
        .ok_or_else(|| anyhow!("invalid root container settings"))?;
    let profiles = fields
        .iter()
        .filter(|(key, _)| key.replace('_', "").eq_ignore_ascii_case("apparmorprofile"))
        .collect::<Vec<_>>();
    ensure!(
        profiles.len() <= 1,
        "ambiguous root container AppArmor selection"
    );
    profiles
        .first()
        .map(|(_, value)| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("root container AppArmor selection must be literal"))
        })
        .transpose()
}

fn configuration_profile() -> Result<()> {
    for name in [
        "CONTAINERS_CONF",
        "CONTAINERS_CONF_OVERRIDE",
        "XDG_CONFIG_HOME",
    ] {
        ensure!(
            std::env::var_os(name).is_none_or(|value| value.is_empty()),
            "root container configuration has an unreviewed environment selector"
        );
    }
    ensure!(
        std::env::var_os("HOME").is_none_or(|value| value == "/root"),
        "root container configuration requires the fixed owner home"
    );
    // containers/common v0.62.3 new.go systemConfigs/addConfigs. Modules are
    // opt-in CLI arguments and are absent from all approved native helper argv.
    let mut paths = vec![
        Path::new("/usr/share/containers/containers.conf").to_path_buf(),
        Path::new("/etc/containers/containers.conf").to_path_buf(),
    ];
    for (directory, main) in [
        ("/etc/containers/containers.conf.d", None),
        (
            "/root/.config/containers/containers.conf.d",
            Some("/root/.config/containers/containers.conf"),
        ),
    ] {
        if let Some(main) = main {
            paths.push(Path::new(main).to_path_buf());
        }
        match fs::symlink_metadata(directory) {
            Ok(info) => {
                ensure!(
                    info.is_dir()
                        && !info.file_type().is_symlink()
                        && info.uid() == 0
                        && info.mode() & 0o022 == 0,
                    "unsafe root container configuration directory"
                );
                let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
                ensure!(
                    entries.len() <= 64,
                    "root container configuration exceeds bounds"
                );
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    if !entry.file_type()?.is_dir()
                        && entry.file_name().as_encoded_bytes().ends_with(b".conf")
                    {
                        paths.push(entry.path());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(
        paths.len() <= 64,
        "root container configuration exceeds bounds"
    );
    let mut selected = None;
    for path in paths {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if let Some(profile) = configured_profile(&protected_file(&path, 256 << 10)?)? {
                    selected = Some(profile);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(
        selected.as_deref() == Some(WORKLOAD_PROFILE),
        "effective root container defaults select an unreviewed AppArmor profile"
    );
    Ok(())
}

/// The shared service and job profile is fixed owner-installed policy, never source input.
pub fn apparmor_guard() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "workload confinement guard requires the owner identity"
    );
    let ledger: Ledger = serde_json::from_value(crate::strict::value(
        &protected_file(Path::new(LEDGER), 65536)?,
        65536,
    )?)?;
    let identity = ledger
        .files
        .get(APPARMOR_FILE)
        .ok_or_else(|| anyhow!("workload confinement is not owner installed"))?;
    ensure!(
        ledger.kind == "komizo.bootstrap" && ledger.version == 1 && identity.mode == 0o644,
        "invalid workload confinement ownership record"
    );
    let body = protected_file(Path::new(APPARMOR_FILE), 65536)?;
    ensure!(
        body == APPARMOR_POLICY
            && document_digest(&body) == identity.sha256
            && fs::symlink_metadata(APPARMOR_FILE)?.mode() & 0o7777 == 0o644,
        "workload confinement differs from the reviewed installed policy"
    );
    let config = protected_file(Path::new(ENGINE_CONFIG), 65536)?;
    let configured = ledger
        .files
        .get(ENGINE_CONFIG)
        .ok_or_else(|| anyhow!("root container defaults are not owner installed"))?;
    ensure!(
        config == ENGINE_NETWORK.as_bytes()
            && document_digest(&config) == configured.sha256
            && configured.mode == 0o644
            && fs::symlink_metadata(ENGINE_CONFIG)?.mode() & 0o7777 == 0o644,
        "root container defaults changed after installation"
    );
    configuration_profile()?;
    enforcing_profile(
        &kernel_text(Path::new("/sys/module/apparmor/parameters/enabled"), 32)?,
        &kernel_text(Path::new("/sys/kernel/security/apparmor/profiles"), 2 << 20)?,
    )
}

pub const PROXY_RECEIPT: &str = "/etc/komizo-proxy/binary.json";
const PROXY_BINARY: &str = "/usr/local/bin/caddy";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyBuild {
    kind: String,
    version: u32,
    tools_revision: String,
    platform: String,
    go_version: String,
    caddy_version: String,
    source_sha256: BTreeMap<String, String>,
    binary_sha256: String,
}

fn proxy_build(body: &[u8], platform: &str) -> Result<String> {
    let value: ProxyBuild = serde_json::from_value(crate::strict::value(body, 16384)?)?;
    ensure!(
        value.kind == "komizo.proxy-build"
            && value.version == 1
            && super::validation::hex(&value.tools_revision, 40)
            && value.platform == platform
            && ["linux/amd64", "linux/arm64"].contains(&platform)
            && value.go_version == "1.27.4"
            && value.caddy_version == "2.11.6"
            && value
                .source_sha256
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                == ["caddy-build.sh", "caddy.go.mod", "caddy.go.sum"]
            && value
                .source_sha256
                .values()
                .all(|v| super::validation::digest(v))
            && super::validation::digest(&value.binary_sha256),
        "proxy provenance differs from the reviewed compiler, source closure or native platform"
    );
    Ok(value.binary_sha256)
}

pub(crate) fn public_root_file(path: &Path, maximum: u64, mode: u32) -> Result<fs::File> {
    ensure!(
        path.is_absolute(),
        "proxy provenance requires fixed absolute paths"
    );
    for parent in path.ancestors().skip(1) {
        let info = fs::symlink_metadata(parent)?;
        ensure!(
            info.is_dir()
                && !info.file_type().is_symlink()
                && info.uid() == 0
                && info.mode() & 0o022 == 0
                && info.mode() & 0o111 == 0o111,
            "proxy provenance traverses an unsafe parent"
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == 0
            && info.nlink() == 1
            && info.mode() & 0o022 == 0
            && info.mode() & 0o7777 == mode
            && info.len() > 0
            && info.len() <= maximum,
        "proxy provenance input is not a protected ordinary file"
    );
    Ok(file)
}

/// Public provenance can be checked inside the unprivileged ingress sandbox.
pub fn proxy_guard() -> Result<()> {
    ensure!(
        std::env::consts::OS == "linux",
        "native proxy requires Linux"
    );
    let platform = match std::env::consts::ARCH {
        "x86_64" => "linux/amd64",
        "aarch64" => "linux/arm64",
        _ => return Err(anyhow!("unsupported native proxy architecture")),
    };
    let mut body = Vec::new();
    public_root_file(Path::new(PROXY_RECEIPT), 16384, 0o644)?
        .take(16385)
        .read_to_end(&mut body)?;
    let expected = proxy_build(&body, platform)?;
    let mut binary = public_root_file(Path::new(PROXY_BINARY), 128 << 20, 0o755)?;
    let before = binary.metadata()?;
    ensure!(
        before.mode() & 0o111 == 0o111,
        "proxy binary is not publicly executable"
    );
    let mut hash = Sha256::new();
    let mut header = [0u8; 64];
    binary.read_exact(&mut header)?;
    let machine = u16::from_le_bytes([header[18], header[19]]);
    ensure!(
        header[..7] == *b"\x7fELF\x02\x01\x01"
            && machine == if platform == "linux/amd64" { 62 } else { 183 },
        "installed proxy is not the declared native Linux executable"
    );
    let offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(header[54..56].try_into().unwrap());
    let count = u16::from_le_bytes(header[56..58].try_into().unwrap());
    ensure!(
        size == 56
            && (1..=128).contains(&count)
            && offset >= 64
            && offset
                .checked_add(u64::from(size) * u64::from(count))
                .is_some_and(|end| end <= before.len()),
        "installed proxy has invalid bounded ELF program metadata"
    );
    let mut programs = vec![0; usize::from(size) * usize::from(count)];
    binary.seek(SeekFrom::Start(offset))?;
    binary.read_exact(&mut programs)?;
    ensure!(
        programs
            .chunks_exact(56)
            .all(|entry| u32::from_le_bytes(entry[..4].try_into().unwrap()) != 3),
        "installed proxy requires an unapproved host interpreter"
    );
    binary.seek(SeekFrom::Start(0))?;
    let mut buffer = [0u8; 65536];
    loop {
        let count = binary.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let after = binary.metadata()?;
    ensure!(
        before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && format!("sha256:{:x}", hash.finalize()) == expected,
        "installed proxy binary differs from its protected source receipt"
    );
    Ok(())
}

const SUBMISSION_SHELL: &str = r#"#!/bin/sh
# OpenSSH invokes this root-owned account shell with its fixed forced command.
set -eu
[ "$#" -eq 2 ] && [ "$1" = -c ] && [ "$2" = /usr/local/libexec/komizo-submit-shell ] || exit 126
[ "${SSH_ORIGINAL_COMMAND:-}" = 'komizo-box submit' ] || exit 126
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/local/bin/komizo-box submit
"#;

const SSH_CONFIG: &str = "# Managed native submission boundary. Owner root SSH remains separate.\nMatch User komizo-submit\n    AuthenticationMethods publickey\n    AuthorizedKeysFile /etc/ssh/komizo-submit/authorized_keys\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PermitTTY no\n    DisableForwarding yes\n    AllowAgentForwarding no\n    AllowTcpForwarding no\n    X11Forwarding no\n    PermitTunnel no\n    PermitUserRC no\n    ForceCommand /usr/local/libexec/komizo-submit-shell\nMatch all\n";

fn submission_settings(body: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(body)?;
    for (key, expected) in [
        ("authenticationmethods", "publickey"),
        ("authorizedkeysfile", KEYS),
        ("passwordauthentication", "no"),
        ("kbdinteractiveauthentication", "no"),
        ("permittty", "no"),
        ("disableforwarding", "yes"),
        ("allowagentforwarding", "no"),
        ("allowtcpforwarding", "no"),
        ("x11forwarding", "no"),
        ("permittunnel", "no"),
        ("permituserrc", "no"),
        ("forcecommand", SHELL),
    ] {
        let values = text
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter_map(|(name, value)| (name == key).then_some(value))
            .collect::<Vec<_>>();
        ensure!(
            values == [expected],
            "effective SSH submission settings bypass the installed forced-command boundary"
        );
    }
    Ok(())
}

fn dns_arguments(args: &[String]) -> Result<()> {
    ensure!(
        args.iter().map(String::as_str).collect::<Vec<_>>()
            == ["--config", DNS_CONFIG, "-p", "53", "run"],
        "container DNS helper accepts only its fixed rootful configuration and port"
    );
    Ok(())
}

pub(crate) fn dns_pid() -> Result<Option<u32>> {
    let path = Path::new(DNS_CONFIG).join("aardvark.pid");
    if !path.try_exists()? {
        return Ok(None);
    }
    let body = protected_file(&path, 32)?;
    let text = std::str::from_utf8(&body)?;
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "invalid rootful DNS process identity"
    );
    let pid = text.parse::<u32>()?;
    ensure!(pid > 1, "invalid rootful DNS process identity");
    Ok(Some(pid))
}

fn recorded_dns_files() -> Result<()> {
    let ledger: Ledger = serde_json::from_slice(&protected_file(Path::new(LEDGER), 65536)?)?;
    ensure!(
        ledger.kind == "komizo.bootstrap" && ledger.version == 1,
        "native bootstrap identity missing"
    );
    for path in [
        DNS_HELPER.to_owned(),
        ENGINE_CONFIG.to_owned(),
        format!("/etc/init.d/{DNS_SERVICE}"),
    ] {
        let identity = ledger
            .files
            .get(&path)
            .ok_or_else(|| anyhow!("container DNS boundary is not owner installed"))?;
        ensure!(
            document_digest(&protected_file(Path::new(&path), 65536)?) == identity.sha256
                && fs::symlink_metadata(&path)?.mode() & 0o7777 == identity.mode,
            "container DNS boundary changed after installation"
        );
    }
    Ok(())
}

/// Refuse an unrecorded shared DNS daemon; never move or stop foreign scopes.
pub fn dns_guard() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "container DNS guard requires the host owner identity"
    );
    let binary = public_root_file(Path::new(DNS_BINARY), 64 << 20, 0o755)?;
    let expected = binary.metadata()?;
    let pidfile = Path::new(DNS_CONFIG).join("aardvark.pid");
    let pid = match fs::symlink_metadata(&pidfile) {
        Ok(_) => {
            let body = protected_file(&pidfile, 32)?;
            let text = std::str::from_utf8(&body)?;
            ensure!(
                text.bytes().all(|value| value.is_ascii_digit()) && !text.is_empty(),
                "invalid rootful DNS process identity"
            );
            let pid = text.parse::<u32>()?;
            ensure!(pid > 1, "invalid rootful DNS process identity");
            Some(pid)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    // Inspect all actual instances, including a live daemon with a missing or
    // stale pidfile. Selection uses its real executable, never process text.
    let host_namespace = fs::read_link("/proc/self/ns/net")?;
    let mut observed = false;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(number) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let executable = entry.path().join("exe");
        let Ok(target) = fs::read_link(&executable) else {
            continue;
        };
        if target
            .file_name()
            .is_none_or(|name| !name.to_string_lossy().starts_with("aardvark-dns"))
        {
            continue;
        }
        let Ok(namespace) = fs::read_link(entry.path().join("ns/net")) else {
            continue;
        };
        // An application's private network namespace cannot supply this host's
        // shared rootful DNS. Do not classify its process name as host authority.
        if namespace != host_namespace {
            continue;
        }
        ensure!(
            pid == Some(number) && target == Path::new(DNS_BINARY),
            "unknown existing container DNS daemon requires owner reconciliation"
        );
        observed = true;
        let actual = fs::metadata(&executable)?;
        ensure!(
            actual.dev() == expected.dev()
                && actual.ino() == expected.ino()
                && fs::metadata(entry.path())?.uid() == 0,
            "existing container DNS executable identity differs"
        );
        let argv = fs::read(entry.path().join("cmdline"))?;
        let expected_argv = format!("{DNS_BINARY}\0--config\0{DNS_CONFIG}\0-p\053\0run\0");
        ensure!(
            argv == expected_argv.as_bytes(),
            "existing container DNS argv differs"
        );
        ensure!(
            fs::read_link(entry.path().join("ns/net"))? == fs::read_link("/proc/self/ns/net")?,
            "container DNS uses a foreign network namespace"
        );
        let group = fs::read_to_string(entry.path().join("cgroup"))?;
        ensure!(
            group.trim()
                == format!(
                    "0::{}",
                    super::cgroups::control_leaf(super::cgroups::ControlLeaf::Dns).relative()
                ),
            "shared container DNS is outside its protected budget"
        );
        recorded_dns_files()?;
        super::infrastructure::dns_supervision(number)?;
    }
    ensure!(
        observed || pid.is_none_or(|number| !Path::new(&format!("/proc/{number}")).exists()),
        "container DNS pidfile selects an unrelated live process"
    );
    Ok(())
}

/// The installed helper must be the one Podman actually selects after all
/// system and owner configuration layers have been applied.
pub fn dns_configuration_guard() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "container DNS configuration requires the host owner identity"
    );
    recorded_dns_files()?;
    let info = Engine {
        deadline: Instant::now() + Duration::from_secs(15),
    }
    .json(&["info", "--format=json"])?;
    ensure!(
        info["host"]["networkBackendInfo"]["backend"] == "netavark"
            && info["host"]["networkBackendInfo"]["dns"]["path"] == DNS_HELPER
            && info["host"]["networkBackendInfo"]["path"] == "/usr/libexec/podman/netavark",
        "Podman bypassed the owner-installed container network helper"
    );
    Ok(())
}

/// Netavark's helper transport can request only the fixed distro DNS service.
pub fn dns(args: &[String], output: &mut dyn Write) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "container DNS helper requires the host owner identity"
    );
    if args == ["--version"] {
        public_root_file(Path::new(DNS_BINARY), 64 << 20, 0o755)?;
        output.write_all(&command(
            DNS_BINARY,
            &["--version"],
            Instant::now() + Duration::from_secs(5),
        )?)?;
        return Ok(());
    }
    dns_arguments(args)?;
    dns_guard()?;
    recorded_dns_files()?;
    for path in Path::new(DNS_CONFIG).ancestors() {
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_dir()
                && !info.file_type().is_symlink()
                && info.uid() == 0
                && info.mode() & 0o022 == 0,
            "container DNS configuration crosses an unsafe directory"
        );
    }
    let deadline = Instant::now() + Duration::from_secs(25);
    super::infrastructure::start(super::infrastructure::Role::Dns, deadline)?;
    loop {
        ensure!(
            Instant::now() < deadline,
            "shared container DNS did not become ready"
        );
        if let Some(pid) = dns_pid()?
            && Path::new(&format!("/proc/{pid}")).try_exists()?
        {
            dns_guard()?;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    dns_guard()
}

pub fn infrastructure_supervise(role: &str) -> Result<()> {
    super::infrastructure::supervise(role)
}
pub fn infrastructure_run(role: &str) -> Result<()> {
    super::infrastructure::run(role)
}
pub fn infrastructure_stop(role: &str) -> Result<()> {
    super::infrastructure::stop_owned(super::infrastructure::Role::parse(role)?)
}

#[cfg(target_os = "linux")]
fn confinement_filter() -> Vec<libc::sock_filter> {
    fn load(offset: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }
    fn equal(value: u32, yes: u8, no: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: 0x15,
            jt: yes,
            jf: no,
            k: value,
        }
    }
    fn ret(value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: value,
        }
    }
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    let mut rules = vec![load(4), equal(ARCH, 1, 0), ret(0x8000_0000), load(0)];
    #[cfg(target_arch = "x86_64")]
    rules.extend([
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        },
        ret(0x8000_0000),
    ]);
    for syscall in [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_personality,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_kexec_load,
        libc::SYS_io_uring_setup,
    ] {
        rules.extend([equal(syscall as u32, 0, 1), ret(DENY)]);
    }
    // clone3's flags live behind a pointer: refuse with ENOSYS so libc/Go use
    // clone, whose namespace flags can be checked without following pointers.
    rules.extend([
        equal(libc::SYS_clone3 as u32, 0, 1),
        ret(0x0005_0000 | libc::ENOSYS as u32),
    ]);
    rules.extend([
        equal(libc::SYS_clone as u32, 0, 3),
        load(16),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: (libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWCGROUP) as u32,
        },
        ret(DENY),
        load(0),
    ]);
    for syscall in [libc::SYS_mprotect, libc::SYS_pkey_mprotect] {
        rules.extend([
            equal(syscall as u32, 0, 3),
            load(32),
            libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 1,
                k: libc::PROT_EXEC as u32,
            },
            ret(DENY),
            load(0),
        ]);
    }
    rules.extend([
        equal(libc::SYS_mmap as u32, 0, 4),
        load(32),
        libc::sock_filter {
            code: 0x54,
            jt: 0,
            jf: 0,
            k: (libc::PROT_WRITE | libc::PROT_EXEC) as u32,
        },
        equal((libc::PROT_WRITE | libc::PROT_EXEC) as u32, 0, 1),
        ret(DENY),
        ret(0x7fff_0000),
    ]);
    rules
}

/// Authenticate each fixed script and confinement policy against both its
/// compiled bytes and the owner-install ledger before service effects.
pub(crate) fn infrastructure_files_guard() -> Result<()> {
    let ledger: Ledger = serde_json::from_slice(&protected_file(Path::new(LEDGER), 65536)?)?;
    ensure!(
        ledger.kind == "komizo.bootstrap" && ledger.version == 1,
        "native bootstrap identity missing"
    );
    let mut expected = vec![(
        INFRASTRUCTURE_PROFILE.to_owned(),
        INFRASTRUCTURE_POLICY.to_vec(),
        0o644,
    )];
    for role in [
        super::infrastructure::Role::Controller,
        super::infrastructure::Role::Proxy,
        super::infrastructure::Role::Dns,
        super::infrastructure::Role::Expiry,
    ] {
        expected.push((
            format!("/etc/init.d/{}", role.service()),
            super::infrastructure::service_script(role).into_bytes(),
            0o755,
        ));
    }
    for (path, body, mode) in expected {
        let record = ledger
            .files
            .get(&path)
            .ok_or_else(|| anyhow!("fixed infrastructure is not owner installed"))?;
        ensure!(
            record.sha256 == document_digest(&body)
                && record.mode == mode
                && protected_file(Path::new(&path), 65536)? == body
                && fs::symlink_metadata(path)?.mode() & 0o7777 == mode,
            "fixed infrastructure boundary differs from its owner installation"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn confine(process: &mut Command, proxy: bool) -> Result<()> {
    use std::os::unix::process::CommandExt;
    infrastructure_files_guard()?;
    let profiles = kernel_text(Path::new("/sys/kernel/security/apparmor/profiles"), 2 << 20)?;
    let profile = if proxy { "komizo-proxy" } else { "komizo-dns" };
    ensure!(
        profiles
            .lines()
            .filter(|line| *line == format!("{profile} (enforce)"))
            .count()
            == 1,
        "fixed infrastructure AppArmor profile is not enforcing"
    );
    let identity = if proxy {
        let deadline = Instant::now() + Duration::from_secs(5);
        let row = lookup("passwd", "komizo-proxy", deadline)?
            .ok_or_else(|| anyhow!("proxy identity is missing"))?;
        let fields = row.trim_end().split(':').collect::<Vec<_>>();
        ensure!(
            fields.len() == 7
                && fields[0] == "komizo-proxy"
                && fields[5] == "/var/lib/komizo-proxy"
                && fields[6] == "/sbin/nologin",
            "proxy identity differs from its fixed account"
        );
        let uid = fields[2].parse::<u32>()?;
        let gid = fields[3].parse::<u32>()?;
        ensure!(uid > 0 && gid > 0, "proxy identity must be unprivileged");
        Some((uid, gid))
    } else {
        None
    };
    let last_cap = kernel_text(Path::new("/proc/sys/kernel/cap_last_cap"), 16)?
        .trim()
        .parse::<u32>()?;
    ensure!(
        (10..64).contains(&last_cap),
        "unsupported kernel capability boundary"
    );
    let transition = format!("exec {profile}").into_bytes();
    let filter = confinement_filter();
    unsafe {
        process.pre_exec(move || {
            let check = |result: i32| -> std::io::Result<()> {
                if result < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            };
            check(libc::setgroups(0, std::ptr::null()))?;
            // NOROOT and NO_SETUID_FIXUP locked: a later root exec cannot regain
            // capabilities. Only low-port binding survives in all capability sets.
            check(libc::prctl(libc::PR_SET_SECUREBITS, 1 | 2 | 4 | 8, 0, 0, 0))?;
            for cap in 0..=last_cap {
                if cap != 10 {
                    check(libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0))?;
                }
            }
            if let Some((uid, gid)) = identity {
                check(libc::setgid(gid))?;
                check(libc::setuid(uid))?;
            }
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x2008_0522,
                pid: 0,
            };
            let data = [
                Data {
                    effective: 1 << 10,
                    permitted: 1 << 10,
                    inheritable: 1 << 10,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            check(libc::syscall(libc::SYS_capset, &header, data.as_ptr()) as i32)?;
            check(libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ))?;
            check(libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE,
                10,
                0,
                0,
            ))?;
            check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            // Resolve self in the child. An FD opened in the parent would select
            // the parent's proc task even when inherited across fork.
            let descriptor = libc::open(
                c"/proc/self/attr/apparmor/exec".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            );
            check(descriptor)?;
            let written = libc::write(descriptor, transition.as_ptr().cast(), transition.len());
            let failure = std::io::Error::last_os_error();
            libc::close(descriptor);
            if written != transition.len() as isize {
                return Err(failure);
            }
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr().cast_mut(),
            };
            check(libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0))?;
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn confine(_: &mut Command, _: bool) -> Result<()> {
    Err(anyhow!(
        "fixed infrastructure requires the supported Alpine host"
    ))
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    kind: String,
    version: u32,
    files: BTreeMap<String, FileRecord>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    sha256: String,
    mode: u32,
}

pub fn authorized_keys(body: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !body.is_empty() && body.len() <= 65536,
        "submission public keys exceed bounds"
    );
    let text = std::str::from_utf8(body)?;
    ensure!(
        !text.contains('\r') && !text.contains('\0'),
        "invalid submission public key text"
    );
    let mut keys = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        ensure!(
            line.len() <= 2048 && !line.chars().any(char::is_control),
            "invalid public key line"
        );
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() >= 2 && fields[0] == "ssh-ed25519",
            "submission requires plain Ed25519 public keys without options"
        );
        let blob = STANDARD.decode(fields[1])?;
        ensure!(
            blob.len() == 51
                && blob[..4] == [0, 0, 0, 11]
                && &blob[4..15] == b"ssh-ed25519"
                && blob[15..19] == [0, 0, 0, 32],
            "invalid Ed25519 public key encoding"
        );
        let canonical = STANDARD.encode(blob);
        ensure!(
            keys.insert(canonical, ()).is_none() && keys.len() <= 64,
            "submission public keys must be distinct and bounded"
        );
    }
    ensure!(!keys.is_empty(), "at least one submission key is required");
    Ok(keys
        .keys()
        .map(|key| format!("restrict,command=\"{SHELL}\" ssh-ed25519 {key}\n"))
        .collect::<String>()
        .into_bytes())
}

fn command(program: &str, arguments: &[&str], deadline: Instant) -> Result<Vec<u8>> {
    let mut process = Command::new(program);
    process
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .args(arguments);
    let output = crate::process::capture(&mut process, None, 65536, deadline, || false)?;
    ensure!(
        output.status.success(),
        "native bootstrap command {program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(2048)
            .collect::<String>()
    );
    Ok(output.stdout)
}

fn lookup(database: &str, name: &str, deadline: Instant) -> Result<Option<String>> {
    let mut process = Command::new("/usr/bin/getent");
    process
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([database, name]);
    let output = crate::process::capture(&mut process, None, 4096, deadline, || false)?;
    match output.status.code() {
        Some(0) => Ok(Some(String::from_utf8(output.stdout)?)),
        Some(2) => Ok(None),
        _ => Err(anyhow!("account lookup failed")),
    }
}

fn managed_group_members(name: &str, members: &str) -> bool {
    members.is_empty() || members == name
}

fn account(name: &str, home: &str, shell: &str, deadline: Instant) -> Result<u32> {
    if lookup("group", name, deadline)?.is_none() {
        command("/usr/sbin/addgroup", &["-S", name], deadline)?;
    }
    let group =
        lookup("group", name, deadline)?.ok_or_else(|| anyhow!("system group is missing"))?;
    let group = group.trim_end_matches('\n').split(':').collect::<Vec<_>>();
    ensure!(
        group.len() == 4 && group[0] == name && managed_group_members(name, group[3]),
        "submission groups may not contain other accounts"
    );
    let gid = group[2].parse::<u32>()?;
    ensure!(gid > 0, "system group may not be root");
    if lookup("passwd", name, deadline)?.is_none() {
        command(
            "/usr/sbin/adduser",
            &["-S", "-D", "-H", "-h", home, "-s", shell, "-G", name, name],
            deadline,
        )?;
    }
    let user =
        lookup("passwd", name, deadline)?.ok_or_else(|| anyhow!("system account is missing"))?;
    let fields = user.trim_end().split(':').collect::<Vec<_>>();
    ensure!(
        fields.len() == 7
            && fields[0] == name
            && fields[2].parse::<u32>()? > 0
            && fields[3].parse::<u32>()? == gid
            && fields[5] == home
            && fields[6] == shell,
        "existing account differs from the protected native identity"
    );
    let groups = command("/usr/bin/id", &["-G", name], deadline)?;
    ensure!(
        std::str::from_utf8(&groups)?
            .split_whitespace()
            .collect::<Vec<_>>()
            == [group[2]],
        "system account has unexpected supplemental authority"
    );
    if name == "komizo-submit" {
        // BusyBox adduser -D writes '!', which Linux OpenSSH treats as an
        // account lock even for public-key authentication without PAM.
        // '*' cannot authenticate any password; the effective SSH Match also
        // requires publickey and disables password/interactive authentication.
        let mut process = Command::new("/usr/sbin/chpasswd");
        process
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8")
            .arg("-e");
        let result = crate::process::capture(
            &mut process,
            Some(b"komizo-submit:*\n"),
            4096,
            deadline,
            || false,
        )?;
        ensure!(
            result.status.success(),
            "cannot establish the fixed key-only submission identity"
        );
    }
    Ok(gid)
}

fn directory(path: &str, mode: u32) -> Result<()> {
    let path = Path::new(path);
    for parent in path.ancestors().skip(1) {
        if !parent.exists() {
            continue;
        }
        let info = fs::symlink_metadata(parent)?;
        ensure!(
            info.is_dir()
                && !info.file_type().is_symlink()
                && info.uid() == 0
                && info.mode() & 0o022 == 0,
            "bootstrap path crosses an unsafe parent"
        );
    }
    if !path.try_exists()? {
        fs::create_dir(path)
            .with_context(|| format!("create protected bootstrap directory {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| {
            format!("set protected bootstrap directory mode {}", path.display())
        })?;
    }
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir()
            && !info.file_type().is_symlink()
            && info.uid() == 0
            && info.mode() & 0o777 == mode,
        "bootstrap directory ownership or mode changed"
    );
    Ok(())
}

fn identity_directory(path: &str, uid: u32, gid: u32, mode: u32) -> Result<()> {
    let destination = Path::new(path);
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("runtime directory lacks a parent"))?;
    let info = fs::symlink_metadata(parent)?;
    ensure!(
        info.is_dir()
            && !info.file_type().is_symlink()
            && info.uid() == 0
            && info.mode() & 0o022 == 0,
        "runtime directory parent is unsafe"
    );
    if !destination.try_exists()? {
        fs::create_dir(destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(destination)?;
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
            "cannot set fixed runtime directory ownership"
        );
    }
    let info = fs::symlink_metadata(destination)?;
    ensure!(
        info.is_dir()
            && !info.file_type().is_symlink()
            && info.uid() == uid
            && info.gid() == gid
            && info.mode() & 0o7777 == mode,
        "fixed runtime directory identity changed"
    );
    Ok(())
}

pub(crate) fn proxy_identity() -> Result<(u32, u32)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let row = lookup("passwd", "komizo-proxy", deadline)?
        .ok_or_else(|| anyhow!("proxy account is missing"))?;
    let fields = row.trim_end().split(':').collect::<Vec<_>>();
    ensure!(fields.len() == 7, "invalid proxy account");
    let uid = fields[2].parse::<u32>()?;
    let gid = fields[3].parse::<u32>()?;
    ensure!(
        uid > 0 && gid > 0,
        "proxy runtime identity must be unprivileged"
    );
    ensure!(
        fields[0] == "komizo-proxy"
            && fields[5] == "/var/lib/komizo-proxy"
            && fields[6] == "/sbin/nologin",
        "proxy account differs from its fixed identity"
    );
    Ok((uid, gid))
}

pub(crate) fn runtime_directories() -> Result<()> {
    let (uid, gid) = proxy_identity()?;
    identity_directory("/var/lib/komizo-proxy", uid, gid, 0o700)?;
    identity_directory("/run/komizo-proxy", uid, gid, 0o700)?;
    directory(super::infrastructure::DIRECTORY, 0o700)?;
    let config = crate::strict::value(
        &protected_file(Path::new("/etc/komizo/controller.json"), 65536)?,
        65536,
    )?;
    ensure!(
        config["kind"] == "komizo.controller" && config["version"] == 1,
        "invalid runtime submission identity"
    );
    let submit_gid = config["submission_gid"]
        .as_u64()
        .filter(|id| *id > 0 && *id <= u32::MAX as u64)
        .ok_or_else(|| anyhow!("invalid submission group"))? as u32;
    identity_directory("/run/komizo", 0, submit_gid, 0o750)
}

pub(crate) fn protected_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "bootstrap input requires an absolute owner path"
    );
    for parent in path.ancestors().skip(1) {
        let info = fs::symlink_metadata(parent)?;
        ensure!(
            info.is_dir()
                && !info.file_type().is_symlink()
                && info.uid() == 0
                && info.mode() & 0o022 == 0,
            "bootstrap input traverses an unsafe parent"
        );
    }
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_file()
            && !info.file_type().is_symlink()
            && info.uid() == 0
            && info.nlink() == 1
            && info.mode() & 0o022 == 0
            && info.len() <= maximum as u64,
        "bootstrap input {} is not a protected ordinary file within {maximum} bytes",
        path.display()
    );
    store::read_protected(path, maximum)
}

fn managed(ledger: &mut Ledger, path: &str, body: &[u8], mode: u32) -> Result<()> {
    let exists = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if exists {
        let old = ledger
            .files
            .get(path)
            .ok_or_else(|| anyhow!("unrecorded bootstrap file cannot be replaced"))?;
        let bytes = protected_file(Path::new(path), 65536)?;
        ensure!(
            document_digest(&bytes) == old.sha256
                && fs::symlink_metadata(path)?.mode() & 0o7777 == old.mode,
            "bootstrap file differs from its recorded identity"
        );
    } else {
        ensure!(
            !ledger.files.contains_key(path),
            "recorded bootstrap file is missing"
        );
    }
    store::atomic(Path::new(path), body, mode)?;
    ledger.files.insert(
        path.into(),
        FileRecord {
            sha256: document_digest(body),
            mode,
        },
    );
    store::atomic(Path::new(LEDGER), &serde_json::to_vec(ledger)?, 0o600)
}

pub fn install(public_keys: &Path) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native bootstrap requires the local owner identity"
    );
    let keys = authorized_keys(&protected_file(public_keys, 65536)?)?;
    protected_file(Path::new(CLI), 128 << 20)?;
    proxy_guard()?;
    dns_guard()?;
    let deadline = Instant::now() + Duration::from_secs(180);
    Engine { deadline }.preflight()?;
    let capacity: Capacity = serde_json::from_value(crate::strict::value(
        &protected_file(Path::new("/etc/komizo/capacity.json"), 65536)?,
        65536,
    )?)?;
    capacity.measured()?;
    protected_file(Path::new("/etc/komizo/proxy.json"), 16384)?;
    let initial_proxy = super::proxy::globals()? + &super::render::catchall();
    for (path, mode) in [
        (CONFIG, 0o700),
        ("/etc/komizo/apps", 0o700),
        ("/etc/ssh/komizo-submit", 0o755),
        ("/var/lib/komizo", 0o700),
        (system::SERVICE_CONFIGS, 0o700),
        (super::infrastructure::DIRECTORY, 0o700),
        ("/var/lib/komizo-assets", 0o755),
        ("/etc/komizo-proxy", 0o755),
        ("/usr/local/libexec", 0o755),
        ("/usr/local/libexec/komizo-network", 0o755),
        ("/etc/containers", 0o755),
        ("/etc/apparmor.d", 0o755),
        ("/usr/share/doc", 0o755),
        ("/usr/share/doc/komizo", 0o755),
        ("/etc/containers/containers.conf.d", 0o755),
    ] {
        directory(path, mode)?;
    }
    let mut ledger: Ledger = if Path::new(LEDGER).try_exists()? {
        serde_json::from_value(crate::strict::value(
            &protected_file(Path::new(LEDGER), 65536)?,
            65536,
        )?)?
    } else {
        Ledger {
            kind: "komizo.bootstrap".into(),
            version: 1,
            files: BTreeMap::new(),
        }
    };
    ensure!(
        ledger.kind == "komizo.bootstrap" && ledger.version == 1,
        "invalid native bootstrap ownership record"
    );
    public_root_file(Path::new(APPARMOR_PARSER), 32 << 20, 0o755)?;
    managed(
        &mut ledger,
        "/usr/share/doc/komizo/apparmor-workload.LICENSE",
        APPARMOR_LICENSE,
        0o644,
    )?;
    managed(&mut ledger, APPARMOR_FILE, APPARMOR_POLICY, 0o644)?;
    command(APPARMOR_PARSER, &["-r", APPARMOR_FILE], deadline)?;
    managed(&mut ledger, DNS_HELPER, DNS_WRAPPER.as_bytes(), 0o755)?;
    managed(&mut ledger, ENGINE_CONFIG, ENGINE_NETWORK.as_bytes(), 0o644)?;
    apparmor_guard()?;
    managed(&mut ledger, SHELL, SUBMISSION_SHELL.as_bytes(), 0o755)?;
    let gid = account("komizo-submit", "/nonexistent", SHELL, deadline)?;
    account(
        "komizo-proxy",
        "/var/lib/komizo-proxy",
        "/sbin/nologin",
        deadline,
    )?;
    managed(&mut ledger, KEYS, &keys, 0o644)?;
    managed(
        &mut ledger,
        "/etc/komizo/controller.json",
        &serde_json::to_vec(
            &serde_json::json!({"kind":"komizo.controller","version":1,"submission_gid":gid}),
        )?,
        0o600,
    )?;
    managed(
        &mut ledger,
        "/etc/ssh/sshd_config.d/80-komizo-submit.conf",
        SSH_CONFIG.as_bytes(),
        0o600,
    )?;
    managed(
        &mut ledger,
        INFRASTRUCTURE_PROFILE,
        INFRASTRUCTURE_POLICY,
        0o644,
    )?;
    command(APPARMOR_PARSER, &["-r", INFRASTRUCTURE_PROFILE], deadline)?;
    for role in [
        super::infrastructure::Role::Controller,
        super::infrastructure::Role::Proxy,
        super::infrastructure::Role::Dns,
        super::infrastructure::Role::Expiry,
    ] {
        managed(
            &mut ledger,
            &format!("/etc/init.d/{}", role.service()),
            super::infrastructure::service_script(role).as_bytes(),
            0o755,
        )?;
    }
    let state = Store::new(Path::new("/var/lib/komizo").into())?;
    if Path::new(system::PROXY_CONFIG).try_exists()? {
        let hash = document_digest(&protected_file(Path::new(system::PROXY_CONFIG), 1 << 20)?);
        system::verify_unit(
            &state,
            Path::new(system::PROXY_CONFIG),
            "platform",
            "proxy",
            &hash,
        )?;
    } else {
        system::install(
            &state,
            Path::new(system::PROXY_CONFIG),
            "platform",
            "proxy",
            initial_proxy.as_bytes(),
        )?;
    }
    system::caddy_validate(Path::new(system::PROXY_CONFIG), deadline)?;
    command("/usr/sbin/sshd", &["-t"], deadline)?;
    submission_settings(&command(
        "/usr/sbin/sshd",
        &[
            "-T",
            "-C",
            "user=komizo-submit,host=localhost,addr=127.0.0.1",
        ],
        deadline,
    )?)?;
    let system = System { deadline };
    system::host_pools(&state, &system, &capacity)?;
    infrastructure_files_guard()?;
    for role in [
        super::infrastructure::Role::Proxy,
        super::infrastructure::Role::Controller,
        super::infrastructure::Role::Expiry,
    ] {
        command(
            "/sbin/rc-update",
            &["add", role.service(), "default"],
            deadline,
        )?;
        super::infrastructure::start(role, deadline)?;
    }
    command("/sbin/rc-service", &["sshd", "reload"], deadline)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn managed_group_members_accept_only_empty_or_the_exact_account() {
        let name = "komizo-submit";
        assert!(super::managed_group_members(name, ""));
        assert!(super::managed_group_members(name, name));
        for members in [
            "foreign",
            "komizo-submit,foreign",
            "komizo-submit,komizo-submit",
            "komizo-submit,",
            " komizo-submit",
            "komizo-submit ",
        ] {
            assert!(!super::managed_group_members(name, members));
        }
    }
    use super::*;
    fn key(byte: u8) -> String {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend([byte; 32]);
        format!("ssh-ed25519 {} harmless comment\n", STANDARD.encode(blob))
    }
    #[test]
    fn ssh_submission_requires_effective_match_settings_not_only_valid_syntax() {
        let valid = b"authenticationmethods publickey\nauthorizedkeysfile /etc/ssh/komizo-submit/authorized_keys\npasswordauthentication no\nkbdinteractiveauthentication no\npermittty no\ndisableforwarding yes\nallowagentforwarding no\nallowtcpforwarding no\nx11forwarding no\npermittunnel no\npermituserrc no\nforcecommand /usr/local/libexec/komizo-submit-shell\n";
        submission_settings(valid).unwrap();
        assert!(submission_settings(b"").is_err());
        let text = std::str::from_utf8(valid).unwrap();
        assert!(
            submission_settings(
                text.replace("disableforwarding yes", "disableforwarding no")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            submission_settings(
                text.replace(
                    "forcecommand /usr/local/libexec/komizo-submit-shell",
                    "forcecommand none"
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(
            submission_settings(
                format!("{text}forcecommand /usr/local/libexec/komizo-submit-shell\n").as_bytes()
            )
            .is_err()
        );
    }
    #[test]
    fn root_profile_configuration_is_literal_and_case_ambiguity_is_refused() {
        let configuration: toml::Value = toml::from_str(ENGINE_NETWORK).unwrap();
        assert_eq!(
            configuration["network"]["network_backend"].as_str(),
            Some("netavark")
        );
        assert_eq!(
            configuration["network"]["firewall_driver"].as_str(),
            Some("nftables")
        );
        assert_eq!(
            configured_profile(ENGINE_NETWORK.as_bytes())
                .unwrap()
                .as_deref(),
            Some(WORKLOAD_PROFILE)
        );
        assert_eq!(
            configured_profile(b"[engine]\nnetwork_cmd_path='/usr/bin/pasta'\n").unwrap(),
            None
        );
        assert_eq!(
            configured_profile(b"[Containers]\nAppArmor_Profile='komizo-workload'\n")
                .unwrap()
                .as_deref(),
            Some(WORKLOAD_PROFILE)
        );
        for invalid in [
            "[containers]\napparmor_profile=false",
            "[containers]\napparmor_profile='one'\nAppArmor_Profile='two'",
            "[containers]\napparmor_profile='one'\n[CONTAINERS]\napparmor_profile='two'",
            "[containers]\napparmor_profile=['invalid']",
            "malformed secret-value",
        ] {
            let error = configured_profile(invalid.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret-value"));
        }
    }

    #[test]
    fn workload_profile_requires_enforcement_and_only_the_reviewed_stacked_peer() {
        enforcing_profile("Y\n", "distro (enforce)\nkomizo-workload (enforce)\n").unwrap();
        for (enabled, profiles) in [
            ("N", "komizo-workload (enforce)"),
            ("Y", "komizo-workload (complain)"),
            ("Y", "other (enforce)"),
            ("Y", "komizo-workload (enforce)\nkomizo-workload (enforce)"),
        ] {
            assert!(enforcing_profile(enabled, profiles).is_err());
        }
        let profile = std::str::from_utf8(APPARMOR_POLICY).unwrap();
        assert!(profile.contains("signal (send,receive) peer=crun//&komizo-workload,"));
        assert!(!profile.contains("peer=komizo-workload//&*"));
        for denied in [
            "deny mount,",
            "deny @{PROC}/kcore rwklx,",
            "deny /sys/kernel/security/** rwklx,",
        ] {
            assert!(profile.contains(denied));
        }
        assert_eq!(
            profile
                .lines()
                .filter(|line| line.contains("signal (send,receive)"))
                .count(),
            2
        );
    }

    #[test]
    fn keys_are_forced_restricted_and_do_not_preserve_source_options() {
        let value = String::from_utf8(authorized_keys(key(1).as_bytes()).unwrap()).unwrap();
        assert!(value.starts_with(
            "restrict,command=\"/usr/local/libexec/komizo-submit-shell\" ssh-ed25519 "
        ));
        assert!(!value.contains("harmless"));
        for invalid in [
            String::new(),
            "ssh-ed25519 broken".into(),
            format!("command=\"/bin/sh\" {}", key(1)),
            format!("{}{}", key(1), key(1)),
            key(1).replace('\n', "\r\n"),
        ] {
            assert!(authorized_keys(invalid.as_bytes()).is_err());
        }
    }
    #[test]
    fn dns_helper_cannot_select_another_program_path_port_or_mode() {
        let valid = ["--config", DNS_CONFIG, "-p", "53", "run"]
            .map(str::to_owned)
            .to_vec();
        assert!(dns_arguments(&valid).is_ok());
        for (index, replacement) in [
            (0, "--shell"),
            (1, "/tmp/foreign"),
            (1, "/run/user/1000/aardvark-dns"),
            (3, "5353"),
            (4, "version"),
        ] {
            let mut invalid = valid.clone();
            invalid[index] = replacement.into();
            assert!(dns_arguments(&invalid).is_err());
        }
        let mut extra = valid.clone();
        extra.push("/bin/sh".into());
        assert!(dns_arguments(&extra).is_err());
        assert!(dns_arguments(&[]).is_err());
        let script =
            super::super::infrastructure::service_script(super::super::infrastructure::Role::Dns);
        assert!(!script.contains("need komizo-controller"));
        assert!(!script.contains("rc-update"));
    }

    #[test]
    fn infrastructure_profiles_allow_only_the_two_fixed_daemons_and_owned_writes() {
        let text = std::str::from_utf8(INFRASTRUCTURE_POLICY).unwrap();
        for profile in ["profile komizo-proxy", "profile komizo-dns"] {
            assert!(text.contains(profile));
        }
        for denied in [
            "deny /etc/komizo/** rwklx",
            "deny /var/lib/komizo/** rwklx",
            "deny /root/** rwklx",
            "deny /var/lib/containers/** rwklx",
            "deny mount",
        ] {
            assert_eq!(text.matches(denied).count(), 2);
        }
        assert!(text.contains("owner /var/lib/komizo-proxy/** rwk"));
        assert!(text.contains("owner /run/containers/networks/aardvark-dns/** rwk"));
        let (proxy, dns) = text.split_once("profile komizo-dns").unwrap();
        for rule in [
            "/usr/share/ca-certificates/ r,",
            "/usr/share/ca-certificates/** r,",
        ] {
            assert!(proxy.lines().any(|line| line.trim() == rule));
        }
        assert!(!dns.contains("/usr/share/ca-certificates"));
        assert!(!text.contains("capability,"));
        assert!(!text.contains("file,"));
        assert!(!text.contains("#include <abstractions/base>"));
        assert!(!text.contains(".Private/**"));
        assert!(!text.contains("ptrace (trace)"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_filter_denies_foreign_abi_namespaces_and_executable_writable_memory() {
        // Evaluate the actual shipped cBPF instructions on synthetic seccomp
        // metadata; no filter is installed in the test runner.
        fn evaluate(nr: u32, arch: u32, args: [u64; 6]) -> u32 {
            let mut data = Vec::from(nr.to_ne_bytes());
            data.extend(arch.to_ne_bytes());
            data.extend(0u64.to_ne_bytes());
            for argument in args {
                data.extend(argument.to_ne_bytes());
            }
            let code = confinement_filter();
            let (mut pc, mut accumulator) = (0usize, 0u32);
            for _ in 0..256 {
                let instruction = &code[pc];
                match instruction.code {
                    0x20 => {
                        accumulator = u32::from_ne_bytes(
                            data[instruction.k as usize..instruction.k as usize + 4]
                                .try_into()
                                .unwrap(),
                        );
                        pc += 1;
                    }
                    0x15 => {
                        pc += 1 + usize::from(if accumulator == instruction.k {
                            instruction.jt
                        } else {
                            instruction.jf
                        })
                    }
                    0x45 => {
                        pc += 1 + usize::from(if accumulator & instruction.k != 0 {
                            instruction.jt
                        } else {
                            instruction.jf
                        })
                    }
                    0x54 => {
                        accumulator &= instruction.k;
                        pc += 1;
                    }
                    0x06 => return instruction.k,
                    other => panic!("unexpected shipped filter opcode {other}"),
                }
            }
            panic!("non-terminating sandbox filter")
        }
        #[cfg(target_arch = "x86_64")]
        const ARCH: u32 = 0xc000_003e;
        #[cfg(target_arch = "aarch64")]
        const ARCH: u32 = 0xc000_00b7;
        let allowed = 0x7fff_0000;
        let denied = 0x0005_0000 | libc::EPERM as u32;
        assert_eq!(evaluate(libc::SYS_read as u32, ARCH, [0; 6]), allowed);
        assert_eq!(evaluate(libc::SYS_read as u32, 0, [0; 6]), 0x8000_0000);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            evaluate(libc::SYS_read as u32 | 0x4000_0000, ARCH, [0; 6]),
            0x8000_0000
        );
        for nr in [
            libc::SYS_mount,
            libc::SYS_ptrace,
            libc::SYS_personality,
            libc::SYS_setns,
        ] {
            assert_eq!(evaluate(nr as u32, ARCH, [0; 6]), denied);
        }
        assert_eq!(
            evaluate(
                libc::SYS_clone as u32,
                ARCH,
                [libc::CLONE_NEWUSER as u64, 0, 0, 0, 0, 0]
            ),
            denied
        );
        assert_eq!(
            evaluate(
                libc::SYS_clone as u32,
                ARCH,
                [libc::CLONE_THREAD as u64, 0, 0, 0, 0, 0]
            ),
            allowed
        );
        assert_eq!(
            evaluate(libc::SYS_clone3 as u32, ARCH, [0; 6]),
            0x0005_0000 | libc::ENOSYS as u32
        );
        for nr in [libc::SYS_mprotect, libc::SYS_pkey_mprotect] {
            assert_eq!(
                evaluate(nr as u32, ARCH, [0, 0, libc::PROT_EXEC as u64, 0, 0, 0]),
                denied
            );
            assert_eq!(
                evaluate(nr as u32, ARCH, [0, 0, libc::PROT_READ as u64, 0, 0, 0]),
                allowed
            );
        }
        assert_eq!(
            evaluate(
                libc::SYS_mmap as u32,
                ARCH,
                [0, 0, (libc::PROT_WRITE | libc::PROT_EXEC) as u64, 0, 0, 0]
            ),
            denied
        );
        assert_eq!(
            evaluate(
                libc::SYS_mmap as u32,
                ARCH,
                [0, 0, (libc::PROT_READ | libc::PROT_EXEC) as u64, 0, 0, 0]
            ),
            allowed
        );
    }

    #[test]
    fn proxy_receipt_binds_the_closed_native_source_and_compiler_identity() {
        let receipt = serde_json::json!({
            "kind":"komizo.proxy-build","version":1,"tools_revision":"a".repeat(40),
            "platform":"linux/amd64","go_version":"1.27.4","caddy_version":"2.11.6",
            "source_sha256":{"caddy.go.mod":format!("sha256:{}","b".repeat(64)),
                "caddy.go.sum":format!("sha256:{}","c".repeat(64)),
                "caddy-build.sh":format!("sha256:{}","d".repeat(64))},
            "binary_sha256":format!("sha256:{}","e".repeat(64))
        });
        assert_eq!(
            proxy_build(&serde_json::to_vec(&receipt).unwrap(), "linux/amd64").unwrap(),
            receipt["binary_sha256"].as_str().unwrap()
        );
        for (field, replacement) in [
            ("tools_revision", serde_json::json!("short")),
            ("platform", serde_json::json!("linux/arm64")),
            ("go_version", serde_json::json!("1.26.0")),
            ("caddy_version", serde_json::json!("2.11.5")),
            ("binary_sha256", serde_json::json!("e".repeat(64))),
            (
                "source_sha256",
                serde_json::json!({"unexpected":"sha256:bad"}),
            ),
        ] {
            let mut changed = receipt.clone();
            changed[field] = replacement;
            assert!(proxy_build(&serde_json::to_vec(&changed).unwrap(), "linux/amd64").is_err());
        }
    }
}
