//! Install the native host boundary from explicit owner-provided keys and capacity.
use super::{
    capacity::Capacity,
    engine::Engine,
    store::{self, Store},
    system::{self, System},
    validation::document_digest,
};
use anyhow::{Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub const CONTROLLER: &str = "komizo-controller.service";
pub const PROXY: &str = "komizo-proxy.service";
const SHELL: &str = "/usr/local/libexec/komizo-submit-shell";
const CONFIG: &str = "/etc/komizo";
const LEDGER: &str = "/etc/komizo/bootstrap.json";
const KEYS: &str = "/etc/ssh/komizo-submit/authorized_keys";
const CLI: &str = "/usr/local/bin/komizo-box";

const SUBMISSION_SHELL: &str = r#"#!/bin/sh
# OpenSSH invokes this root-owned account shell with its fixed forced command.
set -eu
[ "$#" -eq 2 ] && [ "$1" = -c ] && [ "$2" = /usr/local/libexec/komizo-submit-shell ] || exit 126
[ "${SSH_ORIGINAL_COMMAND:-}" = 'komizo-box submit' ] || exit 126
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/local/bin/komizo-box submit
"#;

const SSH_CONFIG: &str = "# Managed native submission boundary. Owner root SSH remains separate.\nMatch User komizo-submit\n    AuthenticationMethods publickey\n    AuthorizedKeysFile /etc/ssh/komizo-submit/authorized_keys\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PermitTTY no\n    DisableForwarding yes\n    AllowAgentForwarding no\n    AllowTcpForwarding no\n    X11Forwarding no\n    PermitTunnel no\n    PermitUserEnvironment no\n    ForceCommand /usr/local/libexec/komizo-submit-shell\nMatch all\n";

pub fn controller_unit() -> &'static str {
    "[Unit]\nDescription=Komizo native controller\nWants=network-online.target komizo-proxy.service\nAfter=network-online.target komizo-proxy.service\nRequiresMountsFor=/var/lib/komizo /var/lib/containers\nStartLimitIntervalSec=60\nStartLimitBurst=5\n[Service]\nType=notify\nNotifyAccess=main\nUser=root\nGroup=root\nUMask=0077\nWorkingDirectory=/var/lib/komizo\nEnvironment=HOME=/root\nEnvironment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nExecStart=/usr/local/bin/komizo-box daemon\nRestart=on-failure\nRestartSec=2\nTimeoutStartSec=120\nTimeoutStopSec=30\nKillMode=process\nSlice=komizo-control.slice\nDelegate=yes\n[Install]\nWantedBy=multi-user.target\n"
}

pub fn proxy_unit() -> &'static str {
    "[Unit]\nDescription=Komizo public ingress\nWants=network-online.target\nAfter=network-online.target\nRequiresMountsFor=/var/lib/komizo-assets /var/lib/komizo-proxy\n[Service]\nType=notify\nNotifyAccess=main\nUser=komizo-proxy\nGroup=komizo-proxy\nUMask=0077\nWorkingDirectory=/var/lib/komizo-proxy\nStateDirectory=komizo-proxy\nStateDirectoryMode=0700\nRuntimeDirectory=komizo-proxy\nRuntimeDirectoryMode=0700\nEnvironment=XDG_DATA_HOME=/var/lib/komizo-proxy/data\nEnvironment=XDG_CONFIG_HOME=/var/lib/komizo-proxy/config\nExecStart=/usr/local/bin/caddy run --config /etc/komizo-proxy/Caddyfile --adapter caddyfile\nExecReload=/usr/local/bin/caddy reload --config /etc/komizo-proxy/Caddyfile --adapter caddyfile --address unix//run/komizo-proxy/admin.sock\nRestart=on-failure\nRestartSec=2\nTimeoutStopSec=10\nSlice=komizo-proxy.slice\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nReadOnlyPaths=/var/lib/komizo-assets /etc/komizo-proxy\nInaccessiblePaths=/var/lib/komizo /etc/komizo /run/komizo\n[Install]\nWantedBy=multi-user.target\n"
}

const EXPIRE_SERVICE: &str = "[Unit]\nDescription=Expire recorded Komizo previews\nWants=komizo-controller.service\nAfter=komizo-controller.service\n[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0077\nExecStart=/usr/local/bin/komizo-box expire\nTimeoutStartSec=1500\nSlice=komizo-control.slice\n";
const EXPIRE_TIMER: &str = "[Unit]\nDescription=Check protected preview expiry\n[Timer]\nOnBootSec=60\nOnUnitActiveSec=60\nAccuracySec=1\n[Install]\nWantedBy=timers.target\n";
const TMPFILES: &[u8] = b"d /run/komizo 0750 root komizo-submit -\n";

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
    ensure!(output.status.success(), "native bootstrap command failed");
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

fn account(name: &str, home: &str, shell: &str, deadline: Instant) -> Result<u32> {
    if lookup("group", name, deadline)?.is_none() {
        command("/usr/sbin/groupadd", &["--system", name], deadline)?;
    }
    let group =
        lookup("group", name, deadline)?.ok_or_else(|| anyhow!("system group is missing"))?;
    let group = group.trim_end().split(':').collect::<Vec<_>>();
    ensure!(
        group.len() == 4 && group[0] == name && group[3].is_empty(),
        "submission groups may not contain other accounts"
    );
    let gid = group[2].parse::<u32>()?;
    ensure!(gid > 0, "system group may not be root");
    if lookup("passwd", name, deadline)?.is_none() {
        command(
            "/usr/sbin/useradd",
            &[
                "--system",
                "--no-create-home",
                "--home-dir",
                home,
                "--shell",
                shell,
                "--gid",
                name,
                "--password",
                "*",
                name,
            ],
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
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
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

fn protected_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
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
    if Path::new(path).try_exists()? {
        let old = ledger
            .files
            .get(path)
            .ok_or_else(|| anyhow!("unrecorded bootstrap file cannot be replaced"))?;
        let bytes = protected_file(Path::new(path), 65536)?;
        ensure!(
            document_digest(&bytes) == old.sha256
                && fs::symlink_metadata(path)?.mode() & 0o777 == old.mode,
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
    protected_file(Path::new("/usr/local/bin/caddy"), 128 << 20)?;
    let deadline = Instant::now() + Duration::from_secs(180);
    Engine { deadline }.preflight()?;
    let version = command("/usr/local/bin/caddy", &["version"], deadline)?;
    ensure!(
        std::str::from_utf8(&version)?.split_whitespace().next() == Some("v2.11.6"),
        "native proxy requires the reviewed Caddy version"
    );
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
        ("/run/komizo", 0o750),
        ("/var/lib/komizo-assets", 0o755),
        ("/etc/komizo-proxy", 0o755),
        ("/usr/local/libexec", 0o755),
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
    managed(&mut ledger, SHELL, SUBMISSION_SHELL.as_bytes(), 0o755)?;
    let gid = account("komizo-submit", "/nonexistent", SHELL, deadline)?;
    account(
        "komizo-proxy",
        "/var/lib/komizo-proxy",
        "/usr/sbin/nologin",
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
    managed(&mut ledger, "/etc/tmpfiles.d/komizo.conf", TMPFILES, 0o644)?;
    for (name, body) in [
        (CONTROLLER, controller_unit()),
        (PROXY, proxy_unit()),
        ("komizo-expire.service", EXPIRE_SERVICE),
        ("komizo-expire.timer", EXPIRE_TIMER),
    ] {
        managed(
            &mut ledger,
            &format!("{}/{name}", system::UNITS),
            body.as_bytes(),
            0o644,
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
    let system = System { deadline };
    system::host_pools(&state, &system, &capacity)?;
    system.run(&["enable", CONTROLLER, PROXY, "komizo-expire.timer"])?;
    system.start(PROXY)?;
    system.start(CONTROLLER)?;
    system.start("komizo-expire.timer")?;
    system.run(&["reload", "ssh.service"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(byte: u8) -> String {
        let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        blob.extend([byte; 32]);
        format!("ssh-ed25519 {} harmless comment\n", STANDARD.encode(blob))
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
    fn proxy_has_read_only_public_access_and_no_controller_authority() {
        for value in [
            "User=komizo-proxy",
            "ProtectSystem=strict",
            "ReadOnlyPaths=/var/lib/komizo-assets",
            "InaccessiblePaths=/var/lib/komizo /etc/komizo /run/komizo",
            "RuntimeDirectoryMode=0700",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "Slice=komizo-proxy.slice",
        ] {
            assert!(proxy_unit().contains(value));
        }
        assert!(!proxy_unit().contains("Requires=komizo-controller"));
        assert!(controller_unit().contains("Type=notify"));
        assert!(controller_unit().contains("KillMode=process"));
        assert!(controller_unit().contains("Slice=komizo-control.slice"));
    }
}
