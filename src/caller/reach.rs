use super::{transport::Remote, validate};
use crate::workload::activation::Context;
use anyhow::{Result, ensure};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ok,
    UnknownHost,
    ChangedHost,
    Auth,
    Network,
    Other,
}
pub fn classify(raw: &str) -> Kind {
    let low = raw.to_lowercase();
    if low.contains("remote host identification has changed")
        || (low.contains("host key for") && low.contains("changed"))
    {
        Kind::ChangedHost
    } else if [
        "host key verification failed",
        "no matching host key",
        "key is not known",
    ]
    .iter()
    .any(|s| low.contains(s))
    {
        Kind::UnknownHost
    } else if ["permission denied", "too many authentication failures"]
        .iter()
        .any(|s| low.contains(s))
    {
        Kind::Auth
    } else if [
        "could not resolve",
        "connection refused",
        "connection timed out",
        "no route to host",
        "network is unreachable",
        "operation timed out",
    ]
    .iter()
    .any(|s| low.contains(s))
    {
        Kind::Network
    } else {
        Kind::Other
    }
}
fn indent(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        value
            .split('\n')
            .map(|line| format!("    {line}\n"))
            .collect()
    }
}
pub fn explain(kind: Kind, remote: &Remote, raw: &str) -> anyhow::Error {
    let target = &remote.target;
    let host = &target.host;
    let addr = target.addr();
    let detail = indent(&validate::scrub(raw));
    anyhow::anyhow!(match kind {
        Kind::UnknownHost => format!(
            "{host} is a host this machine has never connected to.\n\n    Its key is not in ~/.ssh/known_hosts, so ssh refuses to continue --\n    nothing is wrong with your key or the server. Meet it once:\n\n        ssh {addr}\n\n    Check the fingerprint it shows against your provider's console, accept,\n    then run this again. Or let komizo do it: --accept-host-key"
        ),
        Kind::ChangedHost => format!(
            "the host key for {host} has CHANGED since you last connected.\n\n    Either the server was rebuilt, or something is impersonating it.\n    komizo will not connect either way. If you rebuilt it deliberately:\n\n        ssh-keygen -R {host}\n\n    If you did not, stop and find out why before going further.\n\n{detail}"
        ),
        Kind::Auth => format!(
            "{addr} refused the key.\n\n    komizo needs an existing password-less login to work from; it does not\n    create your access, only the deploy account's. If you normally type a\n    password:\n\n        ssh-copy-id {addr}\n\n{detail}"
        ),
        Kind::Network => format!("cannot reach {host}.\n\n{detail}"),
        _ => format!("could not connect to {addr}.\n\n{detail}"),
    })
}
pub fn probe(ctx: &Context, remote: &Remote) -> Result<(Kind, String)> {
    let result = crate::process::capture(
        &mut remote.command("true"),
        None,
        4096,
        ctx.deadline,
        || ctx.check().is_err(),
    )?;
    if result.status.success() {
        Ok((Kind::Ok, String::new()))
    } else {
        let raw = String::from_utf8_lossy(&result.stderr).trim().to_string();
        Ok((classify(&raw), raw))
    }
}
pub fn write_known_hosts(home: &Path, scan: &[u8]) -> Result<PathBuf> {
    use std::io::Read;
    let directory = home.join(".ssh");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let path = directory.join("known_hosts");
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 16 << 20,
        "known_hosts must be a bounded regular file"
    );
    let mut existing = String::new();
    std::io::Read::by_ref(&mut file)
        .take(16 << 20)
        .read_to_string(&mut existing)?;
    let mut seen = existing
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect::<std::collections::BTreeSet<_>>();
    let mut add = String::new();
    for line in String::from_utf8_lossy(scan).lines().map(str::trim) {
        if !line.is_empty() && !line.starts_with('#') && seen.insert(line.to_string()) {
            add.push_str(line);
            add.push('\n');
        }
    }
    if !add.is_empty() {
        file.write_all(add.as_bytes())?;
        file.sync_all()?;
    }
    Ok(path)
}
pub fn ensure_reachable(
    ctx: &Context,
    remote: &Remote,
    accept: bool,
    progress: &mut dyn Write,
) -> Result<()> {
    let (kind, raw) = probe(ctx, remote)?;
    if kind == Kind::Ok {
        return Ok(());
    }
    if kind != Kind::UnknownHost || !accept {
        return Err(explain(kind, remote, &raw));
    }
    let mut command = Command::new("ssh-keyscan");
    command.args(["-T", "5"]);
    if remote.target.port != 22 {
        command.args(["-p", &remote.target.port.to_string()]);
    }
    command.arg(&remote.target.host);
    let result = crate::process::capture(
        &mut command,
        None,
        1 << 20,
        ctx.deadline.min(Instant::now() + Duration::from_secs(10)),
        || ctx.check().is_err(),
    )?;
    ensure!(
        result.status.success() && !crate::wire::trim_space(&result.stdout).is_empty(),
        "could not reach {} to read its host key",
        remote.target.host
    );
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    let path = write_known_hosts(&home, &result.stdout)?;
    writeln!(
        progress,
        "    added {} to {}",
        remote.target.host,
        path.display()
    )?;
    writeln!(
        progress,
        "warning: accepted {}'s host key without verification (--accept-host-key);\n    it came from the network, not the server's console -- trust the network accordingly",
        remote.target.host
    )?;
    let (kind, raw) = probe(ctx, remote)?;
    ensure!(kind == Kind::Ok, "{}", explain(kind, remote, &raw));
    Ok(())
}
pub fn box_command(args: &[String]) -> String {
    format!(
        "/usr/local/bin/komizo-box {}",
        args.iter()
            .map(|arg| crate::scripts::sh_quote(arg))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
impl Remote {
    pub fn ask_box(&self, ctx: &Context, args: &[String]) -> Result<Vec<u8>> {
        let result = crate::process::capture(
            &mut self.command(&box_command(args)),
            None,
            16 << 20,
            ctx.deadline,
            || ctx.check().is_err(),
        )?;
        if result.status.code() == Some(127) {
            anyhow::bail!(
                "{} has no komizo agent installed.\n\n    komizo setup --host {}\n\n    That installs /usr/local/bin/komizo-box, which is how komizo reads a server.",
                self.target.host,
                self.target.host
            );
        }
        if !result.status.success() {
            let message = String::from_utf8_lossy(&result.stderr);
            let last = message
                .trim()
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .trim();
            if !last.is_empty() {
                anyhow::bail!("{}: {}", self.target.host, validate::scrub(last));
            }
            anyhow::bail!("{}: {}", self.target.host, result.status);
        }
        Ok(crate::wire::trim_space(&result.stdout).to_vec())
    }
    pub fn fetch<T: crate::host::store::Document>(
        &self,
        ctx: &Context,
        args: &[String],
    ) -> Result<T> {
        crate::host::store::decode(&self.ask_box(ctx, args)?)
            .map_err(|e| anyhow::anyhow!("could not read what {} reported: {e}", self.target.host))
    }
    pub fn journey(&self, ctx: &Context, args: &[String], body: &[u8]) -> Result<Vec<u8>> {
        let duration = if args.get(1).is_some_and(|s| s == "activation-wait") {
            Duration::from_secs(26 * 60)
        } else {
            Duration::from_secs(120)
        };
        let ctx = crate::runtime::bounded(ctx, duration);
        let result = crate::process::capture(
            &mut self.command(&box_command(args)),
            Some(body),
            4 << 20,
            ctx.deadline,
            || ctx.check().is_err(),
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "host operation refused or transport interrupted; inspect current state"
            )
        })?;
        if !result.status.success() {
            if args.get(1).is_some_and(|s| s == "policy-bootstrap") && !result.stderr.is_empty() {
                anyhow::bail!(
                    "host policy bootstrap refused: {}",
                    String::from_utf8_lossy(&result.stderr[..result.stderr.len().min(2048)]).trim()
                );
            }
            anyhow::bail!("host operation refused or transport interrupted; inspect current state");
        }
        Ok(result.stdout)
    }
}
