//! System OpenSSH retains configured users, jump hosts and authentication.
use super::validate;
use crate::{flags::Flags, host::authority::quote, workload::activation::Context};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[derive(Clone, Debug)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: i64,
    pub port_explicit: bool,
    pub aliases: Vec<String>,
}
impl Target {
    pub fn parse(raw: &str) -> Result<Self> {
        let (user, host) = raw.split_once('@').unwrap_or(("root", raw));
        ensure!(!host.is_empty(), "no hostname in {}", quote(raw));
        validate::login_user(user)?;
        Ok(Self {
            user: user.into(),
            host: host.into(),
            port: 22,
            port_explicit: false,
            aliases: vec![],
        })
    }
    pub fn resolve(flags: &Flags, ctx: &Context) -> Result<Self> {
        let host = flags.text("host");
        ensure!(
            !host.is_empty(),
            "--host is required, e.g. --host root@myapp.example.com"
        );
        let mut target = Self::parse(host)?;
        let port = flags.integer("port");
        ensure!(
            (1..=65535).contains(&port),
            "--port must be 1-65535, got {port}"
        );
        target.port = port;
        target.port_explicit = flags.seen.contains("port");
        validate::host(&target.host)?;
        if !target.port_explicit {
            let mut command = Command::new("ssh");
            command.args(["-G", &target.addr()]);
            if let Ok(output) = crate::process::capture(
                &mut command,
                None,
                1 << 20,
                ctx.deadline.min(Instant::now() + Duration::from_secs(10)),
                || ctx.check().is_err(),
            ) && output.status.success()
            {
                target.resolve_port_from_output(&String::from_utf8_lossy(&output.stdout));
            }
        }
        Ok(target)
    }
    pub fn resolve_port_from_output(&mut self, output: &str) {
        if self.port_explicit {
            return;
        }
        for line in output.lines() {
            if let Some(value) = line.strip_prefix("port ") {
                if let Ok(port) = value.trim().parse::<i64>()
                    && port > 0
                {
                    self.port = port;
                }
                return;
            }
        }
    }
    pub fn addr(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }
    pub fn display(&self) -> String {
        if self.port == 22 {
            self.addr()
        } else {
            format!("{}:{}", self.addr(), self.port)
        }
    }
    pub fn host_display(&self) -> String {
        if self.port == 22 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
    pub fn known_host_name(&self, host: &str) -> String {
        if self.port == 22 {
            host.into()
        } else {
            format!("[{host}]:{}", self.port)
        }
    }
    pub fn known_hosts_names(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        std::iter::once(&self.host)
            .chain(self.aliases.iter())
            .filter(|host| !host.is_empty() && seen.insert((*host).clone()))
            .map(|host| self.known_host_name(host))
            .collect()
    }
    pub fn known_hosts(&self, keys: &[(String, String)]) -> String {
        self.known_hosts_names()
            .iter()
            .flat_map(|host| {
                keys.iter()
                    .map(move |(kind, key)| format!("{host} {kind} {key}"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    pub fn ssh_args(&self, control: Option<&str>, extra: &[String]) -> Vec<String> {
        let mut args = vec![];
        for option in [
            "BatchMode=yes",
            "ConnectTimeout=10",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "UpdateHostKeys=no",
            "ServerAliveInterval=5",
            "ServerAliveCountMax=3",
        ] {
            args.extend(["-o".into(), option.into()]);
        }
        if let Some(path) = control {
            args.extend([
                "-o".into(),
                "ControlMaster=auto".into(),
                "-o".into(),
                format!("ControlPath={path}"),
                "-o".into(),
                "ControlPersist=60s".into(),
            ]);
        } else {
            args.extend([
                "-o".into(),
                "ControlMaster=no".into(),
                "-o".into(),
                "ControlPath=none".into(),
            ]);
        }
        if self.port_explicit {
            args.extend(["-p".into(), self.port.to_string()]);
        }
        args.push(self.addr());
        args.extend_from_slice(extra);
        args
    }
}
pub fn multiplex_socket_path(directory: &Path) -> Option<PathBuf> {
    let path = directory.join("komizo-%C");
    (path.as_os_str().as_encoded_bytes().len() + 38 + 24 < 104).then_some(path)
}
pub fn control_path(home: &Path) -> Option<PathBuf> {
    let directory = home.join(".ssh");
    let path = multiplex_socket_path(&directory)?;
    std::fs::create_dir_all(&directory).ok()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&directory)
        .ok()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .ok()?;
    Some(path)
}
pub fn env_prefix(environment: &BTreeMap<String, String>) -> Result<String> {
    let mut output = String::new();
    for (name, value) in environment {
        ensure!(
            !name.is_empty()
                && (name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'))
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid remote environment name"
        );
        output.push_str(name);
        output.push('=');
        output.push_str(&crate::scripts::sh_quote(value));
        output.push(' ');
    }
    Ok(output)
}
pub struct Remote {
    pub target: Target,
    pub program: PathBuf,
    pub control: Option<PathBuf>,
}
pub struct Heard {
    pub stdout: bool,
    pub stderr: bool,
    pub result: Result<()>,
}
struct Watching<'a> {
    output: &'a mut dyn Write,
    heard: bool,
}
impl Write for Watching<'_> {
    fn write(&mut self, body: &[u8]) -> io::Result<usize> {
        if !body.is_empty() {
            self.heard = true;
        }
        self.output.write(body)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
impl Remote {
    pub fn new(target: Target) -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Self {
            target,
            program: "ssh".into(),
            control: home.as_deref().and_then(control_path),
        }
    }
    pub fn command(&self, remote: &str) -> Command {
        let mut command = Command::new(&self.program);
        command.args(self.target.ssh_args(
            self.control.as_deref().and_then(Path::to_str),
            &[remote.into()],
        ));
        command
    }
    pub fn capture(
        &self,
        ctx: &Context,
        remote: &str,
        input: Option<&[u8]>,
        maximum: usize,
    ) -> Result<Vec<u8>> {
        let result = crate::process::capture(
            &mut self.command(remote),
            input,
            maximum,
            ctx.deadline,
            || ctx.check().is_err(),
        )?;
        ensure!(
            result.status.success(),
            "SSH {}: {}",
            result.status,
            validate::scrub(String::from_utf8_lossy(&result.stderr).trim())
        );
        Ok(result.stdout)
    }
    pub fn quiet(&self, ctx: &Context, remote: &str) -> Result<String> {
        Ok(
            String::from_utf8_lossy(&self.capture(ctx, remote, None, 16 << 20)?)
                .trim_end_matches('\n')
                .into(),
        )
    }
    pub fn script(
        &self,
        ctx: &Context,
        script: &str,
        environment: &BTreeMap<String, String>,
        output: &mut dyn Write,
        progress: &mut dyn Write,
    ) -> Heard {
        let command = match env_prefix(environment) {
            Ok(prefix) => format!("{prefix}sh -s"),
            Err(e) => {
                return Heard {
                    stdout: false,
                    stderr: false,
                    result: Err(e),
                };
            }
        };
        let mut out = Watching {
            output,
            heard: false,
        };
        let mut err = Watching {
            output: progress,
            heard: false,
        };
        let result = crate::process::stream(
            &mut self.command(&command),
            Some(script.as_bytes()),
            8192,
            ctx.deadline,
            || ctx.check().is_err(),
            &mut out,
            &mut err,
        )
        .and_then(|result| {
            ensure!(result.status.success(), "SSH {}", result.status);
            Ok(())
        });
        Heard {
            stdout: out.heard,
            stderr: err.heard,
            result,
        }
    }
    pub fn piped(
        &self,
        ctx: &Context,
        remote: &str,
        input: Stdio,
        output: &mut dyn Write,
        progress: &mut dyn Write,
    ) -> Result<()> {
        let result = crate::process::stream_input(
            &mut self.command(remote),
            input,
            8192,
            ctx.deadline,
            || ctx.check().is_err(),
            output,
            progress,
        )?;
        ensure!(result.status.success(), "SSH {}", result.status);
        Ok(())
    }
    pub fn read_known_hosts(&self, ctx: &Context) -> Result<String> {
        let body = self.quiet(ctx, "cat /etc/ssh/ssh_host_*_key.pub 2>/dev/null")?;
        let keys: Vec<_> = body
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 2
                    || !(fields[0].starts_with("ssh-") || fields[0].starts_with("ecdsa-"))
                {
                    return None;
                }
                Some((fields[0].into(), fields[1].into()))
            })
            .collect();
        ensure!(
            !keys.is_empty(),
            "the server reported no host keys -- is /etc/ssh readable as {}?",
            self.target.user
        );
        Ok(self.target.known_hosts(&keys))
    }
}
pub struct ScrubWriter<'a> {
    output: &'a mut dyn Write,
    pending: Vec<u8>,
    partial_line: bool,
}
impl<'a> ScrubWriter<'a> {
    pub fn new(output: &'a mut dyn Write) -> Self {
        Self {
            output,
            pending: vec![],
            partial_line: false,
        }
    }
    pub fn finish(&mut self) -> io::Result<()> {
        self.drain(true)?;
        if self.partial_line {
            self.output.write_all(b"\n")?;
            self.partial_line = false;
        }
        self.output.flush()
    }
    fn drain(&mut self, final_chunk: bool) -> io::Result<()> {
        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(text) => {
                    self.output.write_all(validate::scrub(text).as_bytes())?;
                    self.pending.clear();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    if valid > 0 {
                        let text = std::str::from_utf8(&self.pending[..valid]).unwrap();
                        self.output.write_all(validate::scrub(text).as_bytes())?;
                        self.pending.drain(..valid);
                    }
                    if error.error_len().is_none() && !final_chunk {
                        break;
                    }
                    self.output.write_all("�".as_bytes())?;
                    self.pending.drain(..1);
                }
            }
        }
        Ok(())
    }
}
impl Write for ScrubWriter<'_> {
    fn write(&mut self, body: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(body);
        if let Some(last) = body.last() {
            self.partial_line = *last != b'\n';
        }
        self.drain(false)?;
        Ok(body.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
