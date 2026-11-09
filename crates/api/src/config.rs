use crate::error::{Result, invalid};
use std::{net::IpAddr, path::PathBuf};

#[derive(Clone)]
pub struct Config {
    pub bind: String,
    pub port: u16,
    pub host: String,
    pub owner_client: PathBuf,
    pub identity: Option<PathBuf>,
    pub parent_pid: Option<u32>,
}
pub fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| hex(v, 64))
}
pub fn host(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok()
        || (!value.is_empty()
            && value.len() <= 253
            && value.is_ascii()
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}
impl Config {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut config = Self {
            bind: "127.0.0.1".into(),
            port: 0,
            host: String::new(),
            owner_client: PathBuf::new(),
            identity: None,
            parent_pid: None,
        };
        if args.first().map(String::as_str) != Some("ui") {
            return Err(invalid("expected local ui mode"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut args = args[1..].iter();
        while let Some(argument) = args.next() {
            let (key, value) = match argument.split_once('=') {
                Some((key, value)) => (key, value.to_owned()),
                None => (
                    argument.as_str(),
                    args.next()
                        .ok_or_else(|| invalid("flag requires a value"))?
                        .clone(),
                ),
            };
            if value.is_empty()
                || value.len() > 4096
                || value.chars().any(char::is_control)
                || !seen.insert(key.to_owned())
            {
                return Err(invalid("invalid or duplicate local UI option"));
            }
            match key {
                "--bind" => {
                    config.bind = if value == "localhost" {
                        "127.0.0.1".into()
                    } else {
                        value
                    }
                }
                "--port" => {
                    config.port = value
                        .parse()
                        .ok()
                        .ok_or_else(|| invalid("port must be 0-65535"))?
                }
                "--host" => config.host = value,
                "--owner-client" => config.owner_client = value.into(),
                "--identity" => config.identity = Some(value.into()),
                "--parent-pid" => {
                    let pid = value
                        .parse::<u32>()
                        .map_err(|_| invalid("invalid launcher PID"))?;
                    if pid == 0 || pid != unsafe { libc::getppid() } as u32 {
                        return Err(invalid("launcher is unavailable"));
                    }
                    config.parent_pid = Some(pid);
                }
                _ => return Err(invalid("unsupported local UI option")),
            }
        }
        if !config
            .bind
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
        {
            return Err(invalid("the owner UI must bind a loopback address"));
        }
        if !host(&config.host) {
            return Err(invalid("a literal owner host is required"));
        }
        if !config.owner_client.is_absolute() || !config.owner_client.is_file() {
            return Err(invalid("an absolute owner client executable is required"));
        }
        if config
            .identity
            .as_ref()
            .is_some_and(|path| !path.is_absolute() || !path.is_file())
        {
            return Err(invalid("owner identity must be an explicit absolute file"));
        }
        Ok(config)
    }
    pub fn authority(&self) -> String {
        let bind = if self.bind.contains(':') {
            format!("[{}]", self.bind)
        } else {
            self.bind.clone()
        };
        format!("{bind}:{}", self.port)
    }
}
