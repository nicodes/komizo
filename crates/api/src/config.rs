use crate::{
    error::{Result, invalid},
    signed,
    store::{self, Paths},
};
use serde::Deserialize;
use std::path::PathBuf;
#[derive(Clone)]
pub struct Config {
    pub mode: String,
    pub bind: String,
    pub port: u16,
    pub hosts: Vec<String>,
    pub socket: PathBuf,
    pub credential: PathBuf,
    pub preview_knob: PathBuf,
    pub paths: Paths,
    pub parent_pid: Option<u32>,
}
impl Config {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut config = Self {
            mode: "ui".into(),
            bind: "127.0.0.1".into(),
            port: 8480,
            hosts: Vec::new(),
            socket: "/run/komizo/api/api.sock".into(),
            credential: "/etc/komizo/agent.json".into(),
            preview_knob: "/etc/komizo/preview".into(),
            paths: Paths::default(),
            parent_pid: None,
        };
        let mut args = args.iter();
        if let Some(mode) = args.next() {
            if !matches!(mode.as_str(), "ui" | "serve" | "preview-ask") {
                return Err(invalid("expected ui, serve or preview-ask"));
            }
            config.mode = mode.clone();
        }
        while let Some(argument) = args.next() {
            let (key, value) = if let Some((key, value)) = argument.split_once('=') {
                (key, value.to_owned())
            } else {
                (
                    argument.as_str(),
                    args.next()
                        .ok_or_else(|| invalid("flag requires a value"))?
                        .clone(),
                )
            };
            match key {
                "--bind" => config.bind = value,
                "--port" => {
                    config.port = value.parse().map_err(|_| invalid("port must be 1-65535"))?;
                    if config.port == 0 {
                        return Err(invalid("port must be 1-65535"));
                    }
                }
                "--hosts" => {
                    config.hosts = value
                        .split(',')
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                        .collect()
                }
                "--socket" => config.socket = value.into(),
                "--config" => config.credential = value.into(),
                "--preview-knob" => config.preview_knob = value.into(),
                "--report" => config.paths.report = value.into(),
                "--history" => config.paths.history = value.into(),
                "--metrics" => config.paths.metrics = value.into(),
                "--inbox" => config.paths.inbox = value.into(),
                "--results" => config.paths.results = value.into(),
                "--logs" => config.paths.logs = value.into(),
                "--apps" => config.paths.apps = value.into(),
                "--parent-pid" => {
                    let pid = value
                        .parse::<u32>()
                        .map_err(|_| invalid("invalid launcher PID"))?;
                    if pid == 0 || pid != unsafe { libc::getppid() } as u32 {
                        return Err(invalid("launcher is unavailable"));
                    }
                    config.parent_pid = Some(pid);
                }
                _ => return Err(invalid("unsupported API flag")),
            }
        }
        if config.bind != "localhost" && config.bind.parse::<std::net::IpAddr>().is_err() {
            return Err(invalid("bind must be an IP address or localhost"));
        }
        Ok(config)
    }
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Credential {
    server_id: String,
    registry_key: String,
    operator_keys: Vec<String>,
    log_keys: Vec<String>,
}
pub struct Authority {
    pub server: String,
    pub registry: [u8; 32],
    pub operators: Vec<[u8; 32]>,
    pub logs: Vec<[u8; 32]>,
}
impl Authority {
    pub fn load(path: &std::path::Path) -> Result<Option<Self>> {
        let raw = match store::bytes(path, 1 << 20) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let conf: Credential =
            serde_json::from_slice(&raw).map_err(|_| invalid("agent credential is unreadable"))?;
        if conf.server_id.is_empty() || conf.registry_key.is_empty() {
            return Ok(None);
        }
        let registry =
            signed::key(&conf.registry_key).map_err(|_| invalid("unusable registry key"))?;
        let mut operators = Vec::new();
        for raw in conf.operator_keys {
            let key = signed::key(
                raw.trim()
                    .strip_prefix("kmz_dev_")
                    .ok_or_else(|| invalid("unusable operator key"))?,
            )
            .map_err(|_| invalid("unusable operator key"))?;
            operators.push(key);
        }
        let mut logs = operators.clone();
        for raw in conf.log_keys {
            let key = signed::key(
                raw.trim()
                    .strip_prefix("kmz_log_")
                    .ok_or_else(|| invalid("unusable log key"))?,
            )
            .map_err(|_| invalid("unusable log key"))?;
            logs.push(key);
        }
        Ok(Some(Self {
            server: conf.server_id,
            registry,
            operators,
            logs,
        }))
    }
    pub fn reports(&self) -> Vec<[u8; 32]> {
        let mut keys = self.operators.clone();
        keys.push(self.registry);
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_defaults_and_explicit_flags_preserve_local_binding() {
        let default = Config::parse(&[]).unwrap();
        assert_eq!(default.bind, "127.0.0.1");
        assert_eq!(default.port, 8480);
        for bad in ["0", "65536", "-1", "no"] {
            assert!(Config::parse(&["ui".into(), "--port".into(), bad.into()]).is_err());
        }
        let explicit = Config::parse(&[
            "ui".into(),
            "--bind".into(),
            "0.0.0.0".into(),
            "--port=4999".into(),
        ])
        .unwrap();
        assert_eq!(explicit.bind, "0.0.0.0");
        assert_eq!(explicit.port, 4999);
        assert!(Config::parse(&["ui".into(), "--bind=external.example".into()]).is_err());
    }
}
