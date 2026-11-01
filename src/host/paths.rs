use super::{Host, Probe, system::lines};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
};
pub const STATE_DIR: &str = "/var/lib/komizo";
pub const APPS_DIR: &str = "/var/lib/komizo/apps";
pub const RUN_DIR: &str = "/run/komizo";
pub const REPORT_PATH: &str = "/run/komizo/report.json";
pub const SERVED_DIR: &str = "/var/lib/komizo/served";
pub const HISTORY_PATH: &str = "/var/lib/komizo/served/history.jsonl";
pub const METRICS_PATH: &str = "/var/lib/komizo/served/metrics.json";
pub const VERSION_PATH: &str = "/var/lib/komizo/version";
pub const API_SOCKET_DIR: &str = "/run/komizo/api";
pub const API_SOCKET_PATH: &str = "/run/komizo/api/api.sock";
pub const PENDING_DIR: &str = "/var/lib/komizo/pending";
pub const RESULTS_DIR: &str = "/var/lib/komizo/served/results";
pub const LOGS_DIR: &str = "/var/lib/komizo/served/logs";
pub const SRV_DIR: &str = "/srv";
pub const PROXY_DIR: &str = "/srv/_proxy";
pub const ACCESS_LOG: &str = "/srv/_proxy/logs/access.log";
pub const CADDYFILE: &str = "/srv/_proxy/Caddyfile";
pub const OS_RELEASE: &str = "/etc/os-release";
pub const DEPLOY_FLOORS_PATH: &str = "/etc/komizo/deploy-floors";
pub type State = BTreeMap<String, String>;
#[derive(Clone, Debug)]
pub struct AppState {
    pub name: String,
    pub values: State,
}
impl AppState {
    pub fn dir(&self) -> &str {
        self.get("APP_DIR")
    }
    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).map(String::as_str).unwrap_or_default()
    }
}
pub fn read_state(path: &Path) -> Result<State> {
    let bytes = crate::statefile::read(path, 1 << 20)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let mut values = State::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        ensure!(
            line.len() < 64 << 10,
            "app state line exceeds scanner bound"
        );
        if let Some((key, value)) = line.split_once('=') {
            values.entry(key.into()).or_insert_with(|| value.into());
        }
    }
    Ok(values)
}
pub fn app_state_path(root: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty() && !name.contains(['/', '.', '\0']),
        "{name:?} is not an app name"
    );
    Ok(Probe { root: root.into() }.path(Path::new(APPS_DIR).join(format!("{name}.env"))))
}
pub fn app_settings(root: &Path, name: &str) -> Result<State> {
    read_state(&app_state_path(root, name)?)
        .map_err(|_| anyhow!("no app called {name:?} on this box"))
}
pub fn app_dir(root: &Path, name: &str) -> Result<String> {
    let path = app_state_path(root, name)?;
    let state = read_state(&path).map_err(|_| anyhow!("no app called {name:?} on this box"))?;
    let dir = state
        .get("APP_DIR")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "{} names no APP_DIR, so komizo does not know where {name:?} is",
                path.display()
            )
        })?;
    Ok(dir.clone())
}
pub fn read_value(path: &Path, key: &str) -> String {
    let prefix = format!("{key}=");
    lines(path)
        .iter()
        .find_map(|line| line.strip_prefix(&prefix).map(|v| v.trim().to_owned()))
        .unwrap_or_default()
}
pub fn split_list(value: &str) -> Vec<String> {
    value
        .split([',', ' ', '\t'])
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
impl Probe {
    pub fn app_states(&self) -> Vec<AppState> {
        self.app_states_inner(false).unwrap_or_default()
    }
    pub fn app_states_available(&self) -> Result<Vec<AppState>> {
        self.app_states_inner(true)
    }
    fn app_states_inner(&self, strict: bool) -> Result<Vec<AppState>> {
        let mut output = vec![];
        for entry in std::fs::read_dir(self.path(APPS_DIR))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(name) = name.strip_suffix(".env") else {
                continue;
            };
            if entry.file_type()?.is_dir() {
                continue;
            }
            match read_state(&entry.path()) {
                Ok(values) => output.push(AppState {
                    name: name.into(),
                    values,
                }),
                Err(e) if strict => return Err(e),
                Err(_) => {}
            }
        }
        output.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(output)
    }
    pub fn hosts(&self, dir: &str) -> Vec<Host> {
        lines(self.path(Path::new(dir).join("hostnames")))
            .iter()
            .filter_map(|line| {
                let fields: Vec<_> = line
                    .split('#')
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .collect();
                Some(Host {
                    name: fields.first()?.to_string(),
                    service: if fields.len() >= 3 && fields[1] == "->" {
                        fields[2].into()
                    } else {
                        String::new()
                    },
                })
            })
            .collect()
    }
    pub fn orphans(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.path(SRV_DIR)) else {
            return vec![];
        };
        let mut names = vec![];
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && !name.starts_with('_')
                && std::fs::metadata(self.path(Path::new(APPS_DIR).join(format!("{name}.env"))))
                    .is_err()
            {
                names.push(name);
            }
        }
        names.sort();
        names
    }
}
