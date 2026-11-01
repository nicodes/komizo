use super::{
    paths::{CADDYFILE, PROXY_DIR, split_list},
    system::lines,
    *,
};
use crate::wire::{Slice, Time};
use anyhow::Result;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Component, Path},
};
pub const DOCKER_API: &str = "1.45";
pub const PS_FORMAT: &str = "{{.ID}}\t{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Image}}\t{{.Label \"com.docker.compose.project.working_dir\"}}";
pub const INSPECT_FORMAT: &str = "{{.Id}}\t{{.State.StartedAt}}\t{{.State.FinishedAt}}\t{{.State.ExitCode}}\t{{.State.Pid}}\t{{range $n, $c := .NetworkSettings.Networks}}{{$n}}={{range $c.Aliases}}{{.}},{{end}} {{end}}\t{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}}={{.Source}} {{end}}{{end}}\t{{with index .State \"Health\"}}{{.Status}}{{end}}";
#[derive(Clone, Debug, Default, Serialize)]
pub struct Mount {
    pub name: String,
    pub source: String,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct ContainerInfo {
    pub inspection_unavailable: bool,
    pub tty: bool,
    pub id: String,
    pub name: String,
    pub state: String,
    pub health: String,
    pub status: String,
    pub service: String,
    pub image: String,
    pub working_dir: String,
    pub started_at: Time,
    pub finished_at: Time,
    pub exit_code: i64,
    pub pid: i64,
    pub networks: BTreeMap<String, Slice<String>>,
    pub mounts: Slice<Mount>,
}
#[derive(Clone, Debug)]
pub struct Inventory {
    pub status: String,
    pub failure: String,
    rows: Vec<ContainerInfo>,
    by_id: BTreeMap<String, usize>,
    by_dir: BTreeMap<String, Vec<usize>>,
}
impl Default for Inventory {
    fn default() -> Self {
        Self {
            status: "current".into(),
            failure: String::new(),
            rows: vec![],
            by_id: BTreeMap::new(),
            by_dir: BTreeMap::new(),
        }
    }
}
impl Inventory {
    pub fn unavailable(failure: &str) -> Self {
        Self {
            status: "unavailable".into(),
            failure: failure.into(),
            ..Default::default()
        }
    }
    pub fn partial(&mut self, failure: &str) {
        self.status = "partial".into();
        self.failure = failure.into();
    }
    pub fn insert(&mut self, container: ContainerInfo) {
        let index = self.rows.len();
        self.by_id.insert(container.id.clone(), index);
        if !container.working_dir.is_empty() {
            self.by_dir
                .entry(clean_path(&container.working_dir))
                .or_default()
                .push(index);
        }
        self.rows.push(container);
    }
    pub fn sorted(&self) -> Vec<&ContainerInfo> {
        let mut rows: Vec<_> = self.by_id.values().map(|&i| &self.rows[i]).collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }
    pub fn for_dir(&self, dir: &str) -> Vec<&ContainerInfo> {
        if dir.is_empty() {
            return vec![];
        }
        self.by_dir
            .get(&clean_path(dir))
            .into_iter()
            .flatten()
            .map(|&i| &self.rows[i])
            .collect()
    }
    pub fn by_id_mut(&mut self, id: &str) -> Option<&mut ContainerInfo> {
        self.by_id.get(id).copied().map(|i| &mut self.rows[i])
    }
    pub fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }
    pub fn from_cli(
        list: Result<String>,
        inspect: impl FnOnce(&[String]) -> Result<String>,
    ) -> Self {
        let Ok(list) = list else {
            return Self::unavailable("list_unavailable");
        };
        let mut inv = Self::default();
        let mut ids = vec![];
        for line in list.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            let f: Vec<_> = line.trim_end_matches('\r').split('\t').collect();
            if f.len() < 7 || f[0].is_empty() {
                inv.partial("list_invalid");
                continue;
            }
            ids.push(f[0].to_owned());
            inv.insert(ContainerInfo {
                inspection_unavailable: true,
                id: f[0].into(),
                name: f[1].into(),
                state: f[2].into(),
                status: f[3].into(),
                service: f[4].into(),
                image: f[5].into(),
                working_dir: f[6].into(),
                ..Default::default()
            });
        }
        if ids.is_empty() {
            return inv;
        }
        let Ok(details) = inspect(&ids) else {
            inv.partial("inspection_unavailable");
            return inv;
        };
        for line in details.split('\n') {
            let f: Vec<_> = line.trim_end_matches('\r').split('\t').collect();
            if f.len() < 7 {
                continue;
            }
            let Some(c) = inv.by_id_mut(f[0]) else {
                continue;
            };
            c.inspection_unavailable = false;
            c.started_at = parse_stamp(f[1]);
            c.finished_at = parse_stamp(f[2]);
            c.exit_code = f[3].parse().unwrap_or(0);
            c.pid = f[4].parse().unwrap_or(0);
            c.networks = parse_networks(f[5]);
            c.mounts = parse_mounts(f[6]).into();
            if f.len() > 7 {
                c.health = f[7].into();
            }
        }
        if inv
            .by_id
            .values()
            .any(|&i| inv.rows[i].inspection_unavailable)
        {
            inv.partial("inspection_unavailable");
        }
        inv
    }
}
pub fn clean_path(input: &str) -> String {
    if input.is_empty() {
        return ".".into();
    }
    let absolute = input.starts_with('/');
    let mut parts = vec![];
    for part in Path::new(input).components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if parts.last().is_some_and(|p| p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..".into());
                }
            }
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            Component::Prefix(_) => {}
        }
    }
    let body = parts.join("/");
    if absolute {
        format!("/{body}")
    } else if body.is_empty() {
        ".".into()
    } else {
        body
    }
}
pub fn parse_networks(value: &str) -> BTreeMap<String, Slice<String>> {
    value
        .split(' ')
        .filter_map(|entry| {
            let (name, aliases) = entry.split_once('=')?;
            if name.is_empty() {
                return None;
            }
            let values = split_list(aliases);
            Some((
                name.into(),
                if values.is_empty() {
                    Slice::default()
                } else {
                    values.into()
                },
            ))
        })
        .collect()
}
pub fn parse_mounts(value: &str) -> Vec<Mount> {
    value
        .split(' ')
        .filter_map(|entry| {
            let (name, source) = entry.split_once('=')?;
            (!name.is_empty() && !source.is_empty()).then(|| Mount {
                name: name.into(),
                source: source.into(),
            })
        })
        .collect()
}
pub fn parse_stamp(value: &str) -> Time {
    use chrono::Datelike;
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .filter(|t| t.year() > 1 && t.timestamp_subsec_nanos() < 1_000_000_000)
        .map(Time)
        .unwrap_or_default()
}
fn first_indented(path: &Path, key: &str) -> String {
    lines(path)
        .iter()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed == line {
                None
            } else {
                trimmed.strip_prefix(key).map(|v| v.trim().to_owned())
            }
        })
        .unwrap_or_default()
}
impl Probe {
    pub fn containers(&self, dir: &str, inventory: &Inventory) -> Vec<Container> {
        inventory
            .for_dir(dir)
            .into_iter()
            .map(|c| {
                let ports = self.listening_ports(c.pid);
                Container {
                    inspection: if c.inspection_unavailable {
                        "unavailable"
                    } else {
                        "current"
                    }
                    .into(),
                    service: c.service.clone(),
                    name: c.name.clone(),
                    state: c.state.clone(),
                    health: c.health.clone(),
                    status: c.status.clone(),
                    image: c.image.clone(),
                    started_at: c.started_at,
                    finished_at: c.finished_at,
                    exit_code: c.exit_code,
                    ports: if ports.is_empty() {
                        Slice::default()
                    } else {
                        ports.into()
                    },
                }
            })
            .collect()
    }
    pub fn proxy(&self, inventory: &Inventory) -> Option<Proxy> {
        if !self.path(PROXY_DIR).is_dir() {
            return None;
        }
        let compose = self.path(Path::new(PROXY_DIR).join("compose.yml"));
        let mut proxy = Proxy {
            state: "stopped".into(),
            status: "not created".into(),
            network: first_indented(&compose, "name:"),
            image: first_indented(&compose, "image:"),
            ..Default::default()
        };
        if proxy.network.is_empty() {
            proxy.network = "?".into();
        }
        if proxy.image.is_empty() {
            proxy.image = "?".into();
        }
        if let Some(c) = inventory
            .sorted()
            .into_iter()
            .find(|c| c.name == "komizo-proxy")
        {
            proxy.state = c.state.clone();
            proxy.status = c.status.clone();
            proxy.started_at = c.started_at;
            proxy.finished_at = c.finished_at;
        }
        for line in lines(self.path(CADDYFILE)) {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() >= 2 && f[0] == "ask" {
                proxy.tls_ask = f[1].into();
                break;
            }
        }
        Some(proxy)
    }
    pub fn network_from_metadata(
        &self,
        name: &str,
        metadata: &str,
        inventory: &Inventory,
    ) -> Network {
        let f: Vec<_> = metadata.trim().split('\t').collect();
        let mut network = Network {
            name: name.into(),
            driver: f[0].into(),
            subnet: f.get(1).unwrap_or(&"").to_string(),
            ..Default::default()
        };
        let members: Vec<_> = inventory
            .sorted()
            .into_iter()
            .filter_map(|c| {
                c.networks.get(name).map(|aliases| NetworkMember {
                    container: c.name.clone(),
                    aliases: aliases.clone(),
                })
            })
            .collect();
        if !members.is_empty() {
            network.members = members.into();
        }
        network
    }
    pub fn container_stats(&self, inventory: &Inventory) -> Vec<ContainerStat> {
        let mut output = vec![];
        for state in self.app_states() {
            for c in inventory.for_dir(state.dir()) {
                if c.pid <= 0 || c.service.is_empty() {
                    continue;
                }
                let mut stat = self.cgroup_stat(c.pid);
                stat.app = state.name.clone();
                stat.service = c.service.clone();
                output.push(stat);
            }
        }
        output
    }
}
