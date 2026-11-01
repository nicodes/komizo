use super::{diagnose::diagnose, inventory::Inventory, paths::*, system::lines, *};
use crate::wire::{Slice, Time};
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
fn read_json<T: DeserializeOwned>(path: &Path, maximum: usize) -> Option<T> {
    let bytes = crate::statefile::read(path, maximum).ok()??;
    serde_json::from_slice(&bytes).ok()
}
fn protected_read(path: &Path, maximum: usize, mask: u32) -> Option<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let info = file.metadata().ok()?;
    if !info.is_file() || info.uid() != 0 || info.mode() & mask != 0 || info.len() > maximum as u64
    {
        return None;
    }
    let mut bytes = vec![];
    file.take(maximum as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}
fn protected_dir(path: &Path, mask: u32) -> bool {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|f| f.metadata())
        .is_ok_and(|m| m.uid() == 0 && m.mode() & mask == 0)
}
fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Probe {
    pub fn host_keys(&self) -> Vec<HostKey> {
        let Ok(entries) = fs::read_dir(self.path("/etc/ssh")) else {
            return vec![];
        };
        let mut paths: Vec<_> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("ssh_host_") && name.ends_with("_key.pub")
            })
            .map(|e| e.path())
            .collect();
        paths.sort();
        paths
            .into_iter()
            .flat_map(lines)
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() >= 2
                    && (fields[0].starts_with("ssh-") || fields[0].starts_with("ecdsa-"))
                {
                    Some(HostKey {
                        r#type: fields[0].into(),
                        key: fields[1].into(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn server_facts(&self, state: &str, docker: &str, agent: &str) -> Server {
        let os = lines(self.path(OS_RELEASE))
            .iter()
            .find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim().trim_matches('"').to_owned())
            })
            .unwrap_or_default();
        let keys = if state == "ready" {
            self.host_keys()
        } else {
            vec![]
        };
        Server {
            state: state.into(),
            docker: docker.into(),
            os,
            uptime_s: self.uptime(),
            komizo: self.komizo_install(agent),
            host_keys: if keys.is_empty() {
                Slice::default()
            } else {
                keys.into()
            },
        }
    }
    pub fn static_serving(&self, app: &App, inventory: &Inventory) -> Option<StaticServing> {
        let policy = protected_read(
            &self.path(format!("/etc/komizo/workloads/{}.json", app.name)),
            1 << 20,
            0o022,
        )?;
        let policy: Value = serde_json::from_slice(&policy).ok()?;
        if !policy["static"].is_object()
            || policy["app"].as_str() != Some(&app.name)
            || policy["app_dir"].as_str() != Some(&app.dir)
            || policy["source_repository"]
                .as_str()
                .unwrap_or_default()
                .is_empty()
        {
            return None;
        }
        let record = self.path(format!("/var/lib/komizo/static/{}.json", app.name));
        if !protected_dir(record.parent()?, 0o077) {
            return None;
        }
        let body = protected_read(&record, 2 << 20, 0o077)?;
        let serving: StaticServing = serde_json::from_slice(&body).ok()?;
        if policy["static"]["proxy"].as_str() != Some(&serving.proxy)
            || serving.version != 1
            || !lowercase_hex(&serving.revision, 40)
            || serving.revision != app.version
            || !lowercase_hex(&serving.route_sha256, 64)
        {
            return None;
        }
        let route = protected_read(
            &self.path(format!("/srv/_proxy/routes/{}.caddy", app.name)),
            1 << 20,
            0o022,
        )?;
        if format!("{:x}", Sha256::digest(route)) != serving.route_sha256 {
            return None;
        }
        if serving.active
            && (!lowercase_hex(&serving.tree_sha256, 64)
                || !protected_dir(
                    &self.path(format!("/srv/_public/{}/{}", app.name, serving.revision)),
                    0o022,
                )
                || !inventory
                    .sorted()
                    .iter()
                    .any(|c| c.name == serving.proxy && c.state == "running"))
        {
            return None;
        }
        Some(serving)
    }
    pub fn apps(&self, inventory: &Inventory) -> Vec<App> {
        let mut output = vec![];
        for state in self.app_states() {
            let mut app = App {
                name: state.name.clone(),
                user: state.get("CI_USER").into(),
                dir: state.dir().into(),
                config_image: state.get("CONFIG_IMAGE").into(),
                version: "none".into(),
                ..Default::default()
            };
            let known = split_list(state.get("KNOWN_AS"));
            if !known.is_empty() {
                app.known_as = known.into();
            }
            app.deployment = read_json::<Deployment>(
                &self.path(format!(
                    "/var/lib/komizo/releases/{}/operation.json",
                    app.name
                )),
                65536,
            )
            .filter(|o| o.version == 1 && o.app == app.name);
            if app.user.is_empty() {
                app.user = "?".into();
            }
            if let Some(policy) = read_json::<Value>(
                &self.path(format!("/etc/komizo/workloads/{}.json", app.name)),
                1 << 20,
            ) && let Some(name) = policy["ingress_network"].as_str().filter(|s| !s.is_empty())
            {
                let mut network = Network {
                    name: name.into(),
                    ..Default::default()
                };
                let members: Vec<_> = inventory
                    .sorted()
                    .iter()
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
                app.ingress = Some(network);
            }
            if state.get("STOPPED") == "1" {
                app.stopped = true;
                app.stopped_by = state.get("STOPPED_BY").into();
                app.stopped_at = serde_json::from_value(serde_json::json!(state.get("STOPPED_AT")))
                    .unwrap_or_default();
            }
            if !app.dir.is_empty() {
                let version =
                    read_value(&self.path(Path::new(&app.dir).join(".env")), "APP_VERSION");
                if !version.is_empty() {
                    app.version = version;
                }
                let hosts = self.hosts(&app.dir);
                if !hosts.is_empty() {
                    app.hosts = hosts.into();
                }
                app.containers = self.containers(&app.dir, inventory).into();
            }
            app.r#static = self.static_serving(&app, inventory);
            app.runtime_state = self.runtime_state(&app);
            if inventory.status == "unavailable" && !app.stopped && app.r#static.is_none() {
                app.runtime_state = "unknown".into();
            }
            output.push(app);
        }
        output
    }
    pub fn assemble_report(
        &self,
        server: Server,
        inventory: &Inventory,
        network_metadata: Option<&str>,
        at: Time,
    ) -> Report {
        let mut report = Report {
            v: REPORT_VERSION,
            at,
            server,
            apps: vec![].into(),
            problems: vec![].into(),
            ..Default::default()
        };
        if !report.server.ready() {
            return report;
        }
        report.inventory = Some(Observation {
            status: inventory.status.clone(),
            failure: inventory.failure.clone(),
            at,
        });
        report.apps = self.apps(inventory).into();
        report.proxy = self.proxy(inventory);
        if let Some(metadata) = network_metadata {
            let name = report
                .proxy
                .as_ref()
                .map(|p| p.network.as_str())
                .filter(|s| !s.is_empty() && *s != "?")
                .unwrap_or("edge");
            report.network = Some(self.network_from_metadata(name, metadata, inventory));
        }
        let orphans = self.orphans();
        if !orphans.is_empty() {
            report.orphans = orphans.into();
        }
        report.system = self.system_counters();
        let containers = self.container_stats(inventory);
        if !containers.is_empty() {
            report.system.containers = containers.into();
        }
        report.sweep = read_json(
            &self.path(Path::new(SERVED_DIR).join("sweep.json")),
            1 << 20,
        );
        report.preview = read_json(
            &self.path(Path::new(SERVED_DIR).join("preview-reap.json")),
            1 << 20,
        );
        let problems = diagnose(&report);
        report.problems = if problems.is_empty() {
            Slice::default()
        } else {
            problems.into()
        };
        report
    }
}
pub fn now() -> Time {
    Time(Utc::now().fixed_offset())
}
