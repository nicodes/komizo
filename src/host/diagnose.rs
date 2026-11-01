use super::*;
use std::collections::{BTreeMap, BTreeSet};
impl Server {
    pub fn ready(&self) -> bool {
        self.state == "ready"
    }
    pub fn os_name(&self) -> &str {
        if self.os.is_empty() {
            "alpine"
        } else {
            &self.os
        }
    }
}
impl App {
    pub fn running(&self) -> usize {
        self.containers
            .iter()
            .filter(|c| c.state == "running")
            .count()
    }
    pub fn routes(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        self.hosts
            .iter()
            .filter(|h| !h.name.is_empty() && seen.insert(h.name.clone()))
            .map(|h| h.name.clone())
            .collect()
    }
}
impl Proxy {
    pub fn running(&self) -> bool {
        self.state == "running"
    }
}
fn members(network: Option<&Network>) -> BTreeSet<&str> {
    network
        .into_iter()
        .flat_map(|n| n.members.iter().map(|m| m.container.as_str()))
        .collect()
}
pub fn duplicate_aliases(network: &Network) -> BTreeMap<String, Vec<String>> {
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for member in network.members.iter() {
        let mut claimed = BTreeSet::new();
        for alias in member.aliases.iter() {
            if !alias.is_empty() && claimed.insert(alias) {
                seen.entry(alias.clone())
                    .or_default()
                    .push(member.container.clone());
            }
        }
    }
    seen.retain(|_, containers| {
        containers.sort();
        containers.len() > 1
    });
    seen
}
pub fn diagnose(report: &Report) -> Vec<Problem> {
    let mut output = vec![];
    let mut add = |kind: &str, app: &str, detail: String| {
        output.push(Problem {
            kind: kind.into(),
            app: app.into(),
            detail,
        })
    };
    if report
        .inventory
        .as_ref()
        .is_some_and(|i| i.status != "current")
    {
        add(
            "observation_incomplete",
            "",
            "container observation is incomplete; inspect again before deciding an operation"
                .into(),
        );
    }
    if report.proxy.as_ref().is_some_and(|p| !p.running()) {
        add(
            "proxy_stopped",
            "",
            "the shared reverse proxy is not running -- nothing is being served".into(),
        );
    }
    if let Some(network) = &report.network {
        for (alias, containers) in duplicate_aliases(network) {
            add(
                "alias_clash",
                "",
                format!(
                    "{alias:?} resolves to {} containers on network {:?} ({}) -- traffic to it is split between them at random",
                    containers.len(),
                    network.name,
                    containers.join(", ")
                ),
            );
        }
    }
    let attached = members(report.network.as_ref());
    for app in report.apps.iter() {
        let running = app.running();
        if !app.stopped && matches!(app.runtime_state.as_str(), "degraded" | "down") && running > 0
        {
            add(
                "app_down",
                &app.name,
                "one or more required services are unavailable".into(),
            );
        }
        let network = app.ingress.as_ref().or(report.network.as_ref());
        let local = app.ingress.as_ref().map(|n| members(Some(n)));
        let app_attached = local.as_ref().unwrap_or(&attached);
        if let Some(ingress) = &app.ingress
            && report.proxy.as_ref().is_some_and(Proxy::running)
            && !app_attached.contains("komizo-proxy")
            && running > 0
            && !app.hosts.is_empty()
        {
            add(
                "detached",
                &app.name,
                format!(
                    "{} ingress {:?} is detached from the shared proxy",
                    app.name, ingress.name
                ),
            );
        }
        if app.r#static.as_ref().is_some_and(|s| s.active) && running > 0 {
            add(
                "deployment_incomplete",
                &app.name,
                format!(
                    "{} static serving is accepted but its redundant gate still runs; retire it through the root operator",
                    app.name
                ),
            );
        }
        if let Some(operation) = &app.deployment {
            match operation.phase.as_str() {
                "failed" | "staging_failed" | "activation_failed" | "readiness_failed" => add(
                    "deployment_incomplete",
                    &app.name,
                    format!(
                        "{} deployment {} ended in {}; inspect its journal before changing versions",
                        app.name, operation.candidate, operation.phase
                    ),
                ),
                "admitted" | "staging" | "configured" | "activating" => {
                    let expired = if operation.deadline.is_zero() {
                        report.at.utc().signed_duration_since(operation.at.utc())
                            > chrono::Duration::minutes(10)
                    } else {
                        report.at >= operation.deadline
                    };
                    if expired {
                        add(
                            "deployment_incomplete",
                            &app.name,
                            format!(
                                "{} deployment {} in {} exceeded its observation deadline; inspect its journal",
                                app.name, operation.candidate, operation.phase
                            ),
                        );
                    }
                }
                _ => {}
            }
        }
        if !app.hosts.is_empty()
            && running > 0
            && let Some(network) = network
            && !app
                .containers
                .iter()
                .any(|c| c.state == "running" && app_attached.contains(c.name.as_str()))
        {
            add(
                "detached",
                &app.name,
                format!(
                    "{} publishes {} hostname(s) but no running container is attached to network {:?}",
                    app.name,
                    app.hosts.len(),
                    network.name
                ),
            );
        }
        if app.stopped && running > 0 {
            add(
                "stopped_but_running",
                &app.name,
                format!(
                    "{} is recorded as stopped but {} of its {} container(s) are running, so it cannot report as down: start it to clear the record, or stop it again",
                    app.name,
                    running,
                    app.containers.len()
                ),
            );
        }
        if app.stopped && app.r#static.as_ref().is_some_and(|s| s.active) {
            add(
                "stopped_but_running",
                &app.name,
                format!(
                    "{} is recorded as stopped but its static serving route remains active",
                    app.name
                ),
            );
        }
        if !app.stopped
            && !app.containers.is_empty()
            && running == 0
            && !app.r#static.as_ref().is_some_and(|s| s.active)
        {
            add(
                "app_down",
                &app.name,
                format!(
                    "{} has {} container(s) and none of them are running",
                    app.name,
                    app.containers.len()
                ),
            );
        }
    }
    if report.proxy.as_ref().is_some_and(|p| p.tls_ask.is_empty()) {
        let wildcard: Vec<_> = report
            .apps
            .iter()
            .filter(|a| a.hosts.iter().any(|h| h.name.trim().starts_with("*.")))
            .map(|a| a.name.as_str())
            .collect();
        if !wildcard.is_empty() {
            add(
                "no_tls_gate",
                "",
                format!(
                    "{} use a wildcard hostname but no on-demand TLS gate is set -- their certificates will fail",
                    wildcard.join(", ")
                ),
            );
        }
    }
    for orphan in report.orphans.iter() {
        add(
            "orphan_dir",
            orphan,
            format!("/srv/{orphan} has no state file behind it -- left over from a removal?"),
        );
    }
    output
}
