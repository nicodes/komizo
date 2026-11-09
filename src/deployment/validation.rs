use super::model::*;
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(k, v)| (k.clone(), sorted(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => values.iter().map(sorted).collect(),
            value => value.clone(),
        }
    }
    Ok(serde_json::to_vec(&sorted(value))?)
}

pub fn document_digest(body: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(body))
}

pub fn bounded_value(body: &[u8], limit: usize) -> Result<Value> {
    ensure!(
        body.len() <= limit,
        "security document exceeds its byte bound"
    );
    let (mut quoted, mut escaped, mut tokens) = (false, false, 0usize);
    for byte in body {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if b"[]{}:,".contains(byte) {
            tokens += 1;
            ensure!(
                tokens <= 32768,
                "security document exceeds its structural bound"
            );
        }
    }
    crate::strict::value(body, limit)
}
pub fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| hex(v, 64))
}
pub fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn safe_text(value: &str, maximum: usize) -> bool {
    value.len() <= maximum && !value.chars().any(|c| c.is_control())
}
pub fn absolute(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 1024
        && safe_text(value, 1024)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+[]".contains(&b))
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !value.contains("//")
        && (value == "/" || !value.ends_with('/'))
}
pub fn hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
pub fn image_reference(value: &str) -> bool {
    value.split_once('@').is_some_and(|(repository, hash)| {
        digest(hash)
            && repository.contains('/')
            && !repository.contains(['@', '$', '\\'])
            && repository.len() <= 512
            && repository
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"./_:-".contains(&b))
            && repository
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..")
    })
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1 << 20..=1u64 << 40).contains(&self.memory_bytes)
                && self.memory_swap_bytes >= self.memory_bytes
                && self.memory_swap_bytes <= 1u64 << 41
                && (1..=1_000_000).contains(&self.milli_cpus)
                && (1..=1_048_576).contains(&self.pids),
            "resources require finite positive memory, CPU and PID limits"
        );
        Ok(())
    }
    pub fn fits(&self, grant: &Self) -> bool {
        self.memory_bytes <= grant.memory_bytes
            && self.memory_swap_bytes <= grant.memory_swap_bytes
            && self.milli_cpus <= grant.milli_cpus
            && self.pids <= grant.pids
    }
}

fn arguments(values: &[String]) -> Result<()> {
    ensure!(
        values.len() <= 128 && values.iter().all(|v| safe_text(v, 8192)),
        "invalid container arguments"
    );
    Ok(())
}
fn headers(values: &BTreeMap<String, String>) -> Result<()> {
    ensure!(values.len() <= 64, "too many response headers");
    for (key, value) in values {
        ensure!(
            !key.is_empty()
                && key.len() <= 80
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && safe_text(value, 16384)
                && !value.contains(['{', '}'])
                && ![
                    "host",
                    "connection",
                    "transfer-encoding",
                    "x-komizo-release",
                    "x-komizo-revision"
                ]
                .contains(&key.to_ascii_lowercase().as_str()),
            "unsafe or reserved response header"
        );
    }
    Ok(())
}
fn container(value: &Container, job: bool, workload: &Workload) -> Result<()> {
    ensure!(
        name(&value.artifact),
        "container artifact must be a logical artifact name"
    );
    ensure!(
        !value.user.is_empty()
            && value.user.len() <= 64
            && value.user.bytes().all(|b| b.is_ascii_digit() || b == b':')
            && value.user.split(':').count() <= 2
            && value.user.split(':').all(|n| n.parse::<u32>().is_ok()),
        "container user requires numeric UID and optional GID"
    );
    value.limits.validate()?;
    arguments(&value.command)?;
    arguments(&value.entrypoint)?;
    ensure!(
        value.environment.len() <= 128,
        "too many environment entries"
    );
    for (key, val) in &value.environment {
        ensure!(
            !key.is_empty()
                && key.len() <= 128
                && key.as_bytes()[0].is_ascii_alphabetic()
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && safe_text(val, 16384),
            "invalid literal environment entry"
        );
    }
    ensure!(
        value.environment_files.len() <= 32 && value.environment_files.iter().all(|v| name(v)),
        "invalid secret file reference"
    );
    let mut targets = BTreeSet::new();
    for secret in &value.secrets {
        ensure!(
            name(&secret.source)
                && absolute(&secret.target)
                && secret.target != "/"
                && secret.mode <= 0o777
                && secret.mode & 0o022 == 0
                && targets.insert(&secret.target),
            "unsafe or duplicate secret mount"
        );
    }
    for mount in &value.volumes {
        ensure!(
            workload.volumes.contains_key(&mount.name)
                && absolute(&mount.target)
                && mount.target != "/"
                && !mount.target.starts_with("/proc")
                && !mount.target.starts_with("/sys")
                && targets.insert(&mount.target),
            "unsafe, duplicate or undeclared volume mount"
        );
    }
    for (path, tmp) in &value.tmpfs {
        ensure!(
            absolute(path)
                && path != "/"
                && !path.starts_with("/proc")
                && !path.starts_with("/sys")
                && tmp.size_bytes > 0
                && tmp.size_bytes <= value.limits.memory_bytes
                && tmp.mode <= 0o7777
                && targets.insert(path),
            "unsafe tmpfs mount"
        );
    }
    let mut networks = BTreeSet::new();
    ensure!(
        value.networks.len() <= 16
            && value
                .networks
                .iter()
                .all(|n| workload.networks.contains_key(n) && networks.insert(n)),
        "unknown or duplicate network"
    );
    if let Some(h) = &value.health {
        arguments(&h.command)?;
        ensure!(
            !job && !h.command.is_empty()
                && (1..=3600).contains(&h.interval_seconds)
                && (1..=300).contains(&h.timeout_seconds)
                && (1..=100).contains(&h.retries)
                && h.start_period_seconds <= 1800
                && h.start_interval_seconds
                    .is_none_or(|n| (1..=300).contains(&n)),
            "invalid service healthcheck"
        );
    }
    ensure!(
        if job {
            value
                .timeout_seconds
                .is_some_and(|n| (1..=1500).contains(&n))
        } else {
            value.timeout_seconds.is_none()
        },
        "jobs require a finite timeout; services cannot declare a job timeout"
    );
    ensure!(
        value.read_only,
        "container root filesystems must be read only"
    );
    let allowed = [
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "SETGID",
        "SETUID",
        "NET_BIND_SERVICE",
    ];
    let mut caps = BTreeSet::new();
    ensure!(
        value
            .capabilities
            .iter()
            .all(|c| allowed.contains(&c.as_str()) && caps.insert(c)),
        "unsafe or duplicate capability"
    );
    ensure!(
        (1..=900).contains(&value.stop_timeout_seconds),
        "unbounded container shutdown"
    );
    ensure!(
        value.working_directory.as_deref().is_none_or(absolute),
        "invalid container working directory"
    );
    for (key, limit) in &value.ulimits {
        ensure!(
            ["nofile", "nproc", "core", "fsize", "memlock"].contains(&key.as_str())
                && limit.soft <= limit.hard
                && limit.hard <= 1 << 40,
            "invalid process limit"
        );
    }
    ensure!(
        value.sysctls.iter().all(|(k, v)| [
            "net.ipv4.ip_unprivileged_port_start",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ping_group_range"
        ]
        .contains(&k.as_str())
            && safe_text(v, 128)),
        "unsupported container sysctl"
    );
    for (dep, condition) in &value.needs {
        match condition {
            Condition::Completed => ensure!(
                workload.jobs.contains_key(dep),
                "completed dependency must name a job"
            ),
            Condition::Healthy => ensure!(
                workload
                    .services
                    .get(dep)
                    .is_some_and(|s| s.health.is_some()),
                "healthy dependency must name a service with a healthcheck"
            ),
            Condition::Started => ensure!(
                workload.services.contains_key(dep),
                "started dependency must name a service"
            ),
        }
    }
    Ok(())
}

pub fn dependency_order(workload: &Workload) -> Result<Vec<String>> {
    fn visit(
        name: &str,
        w: &Workload,
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
        order: &mut Vec<String>,
    ) -> Result<()> {
        if done.contains(name) {
            return Ok(());
        }
        ensure!(active.insert(name.into()), "cyclic workload dependency");
        let value = w
            .services
            .get(name)
            .or_else(|| w.jobs.get(name))
            .ok_or_else(|| anyhow!("unknown workload dependency"))?;
        for dependency in value.needs.keys() {
            visit(dependency, w, active, done, order)?;
        }
        active.remove(name);
        done.insert(name.into());
        order.push(name.into());
        Ok(())
    }
    let mut order = vec![];
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    for key in workload.services.keys().chain(workload.jobs.keys()) {
        visit(key, workload, &mut active, &mut done, &mut order)?;
    }
    Ok(order)
}

impl Workload {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.services.len() + self.jobs.len() <= 32
                && self.assets.len() <= 8
                && self.networks.len() <= 16
                && self.volumes.len() <= 32
                && (!self.services.is_empty() || !self.assets.is_empty()),
            "workload requires services or static assets within finite bounds"
        );
        for key in self
            .services
            .keys()
            .chain(self.jobs.keys())
            .chain(self.assets.keys())
            .chain(self.networks.keys())
            .chain(self.volumes.keys())
        {
            ensure!(
                name(key),
                "workload names must be bounded lowercase identifiers"
            );
        }
        ensure!(
            self.jobs.keys().all(|n| !self.services.contains_key(n)),
            "service and job names must be distinct"
        );
        for value in self.services.values() {
            container(value, false, self)?;
        }
        for value in self.jobs.values() {
            container(value, true, self)?;
        }
        dependency_order(self)?;
        for asset in self.assets.values() {
            ensure!(name(&asset.artifact), "invalid static artifact name");
            headers(&asset.serving.headers)?;
            ensure!(
                asset.serving.route_rules.len() <= 64,
                "too many static routing rules"
            );
            for rule in &asset.serving.route_rules {
                ensure!(
                    rule.pattern.len() <= 1024
                        && !rule.pattern.contains("{$")
                        && regex::Regex::new(&rule.pattern).is_ok()
                        && rule.replacement.starts_with('/')
                        && safe_text(&rule.replacement, 1024)
                        && !rule.replacement.contains(['{', '}', '\\'])
                        && rule
                            .redirect_status
                            .is_none_or(|s| [301, 302, 307, 308].contains(&s)),
                    "invalid static routing rule"
                );
                for (i, _) in rule.replacement.match_indices('$') {
                    ensure!(
                        rule.replacement
                            .as_bytes()
                            .get(i + 1)
                            .is_some_and(u8::is_ascii_digit),
                        "rewrite supports numeric capture references only"
                    );
                }
            }
            ensure!(
                asset
                    .serving
                    .not_found
                    .as_deref()
                    .is_none_or(|p| !p.is_empty()
                        && !p.starts_with('/')
                        && safe_text(p, 1024)
                        && !p.contains(['{', '}', '\\'])
                        && Path::new(p)
                            .components()
                            .all(|c| matches!(c, Component::Normal(_)))),
                "invalid static error document"
            );
            ensure!(
                asset.serving.header_rules.len() <= 64
                    && asset.serving.fallbacks.len() <= 8
                    && asset.serving.deny_paths.len() <= 64,
                "serving rules exceed bounds"
            );
            for fallback in &asset.serving.fallbacks {
                ensure!(
                    !fallback.is_empty()
                        && !fallback
                            .replace("{path}", "path")
                            .contains(['\\', '\0', '\r', '\n', '{', '}'])
                        && Path::new(fallback.trim_start_matches('/'))
                            .components()
                            .all(|p| matches!(p, Component::Normal(_))),
                    "invalid static fallback path"
                );
            }
            for path in &asset.serving.deny_paths {
                ensure!(
                    path.starts_with('/') && safe_text(path, 1024) && !path.contains(['{', '}']),
                    "invalid denied path"
                );
            }
            for rule in &asset.serving.header_rules {
                headers(&rule.headers)?;
                ensure!(
                    rule.paths.len() + rule.except_paths.len() <= 64
                        && rule.paths.iter().chain(&rule.except_paths).all(|p| (p
                            .starts_with('/')
                            || p.starts_with("*."))
                            && safe_text(p, 1024)
                            && !p.contains(['{', '}']))
                        && rule.methods.iter().all(|m| [
                            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
                        ]
                        .contains(&m.as_str())),
                    "invalid header selector"
                );
                if let Some(pattern) = &rule.path_regexp {
                    ensure!(
                        pattern.len() <= 1024
                            && !pattern.contains("{$")
                            && regex::Regex::new(pattern).is_ok(),
                        "invalid header regular expression"
                    );
                }
            }
            ensure!(
                asset
                    .serving
                    .precompressed
                    .iter()
                    .all(|s| ["br", "gzip", "zstd"].contains(&s.as_str()))
                    && asset
                        .serving
                        .encode
                        .iter()
                        .all(|s| ["gzip", "zstd"].contains(&s.as_str()))
                    && asset
                        .serving
                        .encode_content_types
                        .iter()
                        .all(|s| safe_text(s, 256) && !s.contains(['{', '}'])),
                "unsupported content encoding"
            );
        }
        let mut routes = BTreeSet::new();
        ensure!(
            !self.routes.is_empty() && self.routes.len() <= 64,
            "workload requires a finite route declaration"
        );
        for route in &self.routes {
            ensure!(
                hostname(&route.host)
                    && route.path.starts_with('/')
                    && safe_text(&route.path, 1024)
                    && !route.path.contains(['{', '}', '\\'])
                    && routes.insert((&route.host, &route.path))
                    && route.target.is_some() != route.redirect.is_some(),
                "invalid, duplicate or ambiguous route"
            );
            headers(&route.headers)?;
            if let Some(proxy) = &route.proxy {
                ensure!(
                    matches!(&route.target, Some(RouteTarget::Service { .. }))
                        && proxy
                            .encode
                            .iter()
                            .all(|e| ["gzip", "zstd"].contains(&e.as_str()))
                        && proxy
                            .encode_content_types
                            .iter()
                            .all(|s| safe_text(s, 256) && !s.contains(['{', '}']))
                        && proxy
                            .dial_timeout_seconds
                            .is_none_or(|s| (1..=300).contains(&s))
                        && proxy
                            .response_header_timeout_seconds
                            .is_none_or(|s| (1..=600).contains(&s))
                        && proxy.error_status.is_none_or(|s| (400..=599).contains(&s))
                        && proxy
                            .error_body
                            .as_ref()
                            .is_none_or(|s| safe_text(s, 1024) && !s.contains(['{', '}'])),
                    "invalid proxy policy"
                );
            }
            match &route.target {
                Some(RouteTarget::Asset { name }) => ensure!(
                    self.assets.contains_key(name),
                    "route selects an unknown asset"
                ),
                Some(RouteTarget::Service { name, port }) => ensure!(
                    self.services.contains_key(name) && *port > 0,
                    "route selects an unknown service or port"
                ),
                None => {}
            }
            if let Some(redirect) = &route.redirect {
                let url = reqwest::Url::parse(&redirect.to)?;
                ensure!(
                    url.scheme() == "https"
                        && !redirect.to.contains(['{', '}'])
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none()
                        && self
                            .routes
                            .iter()
                            .any(|r| Some(r.host.as_str()) == url.host_str())
                        && [301, 302, 307, 308].contains(&redirect.status),
                    "redirect must select an owned HTTPS hostname"
                );
            }
        }
        validate_readiness(
            &self.readiness,
            &self.routes.iter().map(|r| r.host.clone()).collect(),
        )?;
        Ok(())
    }
}

pub fn validate_readiness(probes: &[Readiness], hosts: &BTreeSet<String>) -> Result<()> {
    ensure!(probes.len() <= 16, "too many readiness probes");
    for probe in probes {
        let url = reqwest::Url::parse(&probe.url)?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.host_str().is_some_and(|h| hosts.contains(h))
                && (200..=399).contains(&probe.status)
                && probe.revision_field.as_ref().is_none_or(|s| name(s))
                && probe.contains.as_ref().is_none_or(|s| safe_text(s, 8192)),
            "readiness must select an admitted HTTPS endpoint"
        );
    }
    Ok(())
}

impl Release {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.release" && self.version == 1 && name(&self.application),
            "invalid release kind, version or application"
        );
        ensure!(
            !self.source.repository.is_empty()
                && safe_text(&self.source.repository, 256)
                && safe_text(&self.source.repository_id, 32)
                && !self.source.revision.is_empty()
                && safe_text(&self.source.revision, 128),
            "invalid release source identity"
        );
        if let Some(providers) = &self.providers {
            ensure!(
                hex(&providers.cookbook_revision, 40)
                    && hex(&providers.tools_revision, 40)
                    && hex(&providers.core_revision, 40),
                "invalid source provider identity"
            );
        }
        self.workload.validate()?;
        ensure!(
            !self.artifacts.is_empty() && self.artifacts.len() <= 32,
            "release requires a bounded artifact inventory"
        );
        let mut used = BTreeSet::new();
        for value in self
            .workload
            .services
            .values()
            .chain(self.workload.jobs.values())
        {
            ensure!(
                matches!(
                    self.artifacts.get(&value.artifact),
                    Some(Artifact::Image { .. })
                ),
                "container must select an image artifact"
            );
            used.insert(&value.artifact);
        }
        for value in self.workload.assets.values() {
            ensure!(
                matches!(
                    self.artifacts.get(&value.artifact),
                    Some(Artifact::Archive { .. })
                ),
                "static asset must select an archive artifact"
            );
            used.insert(&value.artifact);
        }
        ensure!(
            used.len() == self.artifacts.len(),
            "release contains unused artifacts"
        );
        for (key, value) in &self.artifacts {
            ensure!(
                name(key) && image_reference(value.reference()) && digest(value.digest()),
                "invalid immutable artifact identity"
            );
            match value {
                Artifact::Image {
                    reference,
                    digest: hash,
                    config_digest,
                    platform,
                } => ensure!(
                    reference.ends_with(&format!("@{hash}"))
                        && digest(config_digest)
                        && ["linux/amd64", "linux/arm64"].contains(&platform.as_str()),
                    "image requires matching manifest, configuration and platform identity"
                ),
                Artifact::Archive {
                    size_bytes,
                    media_type,
                    ..
                } => ensure!(
                    *size_bytes > 0 && *size_bytes <= 4u64 << 30 && media_type == STATIC_MEDIA_TYPE,
                    "invalid static archive identity"
                ),
            }
        }
        if let Some(contract) = &self.stateful_contract {
            contract.validate(&self.source.revision)?;
        }
        Ok(())
    }
}

impl StatefulContract {
    pub fn validate(&self, revision: &str) -> Result<()> {
        ensure!(
            self.version == 1
                && self.source_revision == revision
                && self.schema.minimum >= 1
                && self.schema.minimum <= self.schema.write
                && self.schema.write <= self.schema.maximum
                && self.schema.maximum <= 1_000_000
                && safe_text(&self.data_revision, 128)
                && !self.data_revision.is_empty()
                && safe_text(&self.credential_revision, 128)
                && !self.credential_revision.is_empty()
                && !self.migrations.is_empty()
                && self.migrations.len() <= 128,
            "invalid stateful compatibility contract"
        );
        let mut names = BTreeSet::new();
        ensure!(
            self.migrations.iter().all(|m| safe_text(&m.identity, 128)
                && !m.identity.is_empty()
                && hex(&m.sha256, 64)
                && names.insert(&m.identity)),
            "invalid or duplicate migration identity"
        );
        Ok(())
    }
    pub fn permits_rollback(&self, current: &Self, observed_schema: u64) -> Result<()> {
        ensure!(
            self.recovery_action == RecoveryAction::ImageRollback
                && observed_schema == current.schema.write
                && self.schema.minimum <= observed_schema
                && observed_schema <= self.schema.maximum
                && self.data_revision == current.data_revision
                && self.credential_revision == current.credential_revision,
            "rollback is incompatible with retained data or credentials"
        );
        let known: BTreeMap<_, _> = current
            .migrations
            .iter()
            .map(|m| (&m.identity, &m.sha256))
            .collect();
        ensure!(
            self.migrations
                .iter()
                .all(|m| known.get(&m.identity) == Some(&&m.sha256)),
            "retained migration identity changed"
        );
        Ok(())
    }
}

pub fn read_release(body: &[u8]) -> Result<ReleaseDocument> {
    let value = bounded_value(body, MAX_DOCUMENT_BYTES)?;
    let release: Release = serde_json::from_value(value.clone())?;
    release.validate()?;
    let canonical = canonical(&value)?;
    let digest = document_digest(&canonical);
    Ok(ReleaseDocument {
        release,
        canonical,
        digest,
    })
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.policy" && self.version == 1 && name(&self.application),
            "invalid host policy identity"
        );
        self.limits.validate()?;
        self.controls.validate(&self.limits)?;
        ensure!(
            self.startup_memory_bytes <= 512 << 20,
            "startup allocation exceeds its finite bound"
        );
        if let Some(service_limits) = &self.service_limits {
            service_limits.validate()?;
        }
        ensure!(
            !self.artifact_prefixes.is_empty()
                && self.artifact_prefixes.len() <= 16
                && self.artifact_prefixes.iter().all(|p| p.contains('/')
                    && safe_text(p, 512)
                    && !p.contains(['@', '$', '\\', ' '])
                    && !p.ends_with('/')),
            "invalid approved artifact families"
        );
        let hosts: BTreeSet<_> = self.hostnames.iter().cloned().collect();
        ensure!(
            !hosts.is_empty()
                && hosts.len() == self.hostnames.len()
                && hosts.len() <= 64
                && hosts.iter().all(|h| hostname(h)),
            "invalid admitted hostnames"
        );
        validate_readiness(&self.readiness, &hosts)?;
        ensure!(
            !self.readiness.is_empty()
                && (1..=1500).contains(&self.operation_timeout_seconds)
                && self.max_asset_file_bytes > 0
                && self.max_asset_file_bytes <= self.max_asset_bytes
                && self.max_asset_bytes <= 4u64 << 30
                && self.max_image_bytes > 0
                && self.max_image_bytes <= 8u64 << 30,
            "host policy needs bounded readiness, deadline and archive limits"
        );
        if let Authority::Github {
            repository,
            repository_id,
            workflows,
            reference,
            environment,
            publisher_workflows,
        } = &self.authority
        {
            ensure!(
                repository.split('/').count() == 2
                    && safe_text(repository, 256)
                    && !repository_id.is_empty()
                    && repository_id.bytes().all(|b| b.is_ascii_digit())
                    && reference == "refs/heads/main"
                    && !environment.is_empty()
                    && safe_text(environment, 128)
                    && !workflows.is_empty()
                    && workflows
                        .keys()
                        .filter(|a| a.ends_with("deploy"))
                        .all(|a| publisher_workflows.contains_key(a))
                    && publisher_workflows
                        .iter()
                        .all(|(action, w)| workflows.contains_key(action)
                            && action.ends_with("deploy")
                            && w.rsplit_once('@').is_some_and(|(path, revision)| path
                                .contains("/.github/workflows/")
                                && safe_text(path, 512)
                                && hex(revision, 40)))
                    && workflows.iter().all(|(a, w)| name(a)
                        && w.starts_with(&format!("{repository}/.github/workflows/"))
                        && w.ends_with("@refs/heads/main")
                        && safe_text(w, 512)),
                "invalid GitHub workflow authority"
            );
        }
        for (key, grant) in &self.secrets {
            ensure!(
                name(key)
                    && absolute(&grant.path)
                    && grant.path != "/"
                    && (!grant.services.is_empty() || !grant.jobs.is_empty())
                    && grant.services.iter().chain(&grant.jobs).all(|s| name(s))
                    && (grant.environment_file || grant.mount)
                    && safe_text(&grant.generation, 128)
                    && !grant.generation.is_empty(),
                "invalid service secret grant"
            );
        }
        if let Some(preview) = &self.previews {
            ensure!(
                !preview.readiness.is_empty(),
                "preview policy requires its own protected readiness probes"
            );
            let probes = preview
                .readiness
                .iter()
                .map(|probe| {
                    let mut probe = probe.clone();
                    probe.url = probe.url.replace("{instance}", "pr-1");
                    probe
                })
                .collect::<Vec<_>>();
            ensure!(
                probes.iter().all(|p| !p.url.contains(['{', '}'])),
                "preview readiness has unsupported placeholders"
            );
            validate_readiness(
                &probes,
                &[
                    format!("pr-1.{}", preview.hostname_suffix),
                    format!("pr-1-api.{}", preview.hostname_suffix),
                ]
                .into_iter()
                .collect(),
            )?;
            preview.limits.validate()?;
            preview.controls.validate(&preview.limits)?;
            if let Some(limits) = &preview.service_limits {
                limits.validate()?;
            }
            for (alias, grant) in &preview.secrets {
                ensure!(
                    name(alias)
                        && grant.path.starts_with(&format!(
                            "/var/lib/komizo/preview-secrets/{}/{{instance}}/",
                            self.application
                        ))
                        && absolute(&grant.path.replace("{instance}", "pr-1"))
                        && (!grant.services.is_empty() || !grant.jobs.is_empty())
                        && grant.services.iter().chain(&grant.jobs).all(|n| name(n))
                        && (grant.environment_file || grant.mount)
                        && hex(&grant.generation, 32),
                    "preview secret grants require isolated instance paths and explicit service scope"
                );
            }
            if let Some(task) = &preview.prepare {
                task.validate()?;
            }
            ensure!(
                hostname(&preview.hostname_suffix)
                    && !preview.environment.is_empty()
                    && safe_text(&preview.environment, 128)
                    && (1..=100).contains(&preview.max_instances)
                    && (60..=604800).contains(&preview.max_ttl_seconds)
                    && preview.limits.fits(&self.limits)
                    && preview.api_path.as_ref().is_none_or(|p| p.starts_with('/')
                        && p.len() <= 128
                        && !p.contains(['{', '}', '?', '#'])
                        && !p.ends_with('/')),
                "invalid preview allocation"
            );
        }
        if let Some(task) = &self.backup {
            task.validate()?;
        }
        Ok(())
    }
    pub fn admit(&self, release: &Release, instance: &str) -> Result<()> {
        self.validate()?;
        release.validate()?;
        ensure!(
            release.application == self.application,
            "release belongs to another application"
        );
        let preview = instance != "production";
        let (limits, grants) = if preview {
            ensure!(
                instance
                    .strip_prefix("pr-")
                    .is_some_and(|n| n.parse::<u64>().is_ok_and(|v| v > 0)),
                "invalid instance identity"
            );
            let p = self
                .previews
                .as_ref()
                .ok_or_else(|| anyhow!("previews are not admitted"))?;
            (&p.limits, &p.secrets)
        } else {
            (&self.limits, &self.secrets)
        };
        for artifact in release.artifacts.values() {
            let repository = artifact.reference().split('@').next().unwrap();
            ensure!(
                self.artifact_prefixes
                    .iter()
                    .any(|prefix| repository == prefix
                        || repository
                            .strip_prefix(prefix)
                            .is_some_and(|s| s.starts_with('-') || s.starts_with('/'))),
                "artifact is outside the application's admitted family"
            );
        }
        let mut memory = 0u64;
        let mut swap = 0u64;
        let mut cpu = 0u64;
        let mut pids = 0u64;
        for (service, value) in release
            .workload
            .services
            .iter()
            .chain(&release.workload.jobs)
        {
            let service_limits = if preview {
                self.previews
                    .as_ref()
                    .unwrap()
                    .service_limits
                    .as_ref()
                    .unwrap_or(limits)
            } else {
                self.service_limits.as_ref().unwrap_or(limits)
            };
            ensure!(
                value.limits.fits(service_limits),
                "service exceeds its instance allocation"
            );
            memory = memory
                .checked_add(value.limits.memory_bytes)
                .ok_or_else(|| anyhow!("memory overflow"))?;
            swap = swap
                .checked_add(value.limits.memory_swap_bytes)
                .ok_or_else(|| anyhow!("swap overflow"))?;
            cpu = cpu
                .checked_add(u64::from(value.limits.milli_cpus))
                .ok_or_else(|| anyhow!("CPU overflow"))?;
            pids = pids
                .checked_add(u64::from(value.limits.pids))
                .ok_or_else(|| anyhow!("PID overflow"))?;
            for alias in value
                .environment_files
                .iter()
                .chain(value.secrets.iter().map(|s| &s.source))
            {
                let grant = grants
                    .get(alias)
                    .ok_or_else(|| anyhow!("unknown secret reference"))?;
                ensure!(
                    if release.workload.jobs.contains_key(service) {
                        grant.jobs.contains(service)
                    } else {
                        grant.services.contains(service)
                    },
                    "secret is outside this service's grant"
                );
                ensure!(
                    !value.environment_files.contains(alias) || grant.environment_file,
                    "secret cannot be delivered as an environment file"
                );
                ensure!(
                    !value.secrets.iter().any(|s| &s.source == alias) || grant.mount,
                    "secret cannot be mounted"
                );
            }
        }
        if self.aggregate_mode == AggregateMode::Sum {
            ensure!(
                memory <= limits.memory_bytes
                    && swap <= limits.memory_swap_bytes
                    && cpu <= u64::from(limits.milli_cpus)
                    && pids <= u64::from(limits.pids),
                "complete workload exceeds its admitted allocation"
            );
        }
        for route in &release.workload.routes {
            if preview {
                let suffix = &self.previews.as_ref().unwrap().hostname_suffix;
                ensure!(
                    route.host == format!("{instance}.{suffix}")
                        || route.host == format!("{instance}-api.{suffix}"),
                    "preview route is outside its assigned namespace"
                );
            } else {
                ensure!(
                    self.hostnames.contains(&route.host),
                    "route is outside admitted hostnames"
                );
            }
        }
        if let Authority::Github {
            repository,
            repository_id,
            ..
        } = &self.authority
        {
            ensure!(
                release.source.repository == *repository
                    && release.source.repository_id == *repository_id
                    && hex(&release.source.revision, 40),
                "source repository or revision differs from host authority"
            );
        }
        ensure!(
            !self.require_stateful_contract || release.stateful_contract.is_some(),
            "application requires a stateful contract"
        );
        Ok(())
    }
}

impl ProtectedTask {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            absolute(&self.program)
                && digest(&self.sha256)
                && (1..=1500).contains(&self.timeout_seconds)
                && (1..=64u64 << 30).contains(&self.max_export_bytes),
            "invalid protected bounded task"
        );
        Ok(())
    }
}

impl ResourceControls {
    pub fn validate(&self, limits: &Limits) -> Result<()> {
        ensure!(
            self.memory_low_bytes <= limits.memory_bytes
                && (self.memory_high_bytes == 0
                    || (self.memory_high_bytes >= self.memory_low_bytes
                        && self.memory_high_bytes <= limits.memory_bytes))
                && self.cpu_weight.is_none_or(|w| (1..=10000).contains(&w))
                && self.io_weight.is_none_or(|w| (1..=10000).contains(&w))
                && self.io_max.len() <= 16,
            "invalid protected resource controls"
        );
        let mut devices = BTreeSet::new();
        for rate in &self.io_max {
            ensure!(
                rate.device
                    .split_once(':')
                    .is_some_and(|(a, b)| a.parse::<u32>().is_ok() && b.parse::<u32>().is_ok())
                    && devices.insert(&rate.device)
                    && rate.read_bytes_per_second > 0
                    && rate.write_bytes_per_second > 0,
                "invalid protected IO rate"
            );
        }
        Ok(())
    }
}
