//! Reviewed host topology and environment authority never comes from application CI.
use super::{Record, knob::Knob};
use crate::{
    host::{PreviewProfile, Probe},
    wire::Secret,
    workload::policy::{commit_id, go_regex},
};
use anyhow::{Result, anyhow, ensure};
use aws_lc_rs::hmac;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    ops::Deref,
    os::unix::fs::MetadataExt,
    path::Path,
};
pub const PROFILES_DIR: &str = "/etc/komizo/preview-profiles";
pub const MAX_BYTES: usize = 128 << 10;
#[derive(Clone, Debug)]
pub struct Profile {
    pub values: PreviewProfile,
    pub digest: String,
}
impl Deref for Profile {
    type Target = PreviewProfile;
    fn deref(&self) -> &PreviewProfile {
        &self.values
    }
}
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub fn parse(body: &[u8]) -> Result<Profile> {
    ensure!(body.len() <= MAX_BYTES, "preview profile exceeds limit");
    let mut value: Value =
        serde_json::from_slice(body).map_err(|_| anyhow!("invalid preview profile"))?;
    value = crate::strict::fields(
        value,
        &[
            "version",
            "services",
            "image_prefixes",
            "credential_namespace",
            "credentials",
            "environment_rules",
            "compose_template",
        ],
    )
    .map_err(|_| anyhow!("invalid preview profile"))?;
    if let Some(values) = value
        .get_mut("environment_rules")
        .and_then(Value::as_array_mut)
    {
        for value in values {
            *value =
                crate::strict::fields(value.take(), &["name", "pattern", "equals_field", "suffix"])
                    .map_err(|_| anyhow!("invalid preview profile"))?;
        }
    }
    let profile: PreviewProfile =
        serde_json::from_value(value).map_err(|_| anyhow!("invalid preview profile"))?;
    ensure!(
        profile.version == 1
            && (1..=32).contains(&profile.services.len())
            && (1..=16).contains(&profile.image_prefixes.len())
            && profile.credentials.len() <= 32
            && profile.environment_rules.len() <= 64
            && !profile.compose_template.is_empty(),
        "preview profile requires one bounded versioned definition"
    );
    for names in [&profile.services, &profile.credentials] {
        let mut seen = BTreeSet::new();
        for name in names.iter() {
            ensure!(
                valid_name(name) && seen.insert(name),
                "invalid or duplicate preview profile name"
            );
        }
    }
    ensure!(
        profile.credentials.is_empty()
            || (!profile.credential_namespace.is_empty()
                && profile.credential_namespace.len() <= 128
                && !profile.credential_namespace.contains(['\r', '\n', '\0'])),
        "preview credentials need an explicit bounded namespace"
    );
    for prefix in profile.image_prefixes.iter() {
        ensure!(
            !prefix.is_empty()
                && prefix.ends_with(':')
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:/_-".contains(&b)),
            "preview profile image prefix must end before an immutable revision tag"
        );
    }
    let mut seen = BTreeSet::new();
    for rule in profile.environment_rules.iter() {
        ensure!(
            valid_name(&rule.name)
                && seen.insert(rule.name.as_str())
                && (rule.pattern.is_empty() != rule.equals_field.is_empty())
                && rule.pattern.len() <= 512
                && rule.suffix.len() <= 256
                && !rule.suffix.contains(['\r', '\n', '\0']),
            "invalid preview environment rule"
        );
        if !rule.pattern.is_empty() {
            ensure!(
                rule.pattern.starts_with('^') && rule.pattern.ends_with('$'),
                "environment patterns must match the whole value"
            );
            ensure!(
                go_regex(&rule.pattern),
                "invalid preview environment pattern"
            );
        }
    }
    for rule in profile.environment_rules.iter() {
        ensure!(
            rule.equals_field.is_empty()
                || (seen.contains(rule.equals_field.as_str()) && rule.equals_field != rule.name),
            "invalid preview environment relationship"
        );
    }
    crate::template::validate("preview", &profile.compose_template)?;
    Ok(Profile {
        values: profile,
        digest: format!("{:x}", Sha256::digest(body)),
    })
}
pub fn read(root: &Path, app: &str) -> Result<Option<Profile>> {
    ensure!(super::valid_app(app), "invalid preview application");
    let path =
        Probe { root: root.into() }.path(Path::new(PROFILES_DIR).join(format!("{app}.json")));
    let info = match fs::symlink_metadata(&path) {
        Ok(info) => info,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        info.is_file()
            && info.mode() & 0o777 == 0o600
            && info.uid() == 0
            && info.len() <= MAX_BYTES as u64,
        "preview profile is not protected"
    );
    for parent in path.ancestors().skip(1) {
        if parent == Path::new("/") || parent == Path::new(".") {
            break;
        }
        let info = fs::symlink_metadata(parent)?;
        ensure!(
            info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0,
            "preview profile parent is not protected"
        );
        if !root.as_os_str().is_empty() && parent == root {
            break;
        }
    }
    let bytes = crate::statefile::read(&path, MAX_BYTES)?
        .ok_or_else(|| anyhow!("preview profile unavailable"))?;
    parse(&bytes).map(Some)
}
impl Profile {
    pub fn validate_compose(&self, body: &str, r: &Record, k: &Knob, network: &str) -> Result<()> {
        let document =
            super::profile_yaml::parse(body).map_err(|_| anyhow!("preview compose is invalid"))?;
        let top = document
            .as_object()
            .ok_or_else(|| anyhow!("preview compose is invalid"))?;
        let map = |name: &str| -> Result<BTreeMap<String, Value>> {
            match top.get(name) {
                None | Some(Value::Null) => Ok(BTreeMap::new()),
                Some(Value::Object(values)) => {
                    Ok(values.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                }
                _ => Err(anyhow!("preview compose is invalid")),
            }
        };
        let services = map("services")?;
        let networks = map("networks")?;
        let volumes = map("volumes")?;
        for value in services.values().chain(volumes.values()) {
            ensure!(
                value.is_object() || value.is_null(),
                "preview compose is invalid"
            );
        }
        fn external(value: &Value) -> Result<bool> {
            match value.get("external") {
                None | Some(Value::Null) => Ok(false),
                Some(Value::Bool(value)) => Ok(*value),
                Some(Value::String(value))
                    if matches!(value.as_str(), "yes" | "Yes" | "YES" | "on" | "On" | "ON") =>
                {
                    Ok(true)
                }
                Some(Value::String(value))
                    if matches!(value.as_str(), "no" | "No" | "NO" | "off" | "Off" | "OFF") =>
                {
                    Ok(false)
                }
                _ => Err(anyhow!("preview compose is invalid")),
            }
        }
        for value in networks.values() {
            ensure!(
                value.is_object() || value.is_null(),
                "preview compose is invalid"
            );
            external(value)?;
            ensure!(
                value
                    .get("name")
                    .is_none_or(|v| v.is_null() || v.is_string()),
                "preview compose is invalid"
            );
        }
        for key in top.keys() {
            ensure!(
                matches!(key.as_str(), "services" | "networks" | "volumes")
                    || key.starts_with("x-"),
                "unsupported preview compose section"
            );
        }
        ensure!(
            services.len() == self.services.len(),
            "preview compose service count differs from declaration"
        );
        let allowed:BTreeSet<_>="image mem_limit memswap_limit cgroup_parent cpu_shares cpus restart read_only cap_drop cap_add security_opt pids_limit tmpfs environment volumes networks healthcheck depends_on entrypoint command user env_file ports container_name".split_whitespace().collect();
        let declared: BTreeSet<_> = self.services.iter().map(String::as_str).collect();
        let mut used = BTreeSet::new();
        for (name, value) in &services {
            let role = if *name == format!("{}-gate", r.project) {
                "gate"
            } else {
                name
            };
            ensure!(
                declared.contains(role) && used.insert(role),
                "undeclared preview compose service"
            );
            if let Some(values) = value.as_object() {
                for key in values.keys() {
                    ensure!(
                        allowed.contains(key.as_str()),
                        "unsupported preview service capability"
                    );
                }
            }
            let text = |key: &str| {
                value
                    .get(key)
                    .filter(|v| !v.is_null())
                    .map(crate::workload::resources::scalar)
                    .unwrap_or_default()
            };
            let image = text("image");
            let pinned = image.split_once('@').is_some_and(|(repository, digest)| {
                !repository.is_empty()
                    && repository.as_bytes()[0].is_ascii_alphanumeric()
                    && repository
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
                    && crate::workload::release::digest(digest)
            });
            ensure!(
                r.images.contains(&image) || pinned,
                "preview image is neither an admitted component nor pinned infrastructure"
            );
            let limit = k.service_memory(&r.app, role);
            ensure!(
                text("mem_limit") == limit
                    && text("memswap_limit") == limit
                    && text("cgroup_parent") == k.cgroup_parent
                    && text("cpu_shares") == "128"
                    && text("cpus") == k.cpu_limit,
                "preview service resource limits differ from admission"
            );
            ensure!(
                text("pids_limit")
                    .parse::<i64>()
                    .is_ok_and(|n| (1..=128).contains(&n)),
                "preview service requires bounded process count"
            );
            let container = text("container_name");
            ensure!(
                container.is_empty() || container == format!("{}-gate", r.project),
                "preview container name escapes project"
            );
            for key in ["volumes", "env_file", "ports", "networks", "cap_add"] {
                let Some(raw) = value.get(key).filter(|v| !v.is_null()) else {
                    continue;
                };
                let items = raw.as_array().ok_or_else(|| {
                    anyhow!(
                        "preview mounts, networks and ports require explicit short declarations"
                    )
                })?;
                for item in items {
                    let item = item
                        .as_str()
                        .ok_or_else(|| anyhow!("invalid preview resource reference"))?;
                    match key {
                        "volumes" => ensure!(
                            item.split_once(':')
                                .is_some_and(|(source, _)| volumes.contains_key(source)),
                            "preview volume must be project-owned"
                        ),
                        "env_file" => ensure!(
                            item == "stack.env",
                            "preview may read only its own stack.env"
                        ),
                        "ports" => ensure!(
                            role == "gate" && item == format!("127.0.0.1:{}:80", r.gate_port),
                            "preview port escapes assigned loopback listener"
                        ),
                        "networks" => ensure!(
                            networks.get(item).is_some_and(
                                |value| role == "gate" || !external(value).unwrap_or(true)
                            ),
                            "preview network escapes private topology"
                        ),
                        "cap_add" => ensure!(
                            " CHOWN DAC_OVERRIDE FOWNER SETGID SETUID "
                                .contains(&format!(" {item} ")),
                            "preview requests a host capability"
                        ),
                        _ => unreachable!(),
                    }
                }
            }
        }
        for (name, value) in &volumes {
            ensure!(valid_name(name), "invalid preview volume name");
            ensure!(
                value.as_object().is_none_or(|value| value.is_empty()),
                "preview volumes cannot select external names or host paths"
            );
        }
        for (name, value) in &networks {
            ensure!(valid_name(name), "invalid preview network name");
            let fields = value
                .as_object()
                .ok_or_else(|| anyhow!("preview networks need explicit declarations"))?;
            for key in fields.keys() {
                ensure!(
                    matches!(key.as_str(), "internal" | "external" | "name"),
                    "preview network requests unsupported driver or capability"
                );
            }
        }
        for value in networks.values() {
            let is_external = external(value)?;
            let name = value.get("name").and_then(Value::as_str).unwrap_or("");
            ensure!(
                (is_external && name == network) || (!is_external && name.is_empty()),
                "preview network name escapes project"
            );
        }
        Ok(())
    }
    pub fn validate_images(&self, images: &[String]) -> Result<()> {
        ensure!(
            images.len() == self.image_prefixes.len(),
            "preview images do not match the declared components"
        );
        let mut revision = None;
        for (image, prefix) in images.iter().zip(self.image_prefixes.iter()) {
            let tag = image.strip_prefix(prefix).unwrap_or("");
            ensure!(
                commit_id(tag) && revision.is_none_or(|previous| previous == tag),
                "preview requires matching immutable component revisions"
            );
            revision = Some(tag);
        }
        Ok(())
    }
    pub fn validate_environment(&self, path: &Path) -> Result<()> {
        if self.environment_rules.is_empty() {
            return Ok(());
        }
        let info = fs::symlink_metadata(path).ok();
        ensure!(
            info.as_ref().is_some_and(|info| info.is_file()
                && info.mode() & 0o777 == 0o600
                && info.len() <= 4096),
            "preview requires bounded private stack.env"
        );
        let body = crate::statefile::read(path, 4096)
            .map_err(|_| anyhow!("preview environment unavailable"))?
            .ok_or_else(|| anyhow!("preview environment unavailable"))?;
        let mut values = BTreeMap::new();
        let rules: BTreeSet<_> = self
            .environment_rules
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        for line in String::from_utf8_lossy(&body).trim().split('\n') {
            let (key, value) = line.split_once('=').ok_or_else(|| {
                anyhow!("preview environment contains an unsupported or duplicate field")
            })?;
            ensure!(
                rules.contains(key) && !values.contains_key(key),
                "preview environment contains an unsupported or duplicate field"
            );
            values.insert(key.to_owned(), value.to_owned());
        }
        for rule in self.environment_rules.iter() {
            let value = values.get(&rule.name);
            ensure!(
                value.is_some_and(|value| (rule.pattern.is_empty()
                    || regex::Regex::new(&rule.pattern).unwrap().is_match(value))
                    && (rule.equals_field.is_empty()
                        || *value
                            == format!(
                                "{}{}",
                                values
                                    .get(&rule.equals_field)
                                    .map(String::as_str)
                                    .unwrap_or(""),
                                rule.suffix
                            ))),
                "preview environment does not match its operator policy"
            );
        }
        Ok(())
    }
    pub fn compose(&self, r: &Record, k: &Knob, network: &str) -> Result<String> {
        let mut values = serde_json::Map::new();
        let Value::Object(knob) = serde_json::to_value(k)? else {
            unreachable!()
        };
        values.extend(knob);
        for (key, value) in [
            ("V", r.v.into()),
            ("App", r.app.clone().into()),
            ("PR", r.pr.into()),
            ("Project", r.project.clone().into()),
            ("Images", serde_json::to_value(&r.images)?),
            ("DBName", r.db_name.clone().into()),
            ("DBPassword", r.db_password.expose().into()),
            ("GatePort", r.gate_port.into()),
            ("Host", r.web_host(k).into()),
            ("APIHost", r.public_api_host(k).into()),
            ("BasePath", r.base_path.clone().into()),
            ("RouteFile", r.route_file.clone().into()),
            ("Network", network.into()),
            ("CgroupParent", k.cgroup_parent.clone().into()),
        ] {
            values.insert(key.into(), value);
        }
        let limits: BTreeMap<_, _> = self
            .services
            .iter()
            .map(|name| (name, k.service_memory(&r.app, name)))
            .collect();
        let mut credentials = BTreeMap::new();
        for role in self.credentials.iter() {
            credentials.insert(
                role,
                credential(&r.db_password, &self.credential_namespace, role),
            );
        }
        values.insert("Limits".into(), serde_json::to_value(limits)?);
        values.insert("Credentials".into(), serde_json::to_value(credentials)?);
        crate::template::render("preview", &self.compose_template, &values.into(), 1 << 20)
    }
}
pub fn credential(seed: &Secret, namespace: &str, role: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, seed.expose().as_bytes());
    let digest = hmac::sign(&key, format!("{namespace}{role}").as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
pub fn configure(
    ctx: &crate::workload::activation::Context,
    root: &Path,
    app: &str,
    body: &[u8],
) -> Result<()> {
    use std::{io::Write, os::unix::fs::DirBuilderExt};
    ensure!(
        unsafe { libc::geteuid() } == 0 && super::valid_app(app),
        "preview configure requires the host operator and one application"
    );
    parse(body)?;
    let _operation = super::runtime::operation(ctx, root)?;
    let _allocation = super::runtime::lock(ctx, root, "previews.lock")?;
    ensure!(
        !super::store::list(root)?
            .iter()
            .any(|record| record.app == app),
        "drain application previews before changing the profile"
    );
    let directory = Probe { root: root.into() }.path(PROFILES_DIR);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let info = fs::symlink_metadata(&directory)?;
    ensure!(
        info.is_dir() && info.mode() & 0o777 == 0o700,
        "preview profile directory is not protected"
    );
    ensure!(
        info.uid() == 0,
        "preview profile directory is not root-owned"
    );
    for parent in directory.ancestors().skip(1) {
        if parent == Path::new("/") {
            break;
        }
        let info = fs::symlink_metadata(parent)?;
        ensure!(
            info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0,
            "preview profile parent is not protected"
        );
        if !root.as_os_str().is_empty() && parent == root {
            break;
        }
    }
    read(root, app)?;
    ctx.check()?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".profile-")
        .tempfile_in(&directory)?;
    temporary.write_all(body)?;
    temporary.as_file().sync_all()?;
    temporary.persist(directory.join(format!("{app}.json")))?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
