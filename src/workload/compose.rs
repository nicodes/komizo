//! Repository Compose receives only the powers present in its host policy.
use super::{
    identifier,
    policy::{Policy, check_fields},
    resources, revision, yaml,
};
use crate::host::{authority::quote, inventory::clean_path};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Map, Value, json};
use std::{path::Path, sync::OnceLock};
fn object(value: Option<&Value>) -> Option<&Map<String, Value>> {
    static EMPTY: OnceLock<Map<String, Value>> = OnceLock::new();
    match value {
        None | Some(Value::Null) => Some(EMPTY.get_or_init(Map::new)),
        Some(value) => value.as_object(),
    }
}
fn resources_valid(doc: &mut Map<String, Value>, policy: &Policy) -> Result<()> {
    for kind in ["volumes", "networks"] {
        let entries = object(doc.get(kind))
            .ok_or_else(|| anyhow!("{kind} must be an object"))?
            .clone();
        for (name, raw) in entries {
            ensure!(identifier(&name), "invalid resource name");
            let mut configuration = object(Some(&raw))
                .ok_or_else(|| anyhow!("resource must be an object"))?
                .clone();
            if kind == "volumes" {
                check_fields(&configuration, "volume", &["name"])?;
                if let Some(value) = configuration.get("name") {
                    ensure!(
                        value.as_str().is_some_and(|name| identifier(name)
                            && name.starts_with(&(policy.app.clone() + "_"))),
                        "foreign volume namespace refused"
                    );
                }
            } else {
                check_fields(&configuration, "network", &["internal", "external", "name"])?;
                if let Some(value) = configuration.get("internal") {
                    ensure!(value.is_boolean(), "network internal must be boolean");
                }
                if let Some(value) = configuration.get("external") {
                    ensure!(value.is_boolean(), "network external must be boolean");
                }
                if configuration.get("external") == Some(&Value::Bool(true)) {
                    let name_ = configuration
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("external network needs a host-approved name"))?;
                    let mut network =
                        name_.replace("${SHARED_NETWORK:-edge}", &policy.shared_network);
                    ensure!(
                        network == policy.shared_network,
                        "foreign external network refused"
                    );
                    if !policy.ingress_network.is_empty() {
                        network = policy.ingress_network.clone();
                    }
                    configuration.insert("name".into(), network.into());
                    doc.get_mut(kind)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert(name, configuration.into());
                } else {
                    ensure!(
                        !configuration.contains_key("name"),
                        "custom network namespace refused"
                    );
                }
            }
        }
    }
    Ok(())
}
pub fn allowed_image(image: &str, prefix: &str, version: &str) -> bool {
    if image.contains([' ', '$', '\\', '\n', '\r', '\t']) {
        return false;
    }
    fn digest(value: &str) -> bool {
        value
            .strip_prefix("sha256:")
            .is_some_and(super::policy::content_identity)
    }
    if let Some(reference) = image.strip_prefix(prefix) {
        if let Some((component, hash)) = reference.split_once('@') {
            let component = component
                .strip_suffix(&format!(":{version}"))
                .unwrap_or(component);
            return identifier(component) && digest(hash);
        }
        return reference
            .split_once(':')
            .is_some_and(|(component, tag)| identifier(component) && tag == version);
    }
    for base in ["postgres", "redis"] {
        if let Some((repository, hash)) = image.split_once('@')
            && digest(hash)
            && (repository == base
                || repository
                    .strip_prefix(&(base.to_owned() + ":"))
                    .is_some_and(revision))
        {
            return true;
        }
    }
    false
}
fn env_files(raw: Option<&Value>, policy: &Policy, service: &str) -> Result<()> {
    let files = match raw {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::String(value)) => vec![Value::String(value.clone())],
        Some(Value::Array(values)) => values.clone(),
        _ => anyhow::bail!("env_file must contain relative filenames"),
    };
    for raw in files {
        let name = raw
            .as_str()
            .filter(|s| !s.contains(['$', '\0', '\n', '\r']) && !s.starts_with('/'))
            .ok_or_else(|| anyhow!("env_file must be a literal app-relative filename"))?;
        let clean = clean_path(name);
        let allowed = clean == "secrets.env"
            || clean == format!("secrets/current/{service}.env")
            || clean == format!("secrets/{service}.env")
            || service == "postgres"
                && matches!(
                    clean.as_str(),
                    "postgres-owner.env" | "secrets/postgres-owner.env"
                );
        ensure!(allowed, "env_file is outside service secret scope");
        if let Ok(real) = std::fs::canonicalize(Path::new(&policy.app_dir).join(clean)) {
            ensure!(
                real.starts_with(&policy.app_dir),
                "env_file symlink escapes this app"
            );
        }
    }
    Ok(())
}
const SERVICE_FIELDS: &[&str] = &[
    "image",
    "user",
    "read_only",
    "cap_drop",
    "cap_add",
    "security_opt",
    "logging",
    "sysctls",
    "tmpfs",
    "restart",
    "networks",
    "env_file",
    "environment",
    "volumes",
    "healthcheck",
    "depends_on",
    "mem_limit",
    "memswap_limit",
    "cpus",
    "cpu_shares",
    "pids_limit",
    "stop_grace_period",
    "entrypoint",
    "command",
    "init",
    "working_dir",
    "ulimits",
];
fn service_valid(
    name: &str,
    service: &mut Map<String, Value>,
    doc: &Map<String, Value>,
    policy: &Policy,
    version: &str,
) -> Result<()> {
    check_fields(service, "service", SERVICE_FIELDS)?;
    let mut image = service
        .get("image")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("service image is required"))?
        .to_owned();
    for expression in [
        "${APP_VERSION:?set the exact release commit}",
        "${APP_VERSION:?}",
        "${APP_VERSION}",
        "${APP_VERSION:-latest}",
        "$APP_VERSION",
    ] {
        image = image.replace(expression, version);
    }
    static INTERPOLATION: OnceLock<regex::Regex> = OnceLock::new();
    image = INTERPOLATION
        .get_or_init(|| regex::Regex::new(r"\$\{APP_VERSION:\?[^}]*\}").unwrap())
        .replace_all(&image, regex::NoExpand(version))
        .into_owned();
    ensure!(
        allowed_image(&image, &policy.image_prefix, version),
        "service {} uses an unauthorized image",
        quote(name)
    );
    service.insert("image".into(), image.clone().into());
    env_files(service.get("env_file"), policy, name)?;
    if let Some(raw) = service.get("volumes") {
        let mounts = raw
            .as_array()
            .ok_or_else(|| anyhow!("service volumes must be a list"))?;
        let volumes = object(doc.get("volumes")).unwrap();
        for raw in mounts {
            let mount = raw
                .as_str()
                .ok_or_else(|| anyhow!("only named volume short syntax is permitted"))?;
            let parts: Vec<_> = mount.split(':').collect();
            ensure!(
                (2..=3).contains(&parts.len()) && identifier(parts[0]) && parts[1].starts_with('/'),
                "host and anonymous mounts refused"
            );
            ensure!(volumes.contains_key(parts[0]), "undeclared volume refused");
            ensure!(
                parts.len() != 3 || matches!(parts[2], "ro" | "rw"),
                "unsupported volume option"
            );
        }
    }
    if let Some(raw) = service.get("cap_drop") {
        ensure!(
            raw.as_array()
                .is_some_and(|v| v.len() == 1 && v[0] == "ALL"),
            "all capabilities must be dropped"
        );
    } else {
        service.insert("cap_drop".into(), json!(["ALL"]));
    }
    let postgres = image.starts_with("postgres@")
        || image.starts_with("postgres:")
        || image.starts_with(&(policy.image_prefix.clone() + "postgres:"))
        || image.starts_with(&(policy.image_prefix.clone() + "postgres@"));
    if let Some(raw) = service.get("cap_add") {
        let values = raw
            .as_array()
            .ok_or_else(|| anyhow!("cap_add must be a list"))?;
        for value in values {
            ensure!(
                value.as_str().is_some_and(|cap| cap == "NET_BIND_SERVICE"
                    || postgres
                        && [
                            "CHOWN",
                            "DAC_OVERRIDE",
                            "FOWNER",
                            "SETGID",
                            "SETUID",
                            "SETPCAP",
                            "SYS_NICE"
                        ]
                        .contains(&cap)),
                "capability grant refused"
            );
        }
    } else if postgres {
        service.insert(
            "cap_add".into(),
            json!(["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]),
        );
    }
    if let Some(raw) = service.get("security_opt") {
        ensure!(
            raw.as_array().is_some_and(|v| v.len() == 1
                && (v[0] == "no-new-privileges:true" || v[0] == "no-new-privileges=true")),
            "security option refused"
        );
    } else {
        service.insert("security_opt".into(), json!(["no-new-privileges:true"]));
    }
    if let Some(raw) = service.get("sysctls") {
        ensure!(
            raw.as_object().is_some_and(|m| m.len() == 1
                && m.get("net.ipv4.ip_unprivileged_port_start")
                    .is_some_and(|v| resources::scalar(v) == "0")),
            "sysctl refused"
        );
    }
    let networks = object(doc.get("networks")).unwrap();
    let mut names = vec![];
    match service.get("networks") {
        None => names.push("default".to_owned()),
        Some(Value::Array(values)) => {
            for value in values {
                names.push(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("invalid service network"))?
                        .to_owned(),
                );
            }
        }
        Some(Value::Object(values)) => {
            for (name, configuration) in values {
                let options = object(Some(configuration))
                    .ok_or_else(|| anyhow!("network attachment options refused"))?;
                check_fields(options, "network attachment", &["aliases"])?;
                if let Some(raw) = options.get("aliases") {
                    let aliases = raw
                        .as_array()
                        .ok_or_else(|| anyhow!("invalid network aliases"))?;
                    let network = object(networks.get(name)).unwrap();
                    ensure!(
                        network.get("external") != Some(&Value::Bool(true)),
                        "aliases on ingress refused"
                    );
                    for alias in aliases {
                        ensure!(
                            alias.as_str().is_some_and(identifier),
                            "invalid network alias"
                        );
                    }
                }
                names.push(name.clone());
            }
        }
        _ => anyhow::bail!("invalid service networks"),
    }
    for network_name in names {
        if network_name == "default" && !networks.contains_key(&network_name) {
            continue;
        }
        let raw = networks
            .get(&network_name)
            .ok_or_else(|| anyhow!("undeclared network refused"))?;
        let options = object(Some(raw)).unwrap();
        ensure!(
            options.get("external") != Some(&Value::Bool(true))
                || name == policy.app.clone() + "-gate",
            "only this app's gateway may join ingress"
        );
    }
    if let Some(raw) = service.get("logging") {
        let logging = raw
            .as_object()
            .ok_or_else(|| anyhow!("invalid logging configuration"))?;
        check_fields(logging, "logging", &["driver", "options"])?;
        ensure!(
            logging.get("driver") == Some(&json!("json-file")),
            "logging driver refused"
        );
        let options =
            object(logging.get("options")).ok_or_else(|| anyhow!("invalid logging options"))?;
        check_fields(options, "logging option", &["max-size", "max-file"])?;
    }
    service.insert(
        "logging".into(),
        json!({"driver":"json-file","options":{"max-size":"10m","max-file":"3"}}),
    );
    if let Some(raw) = service.get("pids_limit") {
        ensure!(
            resources::scalar(raw)
                .parse::<i64>()
                .is_ok_and(|n| (1..=1024).contains(&n)),
            "pids_limit must be between 1 and 1024"
        );
    } else {
        service.insert("pids_limit".into(), 128.into());
    }
    if let Some(raw) = service.get("ulimits") {
        let limits = raw.as_object().ok_or_else(|| anyhow!("invalid ulimits"))?;
        check_fields(limits, "ulimit", &["nofile", "nproc"])?;
        for raw in limits.values() {
            let values = raw
                .as_object()
                .ok_or_else(|| anyhow!("ulimits require bounded soft/hard values"))?;
            check_fields(values, "ulimit", &["soft", "hard"])?;
            let soft = values
                .get("soft")
                .and_then(|v| resources::scalar(v).parse::<i64>().ok());
            let hard = values
                .get("hard")
                .and_then(|v| resources::scalar(v).parse::<i64>().ok());
            ensure!(
                matches!((soft,hard),(Some(s),Some(h))if s>0&&h>=s&&h<=65536),
                "ulimits must be bounded"
            );
        }
    }
    if let Some(raw) = service.get("healthcheck") {
        let health = raw
            .as_object()
            .ok_or_else(|| anyhow!("invalid healthcheck"))?;
        check_fields(
            health,
            "healthcheck",
            &[
                "test",
                "interval",
                "timeout",
                "retries",
                "start_period",
                "start_interval",
                "disable",
            ],
        )?;
    }
    Ok(())
}
pub fn validate(body: &[u8], policy: &Policy, version: &str) -> Result<Vec<u8>> {
    policy.check()?;
    ensure!(revision(version), "invalid release revision");
    let value = yaml::parse(body)?;
    let mut doc = value
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("workload must be an object"))?;
    check_fields(&doc, "workload", &["services", "networks", "volumes"])?;
    let mut services = doc
        .get("services")
        .and_then(Value::as_object)
        .filter(|s| s.len() <= 32)
        .cloned()
        .ok_or_else(|| anyhow!("workload needs an object with at most 32 services"))?;
    resources_valid(&mut doc, policy)?;
    for (name, raw) in &mut services {
        ensure!(identifier(name), "invalid service name");
        let service = raw
            .as_object_mut()
            .ok_or_else(|| anyhow!("service must be an object"))?;
        service_valid(name, service, &doc, policy, version)?;
    }
    resources::bound_services(&mut services, policy.resources.as_ref())?;
    doc.insert("services".into(), services.into());
    doc.insert("name".into(), policy.app.clone().into());
    let document = Value::Object(doc);
    super::json::pretty(&document)
}
