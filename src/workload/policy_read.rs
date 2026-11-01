//! Protected policy JSON rejects unknown fields at every typed boundary.
use super::{policy::Policy, yaml::MAX_BYTES};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Map, Value, value::RawValue};
use std::collections::BTreeSet;
#[derive(Clone, Copy)]
enum Shape {
    Policy,
    Resource,
    Budget,
    Readiness,
    Probe,
    Static,
    Limits,
    Serving,
    Header,
    Deployment,
    Backup,
}
fn fields(shape: Shape) -> &'static [&'static str] {
    match shape {
        Shape::Policy => &[
            "version",
            "app",
            "app_dir",
            "image_prefix",
            "shared_network",
            "source_repository",
            "owner_approval",
            "repository_id",
            "resources",
            "readiness",
            "ingress_network",
            "require_stateful_contract",
            "require_delivery_authorization",
            "static",
            "deployment",
            "routine_backup",
        ],
        Shape::Resource => &[
            "aggregate_mode",
            "cgroup_parent",
            "default",
            "services",
            "max_memory_bytes",
            "max_memory_reserve_bytes",
            "max_memory_swap_bytes",
            "max_milli_cpus",
            "startup_allowance_bytes",
        ],
        Shape::Budget => &[
            "memory_bytes",
            "memory_reserve_bytes",
            "memory_swap_bytes",
            "milli_cpus",
        ],
        Shape::Readiness => &["probes"],
        Shape::Probe => &["url", "revision_field"],
        Shape::Static => &[
            "image_directory",
            "limits",
            "serving",
            "gate_config_sha256",
            "proxy",
            "hostnames",
        ],
        Shape::Limits => &["max_bytes", "max_file_bytes"],
        Shape::Serving => &[
            "fallbacks",
            "deny_paths",
            "headers",
            "header_rules",
            "precompressed",
            "encode",
            "encode_content_types",
        ],
        Shape::Header => &[
            "paths",
            "except_paths",
            "path_regexp",
            "methods",
            "existing_file",
            "headers",
        ],
        Shape::Deployment => &["route_path", "proxy", "proxy_dir"],
        Shape::Backup => &[
            "workflow_repository",
            "workflow_revision",
            "program_sha256",
            "timeout_seconds",
        ],
    }
}
fn normalized(value: Value, shape: Shape) -> Result<Value> {
    if value.is_null() {
        return Ok(value);
    }
    let Value::Object(values) = value else {
        anyhow::bail!("invalid policy shape");
    };
    let mut output = Map::new();
    let mut seen = BTreeSet::new();
    for (key, mut value) in values {
        let field = fields(shape)
            .iter()
            .find(|field| field.eq_ignore_ascii_case(&key))
            .ok_or_else(|| anyhow!("unknown policy field"))?;
        ensure!(seen.insert(*field), "ambiguous policy field");
        let nested = match (shape, *field) {
            (Shape::Policy, "resources") => Some(Shape::Resource),
            (Shape::Policy, "readiness") => Some(Shape::Readiness),
            (Shape::Policy, "static") => Some(Shape::Static),
            (Shape::Policy, "deployment") => Some(Shape::Deployment),
            (Shape::Policy, "routine_backup") => Some(Shape::Backup),
            (Shape::Resource, "default") => Some(Shape::Budget),
            (Shape::Static, "limits") => Some(Shape::Limits),
            (Shape::Static, "serving") => Some(Shape::Serving),
            _ => None,
        };
        if let Some(shape) = nested {
            value = normalized(value, shape)?;
        } else if matches!((shape, *field), (Shape::Resource, "services")) && !value.is_null() {
            let Value::Object(values) = value else {
                anyhow::bail!("invalid policy services");
            };
            value = Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| normalized(value, Shape::Budget).map(|value| (key, value)))
                    .collect::<Result<_>>()?,
            );
        } else if matches!(
            (shape, *field),
            (Shape::Readiness, "probes") | (Shape::Serving, "header_rules")
        ) && !value.is_null()
        {
            let Value::Array(values) = value else {
                anyhow::bail!("invalid policy entries");
            };
            let child = if matches!(shape, Shape::Readiness) {
                Shape::Probe
            } else {
                Shape::Header
            };
            value = Value::Array(
                values
                    .into_iter()
                    .map(|value| normalized(value, child))
                    .collect::<Result<_>>()?,
            );
        } else if matches!((shape, *field), (Shape::Serving | Shape::Header, "headers"))
            && let Some(values) = value.as_object_mut()
        {
            for value in values.values_mut() {
                if value.is_null() {
                    *value = Value::String(String::new());
                }
            }
        }
        output.insert((*field).into(), value);
    }
    Ok(output.into())
}
pub fn read_policy(body: &[u8]) -> Result<Policy> {
    let bounded = || anyhow!("invalid bounded host workload policy document");
    ensure!(
        body.len() <= MAX_BYTES,
        "invalid bounded host workload policy document"
    );
    let mut stream = serde_json::Deserializer::from_slice(body).into_iter::<Box<RawValue>>();
    let raw = stream.next().ok_or_else(bounded)?.map_err(|_| bounded())?;
    let offset = stream.byte_offset();
    let value = crate::strict::value(raw.get().as_bytes(), MAX_BYTES).map_err(|_| bounded())?;
    let value = normalized(value, Shape::Policy)
        .map_err(|_| anyhow!("invalid host workload policy document"))?;
    let policy: Policy = serde_json::from_value(value)
        .map_err(|_| anyhow!("invalid host workload policy document"))?;
    ensure!(
        body[offset..]
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r')),
        "host workload policy must contain one document"
    );
    policy.check()?;
    Ok(policy)
}
pub fn read_resources(body: &[u8]) -> Result<super::resources::ResourcePolicy> {
    let value = normalized(crate::strict::value(body, MAX_BYTES)?, Shape::Resource)?;
    let resources: super::resources::ResourcePolicy = serde_json::from_value(value)?;
    resources.check()?;
    Ok(resources)
}
pub fn read_readiness(body: &[u8]) -> Result<super::policy::ReadinessPolicy> {
    let value = normalized(crate::strict::value(body, MAX_BYTES)?, Shape::Readiness)?;
    let readiness: super::policy::ReadinessPolicy = serde_json::from_value(value)?;
    readiness.check()?;
    Ok(readiness)
}
