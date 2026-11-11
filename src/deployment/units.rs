use super::{model::*, store::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub fn namespace(application: &str, instance: &str) -> Result<String> {
    Store::instance_key(application, instance)?;
    let hash = document_digest(format!("{application}\0{instance}").as_bytes());
    Ok(format!("kmz-{}", &hash[7..27]))
}
pub fn object_name(application: &str, instance: &str, kind: &str, logical: &str) -> Result<String> {
    ensure!(
        name(logical) && ["network", "volume"].contains(&kind),
        "invalid retained object scope"
    );
    let hash = document_digest(format!("{kind}\0{logical}").as_bytes());
    Ok(format!(
        "{}-{}-{}",
        namespace(application, instance)?,
        if kind == "network" { "n" } else { "v" },
        &hash[7..27]
    ))
}
pub fn config_path(container: &str) -> Result<PathBuf> {
    let service = container.strip_prefix("kmz-").is_some_and(|rest| {
        rest.is_ascii()
            && rest.len() >= 22
            && hex(&rest[..20], 20)
            && rest.as_bytes()[20] == b'-'
            && name(&rest[21..])
    });
    let task = container.strip_suffix(".service").is_some_and(|body| {
        ["backup", "prepare", "reconcile"].iter().any(|kind| {
            body.strip_prefix(&format!("komizo-{kind}-"))
                .is_some_and(|id| hex(id, 32))
        })
    });
    let allocation = container.strip_prefix("cgroup-").is_some_and(|value| {
        ["root", "control", "proxy", "production", "previews"].contains(&value)
            || value.strip_prefix("kmz-").is_some_and(|id| hex(id, 20))
    });
    ensure!(
        service || task || allocation,
        "configuration name is outside exact owned service/task/resource scopes"
    );
    Ok(Path::new(super::system::SERVICE_CONFIGS).join(format!("{container}.json")))
}

pub struct Bindings<'a> {
    pub application: &'a str,
    pub instance: &'a str,
    pub release_digest: &'a str,
    pub ownership: &'a str,
    pub networks: &'a BTreeMap<String, ObjectRecord>,
    pub volumes: &'a BTreeMap<String, ObjectRecord>,
    pub environment_files: &'a BTreeMap<String, String>,
    pub secrets: &'a BTreeMap<String, String>,
    pub ingress: Option<&'a str>,
}

/// The same finite native argv contract drives jobs and protected service configuration.
pub fn options(
    kind: super::cgroups::WorkloadKind,
    service: &str,
    value: &Container,
    bindings: &Bindings<'_>,
) -> Result<Vec<String>> {
    ensure!(
        name(service) && digest(bindings.release_digest) && hex(bindings.ownership, 32),
        "invalid runtime identity"
    );
    let mut args = vec![
        "--pull=never".into(),
        "--read-only".into(),
        "--read-only-tmpfs=false".into(),
        "--cap-drop=all".into(),
        "--security-opt=no-new-privileges".into(),
        format!(
            "--security-opt=apparmor={}",
            super::bootstrap::WORKLOAD_PROFILE
        ),
        "--http-proxy=false".into(),
        "--restart=no".into(),
        "--image-volume=ignore".into(),
        "--cgroups=enabled".into(),
        "--log-driver=k8s-file".into(),
        "--log-opt=max-size=1048576".into(),
        "--user".into(),
        value.user.clone(),
        "--memory".into(),
        value.limits.memory_bytes.to_string(),
        "--memory-swap".into(),
        value.limits.memory_swap_bytes.to_string(),
        "--cpu-period=1000000".into(),
        "--cpu-quota".into(),
        (u64::from(value.limits.milli_cpus) * 1000).to_string(),
        "--pids-limit".into(),
        value.limits.pids.to_string(),
        "--cgroup-parent".into(),
        super::cgroups::workload_group(
            bindings.application,
            bindings.instance,
            kind,
            service,
            bindings.ownership,
        )?
        .relative()
        .into(),
        "--stop-timeout".into(),
        value.stop_timeout_seconds.to_string(),
    ];
    for (key, val) in [
        ("application", bindings.application),
        ("instance", bindings.instance),
        ("service", service),
        ("release", bindings.release_digest),
        ("ownership", bindings.ownership),
    ] {
        args.extend(["--label".into(), format!("io.komizo.{key}={val}")]);
    }
    for cap in &value.capabilities {
        args.extend(["--cap-add".into(), cap.clone()]);
    }
    if value.init {
        args.push("--init".into());
    }
    if let Some(dir) = &value.working_directory {
        args.extend(["--workdir".into(), dir.clone()]);
    }
    if !value.entrypoint.is_empty() {
        args.extend([
            "--entrypoint".into(),
            serde_json::to_string(&value.entrypoint)?,
        ]);
    }
    for (key, val) in &value.environment {
        args.extend(["--env".into(), format!("{key}={val}")]);
    }
    for alias in &value.environment_files {
        let path = bindings
            .environment_files
            .get(alias)
            .ok_or_else(|| anyhow!("missing staged environment reference"))?;
        ensure!(absolute(path), "invalid staged environment path");
        args.extend(["--env-file".into(), path.clone()]);
    }
    for secret in &value.secrets {
        let source = bindings
            .secrets
            .get(&secret.source)
            .ok_or_else(|| anyhow!("missing staged native secret"))?;
        ensure!(
            absolute(source) && absolute(&secret.target),
            "invalid staged native secret binding"
        );
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,source={source},destination={},readonly",
                secret.target
            ),
        ]);
    }
    for mount in &value.volumes {
        let source = bindings
            .volumes
            .get(&mount.name)
            .ok_or_else(|| anyhow!("missing retained volume binding"))?;
        ensure!(
            name(&source.name) && absolute(&mount.target),
            "invalid retained volume binding"
        );
        args.extend([
            "--mount".into(),
            format!(
                "type=volume,source={},destination={},{}",
                source.name,
                mount.target,
                if mount.read_only { "ro" } else { "rw" }
            ),
        ]);
    }
    for (path, tmp) in &value.tmpfs {
        args.extend([
            "--tmpfs".into(),
            format!(
                "{path}:rw,nosuid,nodev,{},size={},mode={:04o}",
                if tmp.executable { "exec" } else { "noexec" },
                tmp.size_bytes,
                tmp.mode
            ),
        ]);
    }
    for key in &value.networks {
        let network = bindings
            .networks
            .get(key)
            .ok_or_else(|| anyhow!("missing owned network binding"))?;
        ensure!(name(&network.name), "invalid owned network name");
        args.extend([
            "--network".into(),
            format!("{}:alias={service}", network.name),
        ]);
    }
    if let Some(network) = bindings.ingress {
        ensure!(name(network), "invalid owned ingress network");
        args.extend(["--network".into(), network.to_owned()]);
    } else if value.networks.is_empty() {
        args.extend(["--network".into(), "none".into()]);
    }
    for (key, limit) in &value.ulimits {
        args.extend([
            "--ulimit".into(),
            format!("{key}={}:{}", limit.soft, limit.hard),
        ]);
    }
    for (key, val) in &value.sysctls {
        args.extend(["--sysctl".into(), format!("{key}={val}")]);
    }
    if let Some(health) = &value.health {
        args.extend([
            "--health-cmd".into(),
            serde_json::to_string(&health.command)?,
            "--health-interval".into(),
            "disable".into(),
            "--health-timeout".into(),
            format!("{}s", health.timeout_seconds),
            "--health-retries".into(),
            health.retries.to_string(),
            "--health-start-period".into(),
            format!("{}s", health.start_period_seconds),
            "--health-on-failure=none".into(),
            "--health-max-log-count=5".into(),
            "--health-max-log-size=500".into(),
        ]);
    }
    Ok(args)
}

/// Root-owned launch data, never an executable service-manager language.
/// Before use, the caller rederives these exact bytes from the admitted release
/// and protected object/credential bindings and verifies the ownership ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub service: String,
    pub release_digest: String,
    pub ownership: String,
    pub container_name: String,
    pub image_id: String,
    pub options: Vec<String>,
    pub command: Vec<String>,
    pub health: Option<Health>,
    pub wanted: bool,
}
impl ServiceConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.service-config"
                && self.version == 1
                && name(&self.application)
                && name(&self.instance)
                && name(&self.service)
                && digest(&self.release_digest)
                && digest(&self.image_id)
                && hex(&self.ownership, 32)
                && self.container_name
                    == format!(
                        "{}-{}",
                        namespace(&self.application, &self.instance)?,
                        self.service
                    )
                && self.options.len() <= 4096
                && self.options.iter().all(|v| safe_text(v, 65536))
                && self.command.len() <= 128
                && self.command.iter().all(|v| safe_text(v, 8192)),
            "protected service configuration identity or bounds differ"
        );
        config_path(&self.container_name)?;
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let body = canonical(&serde_json::to_value(self)?)?;
        ensure!(
            body.len() <= 1 << 20,
            "protected service configuration exceeds bound"
        );
        Ok(body)
    }
    pub fn parse(body: &[u8]) -> Result<Self> {
        let result: Self = serde_json::from_value(crate::strict::value(body, 1 << 20)?)?;
        result.validate()?;
        ensure!(
            result.bytes()? == body,
            "service configuration is not canonical"
        );
        Ok(result)
    }
}

pub fn service_config(
    document: &ReleaseDocument,
    service: &str,
    bindings: &Bindings<'_>,
    wanted: bool,
) -> Result<ServiceConfig> {
    document.release.validate()?;
    let value = document
        .release
        .workload
        .services
        .get(service)
        .ok_or_else(|| anyhow!("service configuration requires a declared service"))?;
    ensure!(
        bindings.application == document.release.application
            && bindings.release_digest == document.digest,
        "runtime bindings differ from the admitted release"
    );
    let Artifact::Image { config_digest, .. } = &document.release.artifacts[&value.artifact] else {
        return Err(anyhow!("service artifact is not an image"));
    };
    let result = ServiceConfig {
        kind: "komizo.service-config".into(),
        version: 1,
        application: bindings.application.into(),
        instance: bindings.instance.into(),
        service: service.into(),
        release_digest: bindings.release_digest.into(),
        ownership: bindings.ownership.into(),
        container_name: format!(
            "{}-{service}",
            namespace(bindings.application, bindings.instance)?
        ),
        image_id: config_digest.clone(),
        options: options(
            super::cgroups::WorkloadKind::Service,
            service,
            value,
            bindings,
        )?,
        command: value.command.clone(),
        health: value.health.clone(),
        wanted,
    };
    result.validate()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_names_are_only_exact_generated_scopes() {
        let container = format!("{}-api", namespace("mailroom", "production").unwrap());
        assert_eq!(
            config_path(&container).unwrap(),
            Path::new(super::super::system::SERVICE_CONFIGS).join(format!("{container}.json"))
        );
        assert!(config_path(&format!("komizo-backup-{}.service", "a".repeat(32))).is_ok());
        assert!(config_path("cgroup-root").is_ok());
        for name in [
            "../outside",
            "api",
            "foreign.service",
            "kmz-ééééééééééééééééééééé-api",
            "cgroup-unknown",
            "komizo-backup-short.service",
            "/tmp/config",
        ] {
            assert!(config_path(name).is_err(), "{name}");
        }
    }
}
