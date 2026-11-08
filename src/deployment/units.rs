use super::{model::*, store::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use std::{collections::BTreeMap, fmt::Write};

pub fn namespace(application: &str, instance: &str) -> Result<String> {
    Store::instance_key(application, instance)?;
    let hash = document_digest(format!("{application}\0{instance}").as_bytes());
    Ok(format!("kmz-{}", &hash[7..27]))
}
pub fn slice(application: &str, instance: &str) -> Result<String> {
    Ok(format!(
        "komizo-i{}.slice",
        &namespace(application, instance)?[4..]
    ))
}
fn scalar(value: &str) -> String {
    value.replace('%', "%%").replace('$', "$$")
}
pub fn word(value: &str) -> String {
    serde_json::to_string(&scalar(value)).expect("string serialization")
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

/// The same finite argv contract drives jobs and the protected Quadlet renderer.
pub fn options(service: &str, value: &Container, bindings: &Bindings<'_>) -> Result<Vec<String>> {
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
        "--http-proxy=false".into(),
        "--restart=no".into(),
        "--image-volume=ignore".into(),
        "--log-driver=journald".into(),
        "--user".into(),
        value.user.clone(),
        "--memory".into(),
        value.limits.memory_bytes.to_string(),
        "--memory-swap".into(),
        value.limits.memory_swap_bytes.to_string(),
        "--cpus".into(),
        format!(
            "{}.{:03}",
            value.limits.milli_cpus / 1000,
            value.limits.milli_cpus % 1000
        ),
        "--pids-limit".into(),
        value.limits.pids.to_string(),
        "--cgroup-parent".into(),
        slice(bindings.application, bindings.instance)?,
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
            name(source) && absolute(&secret.target),
            "invalid staged native secret binding"
        );
        args.extend([
            "--secret".into(),
            format!(
                "{source},type=mount,target={},uid={},gid={},mode={:04o}",
                secret.target, secret.uid, secret.gid, secret.mode
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
            format!("{}s", health.interval_seconds),
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
        if let Some(interval) = health.start_interval_seconds {
            args.extend([
                "--health-startup-cmd".into(),
                serde_json::to_string(&health.command)?,
                "--health-startup-interval".into(),
                format!("{interval}s"),
                "--health-startup-timeout".into(),
                format!("{}s", health.timeout_seconds),
                "--health-startup-retries=0".into(),
                "--health-startup-success=1".into(),
            ]);
        }
    }
    Ok(args)
}

pub fn quadlet(
    document: &ReleaseDocument,
    service: &str,
    bindings: &Bindings<'_>,
    wanted: bool,
) -> Result<String> {
    document.release.validate()?;
    let value = document
        .release
        .workload
        .services
        .get(service)
        .ok_or_else(|| anyhow!("Quadlet requires a declared service"))?;
    let reference = document.release.artifacts[&value.artifact].reference();
    let ns = namespace(bindings.application, bindings.instance)?;
    let mut out = String::new();
    writeln!(
        out,
        "[Unit]\nDescription=Komizo application service\nAfter=network-online.target\nWants=network-online.target\nRequiresMountsFor=/var/lib/komizo\n[Container]\nImage={reference}\nContainerName={ns}-{service}\nGlobalArgs=--remote=false\nCgroupsMode=enabled\nPodmanArgs={}",
        options(service, value, bindings)?
            .iter()
            .map(|v| word(v))
            .collect::<Vec<_>>()
            .join(" ")
    )?;
    if !value.command.is_empty() {
        writeln!(
            out,
            "Exec={}",
            value
                .command
                .iter()
                .map(|v| word(v))
                .collect::<Vec<_>>()
                .join(" ")
        )?;
    }
    writeln!(
        out,
        "[Service]\nSlice={}\nRestart=on-failure\nRestartSec=3\nTimeoutStartSec=300\nTimeoutStopSec={}\nExecStartPre=/usr/local/bin/komizo-box guard --application {} --instance {} --service {}\n[Install]",
        slice(bindings.application, bindings.instance)?,
        value.stop_timeout_seconds + 30,
        bindings.application,
        bindings.instance,
        service
    )?;
    if wanted {
        out.push_str("WantedBy=komizo-workloads.target\n");
    }
    Ok(out)
}

pub fn resource_slice(limits: &Limits) -> Result<String> {
    limits.validate()?;
    Ok(format!(
        "[Unit]\nDescription=Komizo instance allocation\n[Slice]\nCPUAccounting=yes\nMemoryAccounting=yes\nTasksAccounting=yes\nMemoryMax={}\nMemorySwapMax={}\nCPUQuota={}.{}%\nTasksMax={}\n",
        limits.memory_bytes,
        limits.memory_swap_bytes - limits.memory_bytes,
        limits.milli_cpus / 10,
        limits.milli_cpus % 10,
        limits.pids
    ))
}
