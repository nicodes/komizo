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
        "komizo-{}-i{}.slice",
        if instance == "production" {
            "production"
        } else {
            "previews"
        },
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
        "--cpu-period=1000000".into(),
        "--cpu-quota".into(),
        (u64::from(value.limits.milli_cpus) * 1000).to_string(),
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
    ensure!(
        bindings.application == document.release.application
            && bindings.release_digest == document.digest,
        "runtime bindings differ from the admitted release"
    );
    let Artifact::Image {
        config_digest: reference,
        ..
    } = &document.release.artifacts[&value.artifact]
    else {
        return Err(anyhow!("service artifact is not an image"));
    };
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
    if value.health.is_some() {
        writeln!(out, "[Unit]\nWants={ns}-{service}-health.timer")?;
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

pub fn health_units(
    application: &str,
    instance: &str,
    service: &str,
    health: &Health,
) -> Result<(String, String)> {
    ensure!(name(service), "invalid health service scope");
    let base = format!("{}-{service}", namespace(application, instance)?);
    let tick = health
        .start_interval_seconds
        .unwrap_or(health.interval_seconds)
        .min(health.interval_seconds);
    let unit = format!(
        "[Unit]\nDescription=Komizo native health probe\nAfter={base}.service\nRequisite={base}.service\nPartOf={base}.service\n[Service]\nType=oneshot\nSlice={}\nTimeoutStartSec={}\nExecStart=/usr/local/bin/komizo-box health --application {application} --instance {instance} --service {service}\nStandardOutput=null\n",
        slice(application, instance)?,
        health.timeout_seconds + 20
    );
    let timer = format!(
        "[Unit]\nDescription=Komizo native health probe timer\nAfter={base}.service\nPartOf={base}.service\n[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec={tick}s\nAccuracySec=100ms\nUnit={base}-health.service\n"
    );
    Ok((unit, timer))
}

pub fn resource_slice(limits: &Limits) -> Result<String> {
    limits.validate()?;
    Ok(format!(
        "[Unit]\nDescription=Komizo instance allocation\n[Slice]\nCPUAccounting=yes\nMemoryAccounting=yes\nTasksAccounting=yes\nMemoryMax={}\nMemorySwapMax={}\nCPUQuota={}.{}%\nCPUQuotaPeriodSec=1s\nTasksMax={}\n",
        limits.memory_bytes,
        limits.memory_swap_bytes - limits.memory_bytes,
        limits.milli_cpus / 10,
        limits.milli_cpus % 10,
        limits.pids
    ))
}

pub fn controlled_slice(limits: &Limits, controls: &ResourceControls) -> Result<String> {
    controls.validate(limits)?;
    let mut out = resource_slice(limits)?;
    writeln!(out, "MemoryLow={}", controls.memory_low_bytes)?;
    if controls.memory_high_bytes > 0 {
        writeln!(out, "MemoryHigh={}", controls.memory_high_bytes)?;
    }
    if let Some(weight) = controls.cpu_weight {
        writeln!(out, "CPUWeight={weight}")?;
    }
    if let Some(weight) = controls.io_weight {
        writeln!(out, "IOWeight={weight}")?;
    }
    for rate in &controls.io_max {
        writeln!(
            out,
            "IOReadBandwidthMax=/dev/block/{} {}\nIOWriteBandwidthMax=/dev/block/{} {}",
            rate.device, rate.read_bytes_per_second, rate.device, rate.write_bytes_per_second
        )?;
    }
    Ok(out)
}
