use super::{
    controller,
    engine::{Engine, normalize_id},
    jobs,
    model::*,
    store::{self, Installed, Store},
    system, units,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub const STATE: &str = "/var/lib/komizo";
pub const POLICIES: &str = "/etc/komizo/apps";

pub fn owned(
    store: &Store,
    application: &str,
    instance: &str,
    service: &str,
    engine: &Engine,
) -> Result<(Installed, ReleaseDocument, Value)> {
    ensure!(
        name(application) && name(instance) && name(service),
        "invalid native service scope"
    );
    let installed = store
        .installed(application, instance)?
        .ok_or_else(|| anyhow!("application instance is not installed"))?;
    let document = store.release(&installed.release_digest)?;
    ensure!(
        document.release.workload.services.contains_key(service),
        "service is not part of the installed release"
    );
    let record = installed
        .resources
        .containers
        .get(service)
        .ok_or_else(|| anyhow!("service has no protected creation record"))?;
    let unit = Path::new(system::QUADLETS).join(format!(
        "{}-{service}.container",
        units::namespace(application, instance)?
    ));
    system::verify_unit(store, &unit, application, instance, &record.unit_sha256)?;
    let value = engine
        .owned_container(record, application, instance, service)?
        .ok_or_else(|| anyhow!("owned service is not present"))?;
    super::engine::service_mounts(&value, record, &document.release.workload.services[service])?;
    for mount in &document.release.workload.services[service].volumes {
        engine.owned_object(
            "volume",
            installed
                .resources
                .volumes
                .get(&mount.name)
                .ok_or_else(|| anyhow!("service retained volume record missing"))?,
        )?;
    }
    Ok((installed, document, value))
}

pub fn resource(application: &str, instance: &str, service: &str) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "resource access requires the local owner identity"
    );
    let store = Store::new(Path::new(STATE).to_owned())?;
    let engine = Engine {
        deadline: Instant::now() + Duration::from_secs(20),
    };
    let (installed, document, value) = owned(&store, application, instance, service, &engine)?;
    let container = &document.release.workload.services[service];
    let Artifact::Image {
        reference,
        config_digest,
        ..
    } = &document.release.artifacts[&container.artifact]
    else {
        return Err(anyhow!("installed service has no image identity"));
    };
    ensure!(
        normalize_id(value["Image"].as_str().unwrap_or("")) == *config_digest,
        "live service image differs from installed release"
    );
    let volumes = document
        .release
        .workload
        .volumes
        .keys()
        .map(|logical| {
            let record = installed
                .resources
                .volumes
                .get(logical)
                .ok_or_else(|| anyhow!("declared volume binding missing"))?;
            engine.owned_object("volume", record)?;
            Ok((logical.clone(), serde_json::to_value(record)?))
        })
        .collect::<Result<serde_json::Map<_, _>>>()?;
    let release = crate::strict::value(&document.canonical, MAX_DOCUMENT_BYTES)?;
    Ok(
        json!({"kind":"komizo.resource","version":1,"application":application,"instance":instance,"service":service,"release_digest":document.digest,"container_id":value["Id"],"container_name":installed.resources.containers[service].name,"image_ref":reference,"image_config_digest":config_digest,"volumes":volumes,"deployment":{"release":release,"release_digest":document.digest,"provider":document.release.providers}}),
    )
}

pub fn guard(application: &str, instance: &str, service: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "service guard requires protected owner execution"
    );
    super::bootstrap::dns_guard()?;
    super::bootstrap::dns_configuration_guard()?;
    let store = Store::new(Path::new(STATE).to_owned())?;
    let (policy, _) = controller::policy(Path::new(POLICIES), application)?;
    let installed = store
        .installed(application, instance)?
        .ok_or_else(|| anyhow!("service has no installed instance"))?;
    ensure!(
        installed.desired_running,
        "application instance is deliberately stopped"
    );
    let document = store.release(&installed.release_digest)?;
    policy.admit(&document.release, instance)?;
    super::data::require(
        &store,
        &installed,
        &document,
        &Engine {
            deadline: Instant::now() + Duration::from_secs(20),
        },
    )?;
    let container = document
        .release
        .workload
        .services
        .get(service)
        .ok_or_else(|| anyhow!("service is not installed"))?;
    if container.needs.values().any(|c| *c == Condition::Completed) {
        ensure!(
            !store
                .unresolved(application, instance)?
                .iter()
                .any(|op| op.reconciliation_required || op.operation_id != installed.operation_id),
            "service restart is fenced by an unresolved data operation"
        );
    }
    let record = installed
        .resources
        .containers
        .get(service)
        .ok_or_else(|| anyhow!("service creation record missing"))?;
    system::verify_unit(
        &store,
        &Path::new(system::QUADLETS).join(format!(
            "{}-{service}.container",
            units::namespace(application, instance)?
        )),
        application,
        instance,
        &record.unit_sha256,
    )?;
    let engine = Engine {
        deadline: Instant::now() + Duration::from_secs(20),
    };
    engine.image(&record.config_digest, &record.config_digest)?;
    if engine.exists("container", &record.name)? {
        engine.owned_container(record, application, instance, service)?;
    }
    for (name, condition) in &container.needs {
        match condition {
            Condition::Completed => ensure!(
                jobs::completed(&store, &document, name, &installed)?,
                "required one-shot job has not completed"
            ),
            Condition::Started | Condition::Healthy => {
                let record = installed
                    .resources
                    .containers
                    .get(name)
                    .ok_or_else(|| anyhow!("dependency creation record missing"))?;
                let value = engine
                    .owned_container(record, application, instance, name)?
                    .ok_or_else(|| anyhow!("required service is absent"))?;
                ensure!(
                    value["State"]["Running"] == true
                        && (*condition != Condition::Healthy
                            || value["State"]["Health"]["Status"] == "healthy"),
                    "required service has not reached its admitted readiness condition"
                );
            }
        }
    }
    for snapshot in installed.secret_snapshots.values() {
        let body = store::read_protected(Path::new(&snapshot.path), 128 << 10)?;
        ensure!(
            document_digest(&body) == snapshot.sha256,
            "installed secret snapshot changed"
        );
    }
    for mount in &container.volumes {
        engine.owned_object("volume", &installed.resources.volumes[&mount.name])?;
    }
    Ok(())
}

pub fn health(application: &str, instance: &str, service: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "health observation requires protected owner execution"
    );
    let store = Store::new(Path::new(STATE).to_owned())?;
    let namespace = units::namespace(application, instance)?;
    let lockkey = document_digest(service.as_bytes());
    let _guard = store.lock(
        &format!("probe-{}", &namespace[4..]),
        &format!("service-{}", &lockkey[7..27]),
    )?;
    let engine = Engine {
        deadline: Instant::now() + Duration::from_secs(320),
    };
    let (installed, document, value) = owned(&store, application, instance, service, &engine)?;
    ensure!(
        installed.desired_running && value["State"]["Running"] == true,
        "health service is not running"
    );
    let health = document.release.workload.services[service]
        .health
        .as_ref()
        .ok_or_else(|| anyhow!("service has no admitted healthcheck"))?;
    let started = chrono::DateTime::parse_from_rfc3339(
        value["State"]["StartedAt"]
            .as_str()
            .ok_or_else(|| anyhow!("service start time missing"))?,
    )?
    .timestamp();
    let now = controller::now()?;
    let interval = if now.saturating_sub(started) <= i64::from(health.start_period_seconds) {
        health
            .start_interval_seconds
            .unwrap_or(health.interval_seconds)
    } else {
        health.interval_seconds
    };
    let path = store
        .root
        .join("probes")
        .join(namespace)
        .join(format!("{service}.json"));
    if path.try_exists()? {
        let previous = crate::strict::value(&store::read_protected(&path, 4096)?, 4096)?;
        if previous["container_id"] == value["Id"]
            && previous["checked_at"]
                .as_i64()
                .is_some_and(|t| now >= t && now - t < i64::from(interval))
        {
            return Ok(());
        }
    }
    let id = value["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("service identity missing"))?;
    let probe = Engine {
        deadline: Instant::now() + Duration::from_secs(u64::from(health.timeout_seconds) + 15),
    };
    probe.health(id)?;
    store::atomic(
        &path,
        &serde_json::to_vec(
            &json!({"kind":"komizo.probe","version":1,"container_id":id,"checked_at":now}),
        )?,
        0o600,
    )
}

pub fn logs(application: &str, instance: &str, service: &str) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "log access requires the owner identity"
    );
    ensure!(
        name(application) && name(instance) && name(service),
        "invalid log scope"
    );
    let store = Store::new(Path::new(STATE).into())?;
    let installed = store
        .installed(application, instance)?
        .ok_or_else(|| anyhow!("instance is not installed"))?;
    let document = store.release(&installed.release_digest)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let engine = Engine { deadline };
    let id = if document.release.workload.jobs.contains_key(service) {
        jobs::log_id(&store, &document, &installed, service, deadline)?
    } else {
        let record = installed
            .resources
            .containers
            .get(service)
            .ok_or_else(|| anyhow!("service has no protected creation record"))?;
        system::verify_unit(
            &store,
            &Path::new(system::QUADLETS).join(format!(
                "{}-{service}.container",
                units::namespace(application, instance)?
            )),
            application,
            instance,
            &record.unit_sha256,
        )?;
        engine
            .owned_container(record, application, instance, service)?
            .and_then(|value| value["Id"].as_str().map(str::to_owned))
            .unwrap_or_else(|| record.id.clone())
    };
    ensure!(
        hex(&id, 64),
        "log selection has no exact recorded container ID"
    );
    let mut command = std::process::Command::new("/usr/bin/journalctl");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .args(["--quiet", "--no-pager", "--output=cat", "--lines=200"])
        .arg(format!("CONTAINER_ID_FULL={id}"));
    let result = crate::process::capture(&mut command, None, 256 << 10, deadline, || false)?;
    ensure!(
        result.status.success(),
        "bounded native log observation failed"
    );
    let text = redact(
        &installed,
        &document,
        &String::from_utf8_lossy(&result.stdout),
    )?;
    Ok(
        json!({"kind":"komizo.logs","version":1,"application":application,"instance":instance,"service":service,"release_digest":installed.release_digest,"container_id":id,"text":text}),
    )
}

pub(crate) fn redact(
    installed: &Installed,
    document: &ReleaseDocument,
    text: &str,
) -> Result<String> {
    let environment = document
        .release
        .workload
        .services
        .values()
        .chain(document.release.workload.jobs.values())
        .flat_map(|c| c.environment_files.iter())
        .collect::<std::collections::BTreeSet<_>>();
    let mut values = std::collections::BTreeSet::new();
    for (alias, snapshot) in &installed.secret_snapshots {
        let body = store::read_protected(Path::new(&snapshot.path), 128 << 10)?;
        ensure!(
            document_digest(&body) == snapshot.sha256,
            "installed secret identity changed during log observation"
        );
        if let Ok(body) = std::str::from_utf8(&body) {
            if environment.contains(alias) {
                for line in body.lines().filter(|l| !l.starts_with('#')) {
                    if let Some((_, value)) = line.split_once('=')
                        && !value.is_empty()
                    {
                        values.insert(value.to_owned());
                    }
                }
            } else if !body.is_empty() {
                values.insert(body.to_owned());
            }
        }
    }
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    ensure!(
        values.len() <= 1024,
        "secret redaction inventory exceeds log observation bounds"
    );
    let pattern = values
        .iter()
        .map(|s| regex::escape(s))
        .collect::<Vec<_>>()
        .join("|");
    ensure!(
        pattern.len() <= 128 << 10,
        "secret redaction pattern exceeds log observation bounds"
    );
    let mut text = if pattern.is_empty() {
        text.to_owned()
    } else {
        regex::RegexBuilder::new(&pattern)
            .size_limit(4 << 20)
            .dfa_size_limit(4 << 20)
            .build()?
            .replace_all(text, "[redacted]")
            .into_owned()
    };
    if text.len() > 256 << 10 {
        let mut end = 256 << 10;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n[truncated]");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logs_remain_untrusted_text_and_secret_redaction_is_bounded_and_checks_exact_bytes() {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = directory.path().join("runtime.env");
        let body = b"PRIVATE_TOKEN=private-token-value\nSECOND_TOKEN=private-token\n";
        store::atomic(&path, body, 0o600).unwrap();
        let document = read_release(include_bytes!(
            "../../tests/fixtures/deployment/release.json"
        ))
        .unwrap();
        let mut installed = Installed {
            kind: "komizo.installed".into(),
            version: 1,
            application: document.release.application.clone(),
            instance: "production".into(),
            release_digest: document.digest.clone(),
            operation_id: "1".repeat(32),
            desired_running: true,
            removed: false,
            expires_at: None,
            resources: store::Resources::default(),
            secret_snapshots: Default::default(),
        };
        installed.secret_snapshots.insert(
            "runtime".into(),
            super::super::secrets::Snapshot {
                generation: "2".repeat(32),
                path: path.to_str().unwrap().into(),
                sha256: document_digest(body),
            },
        );
        let forged = "{\"kind\":\"komizo.operation\",\"ok\":true}";
        let value = redact(
            &installed,
            &document,
            &format!("{forged}\nprivate-token-value private-token"),
        )
        .unwrap();
        assert!(value.starts_with(forged));
        assert!(!value.contains("private-token"));
        assert!(value.ends_with("[redacted] [redacted]"));
        let value = redact(&installed, &document, &"private-token-value".repeat(50000)).unwrap();
        assert!(value.len() <= (256 << 10) + 20);
        store::atomic(&path, b"PRIVATE_TOKEN=changed\n", 0o600).unwrap();
        assert!(redact(&installed, &document, "anything").is_err());
    }
}
