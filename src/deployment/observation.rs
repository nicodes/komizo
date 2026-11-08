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
    let volumes = container
        .volumes
        .iter()
        .map(|m| {
            Ok((
                m.name.clone(),
                serde_json::to_value(
                    installed
                        .resources
                        .volumes
                        .get(&m.name)
                        .ok_or_else(|| anyhow!("volume binding missing"))?,
                )?,
            ))
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
    let container = document
        .release
        .workload
        .services
        .get(service)
        .ok_or_else(|| anyhow!("service is not installed"))?;
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
