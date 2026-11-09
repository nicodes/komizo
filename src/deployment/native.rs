//! Serialized native effects. Every retained object has protected ownership.
use super::{
    capacity,
    controller::{self, Backend, Job, advance},
    engine::{Engine, volume_identity},
    jobs,
    model::*,
    observation, proxy,
    registry::Registry,
    secrets,
    store::{self, Installed, ObjectRecord, Operation, Resources, Store},
    system::{self, System},
    units,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

pub struct Native;
impl Native {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
    pub fn startup(&self, store: &Store) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        Engine { deadline }.preflight()?;
        let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
        system::host_pools(store, &System { deadline }, &capacity)?;
        store.reconcile_interrupted()?;
        proxy::globals()?;
        Ok(())
    }
}

fn prepared_path(store: &Store, application: &str, instance: &str) -> Result<PathBuf> {
    Ok(store.root.join("prepared").join(format!(
        "{}.json",
        Store::instance_key(application, instance)?
    )))
}

/// Ordinary releases cannot silently rename a database mount or bind an empty
/// replacement volume. Data topology changes require an explicit owner transfer.
pub fn retained_topology(previous: &ReleaseDocument, next: &ReleaseDocument) -> Result<()> {
    let topology = |document: &ReleaseDocument| -> Result<Vec<u8>> {
        let mounts = document
            .release
            .workload
            .services
            .iter()
            .chain(document.release.workload.jobs.iter())
            .map(|(name, c)| {
                let values = c
                    .volumes
                    .iter()
                    .map(|m| (&m.target, &m.name))
                    .collect::<BTreeMap<_, _>>();
                (name, values)
            })
            .filter(|(_, m)| !m.is_empty())
            .collect::<BTreeMap<_, _>>();
        canonical(&json!({"volumes":document.release.workload.volumes,"mounts":mounts}))
    };
    ensure!(
        topology(previous)? == topology(next)?,
        "retained data topology changed; owner transfer is required"
    );
    Ok(())
}

fn stage(store: &Store, policy: &Policy, document: &ReleaseDocument, job: &Job) -> Result<()> {
    let engine = Engine {
        deadline: job.deadline,
    };
    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
    let root = store.root.join("staging").join(&job.operation_id);
    store::protected_directory(&root)?;
    let public = proxy::asset_root(document);
    if !document.release.workload.assets.is_empty() {
        store::protected_directory(&public)?;
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755))?;
    }
    for (key, artifact) in &document.release.artifacts {
        ensure!(Instant::now() < job.deadline, "staging deadline exceeded");
        if let Artifact::Image {
            config_digest,
            platform,
            ..
        } = artifact
        {
            ensure!(
                *platform == engine.platform()?,
                "image targets a different native platform"
            );
            if engine.exists("image", config_digest)? {
                engine.image(config_digest, config_digest)?;
                continue;
            }
        }
        if matches!(artifact, Artifact::Archive { .. }) {
            let targets = document
                .release
                .workload
                .assets
                .iter()
                .filter(|(_, asset)| asset.artifact == *key)
                .map(|(name, _)| public.join(name))
                .collect::<Vec<_>>();
            if targets.iter().any(|p| p.exists()) {
                proxy::verify_assets(store, document)?;
                ensure!(
                    targets.iter().all(|p| p.is_dir()),
                    "immutable asset cache is incomplete"
                );
                continue;
            }
        }
        let staging_bytes = match artifact {
            Artifact::Image { .. } => policy.max_image_bytes.checked_mul(3),
            Artifact::Archive { size_bytes, .. } => size_bytes.checked_add(policy.max_asset_bytes),
        }
        .ok_or_else(|| anyhow!("staging bound overflow"))?;
        capacity::disk(&store.root, capacity.disk_reserve_bytes, staging_bytes)?;
        let (mut registry, manifest) = Registry::new(
            artifact.reference(),
            job.request.registry.as_ref(),
            job.deadline.saturating_duration_since(Instant::now()),
        )?;
        let file = root.join(format!("{key}.oci"));
        match artifact {
            Artifact::Image { config_digest, .. } => {
                registry.image_archive(&manifest, artifact, &file, policy)?;
                engine.import(&file, config_digest)?;
            }
            Artifact::Archive {
                digest, size_bytes, ..
            } => {
                registry.static_archive(&manifest, artifact, &file, policy)?;
                super::assets::verify_file(&file, digest, *size_bytes)?;
                for (name, asset) in &document.release.workload.assets {
                    if asset.artifact == *key {
                        let target = public.join(name);
                        if !target.try_exists()? {
                            super::assets::extract(&file, &target, policy)?;
                        }
                    }
                }
            }
        }
        fs::remove_file(file)?;
    }
    proxy::seal_assets(store, document)
}

fn prepare_preview(store: &Store, policy: &Policy, job: &Job) -> Result<()> {
    if job.request.instance == "production" {
        return Ok(());
    }
    let preview = policy
        .previews
        .as_ref()
        .ok_or_else(|| anyhow!("preview authority missing"))?;
    let active = proxy::instances(store)?
        .into_iter()
        .filter(|i| {
            i.application == policy.application
                && i.instance != "production"
                && i.instance != job.request.instance
                && (i.desired_running || i.expires_at.is_some())
        })
        .count();
    ensure!(
        active < preview.max_instances as usize,
        "application preview capacity refuses another full instance"
    );
    let Some(task) = &preview.prepare else {
        return Ok(());
    };
    let marker = store.root.join("preview-prepared").join(format!(
        "{}.json",
        Store::instance_key(&policy.application, &job.request.instance)?
    ));
    let expected = canonical(
        &json!({"program":task.sha256,"secrets":preview.secrets.iter().map(|(k,v)|(k,&v.generation)).collect::<BTreeMap<_,_>>()}),
    )?;
    if marker.try_exists()? {
        ensure!(
            store::read_protected(&marker, 16384)? == expected,
            "preview credential preparation changed; owner rotation is required"
        );
        return Ok(());
    }
    let program = store::read_protected(Path::new(&task.program), 32 << 20)?;
    ensure!(
        document_digest(&program) == task.sha256,
        "preview preparation bundle bytes changed"
    );
    let deadline = job
        .deadline
        .min(Instant::now() + Duration::from_secs(u64::from(task.timeout_seconds)));
    let mut command = Command::new(&task.program);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    let input = canonical(
        &json!({"kind":"komizo.preview-request","version":1,"application":policy.application,"instance":job.request.instance,"operation_id":job.operation_id,"app_origin":format!("https://{}.{}",job.request.instance,preview.hostname_suffix),"secrets":preview.secrets,"deadline_unix":controller::now()?+deadline.saturating_duration_since(Instant::now()).as_secs() as i64}),
    )?;
    let output = crate::process::capture(&mut command, Some(&input), 65536, deadline, || false)?;
    ensure!(
        output.status.success(),
        "protected preview credential preparation failed"
    );
    store::atomic(&marker, &expected, 0o600)
}

fn retained(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    engine: &Engine,
) -> Result<()> {
    let ns = units::namespace(&installed.application, &installed.instance)?;
    for (name, network) in &document.release.workload.networks {
        if let Some(record) = installed.resources.networks.get(name) {
            engine.owned_object("network", record)?;
            continue;
        }
        let physical = format!("{ns}-n-{name}");
        ensure!(
            !engine.exists("network", &physical)?,
            "unrecorded native network cannot be adopted"
        );
        let mut args = vec![
            "network",
            "create",
            "--driver=bridge",
            "--label",
            "io.komizo.managed=true",
        ];
        if network.internal {
            args.push("--internal");
        }
        args.push(&physical);
        engine.run(&args)?;
        let value = engine.inspect("network", &physical)?;
        let id = value["id"]
            .as_str()
            .ok_or_else(|| anyhow!("network ID missing"))?
            .to_owned();
        ensure!(hex(&id, 64), "network ID invalid");
        installed
            .resources
            .networks
            .insert(name.clone(), ObjectRecord { name: physical, id });
        store.save_installed(installed)?;
    }
    for name in document.release.workload.volumes.keys() {
        if let Some(record) = installed.resources.volumes.get(name) {
            engine.owned_object("volume", record)?;
            continue;
        }
        let physical = format!("{ns}-v-{name}");
        ensure!(
            !engine.exists("volume", &physical)?,
            "unrecorded native volume cannot be adopted"
        );
        engine.run(&[
            "volume",
            "create",
            "--driver=local",
            "--label",
            "io.komizo.managed=true",
            &physical,
        ])?;
        let id = volume_identity(&engine.inspect("volume", &physical)?)?;
        installed
            .resources
            .volumes
            .insert(name.clone(), ObjectRecord { name: physical, id });
        store.save_installed(installed)?;
    }
    Ok(())
}

fn stop_services(
    store: &Store,
    installed: &mut Installed,
    engine: &Engine,
    system: &System,
    remove: bool,
) -> Result<()> {
    installed.desired_running = false;
    store.save_installed(installed)?;
    proxy::refresh(store, system.deadline)?;
    let document = store.release(&installed.release_digest)?;
    let ns = units::namespace(&installed.application, &installed.instance)?;
    let mut ordered = order(&document)?;
    ordered.reverse();
    for name in ordered {
        let Some(container) = document.release.workload.services.get(&name) else {
            continue;
        };
        let Some(record) = installed.resources.containers.get(&name) else {
            continue;
        };
        let path = Path::new(system::QUADLETS).join(format!("{ns}-{name}.container"));
        system::verify_unit(
            store,
            &path,
            &installed.application,
            &installed.instance,
            &record.unit_sha256,
        )?;
        if container.health.is_some() {
            system.stop(&format!("{ns}-{name}-health.timer"))?;
        }
        if engine.exists("container", &record.name)? {
            engine.owned_container(record, &installed.application, &installed.instance, &name)?;
        }
        system.stop(&format!("{ns}-{name}.service"))?;
        if let Some(value) =
            engine.owned_container(record, &installed.application, &installed.instance, &name)?
        {
            ensure!(
                value["State"]["Running"] == false,
                "service remained running after stop"
            );
            if remove {
                engine.run(&["rm", value["Id"].as_str().unwrap()])?;
            }
        }
        if remove {
            system::remove(store, &path, &installed.application, &installed.instance)?;
            if container.health.is_some() {
                for suffix in ["service", "timer"] {
                    system::remove(
                        store,
                        &Path::new(system::UNITS).join(format!("{ns}-{name}-health.{suffix}")),
                        &installed.application,
                        &installed.instance,
                    )?;
                }
            }
        }
    }
    if remove {
        installed.resources.containers.clear();
        store.save_installed(installed)?;
        system.reload()?;
    } else {
        wanted(store, installed, false, system)?;
    }
    Ok(())
}

fn wanted(store: &Store, installed: &mut Installed, value: bool, system: &System) -> Result<()> {
    let ns = units::namespace(&installed.application, &installed.instance)?;
    for (name, record) in &mut installed.resources.containers {
        let path = Path::new(system::QUADLETS).join(format!("{ns}-{name}.container"));
        system::verify_unit(
            store,
            &path,
            &installed.application,
            &installed.instance,
            &record.unit_sha256,
        )?;
        let old = String::from_utf8(store::read_protected(&path, 1 << 20)?)?;
        let mut body = old
            .strip_suffix("WantedBy=multi-user.target\n")
            .unwrap_or(&old)
            .to_owned();
        ensure!(
            body.ends_with("[Install]\n"),
            "managed Quadlet install section changed"
        );
        if value {
            body.push_str("WantedBy=multi-user.target\n");
        }
        record.unit_sha256 = system::install(
            store,
            &path,
            &installed.application,
            &installed.instance,
            body.as_bytes(),
        )?;
    }
    store.save_installed(installed)?;
    system.reload()
}

pub fn order(document: &ReleaseDocument) -> Result<Vec<String>> {
    fn visit(
        name: &str,
        all: &BTreeMap<&str, &Container>,
        seen: &mut BTreeSet<String>,
        active: &mut BTreeSet<String>,
        result: &mut Vec<String>,
    ) -> Result<()> {
        if seen.contains(name) {
            return Ok(());
        }
        ensure!(active.insert(name.to_owned()), "workload dependency cycle");
        for dependency in all
            .get(name)
            .ok_or_else(|| anyhow!("missing workload dependency"))?
            .needs
            .keys()
        {
            visit(dependency, all, seen, active, result)?;
        }
        active.remove(name);
        seen.insert(name.into());
        result.push(name.into());
        Ok(())
    }
    let all = document
        .release
        .workload
        .services
        .iter()
        .chain(document.release.workload.jobs.iter())
        .map(|(n, c)| (n.as_str(), c))
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut active = BTreeSet::new();
    for name in all.keys() {
        visit(name, &all, &mut seen, &mut active, &mut result)?;
    }
    Ok(result)
}

fn install_units(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    system: &System,
) -> Result<()> {
    let ns = units::namespace(&installed.application, &installed.instance)?;
    for (name, container) in &document.release.workload.services {
        let ownership = store::identity()?;
        let env = installed
            .secret_snapshots
            .iter()
            .map(|(a, s)| (a.clone(), s.path.clone()))
            .collect();
        let mounts = container
            .secrets
            .iter()
            .map(|s| {
                Ok((
                    s.source.clone(),
                    secrets::mount_snapshot(
                        &store.root,
                        name,
                        s,
                        &installed.secret_snapshots[&s.source],
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let bindings = units::Bindings {
            application: &installed.application,
            instance: &installed.instance,
            release_digest: &document.digest,
            ownership: &ownership,
            networks: &installed.resources.networks,
            volumes: &installed.resources.volumes,
            environment_files: &env,
            secrets: &mounts,
            ingress: None,
        };
        let body = units::quadlet(document, name, &bindings, true)?;
        let hash = system::install(
            store,
            &Path::new(system::QUADLETS).join(format!("{ns}-{name}.container")),
            &installed.application,
            &installed.instance,
            body.as_bytes(),
        )?;
        if let Some(health) = &container.health {
            let (service, timer) =
                units::health_units(&installed.application, &installed.instance, name, health)?;
            for (suffix, body) in [("service", service), ("timer", timer)] {
                system::install(
                    store,
                    &Path::new(system::UNITS).join(format!("{ns}-{name}-health.{suffix}")),
                    &installed.application,
                    &installed.instance,
                    body.as_bytes(),
                )?;
            }
        }
        let Artifact::Image {
            reference,
            config_digest,
            ..
        } = &document.release.artifacts[&container.artifact]
        else {
            return Err(anyhow!("service image missing"));
        };
        installed.resources.containers.insert(
            name.clone(),
            store::ContainerRecord {
                name: format!("{ns}-{name}"),
                id: String::new(),
                image: reference.clone(),
                config_digest: config_digest.clone(),
                release_digest: document.digest.clone(),
                ownership,
                unit_sha256: hash,
                volumes: container
                    .volumes
                    .iter()
                    .map(|m| {
                        (
                            m.name.clone(),
                            installed.resources.volumes[&m.name].name.clone(),
                        )
                    })
                    .collect(),
            },
        );
        store.save_installed(installed)?;
    }
    system.reload()
}

fn start_service(
    store: &Store,
    installed: &mut Installed,
    document: &ReleaseDocument,
    name: &str,
    engine: &Engine,
    system: &System,
) -> Result<()> {
    let record = &installed.resources.containers[name];
    if engine.exists("container", &record.name)? {
        engine.owned_container(record, &installed.application, &installed.instance, name)?;
    }
    system.start(&format!("{}.service", record.name))?;
    let value = engine.inspect("container", &record.name)?;
    let mut candidate = record.clone();
    candidate.id = value["Id"]
        .as_str()
        .ok_or_else(|| anyhow!("started container ID missing"))?
        .to_owned();
    engine.owned_container(
        &candidate,
        &installed.application,
        &installed.instance,
        name,
    )?;
    installed
        .resources
        .containers
        .insert(name.to_owned(), candidate);
    store.save_installed(installed)?;
    let container = &document.release.workload.services[name];
    if container.health.is_some() {
        system.start(&format!(
            "{}-health.timer",
            installed.resources.containers[name].name
        ))?;
    }
    engine.wait_healthy(
        &installed.resources.containers[name].name,
        container.health.is_some(),
    )?;
    let observed = system.group(&format!(
        "{}.service",
        installed.resources.containers[name].name
    ))?;
    ensure!(
        observed
            .starts_with(Path::new("/sys/fs/cgroup").join(
                units::slice(&installed.application, &installed.instance)?.replace('-', "/")
            ))
            || observed
                .to_str()
                .is_some_and(|p| p
                    .contains(&units::slice(&installed.application, &installed.instance).unwrap())),
        "service escaped its instance slice"
    );
    Ok(())
}

fn activate(
    store: &Store,
    policy: &Policy,
    installed: &mut Installed,
    document: &ReleaseDocument,
    job: &Job,
    operation: &mut Operation,
) -> Result<()> {
    let system = System {
        deadline: job.deadline,
    };
    let engine = Engine {
        deadline: job.deadline,
    };
    if operation.phase == "staging" {
        advance(store, operation, "jobs")?;
    }
    system::instance_slice(store, &system, policy, &installed.instance)?;
    retained(store, installed, document, &engine)?;
    install_units(store, installed, document, &system)?;
    installed.desired_running = true;
    store.save_installed(installed)?;
    for name in order(document)? {
        if document.release.workload.jobs.contains_key(&name) {
            jobs::run(
                store,
                document,
                installed,
                &name,
                &job.operation_id,
                job.deadline,
            )?;
        } else {
            start_service(store, installed, document, &name, &engine, &system)?;
        }
    }
    advance(store, operation, "installing")?;
    advance(store, operation, "activating")?;
    proxy::refresh(store, job.deadline)?;
    advance(store, operation, "readiness")?;
    readiness(document, policy, &installed.instance, job.deadline)?;
    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
    capacity::reserve(
        store,
        &capacity,
        policy,
        document,
        &installed.instance,
        false,
    )?;
    advance(store, operation, "ready")
}

fn readiness(
    document: &ReleaseDocument,
    policy: &Policy,
    instance: &str,
    deadline: Instant,
) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let protected = if instance == "production" {
        policy.readiness.clone()
    } else {
        policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview readiness authority missing"))?
            .readiness
            .iter()
            .map(|p| {
                let mut p = p.clone();
                p.url = p.url.replace("{instance}", instance);
                p
            })
            .collect()
    };
    for check in document
        .release
        .workload
        .readiness
        .iter()
        .chain(protected.iter())
    {
        loop {
            ensure!(
                Instant::now() < deadline,
                "public readiness deadline exceeded"
            );
            let result = (|| -> Result<()> {
                let response = client
                    .get(&check.url)
                    .timeout(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(15)),
                    )
                    .header("Cache-Control", "no-cache")
                    .send()?;
                ensure!(
                    response.status().as_u16() == check.status
                        && response
                            .headers()
                            .get("X-Komizo-Release")
                            .and_then(|v| v.to_str().ok())
                            == Some(&document.digest),
                    "readiness is not serving the accepted release"
                );
                let mut body = Vec::new();
                response.take((1 << 20) + 1).read_to_end(&mut body)?;
                ensure!(body.len() <= 1 << 20, "readiness body exceeds bound");
                if let Some(text) = &check.contains {
                    ensure!(
                        std::str::from_utf8(&body)?.contains(text),
                        "readiness response content differs"
                    );
                }
                if let Some(field) = &check.revision_field {
                    let value = bounded_value(&body, 1 << 20)?;
                    ensure!(
                        value.get(field).and_then(|v| v.as_str())
                            == Some(&document.release.source.revision),
                        "readiness source revision differs"
                    );
                }
                Ok(())
            })();
            if result.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(())
}

fn backup(
    store: &Store,
    policy: &Policy,
    installed: &Installed,
    operation: &mut Operation,
    deadline: Instant,
) -> Result<()> {
    let task = policy
        .backup
        .as_ref()
        .ok_or_else(|| anyhow!("installed state requires a protected backup program"))?;
    let body = store::read_protected(Path::new(&task.program), 32 << 20)?;
    ensure!(
        document_digest(&body) == task.sha256,
        "protected backup bundle bytes changed"
    );
    let directory = store.root.join("exports").join(&operation.operation_id);
    store::protected_directory(&directory)?;
    ensure!(
        fs::read_dir(&directory)?.next().is_none(),
        "backup output directory is not fresh"
    );
    let deadline =
        deadline.min(Instant::now() + Duration::from_secs(u64::from(task.timeout_seconds)));
    let unix =
        controller::now()? + deadline.saturating_duration_since(Instant::now()).as_secs() as i64;
    let mut command = Command::new(&task.program);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C.UTF-8")
        .env("KOMIZO_APPLICATION", &installed.application)
        .env("KOMIZO_INSTANCE", &installed.instance)
        .env("KOMIZO_RELEASE_DIGEST", &installed.release_digest)
        .env("KOMIZO_OPERATION_ID", &operation.operation_id)
        .env("KOMIZO_OUTPUT_DIRECTORY", &directory)
        .env("KOMIZO_DEADLINE_UNIX", unix.to_string());
    let input = canonical(
        &json!({"kind":"komizo.backup-request","version":1,"application":installed.application,"instance":installed.instance,"release_digest":installed.release_digest,"operation_id":operation.operation_id,"output_directory":directory,"deadline_unix":unix}),
    )?;
    let result = crate::process::capture(&mut command, Some(&input), 65536, deadline, || false)?;
    ensure!(result.status.success(), "protected encrypted backup failed");
    ensure!(
        fs::read_dir(&directory)?.count() == 2,
        "backup emitted an unrecognized export"
    );
    let mut files = Vec::new();
    for name in ["snapshot.cms", "receipt.json"] {
        let path = directory.join(name);
        let file = store::open_protected(&path, task.max_export_bytes)?;
        let size = file.metadata()?.len();
        ensure!(size > 0, "backup export is empty");
        let hash = file_hash(file)?;
        files.push(store::Export {
            name: name.into(),
            size_bytes: size,
            sha256: hash,
        });
    }
    let receipt = bounded_value(
        &store::read_protected(&directory.join("receipt.json"), 1 << 20)?,
        1 << 20,
    )?;
    ensure!(
        receipt["application"] == installed.application
            && receipt["instance"] == installed.instance
            && receipt["release_digest"] == installed.release_digest,
        "backup receipt differs from installed source authority"
    );
    operation.backup = Some(store::Backup {
        status: "ready".into(),
        files,
    });
    store.save_operation(operation)?;
    store::atomic(
        &store.root.join("backups").join(format!(
            "{}.json",
            Store::instance_key(&installed.application, &installed.instance)?
        )),
        &canonical(
            &json!({"operation_id":operation.operation_id,"release_digest":installed.release_digest,"installed_operation_id":installed.operation_id,"created_at":controller::now()?}),
        )?,
        0o600,
    )
}

pub fn file_hash(mut file: fs::File) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn require_backup(store: &Store, installed: &Installed) -> Result<()> {
    let path = store.root.join("backups").join(format!(
        "{}.json",
        Store::instance_key(&installed.application, &installed.instance)?
    ));
    let value = bounded_value(&store::read_protected(&path, 4096)?, 4096)?;
    let at = value["created_at"]
        .as_i64()
        .ok_or_else(|| anyhow!("backup time missing"))?;
    let now = controller::now()?;
    ensure!(
        value["release_digest"] == installed.release_digest
            && value["installed_operation_id"] == installed.operation_id
            && at <= now
            && now - at <= 1800,
        "activation requires a recent backup of the actual installed release"
    );
    let operation = store.operation(
        value["operation_id"]
            .as_str()
            .ok_or_else(|| anyhow!("backup operation missing"))?,
    )?;
    ensure!(
        operation.ok
            && operation
                .backup
                .as_ref()
                .is_some_and(|b| b.status == "ready"),
        "backup operation has not completed"
    );
    Ok(())
}

impl Backend for Native {
    fn maintenance(&self, store: &Store) -> Result<()> {
        proxy::refresh(store, Instant::now() + Duration::from_secs(20))
    }
    fn execute(
        &self,
        store: &Store,
        policy: &Policy,
        job: &Job,
        operation: &mut Operation,
    ) -> Result<()> {
        let application = &job.request.application;
        let instance = &job.request.instance;
        let engine = Engine {
            deadline: job.deadline,
        };
        let system = System {
            deadline: job.deadline,
        };
        let previous = store.installed(application, instance)?;
        match job.request.action.as_str() {
            "deploy" => {
                advance(store, operation, "staging")?;
                let document = store.release(&job.request.release_digest)?;
                policy.admit(&document.release, instance)?;
                if let Some(previous) = &previous {
                    retained_topology(&store.release(&previous.release_digest)?, &document)?;
                }
                stage(store, policy, &document, job)?;
                prepare_preview(store, policy, job)?;
                let snapshots = secrets::stage(&store.root, &document, policy, instance)?;
                if let Some(previous) = &previous
                    && !previous.desired_running
                {
                    let prepared = Installed {
                        kind: "komizo.installed".into(),
                        version: 1,
                        application: application.clone(),
                        instance: instance.clone(),
                        release_digest: document.digest.clone(),
                        operation_id: operation.operation_id.clone(),
                        desired_running: false,
                        expires_at: job
                            .request
                            .ttl_seconds
                            .map(|n| job.admitted_at + i64::from(n)),
                        resources: previous.resources.clone(),
                        secret_snapshots: snapshots,
                    };
                    store::atomic(
                        &prepared_path(store, application, instance)?,
                        &serde_json::to_vec(&prepared)?,
                        0o600,
                    )?;
                    let mut stopped = previous.clone();
                    stopped.expires_at = prepared.expires_at;
                    store.save_installed(&stopped)?;
                    advance(store, operation, "installing")?;
                    return advance(store, operation, "prepared_stopped");
                }
                let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                capacity::reserve(store, &capacity, policy, &document, instance, true)?;
                let mut resources = Resources::default();
                if let Some(mut previous) = previous {
                    if !document.release.workload.volumes.is_empty() {
                        require_backup(store, &previous)?;
                    }
                    advance(store, operation, "jobs")?;
                    stop_services(store, &mut previous, &engine, &system, true)?;
                    resources = previous.resources;
                    // activation's jobs transition is entered below; the stop
                    // effect is journalled before touching the prior services.
                }
                let mut installed = Installed {
                    kind: "komizo.installed".into(),
                    version: 1,
                    application: application.clone(),
                    instance: instance.clone(),
                    release_digest: document.digest.clone(),
                    operation_id: operation.operation_id.clone(),
                    desired_running: false,
                    expires_at: job
                        .request
                        .ttl_seconds
                        .map(|n| job.admitted_at + i64::from(n)),
                    resources,
                    secret_snapshots: snapshots,
                };
                store.save_installed(&installed)?;
                activate(store, policy, &mut installed, &document, job, operation)
            }
            "backup" => {
                if let Some(installed) = previous {
                    ensure!(
                        installed.desired_running,
                        "a deliberately stopped instance cannot produce a logical backup"
                    );
                    backup(store, policy, &installed, operation, job.deadline)?;
                } else {
                    ensure!(
                        !prepared_path(store, application, instance)?.try_exists()?,
                        "prepared state prevents absence assertion"
                    );
                    engine.prove_absent(&units::namespace(application, instance)?)?;
                    operation.backup = Some(store::Backup {
                        status: "absent".into(),
                        files: Vec::new(),
                    });
                }
                advance(store, operation, "ready")
            }
            "stop" => {
                let mut installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                advance(store, operation, "staging")?;
                advance(store, operation, "installing")?;
                stop_services(store, &mut installed, &engine, &system, false)?;
                capacity::release(store, application, instance)?;
                advance(store, operation, "prepared_stopped")
            }
            "start" | "restart" => {
                let mut installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                advance(store, operation, "staging")?;
                let prepared = prepared_path(store, application, instance)?;
                if prepared.try_exists()? {
                    let mut next: Installed = serde_json::from_slice(&store::read_protected(
                        &prepared,
                        MAX_DOCUMENT_BYTES,
                    )?)?;
                    let old_document = store.release(&installed.release_digest)?;
                    let document = store.release(&next.release_digest)?;
                    policy.admit(&document.release, instance)?;
                    retained_topology(&old_document, &document)?;
                    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                    capacity::reserve(store, &capacity, policy, &document, instance, true)?;
                    if !document.release.workload.volumes.is_empty() {
                        // Bring up only the previous release's data services;
                        // its exact installed descriptor remains authoritative
                        // throughout capture, before any new migration runs.
                        installed.desired_running = true;
                        store.save_installed(&installed)?;
                        for name in order(&old_document)? {
                            if let Some(service) = old_document.release.workload.services.get(&name)
                                && service.needs.values().all(|c| *c != Condition::Completed)
                            {
                                start_service(
                                    store,
                                    &mut installed,
                                    &old_document,
                                    &name,
                                    &engine,
                                    &system,
                                )?;
                            }
                        }
                        backup(store, policy, &installed, operation, job.deadline)?;
                    }
                    advance(store, operation, "jobs")?;
                    stop_services(store, &mut installed, &engine, &system, true)?;
                    next.resources = installed.resources;
                    next.operation_id = job.operation_id.clone();
                    store.save_installed(&next)?;
                    activate(store, policy, &mut next, &document, job, operation)?;
                    fs::remove_file(prepared)?;
                    Ok(())
                } else {
                    let document = store.release(&installed.release_digest)?;
                    policy.admit(&document.release, instance)?;
                    let capacity = capacity::read(Path::new("/etc/komizo/capacity.json"))?;
                    capacity::reserve(store, &capacity, policy, &document, instance, true)?;
                    system::instance_slice(store, &system, policy, instance)?;
                    if job.request.action == "restart" {
                        advance(store, operation, "jobs")?;
                        stop_services(store, &mut installed, &engine, &system, false)?;
                    }
                    installed.desired_running = true;
                    installed.operation_id = job.operation_id.clone();
                    store.save_installed(&installed)?;
                    wanted(store, &mut installed, true, &system)?;
                    if operation.phase == "staging" {
                        advance(store, operation, "jobs")?;
                    }
                    for name in order(&document)? {
                        if document.release.workload.services.contains_key(&name) {
                            start_service(
                                store,
                                &mut installed,
                                &document,
                                &name,
                                &engine,
                                &system,
                            )?;
                        } else {
                            ensure!(
                                jobs::completed(store, &document, &name, &installed)?,
                                "start cannot replay a one-shot job"
                            );
                        }
                    }
                    advance(store, operation, "installing")?;
                    advance(store, operation, "activating")?;
                    proxy::refresh(store, job.deadline)?;
                    advance(store, operation, "readiness")?;
                    readiness(&document, policy, instance, job.deadline)?;
                    capacity::reserve(store, &capacity, policy, &document, instance, false)?;
                    advance(store, operation, "ready")
                }
            }
            "remove" => {
                ensure!(
                    instance != "production",
                    "production retained data requires explicit owner transfer"
                );
                let mut installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                advance(store, operation, "staging")?;
                advance(store, operation, "installing")?;
                stop_services(store, &mut installed, &engine, &system, true)?;
                let retain = policy
                    .previews
                    .as_ref()
                    .ok_or_else(|| anyhow!("preview authority missing"))?
                    .retain_data_on_remove;
                if !retain {
                    for record in installed.resources.volumes.values() {
                        engine.owned_object("volume", record)?;
                        engine.run(&["volume", "rm", &record.name])?;
                    }
                    installed.resources.volumes.clear();
                }
                for record in installed.resources.networks.values() {
                    engine.owned_object("network", record)?;
                    engine.run(&["network", "rm", &record.name])?;
                }
                installed.resources.networks.clear();
                store.save_installed(&installed)?;
                // A retained ledger stays even after removal; absence is never
                // inferred from a container list or a caller-supplied label.
                installed.expires_at = None;
                store.save_installed(&installed)?;
                let prepared = prepared_path(store, application, instance)?;
                if prepared.try_exists()? {
                    fs::remove_file(prepared)?;
                }
                capacity::release(store, application, instance)?;
                advance(store, operation, "prepared_stopped")
            }
            "secret-set" => {
                let mut policy = policy.clone();
                secrets::rotate(
                    &Path::new(observation::POLICIES).join(format!("{application}.json")),
                    &mut policy,
                    job.request
                        .secret_update
                        .as_ref()
                        .ok_or_else(|| anyhow!("secret update missing"))?,
                    &store.root,
                )?;
                advance(store, operation, "ready")
            }
            "recover" => {
                let installed = previous.ok_or_else(|| anyhow!("instance absent"))?;
                let target =
                    job.request.operation.as_deref().ok_or_else(|| {
                        anyhow!("recovery requires its exact uncertain operation")
                    })?;
                let uncertain = store.operation(target)?;
                ensure!(
                    uncertain.application == *application
                        && uncertain.instance == *instance
                        && uncertain.reconciliation_required,
                    "recovery target is outside this uncertain instance"
                );
                let document = store.release(&installed.release_digest)?;
                jobs::reconcile(store, &document, &installed, target, job.deadline)?;
                for (name, record) in &installed.resources.containers {
                    engine.owned_container(record, application, instance, name)?;
                }
                advance(store, operation, "ready")?;
                store::atomic(
                    &store
                        .root
                        .join("reconciliations")
                        .join(format!("{target}.json")),
                    &canonical(&json!({"resolved_by":operation.operation_id}))?,
                    0o600,
                )
            }
            _ => Err(anyhow!("unsupported native effect")),
        }
    }
}

pub fn expire() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "preview expiry requires owner identity"
    );
    let store = Store::new(Path::new(observation::STATE).into())?;
    for installed in proxy::instances(&store)? {
        let now = controller::now()?;
        if installed.instance == "production" || installed.expires_at.is_none_or(|n| n > now) {
            continue;
        }
        let request = json!({"kind":"komizo.request","version":1,"authority":"owner","application":installed.application,"instance":installed.instance,"action":"remove","release_digest":installed.release_digest,"nonce":store::identity()?,"issued_at":now,"expires_at":now+120,"timeout_seconds":1200});
        let mut response = Vec::new();
        super::transport::submit(&mut &canonical(&request)?[..], &mut response)?;
        let value = bounded_value(&response, 16384)?;
        ensure!(
            value["ok"] == true,
            "preview expiry requires reconciliation"
        );
    }
    Ok(())
}
