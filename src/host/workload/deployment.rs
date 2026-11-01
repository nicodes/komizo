//! Root-owned staging authenticates every input before registry or installed-file effects.
use super::{
    activation::Host,
    effects::Effects,
    files,
    image_cache::missing,
    transaction::{self, Credentials, Snapshot, StagedFile, hash},
};
use crate::{
    host::{paths, preview::capacity, scoped},
    wire::{Secret, Time},
    workload::{
        activation::{ActivationError, ActivationRequest, ActivationRuntime, Context},
        archive, compose,
        host_resources::HostResources,
        policy::{Policy, operation_identity},
        policy_read,
        release::ReleaseAcceptance,
        release_bind, routes,
    },
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};
pub fn state_value<'a>(body: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    body.split('\n')
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_default()
}
impl<E: Effects> Host<E> {
    pub fn stage_deployment(
        &mut self,
        parent: &Context,
        r: &ActivationRequest,
        queue: &Path,
    ) -> Result<ActivationRequest> {
        r.check((self.now)())?;
        ensure!(
            self.operation(r)?.phase == "admitted",
            ActivationError::Reconciliation
        );
        let ctx = parent.with_deadline(r.deadline.utc(), (self.now)());
        let policy_body = self
            .effects
            .read(&self.policies.join(format!("{}.json", r.app)), 1 << 20)?;
        ensure!(
            hash(&policy_body) == r.policy_sha256,
            "staging policy changed"
        );
        let p = policy_read::read_policy(&policy_body)?;
        ensure!(
            p.app == r.app
                && p.deployment
                    .as_ref()
                    .is_some_and(|d| d.route_path == r.route_path && d.proxy == r.proxy),
            "staging authority changed"
        );
        self.policy = p.clone();
        let env = self
            .effects
            .read(&Path::new(&p.app_dir).join(".env"), 1 << 20)?;
        ensure!(
            transaction::deployment_version(&env).is_ok_and(|previous| previous == r.previous),
            "installed revision changed before staging"
        );
        let stage = r
            .stage
            .as_ref()
            .ok_or_else(|| anyhow!("staging requires a stage request"))?;
        let slot = transaction::credential_path(queue, &r.id);
        let mut snapshot = Snapshot::default();
        let mut mutated = false;
        let mut staging = false;
        let result = (|| -> Result<ActivationRequest> {
            self.phase(r, "staging")?;
            staging = true;
            self.effects.checkpoint("journal-staging");
            self.deployment_capacity()?;
            self.startup_capacity(&p)?;
            let accepted: ReleaseAcceptance = self.read_json(
                &self
                    .releases
                    .join(&r.app)
                    .join(format!("{}.json", r.candidate)),
            )?;
            accepted.check(&p, &r.candidate)?;
            let credentials_body = self.effects.read(&slot, 1 << 20)?;
            ensure!(
                hash(&credentials_body) == stage.credential_sha256,
                "staging credential slot changed"
            );
            let mut credentials: Credentials = self.read_json(&slot)?;
            credentials.check(&p)?;
            let docker_dir = slot.parent().unwrap().join("docker");
            fs::DirBuilder::new().mode(0o700).create(&docker_dir)?;
            let ctx = ctx.with_docker_config(docker_dir.clone());
            if stage.local_only {
                ensure!(
                    r.candidate == r.previous && credentials.is_empty(),
                    "local current reconfiguration cannot carry registry authority"
                )
            } else {
                self.effects.login(&ctx, &credentials, &docker_dir)?
            }
            credentials.password = Secret::new(String::new());
            drop(credentials_body);
            fs::remove_file(&slot)?;
            self.effects.checkpoint("registry-login");
            let config_ref = format!("{}config:{}", p.image_prefix, r.candidate);
            if !stage.local_only {
                self.effects
                    .docker(&ctx, &["pull", "-q", &config_ref])
                    .map_err(|_| anyhow!("configuration image pull failed"))?;
            }
            release_bind::bind_release(
                &mut |args| self.effects.docker(&ctx, args),
                &p,
                &accepted,
                &r.candidate,
                &config_ref,
                br#"{"services":{}}"#,
                false,
            )?;
            let volumes = self.effects.docker(
                &ctx,
                &[
                    "image",
                    "inspect",
                    "--format",
                    "{{json .Config.Volumes}}",
                    &config_ref,
                ],
            )?;
            ensure!(
                matches!(volumes.trim(), "null" | "{}"),
                "configuration image may not allocate declared volumes"
            );
            let immutable = self.effects.docker(
                &ctx,
                &["image", "inspect", "--format", "{{.Id}}", &config_ref],
            )?;
            let immutable = immutable.trim();
            ensure!(
                crate::workload::release::digest(immutable),
                "configuration image has no immutable local identity"
            );
            let id = self.effects.docker(
                &ctx,
                &[
                    "create",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--entrypoint",
                    "/komizo-copy-never-run",
                    immutable,
                ],
            )?;
            let id = id.trim().to_owned();
            ensure!(
                crate::workload::policy::content_identity(&id),
                "invalid owned configuration container identity"
            );
            let result = self.stage_configuration(
                &ctx,
                r,
                queue,
                &p,
                &accepted,
                &config_ref,
                &id,
                &env,
                &mut snapshot,
                &mut mutated,
            );
            let cleanup =
                Context::new(std::time::Instant::now() + std::time::Duration::from_secs(30));
            let _ = self
                .effects
                .docker(&cleanup, &["rm", "--force", "--volumes", &id]);
            result
        })();
        let _ = fs::remove_dir_all(slot.parent().unwrap());
        match result {
            Ok(configured) => Ok(configured),
            Err(mut error) => {
                if mutated
                    && let Err(restore) =
                        transaction::restore_snapshot(&snapshot, &mut |path, body, mode| {
                            self.effects.write(path, body, mode)
                        })
                {
                    error = anyhow!("{error}; {restore}")
                }
                if staging && let Err(phase) = self.phase(r, "staging_failed") {
                    error = anyhow!("{error}; {phase}")
                }
                Err(error)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn stage_configuration(
        &mut self,
        ctx: &Context,
        r: &ActivationRequest,
        queue: &Path,
        p: &Policy,
        accepted: &ReleaseAcceptance,
        config_ref: &str,
        id: &str,
        env: &[u8],
        snapshot: &mut Snapshot,
        mutated: &mut bool,
    ) -> Result<ActivationRequest> {
        let stage = r.stage.as_ref().unwrap();
        let mut configuration = None;
        self.effects.archive(
            ctx,
            &["cp", &format!("{id}:/config/."), "-"],
            5 << 20,
            &mut |reader| {
                configuration = Some(archive::read_configuration(reader)?);
                Ok(())
            },
        )?;
        let (compose, hostnames) =
            configuration.ok_or_else(|| anyhow!("configuration copy did not produce files"))?;
        self.effects.checkpoint("configuration-copy");
        let canonical = compose::validate(&compose, p, &r.candidate)?;
        let canonical = release_bind::bind_release(
            &mut |args| self.effects.docker(ctx, args),
            p,
            accepted,
            &r.candidate,
            config_ref,
            &canonical,
            !stage.local_only,
        )?;
        let work = tempfile::Builder::new()
            .prefix("validated-")
            .tempdir_in(transaction::credential_path(queue, &r.id).parent().unwrap())?;
        let validated = work.path().join("compose.json");
        files::write_atomic(&validated, &canonical, 0o600)?;
        self.verify_deployment_secrets(ctx, p, &stage.generation, &validated)?;
        if stage.local_only {
            for image in release_bind::json_image_references(&canonical)? {
                let id = self
                    .effects
                    .docker(ctx, &["image", "inspect", "--format", "{{.Id}}", &image])?;
                ensure!(
                    crate::workload::release::digest(id.trim()),
                    "local current reconfiguration requires every approved cached image"
                );
            }
        } else {
            self.effects
                .docker(
                    ctx,
                    &[
                        "compose",
                        "--project-name",
                        &p.app,
                        "--project-directory",
                        &p.app_dir,
                        "-f",
                        validated.to_str().unwrap(),
                        "--profile",
                        "*",
                        "pull",
                    ],
                )
                .map_err(|_| anyhow!("complete approved image pull failed"))?;
        }
        let proxy_config = self.effects.read(
            &Path::new(&p.deployment.as_ref().unwrap().proxy_dir).join("Caddyfile"),
            1 << 20,
        );
        ensure!(
            proxy_config.is_ok() || hostnames.trim_ascii().is_empty(),
            "route requires the installed proxy configuration"
        );
        let (route, recorded, names) = routes::deployment_route(
            &p.app,
            &r.candidate,
            &hostnames,
            proxy_config
                .unwrap_or_default()
                .windows(4)
                .any(|s| s == b"ask "),
        )?;
        self.deployment_hostnames(p, &names)?;
        self.deployment_ingress(ctx, p, &r.proxy)?;
        let paths = [
            Path::new(&p.app_dir).join("compose.yml"),
            PathBuf::from(&r.route_path),
            Path::new(&p.app_dir).join("hostnames"),
            Path::new(&p.app_dir).join(".env"),
        ];
        *snapshot = Snapshot {
            version: 1,
            id: r.id.clone(),
            ..Default::default()
        };
        for path in &paths {
            let mut file = StagedFile {
                path: path.to_str().unwrap().into(),
                ..Default::default()
            };
            match fs::symlink_metadata(path) {
                Ok(info) => {
                    file.body = self.effects.read(path, 1 << 20)?.into();
                    file.exists = true;
                    file.mode = info.mode() & 0o777
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            snapshot.files.push(file);
        }
        files::write_json(
            &self
                .releases
                .join(&p.app)
                .join(format!("staging-{}.json", r.id)),
            snapshot,
        )?;
        self.effects.checkpoint("snapshot");
        *mutated = true;
        for file in snapshot.files.iter().take(3) {
            let previous = PathBuf::from(format!("{}.prev", file.path));
            if file.exists {
                self.effects.write(&previous, &file.body, file.mode)?
            } else {
                files::remove(&previous)?
            }
        }
        self.effects.write(&paths[0], &canonical, 0o600)?;
        self.effects.checkpoint("compose-swap");
        self.effects.write(&paths[1], &route, 0o644)?;
        self.effects.checkpoint("route-swap");
        self.effects.write(&paths[2], &recorded, 0o644)?;
        self.effects.checkpoint("hostname-swap");
        self.effects
            .docker(
                ctx,
                &[
                    "exec",
                    &r.proxy,
                    "caddy",
                    "validate",
                    "--config",
                    "/etc/caddy/Caddyfile",
                    "--adapter",
                    "caddyfile",
                ],
            )
            .map_err(|_| anyhow!("complete candidate proxy configuration is invalid"))?;
        self.effects.write(
            &paths[3],
            &transaction::deployment_env(env, &r.candidate)?,
            0o600,
        )?;
        self.effects.checkpoint("revision-swap");
        self.phase(r, "configured")?;
        let mut configured = r.clone();
        configured.version = 1;
        configured.scoped_generation = stage.generation.clone();
        configured.stage = None;
        configured.compose_sha256 = hash(&canonical);
        configured.route_sha256 = hash(&route);
        configured.check((self.now)())?;
        files::write_json(&queue.join("pending.json"), &configured)?;
        self.effects.checkpoint("configured-submission");
        Ok(configured)
    }
    pub fn deployment_capacity(&self) -> Result<()> {
        let body = match self
            .effects
            .read(&self.path(paths::DEPLOY_FLOORS_PATH), 1 << 20)
        {
            Ok(body) => body,
            Err(e) if missing(&e) => return Ok(()),
            Err(_) => anyhow::bail!("operator deployment floors are not readable"),
        };
        let (floors, present) = capacity::parse_floors(&String::from_utf8_lossy(&body))?;
        if !present {
            return Ok(());
        }
        let report = self.effects.read(&self.path(paths::REPORT_PATH), 1 << 20)?;
        report_fresh(&report, (self.now)())?;
        ensure!(
            capacity::check_floors(&floors, present, &report)?
                .refuse
                .is_empty(),
            "operator capacity floor is not met"
        );
        Ok(())
    }
    pub fn startup_capacity(&self, p: &Policy) -> Result<()> {
        if !p
            .resources
            .as_ref()
            .is_some_and(|r| r.cgroup_parent.starts_with("/komizo-production/"))
        {
            return Ok(());
        }
        let body = self
            .effects
            .read(&self.path("/etc/komizo/resources.json"), 1 << 20)
            .map_err(|_| anyhow!("installed startup allocation is unavailable"))?;
        let host: HostResources = serde_json::from_slice(&body)
            .map_err(|_| anyhow!("installed startup allocation is invalid"))?;
        let read_usage = |name: &str| -> Result<i64> {
            let path = self.path(format!(
                "/sys/fs/cgroup/komizo-production/{name}/memory.current"
            ));
            let body = crate::statefile::read(&path, 64)
                .map_err(|_| anyhow!("current startup usage is unavailable"))?
                .ok_or_else(|| anyhow!("current startup usage is unavailable"))?;
            let value = std::str::from_utf8(&body)
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|n| *n >= 0)
                .ok_or_else(|| anyhow!("current startup usage is invalid"))?;
            Ok(value)
        };
        let parent = read_usage("")?;
        let usage = host
            .apps
            .keys()
            .map(|name| Ok((name.clone(), read_usage(name)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        host.check_startup(&p.app, p.resources.as_ref(), parent, &usage)
    }
    pub fn deployment_hostnames(&self, p: &Policy, names: &[String]) -> Result<()> {
        for entry in fs::read_dir(self.path(paths::APPS_DIR))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str().and_then(|n| n.strip_suffix(".env")) else {
                continue;
            };
            if name == p.app {
                continue;
            }
            let state = self.effects.read(&entry.path(), 1 << 20)?;
            let state = String::from_utf8_lossy(&state);
            let dir = state_value(&state, "APP_DIR");
            ensure!(
                Path::new(dir).is_absolute()
                    && crate::host::inventory::clean_path(dir) == dir
                    && dir != "/",
                "invalid neighboring app record"
            );
            let metadata = match self
                .effects
                .read(&Path::new(dir).join("hostnames"), 1 << 20)
            {
                Ok(body) => body,
                Err(e) if missing(&e) => continue,
                Err(e) => return Err(e),
            };
            for line in String::from_utf8_lossy(&metadata).split('\n') {
                if let Some(first) = line.split_whitespace().next() {
                    ensure!(
                        !names.iter().any(|name| name.eq_ignore_ascii_case(first)),
                        "hostname is already claimed by another app"
                    )
                }
            }
        }
        Ok(())
    }
    pub fn verify_deployment_secrets(
        &mut self,
        ctx: &Context,
        p: &Policy,
        generation: &str,
        compose: &Path,
    ) -> Result<()> {
        let state = self.effects.read(
            &self.path(Path::new(paths::APPS_DIR).join(format!("{}.env", p.app))),
            1 << 20,
        )?;
        let state = String::from_utf8_lossy(&state);
        let get = |key| state_value(&state, key);
        ensure!(
            get("APP_DIR") == p.app_dir,
            "app state differs from protected policy"
        );
        let definition =
            scoped::parse_definition(get("SCOPED_ENV"), get("SCOPED_SCHEMA"), get("SCOPED_FILES"))?;
        let Some(definition) = definition else {
            ensure!(
                generation.is_empty(),
                "generation is not applicable to this app"
            );
            return Ok(());
        };
        ensure!(
            operation_identity(generation) && get("SCOPED_GENERATION") == generation,
            "scoped generation differs from root app state"
        );
        let secrets = Path::new(&p.app_dir).join("secrets");
        let dir = secrets.join("generations").join(generation);
        for directory in [&secrets, &dir.parent().unwrap().to_path_buf(), &dir] {
            let info = fs::symlink_metadata(directory)?;
            ensure!(
                info.is_dir() && self.effects.owned(&info) && info.mode() & 0o022 == 0,
                "unsafe scoped generation directory"
            )
        }
        ensure!(
            fs::read_link(secrets.join("current"))?
                == Path::new(&format!("generations/{generation}")),
            "scoped generation link differs"
        );
        for name in definition
            .files
            .iter()
            .map(String::as_str)
            .chain(std::iter::once("provenance"))
        {
            let info = fs::symlink_metadata(dir.join(name))?;
            ensure!(
                info.is_file()
                    && self.effects.owned(&info)
                    && info.mode() & 0o777 == if name == "provenance" { 0o400 } else { 0o600 },
                "scoped secret metadata is not protected"
            );
        }
        ensure!(
            self.effects.read(&dir.join("provenance"), 1 << 20)? == definition.marker(generation),
            "scoped provenance differs"
        );
        self.effects.scoped_check(
            ctx,
            &self.path(format!("/usr/local/bin/provision-scoped-env-{}", p.app)),
            compose,
        )
    }
    pub fn deployment_ingress(&mut self, ctx: &Context, p: &Policy, proxy: &str) -> Result<()> {
        if p.ingress_network.is_empty() || p.ingress_network == p.shared_network {
            return Ok(());
        }
        match self.effects.docker(
            ctx,
            &[
                "network",
                "inspect",
                &p.ingress_network,
                "--format",
                r#"{{index .Labels "io.komizo.app"}}"#,
            ],
        ) {
            Ok(label) => ensure!(
                label.trim() == p.app,
                "app ingress lacks the approved ownership label"
            ),
            Err(_) => {
                self.effects
                    .docker(
                        ctx,
                        &[
                            "network",
                            "create",
                            "--internal",
                            "--label",
                            &format!("io.komizo.app={}", p.app),
                            &p.ingress_network,
                        ],
                    )
                    .map_err(|_| anyhow!("app ingress creation failed"))?;
            }
        }
        let networks = self.effects.docker(
            ctx,
            &[
                "inspect",
                "--format",
                r#"{{range $name, $cfg := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}"#,
                proxy,
            ],
        )?;
        if networks
            .split_whitespace()
            .any(|name| name == p.ingress_network)
        {
            return Ok(());
        }
        self.effects
            .docker(ctx, &["network", "connect", &p.ingress_network, proxy])?;
        Ok(())
    }
}
pub fn report_fresh(body: &[u8], now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    ensure!(
        body.len() <= 1 << 20,
        "capacity report unreadable or oversized"
    );
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| anyhow!("capacity report must be from the last two minutes"))?;
    let at = value
        .get("at")
        .and_then(|v| serde_json::from_value::<Time>(v.clone()).ok());
    ensure!(
        at.is_some_and(|at| !at.is_zero()
            && at.0 <= now
            && now - at.utc() <= chrono::Duration::minutes(2)),
        "capacity report must be from the last two minutes"
    );
    Ok(())
}
