//! Protected immutable public-tree publication and owner lifecycle.
use super::{
    activation::Host,
    effects::Effects,
    files::{self, Document},
    image_cache::missing,
    transaction::hash,
};
use crate::{
    host::{StaticServing, application::Subject, locking::DeploymentLock, scoped, stopped},
    wire::{Bytes, Time},
    workload::{
        activation::{ActivationError, ActivationRequest, ActivationRuntime, Context},
        archive,
        policy::{StaticLimits, commit_id},
        release::ReleaseAcceptance,
        release_bind, routes,
        static_tree::{self, STATIC_ROOT},
    },
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticRecord {
    #[serde(flatten)]
    pub serving: StaticServing,
    pub disabled_route: Bytes,
}
impl Document for StaticRecord {
    fn fields() -> &'static [&'static str] {
        &[
            "version",
            "revision",
            "tree_sha256",
            "route_sha256",
            "gate_image",
            "proxy",
            "active",
            "disabled_route",
        ]
    }
}
pub(super) struct StaticOperation {
    pub record: StaticRecord,
    previous: Option<StaticRecord>,
    previous_route: Vec<u8>,
    previous_retain: Vec<u8>,
}
impl<E: Effects> Host<E> {
    pub fn perform_static_owner(
        &mut self,
        ctx: &Context,
        verb: &str,
        subject: &Subject,
        service: &str,
        actor: &str,
    ) -> Result<bool> {
        ensure!(
            service.is_empty(),
            "static serving requires a whole-application operation"
        );
        if verb == "stop" {
            stopped::mark_stopped(
                &subject.root,
                &subject.app,
                actor,
                Time((self.now)().fixed_offset()),
            )?
        }
        let _lock = DeploymentLock::acquire(
            &subject.root,
            &subject.app,
            ctx.remaining()?.min(Duration::from_secs(60)),
            || ctx.cancelled.load(std::sync::atomic::Ordering::Acquire),
        )?;
        let record = match self.read_json::<StaticRecord>(&self.static_path(&subject.app)) {
            Ok(record) => record,
            Err(e) if verb == "stop" && missing(&e) => return Ok(false),
            Err(_) => {
                anyhow::bail!("static serving record unavailable; inspect the deployment journal")
            }
        };
        let p = self.policy.clone();
        let profile = p.r#static.as_ref().unwrap();
        ensure!(
            record.serving.version == 1
                && record.serving.proxy == profile.proxy
                && commit_id(&record.serving.revision)
                && !record.disabled_route.is_empty()
                && record.disabled_route.len() <= 1 << 20,
            "invalid protected static serving record"
        );
        routes::static_route(
            &record.disabled_route,
            &subject.app,
            &record.serving.revision,
            &profile.hostnames,
            &profile.serving,
        )?;
        let scoped = scoped::check_start(&subject.root, &subject.app);
        if verb != "stop" {
            scoped?
        }
        if verb == "stop" {
            let route = record.disabled_route.to_vec();
            let revision = record.serving.revision.clone();
            self.static_operation = Some(StaticOperation {
                record,
                previous: None,
                previous_route: vec![],
                previous_retain: vec![],
            });
            self.static_route(&route, false)?;
            let r = ActivationRequest {
                app: subject.app.clone(),
                candidate: revision,
                proxy: profile.proxy.clone(),
                ..Default::default()
            };
            self.reload_proxy(ctx, &r)?;
            self.compose_workload(ctx, &r, "stop")?;
            self.store_static()?;
            return Ok(true);
        }
        let state = stopped::state_revision(&subject.root, &subject.app)?;
        ensure!(
            verb != "restart" || !stopped::is_stopped(&subject.root, &subject.app)?,
            "stopped static application must be explicitly started"
        );
        ctx.check()?;
        let current = self
            .effects
            .read(&Path::new(&p.app_dir).join(".env"), 1 << 20)?;
        let current = String::from_utf8_lossy(&current);
        let versions: Vec<_> = current
            .split('\n')
            .filter_map(|line| {
                line.strip_prefix("APP_VERSION=")
                    .map(|value| value.strip_suffix('\r').unwrap_or(value))
            })
            .collect();
        ensure!(
            versions.len() == 1 && versions[0] == record.serving.revision,
            "static serving revision differs; inspect the deployment journal"
        );
        let accepted: ReleaseAcceptance = self.read_json(
            &self
                .releases
                .join(&subject.app)
                .join(format!("{}.json", record.serving.revision)),
        )?;
        let compose = self
            .effects
            .read(&Path::new(&p.app_dir).join("compose.yml"), 1 << 20)?;
        release_bind::bind_release(
            &mut |args| self.effects.docker(ctx, args),
            &p,
            &accepted,
            &record.serving.revision,
            &format!("{}config:{}", p.image_prefix, record.serving.revision),
            &compose,
            false,
        )?;
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|e| anyhow!("operation identity: {e}"))?;
        let r = ActivationRequest {
            app: subject.app.clone(),
            candidate: record.serving.revision,
            id: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
            proxy: profile.proxy.clone(),
            route_path: self
                .path(format!("/srv/_proxy/routes/{}.caddy", subject.app))
                .to_str()
                .unwrap()
                .into(),
            ..Default::default()
        };
        let result = (|| -> Result<()> {
            self.prepare_static(ctx, &r)?;
            self.reload_proxy(ctx, &r)?;
            self.verify_once(ctx, &r.candidate, &compose)?;
            self.store_static()
        })();
        if let Err(error) = result {
            let restore = self.abort_static_operation(ctx, &r);
            return Err(match restore {
                Ok(()) => error,
                Err(restore) => anyhow!("{error}; {restore}"),
            });
        }
        let current = stopped::state_revision(&subject.root, &subject.app);
        if !current.as_ref().is_ok_and(|current| *current == state) {
            let cleanup = Context::new(Instant::now() + Duration::from_secs(30));
            let restore = self.abort_static_operation(&cleanup, &r);
            return Err(anyhow!(
                "{}; {}; {}",
                ActivationError::Stopped,
                current.err().map(|e| e.to_string()).unwrap_or_default(),
                restore.err().map(|e| e.to_string()).unwrap_or_default()
            ));
        }
        if verb == "start"
            && !stopped::clear_stopped_if_unchanged(&subject.root, &subject.app, &state)
                .unwrap_or(false)
        {
            let cleanup = Context::new(Instant::now() + Duration::from_secs(30));
            let restore = self.abort_static_operation(&cleanup, &r);
            return Err(anyhow!(
                "{}; {}",
                ActivationError::Stopped,
                restore.err().map(|e| e.to_string()).unwrap_or_default()
            ));
        }
        Ok(true)
    }
    pub fn static_path(&self, app: &str) -> PathBuf {
        self.path(format!("/var/lib/komizo/static/{app}.json"))
    }
    fn static_mount(&mut self, ctx: &Context) -> Result<()> {
        let p = self.policy.r#static.as_ref().unwrap();
        let body=self.effects.docker(ctx,&["inspect","--format",r#"{{range .Mounts}}{{if eq .Destination "/srv/public"}}{"source":{{json .Source}},"read_write":{{json .RW}}}{{end}}{{end}}"#,&p.proxy]);
        let mount = body
            .ok()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok());
        ensure!(
            mount.is_some_and(|mount| mount["read_write"] == false
                && mount["source"].as_str() == self.path(STATIC_ROOT).to_str()),
            "shared proxy requires the isolated read-only public-tree mount"
        );
        Ok(())
    }
    pub fn prepare_static(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()> {
        let p = self.policy.r#static.as_ref().unwrap().clone();
        ensure!(
            r.proxy == p.proxy
                && Path::new(&r.route_path).parent()
                    == Some(self.path("/srv/_proxy/routes").as_path()),
            "static serving requires the protected standard proxy route"
        );
        let compose = self.effects.read(
            &Path::new(&self.policy.app_dir).join("compose.yml"),
            1 << 20,
        )?;
        let mut route = self.effects.read(Path::new(&r.route_path), 1 << 20)?;
        let previous = match self.read_json::<StaticRecord>(&self.static_path(&r.app)) {
            Ok(record) => Some(record),
            Err(e) if missing(&e) => None,
            Err(e) => return Err(e),
        };
        if let Some(previous) = &previous
            && previous.serving.revision == r.candidate
            && !previous.disabled_route.is_empty()
            && !String::from_utf8_lossy(&route)
                .contains(&format!("\treverse_proxy {}-gate:80 {{", r.app))
        {
            route = previous.disabled_route.to_vec()
        }
        let previous_route = self
            .effects
            .read(Path::new(&format!("{}.prev", r.route_path)), 1 << 20)
            .or_else(|_| self.effects.read(Path::new(&r.route_path), 1 << 20))
            .unwrap_or_default();
        let previous_retain = self
            .effects
            .read(
                &Path::new(&self.policy.app_dir).join(".komizo-image-retention"),
                1 << 20,
            )
            .unwrap_or_default();
        self.static_operation = Some(StaticOperation {
            record: StaticRecord {
                serving: StaticServing {
                    version: 1,
                    revision: r.candidate.clone(),
                    proxy: r.proxy.clone(),
                    ..Default::default()
                },
                disabled_route: route.clone().into(),
            },
            previous,
            previous_route,
            previous_retain,
        });
        self.static_mount(ctx)?;
        let gate = archive::static_gate(&compose, &r.app)?;
        self.static_operation
            .as_mut()
            .unwrap()
            .record
            .serving
            .gate_image = gate.clone();
        let active = routes::static_route(&route, &r.app, &r.candidate, &p.hostnames, &p.serving)?;
        let public = self.path(STATIC_ROOT);
        for directory in [&public, &public.join(&r.app)] {
            self.effects.directory(directory, 0o755)?
        }
        let volumes = self
            .effects
            .docker(
                ctx,
                &[
                    "image",
                    "inspect",
                    "--format",
                    "{{json .Config.Volumes}}",
                    &gate,
                ],
            )
            .map_err(|_| anyhow!("cannot verify public image volumes"))?;
        let volumes: Option<BTreeMap<String, serde_json::Value>> =
            serde_json::from_str(&volumes)
                .map_err(|_| anyhow!("cannot verify public image volumes"))?;
        ensure!(
            volumes
                .unwrap_or_default()
                .keys()
                .all(|volume| matches!(volume.as_str(), "/data" | "/config")),
            "static image declares an unreviewed volume"
        );
        static_space(&public, &p.limits)?;
        let cid = self
            .effects
            .docker(
                ctx,
                &[
                    "create",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--mount",
                    "type=tmpfs,destination=/data,tmpfs-size=1048576,tmpfs-mode=0700",
                    "--mount",
                    "type=tmpfs,destination=/config,tmpfs-size=1048576,tmpfs-mode=0700",
                    "--entrypoint",
                    "/nonexistent",
                    &gate,
                ],
            )
            .map_err(|_| anyhow!("cannot open the admitted public image"))?;
        let cid = cid.trim().to_owned();
        ensure!(
            crate::workload::policy::content_identity(&cid),
            "cannot open the admitted public image"
        );
        let result = (|| -> Result<()> {
            self.effects.archive(
                ctx,
                &["cp", &format!("{cid}:/etc/caddy/Caddyfile"), "-"],
                (128 << 10) + (1 << 20),
                &mut |reader| {
                    let mut archive = tar::Archive::new(reader.take(128 << 10));
                    let mut entries = archive.entries()?;
                    let mut entry = entries.next().transpose()?.ok_or_else(|| {
                        anyhow!("static profile configuration is not a bounded regular file")
                    })?;
                    ensure!(
                        entry.path_bytes().as_ref() == b"Caddyfile"
                            && entry.header().entry_type().is_file()
                            && entry.size() <= 65536,
                        "static profile configuration is not a bounded regular file"
                    );
                    let mut body = vec![];
                    entry.read_to_end(&mut body)?;
                    ensure!(
                        hash(&body) == p.gate_config_sha,
                        "gate configuration changed; repeat serving parity review"
                    );
                    drop(entry);
                    ensure!(
                        entries.next().is_none(),
                        "unexpected static profile archive entries"
                    );
                    Ok(())
                },
            )?;
            let stage = public.join(&r.app).join(format!(".prepare-{}", r.id));
            let copied = (|| -> Result<()> {
                let mut tree_sha = String::new();
                let (max_bytes, _) = p.limits.bounds()?;
                self.effects.archive(
                    ctx,
                    &["cp", &format!("{cid}:{}/.", p.image_directory), "-"],
                    max_bytes as u64 + (static_tree::MAX_ENTRIES as u64) * 2048 + (1 << 20),
                    &mut |reader| {
                        tree_sha = static_tree::static_tree(reader, &stage, &p.limits)?;
                        Ok(())
                    },
                )?;
                self.effects.checkpoint("public_copy");
                let final_path = public.join(&r.app).join(&r.candidate);
                match fs::symlink_metadata(&final_path) {
                    Ok(info) => {
                        ensure!(
                            info.is_dir() && self.effects.directory(&final_path, 0o755).is_ok(),
                            "unsafe existing public tree"
                        );
                        ensure!(
                            static_tree::static_tree_checksum(&final_path, &p.limits)
                                .is_ok_and(|existing| existing == tree_sha),
                            "existing public tree differs from its admitted image"
                        )
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        fs::rename(&stage, &final_path)?
                    }
                    Err(e) => return Err(e.into()),
                }
                File::open(final_path.parent().unwrap())?.sync_all()?;
                self.effects.checkpoint("public_rename");
                self.static_operation
                    .as_mut()
                    .unwrap()
                    .record
                    .serving
                    .tree_sha256 = tree_sha;
                self.static_route(&active, true)
            })();
            let _ = fs::remove_dir_all(&stage);
            copied
        })();
        let cleanup = Context::new(Instant::now() + Duration::from_secs(30));
        let _ = self.effects.docker(&cleanup, &["rm", "-v", &cid]);
        result
    }
    pub fn static_route(&mut self, route: &[u8], active: bool) -> Result<()> {
        ensure!(
            self.static_operation.is_some(),
            "static operation not prepared"
        );
        let path = self.path(format!("/srv/_proxy/routes/{}.caddy", self.policy.app));
        files::write_atomic(&path, route, 0o644)?;
        let record = &mut self.static_operation.as_mut().unwrap().record.serving;
        record.route_sha256 = hash(route);
        record.active = active;
        self.effects.checkpoint("route_write");
        Ok(())
    }
    pub fn store_static(&mut self) -> Result<()> {
        let path = self.static_path(&self.policy.app);
        self.effects.directory(path.parent().unwrap(), 0o700)?;
        files::write_json(
            &path,
            &self
                .static_operation
                .as_ref()
                .ok_or_else(|| anyhow!("static operation not prepared"))?
                .record,
        )?;
        self.effects.checkpoint("serving_record");
        Ok(())
    }
    pub fn prepare_stopped_static(&mut self, r: &ActivationRequest) -> Result<()> {
        let route = self.effects.read(Path::new(&r.route_path), 1 << 20)?;
        let compose = self.effects.read(
            &Path::new(&self.policy.app_dir).join("compose.yml"),
            1 << 20,
        )?;
        let gate = archive::static_gate(&compose, &r.app)?;
        self.static_operation = Some(StaticOperation {
            record: StaticRecord {
                serving: StaticServing {
                    version: 1,
                    revision: r.candidate.clone(),
                    gate_image: gate,
                    proxy: r.proxy.clone(),
                    route_sha256: hash(&route),
                    ..Default::default()
                },
                disabled_route: route.into(),
            },
            previous: None,
            previous_route: vec![],
            previous_retain: vec![],
        });
        Ok(())
    }
    pub fn abort_static_operation(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()> {
        let Some(operation) = self.static_operation.as_ref() else {
            return Ok(());
        };
        if operation.previous_route.is_empty() {
            return Ok(());
        }
        let previous_retain = operation.previous_retain.clone();
        let mut previous = operation.previous.clone();
        ctx.check()?;
        let stopped = stopped::is_stopped(&self.root, &r.app)?;
        let route = if stopped {
            operation.record.disabled_route.to_vec()
        } else {
            operation.previous_route.clone()
        };
        files::write_atomic(Path::new(&r.route_path), &route, 0o644)?;
        self.reload_proxy(ctx, r)?;
        if !previous_retain.is_empty() {
            files::write_atomic(
                &Path::new(&self.policy.app_dir).join(".komizo-image-retention"),
                &previous_retain,
                0o600,
            )?
        }
        if let Some(previous) = previous.as_mut() {
            if stopped {
                previous.serving.active = false;
                previous.serving.route_sha256 = hash(&route)
            }
            files::write_json(&self.static_path(&r.app), previous)
        } else {
            files::remove(&self.static_path(&r.app))
        }
    }
    pub fn prune_static(&mut self, r: &ActivationRequest) -> Result<()> {
        let directory = self.path(Path::new(STATIC_ROOT).join(&r.app));
        let limits = self.policy.r#static.as_ref().unwrap().limits.clone();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == r.candidate || name == r.previous || !commit_id(name) {
                continue;
            }
            let path = entry.path();
            let info = fs::symlink_metadata(&path)?;
            ensure!(
                info.is_dir() && self.effects.directory(&path, 0o755).is_ok(),
                "unsafe retired public tree"
            );
            static_tree::static_tree_checksum(&path, &limits)?;
            fs::remove_dir_all(path)?;
        }
        File::open(directory)?.sync_all()?;
        Ok(())
    }
}
pub fn static_space(directory: &Path, limits: &StaticLimits) -> Result<()> {
    let (max_bytes, _) = limits.bounds()?;
    #[cfg(target_os = "linux")]
    {
        let path = std::ffi::CString::new(directory.as_os_str().as_bytes())?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        ensure!(
            unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
            "public extraction would consume the host recovery floor"
        );
        let stat = unsafe { stat.assume_init() };
        ensure!(
            u128::from(stat.f_bavail) * u128::from(stat.f_frsize)
                > ((2_u128 << 30) + 2 * (max_bytes as u128))
                && stat.f_ffree >= 1024 + 2 * (static_tree::MAX_ENTRIES as u64),
            "public extraction would consume the host recovery floor"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (directory, max_bytes);
        anyhow::bail!("static extraction requires the Linux host executor")
    }
}
