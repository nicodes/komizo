//! Privileged activation consumes durable, identity-bound work after SSH disconnects.
use super::{
    effects::Effects,
    files::{self, Document},
    image_cache::missing,
    static_serving::StaticOperation,
    transaction::hash,
};
use crate::{
    host::{Probe, locking::DeploymentLock, stopped},
    wire::Time,
    workload::{
        activation::{
            self, ActivationError, ActivationRequest, ActivationResult, ActivationRuntime, Context,
        },
        archive,
        operation::{self, Operation},
        policy::Policy,
        policy_read, readiness,
        release::ReleaseAcceptance,
        release_bind,
    },
};
use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, Instant, SystemTime},
};
pub struct Host<E> {
    pub root: PathBuf,
    pub policies: PathBuf,
    pub releases: PathBuf,
    pub effects: E,
    pub policy: Policy,
    pub(super) static_operation: Option<StaticOperation>,
    pub client: reqwest::blocking::Client,
    pub now: fn() -> DateTime<Utc>,
}
impl<E: Effects> Host<E> {
    pub fn new(root: PathBuf, effects: E) -> Result<Self> {
        let probe = Probe { root: root.clone() };
        Ok(Self {
            policies: probe.path(super::POLICIES),
            releases: probe.path(super::RELEASES),
            root,
            effects,
            policy: Policy::default(),
            static_operation: None,
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            now: Utc::now,
        })
    }
    pub fn path(&self, path: impl AsRef<Path>) -> PathBuf {
        Probe {
            root: self.root.clone(),
        }
        .path(path)
    }
    pub fn read_json<T: Document>(&self, path: &Path) -> Result<T> {
        files::decode(&self.effects.read(path, 64 << 10)?, 64 << 10)
    }
    pub fn operation(&self, r: &ActivationRequest) -> Result<Operation> {
        let op: Operation = self.read_json(&self.releases.join(&r.app).join("operation.json"))?;
        ensure!(
            op.version == 1
                && op.id == r.id
                && op.candidate == r.candidate
                && op.previous == r.previous
                && op.deadline == r.deadline,
            "activation no longer owns the durable operation"
        );
        Ok(op)
    }
    pub fn compose_workload(
        &mut self,
        ctx: &Context,
        r: &ActivationRequest,
        verb: &str,
    ) -> Result<()> {
        let path = Path::new(&self.policy.app_dir).join("compose.yml");
        let mut args = vec![
            "compose",
            "--project-name",
            &r.app,
            "--project-directory",
            &self.policy.app_dir,
            "-f",
            path.to_str()
                .ok_or_else(|| anyhow!("invalid compose path"))?,
        ];
        match verb {
            "up" => args.extend(["up", "-d", "--remove-orphans", "--pull", "never"]),
            "stop" => args.push("stop"),
            _ => anyhow::bail!("invalid activation compose verb"),
        }
        self.effects.docker(ctx, &args)?;
        Ok(())
    }
    pub fn retain_workload(&mut self, r: &ActivationRequest) -> Result<()> {
        if r.candidate != r.previous {
            let path = Path::new(&self.policy.app_dir).join(".komizo-image-retention");
            if let Ok(info) = fs::symlink_metadata(&path) {
                ensure!(info.is_file(), "unsafe retention destination")
            }
            files::write_atomic(
                &path,
                format!("CURRENT={}\nPREVIOUS={}\n", r.candidate, r.previous).as_bytes(),
                0o600,
            )?;
        }
        for path in [
            Path::new(&self.policy.app_dir).join("compose.yml.prev"),
            Path::new(&self.policy.app_dir).join("hostnames.prev"),
            PathBuf::from(format!("{}.prev", r.route_path)),
        ] {
            files::remove(&path)?
        }
        self.effects.checkpoint("retention");
        Ok(())
    }
    pub fn verify_once(&mut self, ctx: &Context, candidate: &str, compose: &[u8]) -> Result<()> {
        let effects = std::cell::RefCell::new(&mut self.effects);
        let mut run = |args: &[&str]| effects.borrow_mut().docker(ctx, args);
        let mut probe = |probe: &crate::workload::policy::ReadinessProbe| {
            effects
                .borrow_mut()
                .probe(ctx, &self.client, candidate, probe)
        };
        if self.policy.r#static.is_some() {
            readiness::verify_static_readiness(&mut run, &mut probe, &self.policy, candidate)
        } else {
            readiness::verify_readiness(
                &mut run,
                &mut probe,
                &self.policy,
                candidate,
                &format!("{}/compose.yml", self.policy.app_dir),
                compose,
            )
        }
    }
    pub fn activation_pass(&mut self, ctx: &Context, queue: &Path) -> Result<()> {
        let pending = queue.join("pending.json");
        if fs::symlink_metadata(&pending).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(());
        }
        let mut request: ActivationRequest = self.read_json(&pending)?;
        request.check_identity()?;
        let _lock = DeploymentLock::acquire(
            &self.root,
            &request.app,
            ctx.remaining()?.min(Duration::from_secs(60)),
            || ctx.cancelled.load(Ordering::Acquire),
        )?;
        let owned = self.operation(&request);
        let result = if let Ok(op) = owned
            && matches!(op.phase.as_str(), "ready" | "prepared_stopped")
        {
            ActivationResult {
                version: 1,
                id: request.id.clone(),
                app: request.app.clone(),
                candidate: request.candidate.clone(),
                at: op.at,
                phase: op.phase.clone(),
                ok: true,
                started: Some(op.phase == "ready"),
                scoped_generation: request.scoped_generation.clone(),
            }
        } else if request.stage.is_some() {
            match self.stage_deployment(ctx, &request, queue) {
                Ok(configured) => {
                    request = configured;
                    activation::activate(ctx, &request, self).0
                }
                Err(error) => ActivationResult {
                    version: 1,
                    id: request.id.clone(),
                    app: request.app.clone(),
                    candidate: request.candidate.clone(),
                    at: Time((self.now)().fixed_offset()),
                    phase: if error.downcast_ref::<ActivationError>()
                        == Some(&ActivationError::Reconciliation)
                    {
                        "reconciliation_required"
                    } else {
                        "staging_failed"
                    }
                    .into(),
                    ..Default::default()
                },
            }
        } else {
            activation::activate(ctx, &request, self).0
        };
        prune_results(queue, SystemTime::now())?;
        files::write_json(&queue.join(format!("{}.json", request.id)), &result)?;
        match fs::remove_dir_all(queue.join(format!("credentials-{}", request.id))) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if result.ok && matches!(result.phase.as_str(), "ready" | "prepared_stopped") {
            files::remove(
                &self
                    .releases
                    .join(&request.app)
                    .join(format!("staging-{}.json", request.id)),
            )?
        }
        fs::remove_file(pending)?;
        File::open(queue)?.sync_all()?;
        Ok(())
    }
}
impl<E: Effects> ActivationRuntime for Host<E> {
    fn verify(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()> {
        ensure!(
            self.operation(r)?.phase == "configured",
            ActivationError::Reconciliation
        );
        let policy_path = self.policies.join(format!("{}.json", r.app));
        for (path, expected) in [
            (policy_path.as_path(), &r.policy_sha256),
            (Path::new(&r.route_path), &r.route_sha256),
        ] {
            let body = self.effects.read(path, 1 << 20)?;
            ensure!(
                hash(&body) == *expected,
                "configured activation input changed"
            );
            if path.parent() == Some(self.policies.as_path()) {
                self.policy = policy_read::read_policy(&body)?
            }
        }
        ensure!(
            self.policy.app == r.app,
            "activation policy identity differs"
        );
        let compose = self.effects.read(
            &Path::new(&self.policy.app_dir).join("compose.yml"),
            1 << 20,
        )?;
        ensure!(
            hash(&compose) == r.compose_sha256,
            "configured compose changed"
        );
        let env = self
            .effects
            .read(&Path::new(&self.policy.app_dir).join(".env"), 1 << 20)?;
        let env = String::from_utf8_lossy(&env);
        let version = env
            .split('\n')
            .find_map(|line| line.strip_prefix("APP_VERSION="))
            .unwrap_or_default();
        ensure!(version == r.candidate, "configured app revision differs");
        if self.policy.r#static.is_some() {
            archive::static_gate(&compose, &r.app)?;
        }
        if self.policy.has_release_authority() {
            let accepted: ReleaseAcceptance = self.read_json(
                &self
                    .releases
                    .join(&r.app)
                    .join(format!("{}.json", r.candidate)),
            )?;
            release_bind::bind_release(
                &mut |args| self.effects.docker(ctx, args),
                &self.policy,
                &accepted,
                &r.candidate,
                &format!("{}config:{}", self.policy.image_prefix, r.candidate),
                &compose,
                false,
            )?;
        }
        Ok(())
    }
    fn stopped(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<bool> {
        ctx.check()?;
        stopped::is_stopped(&self.root, &r.app)
    }
    fn compose(&mut self, ctx: &Context, r: &ActivationRequest, action: &str) -> Result<()> {
        if self.policy.r#static.is_some() {
            match action {
                "up" => return self.prepare_static(ctx, r),
                "stop" => {
                    if self.static_operation.is_none() {
                        self.prepare_stopped_static(r)?
                    }
                    let route = self
                        .static_operation
                        .as_ref()
                        .unwrap()
                        .record
                        .disabled_route
                        .to_vec();
                    self.static_route(&route, false)?;
                    self.compose_workload(ctx, r, "stop")?;
                    return self.reload_proxy(ctx, r);
                }
                _ => anyhow::bail!("invalid static activation verb"),
            }
        }
        self.compose_workload(ctx, r, action)
    }
    fn reload_proxy(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()> {
        for verb in ["validate", "reload"] {
            self.effects.docker(ctx,&["exec",&r.proxy,"caddy",verb,"--config","/etc/caddy/Caddyfile","--adapter","caddyfile"]).map_err(|_|anyhow!("complete candidate proxy configuration failed; loaded configuration retained"))?;
        }
        self.effects.checkpoint("proxy_reload");
        Ok(())
    }
    fn retain(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()> {
        ctx.check()?;
        if self.policy.r#static.is_some() {
            return Ok(());
        }
        self.retain_workload(r)
    }
    fn ready(&mut self, parent: &Context, r: &ActivationRequest) -> Result<()> {
        ensure!(
            self.policy.readiness.is_some(),
            ActivationError::ReadinessUnspecified
        );
        let body = self.effects.read(
            &Path::new(&self.policy.app_dir).join("compose.yml"),
            1 << 20,
        )?;
        let mut ctx = parent.clone();
        ctx.deadline = ctx.deadline.min(Instant::now() + Duration::from_secs(90));
        loop {
            ensure!(!self.stopped(&ctx, r)?, ActivationError::Stopped);
            if self.verify_once(&ctx, &r.candidate, &body).is_ok() {
                return Ok(());
            }
            sleep(&ctx, Duration::from_secs(2))
                .map_err(|_| anyhow!("candidate readiness did not pass before its deadline"))?;
        }
    }
    fn phase(&mut self, r: &ActivationRequest, phase: &str) -> Result<()> {
        self.operation(r)?;
        let accepted =
            self.policy.r#static.is_some() && matches!(phase, "ready" | "prepared_stopped");
        if accepted {
            if self.static_operation.is_none() {
                self.prepare_stopped_static(r)?
            }
            self.retain_workload(r)?;
            self.store_static()?
        }
        operation::record(
            &self.releases.join(&r.app).join("operation.json"),
            &r.app,
            &r.candidate,
            &r.previous,
            phase,
            Time((self.now)().fixed_offset()),
        )?;
        self.effects.checkpoint(&format!("journal_{phase}"));
        if accepted {
            let cleanup = Context::new(Instant::now() + Duration::from_secs(30));
            if self.compose_workload(&cleanup, r, "stop").is_err() {
                eprintln!("static serving accepted; redundant gate retirement needs reconciliation")
            }
            if phase == "ready" && self.prune_static(r).is_err() {
                eprintln!("static serving accepted; public-tree retention needs reconciliation")
            }
        }
        Ok(())
    }
    fn abort_static(&mut self, ctx: &Context, r: &ActivationRequest) -> Option<Result<()>> {
        Some(self.abort_static_operation(ctx, r))
    }
}
pub fn sleep(ctx: &Context, duration: Duration) -> Result<()> {
    let end = (Instant::now() + duration).min(ctx.deadline);
    while Instant::now() < end {
        ctx.check()?;
        std::thread::sleep(
            end.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20)),
        )
    }
    ctx.check()
}
pub fn wait(ctx: &Context, queue: &Path, id: &str) -> Result<ActivationResult> {
    ensure!(
        crate::workload::policy::operation_identity(id),
        "invalid operation identity"
    );
    let path = queue.join(format!("{id}.json"));
    loop {
        match files::read_json::<ActivationResult>(&path) {
            Ok(result) => {
                ensure!(
                    result.version == 1 && result.id == id,
                    "activation result identity differs"
                );
                return Ok(result);
            }
            Err(error) => {
                if !missing(&error)
                    || !fs::symlink_metadata(&path)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err(error);
                }
            }
        }
        sleep(ctx, Duration::from_millis(200))?
    }
}
pub fn prune_results(directory: &Path, now: SystemTime) -> Result<()> {
    let mut results = vec![];
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name
            .strip_suffix(".json")
            .is_some_and(crate::workload::policy::operation_identity)
        {
            continue;
        }
        let info = fs::symlink_metadata(entry.path())?;
        ensure!(info.is_file(), "unsafe activation result");
        results.push((info.modified()?, entry.path()));
    }
    results.sort();
    let count = results.len();
    for (index, (at, path)) in results.into_iter().enumerate() {
        if index < count.saturating_sub(255)
            || now.duration_since(at).unwrap_or_default() > Duration::from_secs(7 * 24 * 60 * 60)
        {
            fs::remove_file(path)?
        }
    }
    Ok(())
}
