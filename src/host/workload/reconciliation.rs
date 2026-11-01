//! Explicit reviewed recovery proves serving identity without replaying deployment effects.
use super::{
    activation::Host,
    effects::Effects,
    files,
    image_cache::missing,
    transaction::{self, Snapshot, hash},
};
use crate::{
    host::{locking::DeploymentLock, stopped},
    wire::Time,
    workload::{
        activation::{ActivationError, ActivationRequest, ActivationRuntime, Context},
        operation::{self, Operation},
        policy::{Policy, commit_id, content_identity, operation_identity},
        policy_read,
        release::ReleaseAcceptance,
        release_bind,
    },
};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub id: String,
    pub candidate: String,
    pub policy_sha256: String,
    pub phase: String,
    pub serving: String,
    pub outcome: String,
}
impl<E: Effects> Host<E> {
    pub fn empty_registration(
        &mut self,
        ctx: &Context,
        p: &Policy,
        directory: &Path,
    ) -> Result<()> {
        let deployment = p
            .deployment
            .as_ref()
            .ok_or_else(|| anyhow!("initial retry requires protected deployment authority"))?;
        for path in [
            Path::new(&p.app_dir).join(".komizo-image-retention"),
            Path::new(&p.app_dir).join("hostnames"),
            Path::new(&deployment.route_path).into(),
        ] {
            ensure!(
                fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "initial registration has serving metadata"
            );
        }
        ensure!(
            self.effects
                .read(&Path::new(&p.app_dir).join(".env"), 1 << 20)
                .is_ok_and(|body| body.trim_ascii().is_empty()),
            "initial registration has installed environment"
        );
        ensure!(
            self.effects
                .read(&Path::new(&p.app_dir).join("compose.yml"), 1 << 20)
                .is_ok_and(|body| body.trim_ascii() == b"services: {}"),
            "initial registration has installed services"
        );
        ensure!(
            self.effects
                .docker(
                    ctx,
                    &[
                        "ps",
                        "-aq",
                        "--filter",
                        &format!("label=com.docker.compose.project={}", p.app)
                    ]
                )
                .is_ok_and(|body| body.trim().is_empty()),
            "initial registration has container objects or cannot be inspected"
        );
        for entry in fs::read_dir(directory)? {
            ensure!(
                !entry?.file_name().to_string_lossy().starts_with("staging-"),
                "initial registration has a configuration snapshot"
            )
        }
        Ok(())
    }
    pub fn initial_retry_allowed(
        &mut self,
        ctx: &Context,
        p: &Policy,
        directory: &Path,
    ) -> Result<()> {
        ensure!(
            p.deployment.is_some(),
            "initial retry requires protected deployment authority"
        );
        let path = directory.join("operation.json");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let op: Operation = self.read_json(&path)?;
                ensure!(
                    op.app == p.app
                        && op.version == 1
                        && op.previous.is_empty()
                        && op.phase == "reconciled"
                        && operation_identity(&op.id),
                    "initial deployment requires explicit reconciliation"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.empty_registration(ctx, p, directory)
    }
    fn verify_reconciliation(
        &mut self,
        ctx: &Context,
        serving: &str,
        compose: &[u8],
    ) -> Result<()> {
        if let Some(result) = self.effects.reconciliation_readiness(ctx, serving, compose) {
            result
        } else {
            self.verify_once(ctx, serving, compose)
        }
    }
    fn reconcile_initial(
        &mut self,
        ctx: &Context,
        r: &Request,
        op: &Operation,
        directory: &Path,
    ) -> Result<Value> {
        ensure!(
            r.serving.is_empty()
                && op.previous.is_empty()
                && matches!(op.phase.as_str(), "staging" | "staging_failed"),
            "initial reconciliation requires an early first-deployment refusal"
        );
        self.empty_registration(ctx, &self.policy.clone(), directory)?;
        let result = json!({"version":1,"operation_id":op.id,"app":op.app,"candidate":op.candidate,"outcome":r.outcome,"serving":"","application_restart":false,"database_restore":false,"provider_retry":false,"at":Time((self.now)().fixed_offset())});
        files::write_json(
            &directory.join(format!("reconciliation-{}.json", op.id)),
            &result,
        )?;
        operation::record(
            &directory.join("operation.json"),
            &op.app,
            &op.candidate,
            "",
            "reconciled",
            Time((self.now)().fixed_offset()),
        )?;
        Ok(result)
    }
    pub fn reconcile(&mut self, parent: &Context, r: &Request, queue: &Path) -> Result<Value> {
        ensure!(
            operation_identity(&r.id)
                && commit_id(&r.candidate)
                && (r.outcome == "abandon-initial" || commit_id(&r.serving))
                && content_identity(&r.policy_sha256),
            "reconciliation requires exact reviewed identities"
        );
        ensure!(
            matches!(
                r.outcome.as_str(),
                "restore-serving" | "accept-candidate" | "abandon-initial"
            ),
            "unknown reconciliation outcome"
        );
        let mut ctx = parent.clone();
        ctx.deadline = ctx.deadline.min(Instant::now() + Duration::from_secs(180));
        let _lock =
            DeploymentLock::acquire(&self.root, &self.policy.app, ctx.remaining()?, || {
                ctx.cancelled.load(Ordering::Acquire)
            })?;
        files::activation_idle(queue)?;
        let body = self.effects.read(
            &self.policies.join(format!("{}.json", self.policy.app)),
            1 << 20,
        )?;
        ensure!(
            hash(&body) == r.policy_sha256,
            "reviewed reconciliation policy changed"
        );
        let current = policy_read::read_policy(&body)?;
        ensure!(
            current.app == self.policy.app && current.deployment.is_some(),
            "protected deployment authority required"
        );
        self.policy = current;
        let p = self.policy.clone();
        ensure!(
            r.outcome != "accept-candidate" || p.r#static.is_none(),
            "static candidates require their existing ready retention; use restore-serving for initial conversion"
        );
        let path = self.releases.join(&p.app).join("operation.json");
        let op: Operation = self.read_json(&path)?;
        ensure!(
            op.version == 1
                && op.app == p.app
                && op.id == r.id
                && op.candidate == r.candidate
                && op.phase == r.phase,
            "reviewed operation changed"
        );
        ensure!(
            matches!(
                op.phase.as_str(),
                "staging"
                    | "staging_failed"
                    | "configured"
                    | "activating"
                    | "activation_failed"
                    | "readiness_failed"
                    | "failed"
            ),
            "operation is not an interrupted reconciliation fence"
        );
        if r.outcome == "abandon-initial" {
            return self.reconcile_initial(&ctx, r, &op, path.parent().unwrap());
        }
        let compose_path = Path::new(&p.app_dir).join("compose.yml");
        let mut compose = self.effects.read(&compose_path, 1 << 20)?;
        let mut snapshot = Snapshot::default();
        let mut restore_configuration = false;
        if r.outcome == "restore-serving" {
            ensure!(
                !p.require_stateful_contract
                    || matches!(
                        op.phase.as_str(),
                        "staging" | "staging_failed" | "configured"
                    ),
                "stateful activation may have written data; configuration restoration cannot establish compatibility"
            );
            ensure!(
                r.serving == op.previous,
                "restore-serving requires the existing previous revision"
            );
            match self.effects.snapshot(
                &self
                    .releases
                    .join(&p.app)
                    .join(format!("staging-{}.json", op.id)),
            ) {
                Ok(value) => {
                    snapshot = value;
                    restore_configuration = true
                }
                Err(e) => {
                    if !missing(&e)
                        || p.r#static.is_some()
                        || !matches!(op.phase.as_str(), "staging" | "staging_failed")
                    {
                        return Err(e);
                    }
                    let env = self
                        .effects
                        .read(&Path::new(&p.app_dir).join(".env"), 1 << 20)?;
                    ensure!(
                        transaction::deployment_version(&env)
                            .is_ok_and(|version| version == r.serving),
                        "early staging refusal requires the unchanged serving revision"
                    );
                }
            }
            let allowed = [
                compose_path.clone(),
                Path::new(&p.deployment.as_ref().unwrap().route_path).into(),
                Path::new(&p.app_dir).join("hostnames"),
                Path::new(&p.app_dir).join(".env"),
            ];
            ensure!(
                !restore_configuration
                    || (snapshot.version == 1
                        && snapshot.id == op.id
                        && snapshot.files.len() == allowed.len()),
                "snapshot identity differs"
            );
            for (i, file) in snapshot.files.iter().enumerate() {
                ensure!(
                    Path::new(&file.path) == allowed[i]
                        && file.exists
                        && file.mode & 0o022 == 0
                        && file.mode & !0o777 == 0
                        && file.body.len() <= 1 << 20,
                    "snapshot is outside the four protected configuration files"
                );
            }
            if restore_configuration {
                ensure!(
                    transaction::deployment_version(&snapshot.files[3].body)
                        .is_ok_and(|version| version == r.serving),
                    "snapshot revision differs"
                );
                compose = snapshot.files[0].body.to_vec()
            }
        } else {
            ensure!(
                r.serving == op.candidate,
                "accept-candidate requires the exact candidate"
            )
        }
        let retained = self.effects.read(
            &Path::new(&p.app_dir).join(".komizo-image-retention"),
            1 << 20,
        );
        if r.outcome == "restore-serving" {
            ensure!(
                retained.is_ok_and(|body| transaction::parse_retained(&body)
                    .is_ok_and(|(current, _)| current == r.serving)),
                "restoration requires the still-retained serving release"
            )
        }
        let accepted: ReleaseAcceptance = self.read_json(
            &self
                .releases
                .join(&p.app)
                .join(format!("{}.json", r.serving)),
        )?;
        release_bind::bind_release(
            &mut |args| self.effects.docker(&ctx, args),
            &p,
            &accepted,
            &r.serving,
            &format!("{}config:{}", p.image_prefix, r.serving),
            &compose,
            false,
        )?;
        let state = stopped::state_revision(&self.root, &p.app)?;
        ensure!(
            !stopped::is_stopped(&self.root, &p.app)?,
            "owner stop retained; explicitly reconcile while stopped after serving identity review"
        );
        self.verify_reconciliation(&ctx, &r.serving, &compose)
            .map_err(|e| anyhow!("existing serving identity unavailable: {e}"))?;
        if restore_configuration {
            transaction::restore_snapshot(&snapshot, &mut |path, body, mode| {
                self.effects.write(path, body, mode)
            })?;
            self.effects.checkpoint("reconcile_configuration")
        }
        let activation = ActivationRequest {
            app: p.app.clone(),
            id: op.id.clone(),
            candidate: r.serving.clone(),
            previous: op.previous.clone(),
            proxy: p.deployment.as_ref().unwrap().proxy.clone(),
            route_path: p.deployment.as_ref().unwrap().route_path.clone(),
            ..Default::default()
        };
        self.reload_proxy(&ctx, &activation)?;
        for pass in 0..2 {
            if !stopped::state_revision(&self.root, &p.app).is_ok_and(|current| current == state) {
                let _ = self.compose_workload(&ctx, &activation, "stop");
                return Err(ActivationError::Stopped.into());
            }
            if pass == 0 {
                self.verify_reconciliation(&ctx, &r.serving, &compose)?
            }
        }
        if r.outcome == "accept-candidate" {
            self.retain_workload(&activation)?
        }
        let result = json!({"version":1,"operation_id":op.id,"app":p.app,"candidate":op.candidate,"serving":r.serving,"outcome":r.outcome,"configuration_restored":restore_configuration,"application_restart":false,"database_restore":false,"provider_retry":false,"at":Time((self.now)().fixed_offset())});
        files::write_json(
            &self
                .releases
                .join(&p.app)
                .join(format!("reconciliation-{}.json", op.id)),
            &result,
        )?;
        operation::record(
            &path,
            &p.app,
            &op.candidate,
            &op.previous,
            "reconciled",
            Time((self.now)().fixed_offset()),
        )?;
        Ok(result)
    }
}
