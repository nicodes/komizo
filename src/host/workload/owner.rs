//! Owner lifecycle cannot bypass protected deployment or static serving authority.
use super::{
    activation::{Host, sleep},
    effects::Effects,
    files, transaction,
};
use crate::{
    host::{application::Subject, locking::DeploymentLock, scoped, stopped},
    wire::Time,
    workload::{
        activation::{ActivationError, ActivationRequest, ActivationRuntime, Context},
        operation::Operation,
        policy::Policy,
        release::ReleaseAcceptance,
        release_bind,
    },
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
impl<E: Effects> Host<E> {
    pub fn owner_verb(
        &mut self,
        ctx: &Context,
        verb: &str,
        subject: &Subject,
        service: &str,
        actor: &str,
    ) -> Option<Result<()>> {
        if subject.app.is_empty() || !matches!(verb, "start" | "stop" | "restart") {
            return None;
        }
        self.root = subject.root.clone();
        self.policies = self.path(super::POLICIES);
        self.releases = self.path(super::RELEASES);
        let path = self.policies.join(format!("{}.json", subject.app));
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => return Some(Err(e.into())),
        }
        let policy = (|| -> Result<Policy> {
            let p: Policy = self.read_json(&path)?;
            p.check()?;
            ensure!(
                p.app == subject.app && p.app_dir == subject.dir,
                "owner operation differs from its protected workload policy"
            );
            Ok(p)
        })();
        let p = match policy {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        self.policy = p;
        if self.policy.r#static.is_some() {
            return match self.perform_static_owner(ctx, verb, subject, service, actor) {
                Ok(true) => Some(Ok(())),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            };
        }
        self.policy.deployment.as_ref()?;
        let queue = self.path(super::ACTIVATIONS);
        Some(self.perform_typed_owner(ctx, verb, subject, service, actor, &queue))
    }
    pub fn perform_typed_owner(
        &mut self,
        parent: &Context,
        verb: &str,
        subject: &Subject,
        service: &str,
        actor: &str,
        queue: &Path,
    ) -> Result<()> {
        if verb == "stop" && service.is_empty() {
            stopped::mark_stopped(
                &subject.root,
                &subject.app,
                actor,
                Time((self.now)().fixed_offset()),
            )?
        }
        let mut ctx = parent.clone();
        ctx.deadline = ctx.deadline.min(Instant::now() + Duration::from_secs(90));
        let wait = ctx.remaining()?.min(Duration::from_secs(60));
        let _lock = if verb == "stop" {
            DeploymentLock::acquire(&subject.root, &subject.app, wait, || {
                ctx.cancelled.load(Ordering::Acquire)
            })?
        } else {
            scoped::lock_for_start(&subject.root, &subject.app, wait, || {
                ctx.cancelled.load(Ordering::Acquire)
            })?
        };
        let p = self.policy.clone();
        let current: Policy =
            self.read_json(&self.policies.join(format!("{}.json", subject.app)))?;
        ensure!(
            serde_json::to_vec(&p)? == serde_json::to_vec(&current)?,
            "protected lifecycle policy changed while acquiring deployment locks"
        );
        if verb != "stop" {
            self.startup_capacity(&p)?;
            files::activation_idle(queue)?;
            let op: Operation =
                self.read_json(&self.releases.join(&p.app).join("operation.json"))?;
            ensure!(
                matches!(
                    op.phase.as_str(),
                    "ready" | "prepared_stopped" | "activated" | "reconciled"
                ),
                "interrupted deployment must be reconciled before lifecycle startup"
            );
        }
        let compose_path = Path::new(&p.app_dir).join("compose.yml");
        let body = self.effects.read(&compose_path, 1 << 20)?;
        let doc: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| anyhow!("invalid approved compose"))?;
        let services = doc.get("services").and_then(serde_json::Value::as_object);
        ensure!(
            service.is_empty() || services.is_some_and(|services| services.contains_key(service)),
            "service is outside the approved workload"
        );
        let mut args: Vec<String> = [
            "compose",
            "--project-name",
            &p.app,
            "--project-directory",
            &p.app_dir,
            "-f",
            compose_path.to_str().unwrap(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if verb == "stop" {
            args.push("stop".into());
            if !service.is_empty() {
                args.push(service.into())
            }
            self.effects
                .docker(&ctx, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
            return Ok(());
        }
        let state = stopped::state_revision(&subject.root, &subject.app)?;
        let marked = stopped::is_stopped(&subject.root, &subject.app)?;
        ensure!(
            !marked || (verb != "restart" && service.is_empty()),
            "start the whole stopped workload explicitly"
        );
        let env = self
            .effects
            .read(&Path::new(&p.app_dir).join(".env"), 1 << 20)?;
        let version = transaction::deployment_version(&env)
            .map_err(|_| anyhow!("lifecycle needs the current accepted source revision"))?;
        ensure!(
            !version.is_empty(),
            "lifecycle needs the current accepted source revision"
        );
        let retained = self.effects.read(
            &Path::new(&p.app_dir).join(".komizo-image-retention"),
            1 << 20,
        )?;
        ensure!(
            transaction::parse_retained(&retained).is_ok_and(|(current, _)| current == version),
            "lifecycle revision differs from current retention"
        );
        let accepted: ReleaseAcceptance =
            self.read_json(&self.releases.join(&p.app).join(format!("{version}.json")))?;
        release_bind::bind_release(
            &mut |args| self.effects.docker(&ctx, args),
            &p,
            &accepted,
            &version,
            &format!("{}config:{version}", p.image_prefix),
            &body,
            false,
        )?;
        if verb == "restart" {
            let mut running_args = args.clone();
            running_args.extend(["ps", "--status", "running", "--services"].map(str::to_owned));
            let running = self
                .effects
                .docker(
                    &ctx,
                    &running_args.iter().map(String::as_str).collect::<Vec<_>>(),
                )
                .map_err(|_| anyhow!("there are no running containers to restart"))?;
            ensure!(
                !running.trim().is_empty(),
                "there are no running containers to restart"
            );
            let mut seen = BTreeSet::new();
            let mut running: Vec<_> = running.split_whitespace().map(str::to_owned).collect();
            for name in &running {
                ensure!(
                    services.is_some_and(|services| services.contains_key(name))
                        && seen.insert(name.clone()),
                    "running service inventory differs from the approved workload"
                )
            }
            if !service.is_empty() {
                ensure!(
                    seen.contains(service),
                    "the requested service is stopped; start it explicitly"
                );
                running = vec![service.into()]
            }
            args.extend(["restart", "--no-deps"].map(str::to_owned));
            args.extend(running);
        } else {
            args.extend(["up", "-d", "--remove-orphans", "--pull", "never"].map(str::to_owned));
            if !service.is_empty() {
                args.push(service.into())
            }
        }
        self.effects
            .docker(&ctx, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
        loop {
            if stopped::state_revision(&subject.root, &subject.app)? != state {
                let _ = self.stop_after_owner_change(&p.app);
                return Err(ActivationError::Stopped.into());
            }
            if p.readiness.is_none() || self.verify_once(&ctx, &version, &body).is_ok() {
                break;
            }
            sleep(&ctx, Duration::from_secs(2))
                .map_err(|_| anyhow!("owner lifecycle readiness did not pass"))?;
        }
        if verb == "start" && service.is_empty() {
            match stopped::clear_stopped_if_unchanged(&subject.root, &subject.app, &state) {
                Ok(true) => {}
                Ok(false) => {
                    let _ = self.stop_after_owner_change(&p.app);
                    return Err(ActivationError::Stopped.into());
                }
                Err(e) => {
                    let stop = self.stop_after_owner_change(&p.app);
                    return Err(match stop {
                        Ok(()) => e,
                        Err(stop) => anyhow!("{e}; {stop}"),
                    });
                }
            }
        }
        Ok(())
    }
    fn stop_after_owner_change(&mut self, app: &str) -> Result<()> {
        self.compose(
            &Context::new(Instant::now() + Duration::from_secs(30)),
            &ActivationRequest {
                app: app.into(),
                ..Default::default()
            },
            "stop",
        )
    }
}
