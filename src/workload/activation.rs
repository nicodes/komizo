//! Host-owned activation survives disconnects and acknowledges every failed external effect.
use super::{
    identifier,
    policy::{DeploymentStage, commit_id, content_identity, operation_identity},
    revision,
};
use crate::{host::inventory::clean_path, wire::Time, wire_struct};
use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Duration, Utc};
use std::{
    fmt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration as StdDuration, Instant},
};
wire_struct!(ActivationRequest{version:"version":i64=>required,id:"operation_id":String=>required,app:"app":String=>required,candidate:"candidate":String=>required,previous:"previous":String=>optional,policy_sha256:"policy_sha256":String=>required,compose_sha256:"compose_sha256":String=>required,route_sha256:"route_sha256":String=>required,route_path:"route_path":String=>required,proxy:"proxy":String=>required,deadline:"deadline":Time=>required,scoped_generation:"scoped_generation":String=>optional,stage:"stage":Option<DeploymentStage> =>optional});
wire_struct!(ActivationResult{version:"version":i64=>required,id:"operation_id":String=>required,app:"app":String=>required,candidate:"candidate":String=>required,at:"at":Time=>required,phase:"phase":String=>required,ok:"ok":bool=>required,scoped_generation:"scoped_generation":String=>optional,started:"started":Option<bool> =>optional});
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    ReadinessUnspecified,
    Reconciliation,
    Stopped,
}
impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadinessUnspecified => "activation readiness is not configured",
            Self::Reconciliation => "interrupted activation requires reconciliation",
            Self::Stopped => "owner stopped the workload during readiness",
        })
    }
}
impl std::error::Error for ActivationError {}
#[derive(Clone)]
pub struct Context {
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}
impl Context {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn check(&self) -> Result<()> {
        ensure!(!self.cancelled.load(Ordering::Acquire), "context canceled");
        ensure!(Instant::now() < self.deadline, "context deadline exceeded");
        Ok(())
    }
    pub fn remaining(&self) -> Result<StdDuration> {
        self.check()?;
        Ok(self.deadline.saturating_duration_since(Instant::now()))
    }
    pub fn with_deadline(&self, deadline: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        Self {
            deadline: self
                .deadline
                .min(Instant::now() + (deadline - now).to_std().unwrap_or_default()),
            cancelled: self.cancelled.clone(),
        }
    }
}
impl ActivationRequest {
    pub fn check_identity(&self) -> Result<()> {
        ensure!(
            operation_identity(&self.id)
                && identifier(&self.app)
                && revision(&self.candidate)
                && (self.previous.is_empty() || revision(&self.previous))
                && content_identity(&self.policy_sha256)
                && identifier(&self.proxy)
                && Path::new(&self.route_path).is_absolute()
                && clean_path(&self.route_path) == self.route_path
                && Path::new(&self.route_path)
                    .file_name()
                    .and_then(|v| v.to_str())
                    == Some(&format!("{}.caddy", self.app))
                && !self.deadline.is_zero(),
            "invalid host operation identity"
        );
        match self.version {
            1 => ensure!(
                (self.scoped_generation.is_empty() || operation_identity(&self.scoped_generation))
                    && self.stage.is_none()
                    && content_identity(&self.compose_sha256)
                    && content_identity(&self.route_sha256),
                "invalid configured activation identity"
            ),
            2 => {
                ensure!(
                    self.scoped_generation.is_empty()
                        && self.stage.is_some()
                        && self.compose_sha256.is_empty()
                        && self.route_sha256.is_empty()
                        && commit_id(&self.candidate)
                        && (self.previous.is_empty() || commit_id(&self.previous)),
                    "invalid staging identity"
                );
                let stage = self.stage.as_ref().unwrap();
                ensure!(
                    !stage.local_only || self.candidate == self.previous,
                    "local reconfiguration requires the current serving revision"
                );
                stage.check()?;
            }
            _ => anyhow::bail!("unknown host operation version"),
        };
        Ok(())
    }
    pub fn check(&self, now: DateTime<Utc>) -> Result<()> {
        self.check_identity()?;
        ensure!(
            self.deadline.0 > now && self.deadline.0 <= now + Duration::minutes(25),
            "expired or unbounded host activation deadline"
        );
        Ok(())
    }
}
pub trait ActivationRuntime {
    fn verify(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()>;
    fn stopped(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<bool>;
    fn compose(&mut self, ctx: &Context, r: &ActivationRequest, action: &str) -> Result<()>;
    fn reload_proxy(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()>;
    fn retain(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()>;
    fn ready(&mut self, ctx: &Context, r: &ActivationRequest) -> Result<()>;
    fn phase(&mut self, r: &ActivationRequest, phase: &str) -> Result<()>;
    fn abort_static(&mut self, _ctx: &Context, _r: &ActivationRequest) -> Option<Result<()>> {
        None
    }
}
pub fn activate(
    parent: &Context,
    request: &ActivationRequest,
    runtime: &mut impl ActivationRuntime,
) -> (ActivationResult, Result<()>) {
    activate_with_clock(parent, request, runtime, Utc::now)
}
pub fn activate_with_clock(
    parent: &Context,
    r: &ActivationRequest,
    runtime: &mut impl ActivationRuntime,
    mut clock: impl FnMut() -> DateTime<Utc>,
) -> (ActivationResult, Result<()>) {
    let mut result = ActivationResult {
        version: 1,
        id: r.id.clone(),
        app: r.app.clone(),
        candidate: r.candidate.clone(),
        phase: "refused".into(),
        at: Time(clock().fixed_offset()),
        ..Default::default()
    };
    if r.version != 1 || r.stage.is_some() {
        return (
            result,
            Err(anyhow!("staging must complete before activation")),
        );
    }
    let now = clock();
    if let Err(error) = r.check(now) {
        return (result, Err(error));
    }
    let ctx = parent.with_deadline(r.deadline.0.with_timezone(&Utc), now);
    if let Err(error) = runtime.verify(&ctx, r) {
        if error.downcast_ref::<ActivationError>() == Some(&ActivationError::Reconciliation) {
            result.phase = "reconciliation_required".into();
        }
        return (result, Err(error));
    }
    let mut phase = "configured";
    let action = (|| -> Result<()> {
        let mut stopped = runtime.stopped(&ctx, r)?;
        if !stopped {
            runtime.phase(r, "activating")?;
            phase = "activating";
            runtime.compose(&ctx, r, "up")?;
            stopped = runtime.stopped(&ctx, r)?;
            if stopped {
                runtime.compose(&ctx, r, "stop")?;
            }
        }
        runtime.reload_proxy(&ctx, r)?;
        runtime.retain(&ctx, r)?;
        if stopped {
            phase = "prepared_stopped";
            runtime.phase(r, phase)?;
        } else {
            let mut ready_verified = true;
            phase = "activated";
            runtime.phase(r, phase)?;
            if let Err(error) = runtime.ready(&ctx, r) {
                match error.downcast_ref::<ActivationError>() {
                    Some(ActivationError::Stopped) => {}
                    Some(ActivationError::ReadinessUnspecified) => ready_verified = false,
                    _ => return Err(error),
                }
            }
            stopped = runtime.stopped(&ctx, r)?;
            if stopped {
                runtime.compose(&ctx, r, "stop")?;
                phase = "prepared_stopped";
            } else if ready_verified {
                phase = "ready";
            }
            runtime.phase(r, phase)?;
        }
        result.phase = phase.into();
        result.ok = true;
        result.started = Some(!stopped);
        result.scoped_generation = r.scoped_generation.clone();
        Ok(())
    })();
    result.at = Time(clock().fixed_offset());
    let action = match action {
        Ok(()) => Ok(()),
        Err(mut error) => {
            let cleanup = Context::new(Instant::now() + StdDuration::from_secs(30));
            if let Some(Err(abort_error)) = runtime.abort_static(&cleanup, r) {
                error = anyhow!("{error}\n{abort_error}");
            }
            let failure = match phase {
                "activating" => "activation_failed",
                "activated" => "readiness_failed",
                _ => "failed",
            };
            result.phase = failure.into();
            if let Err(ack_error) = runtime.phase(r, failure) {
                result.phase = "acknowledgement_failed".into();
                error = anyhow!("{error}\n{ack_error}");
            }
            Err(error)
        }
    };
    (result, action)
}
