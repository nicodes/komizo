//! Fresh delivery grants precede acceptance, caches, registry authority and task effects.
use super::{
    activation::Host,
    effects::Effects,
    files::{self, Document},
    image_cache::missing,
    transaction,
};
use crate::{
    wire::decode_base64,
    workload::{
        activation::Context,
        delivery::DeliveryAuthorization,
        policy::{Policy, commit_id},
        release::{self, ReleaseAcceptance},
    },
};
use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use std::path::Path;
impl Document for DeliveryAuthorization {
    fn fields() -> &'static [&'static str] {
        &[
            "version",
            "repository",
            "repository_id",
            "app",
            "revision",
            "tree",
            "head",
            "base",
            "ci_run_id",
            "ci_attempt",
            "integration_artifact_id",
            "inputs_sha256",
            "kind",
            "scope",
            "issued_at",
            "expires_at",
        ]
    }
}
pub struct Admission<'a> {
    pub revision: &'a str,
    pub directory: &'a Path,
    pub output: &'a Path,
}
impl<E: Effects> Host<E> {
    pub fn check_delivery(&self, p: &Policy, version: &str, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            commit_id(version),
            "delivery authorization requires an exact commit"
        );
        if !p.require_delivery_authorization {
            return Ok(());
        }
        let authorization:DeliveryAuthorization=self.read_json(&self.path(super::DELIVERY).join(&p.app).join(format!("{version}.json"))).map_err(|_|anyhow!("protected delivery authorization is missing; inspect the actual merge before authorizing"))?;
        authorization.check(p, version, now)
    }
    pub fn verify_task_release(
        &mut self,
        ctx: &Context,
        p: &Policy,
        wire: &[u8],
    ) -> Result<String> {
        ctx.check()?;
        let raw = wire
            .strip_prefix(b"komizo-release/v1:")
            .filter(|_| wire.len() <= 128 << 10)
            .ok_or_else(|| anyhow!("invalid named task proof"))?;
        let body = decode_base64(
            std::str::from_utf8(raw).map_err(|_| anyhow!("invalid named task proof"))?,
        )
        .map_err(|_| anyhow!("invalid named task proof"))?;
        let envelope =
            release::read_envelope(&body).map_err(|_| anyhow!("invalid named task proof"))?;
        let raw = decode_base64(&envelope.manifest)
            .map_err(|_| anyhow!("invalid named task manifest"))?;
        let manifest =
            release::read_manifest(&raw).map_err(|_| anyhow!("invalid named task manifest"))?;
        self.check_delivery(p, &manifest.revision, (self.now)())?;
        release::verify_release(&body, p, &manifest.revision, (self.now)(), &mut |kid| {
            self.effects.release_key(ctx, kid)
        })?;
        ctx.check()?;
        Ok(manifest.revision)
    }
    pub fn admit(
        &mut self,
        ctx: &Context,
        p: &Policy,
        spec: Admission<'_>,
        wire: &[u8],
    ) -> Result<ReleaseAcceptance> {
        ctx.check()?;
        ensure!(
            !spec.output.as_os_str().is_empty(),
            "release admission needs a private output"
        );
        ensure!(
            p.has_release_authority(),
            "release admission requires explicit protected authority"
        );
        ensure!(
            !p.owner_approval || unsafe { libc::geteuid() } == 0,
            "owner approval requires the root SSH operator"
        );
        ensure!(
            spec.revision.len() == 40 && !spec.revision.contains(['/', '.']),
            "authenticated releases require a full commit revision"
        );
        self.check_delivery(p, spec.revision, (self.now)())?;
        let path = spec.directory.join(format!("{}.json", spec.revision));
        let existing = match self.read_json::<ReleaseAcceptance>(&path) {
            Ok(value) => {
                value.check(p, spec.revision)?;
                Some(value)
            }
            Err(e) if missing(&e) => None,
            Err(e) => return Err(e),
        };
        ensure!(wire.len() <= 128 << 10, "release proof exceeds wire limit");
        if wire.trim_ascii().is_empty() {
            ensure!(
                !p.require_delivery_authorization,
                "protected CI admission requires current authenticated proof; use the root owner recovery route"
            );
            ensure!(
                existing.is_some() && transaction::rollback_allowed(p, spec.revision),
                "release requires authenticated Actions proof or the current/previous accepted revision"
            );
            let accepted = existing.unwrap();
            files::write_json(spec.output, &accepted)?;
            return Ok(accepted);
        }
        self.check_delivery(p, spec.revision, (self.now)())?;
        let mut accepted = if p.owner_approval {
            release::approve_owner_release(wire, p, spec.revision, (self.now)())?
        } else {
            let raw = wire
                .strip_prefix(b"komizo-release/v1:")
                .ok_or_else(|| anyhow!("invalid release proof frame"))?;
            let raw =
                std::str::from_utf8(raw).map_err(|_| anyhow!("invalid release proof encoding"))?;
            let body =
                decode_base64(raw.trim()).map_err(|_| anyhow!("invalid release proof encoding"))?;
            release::verify_release(&body, p, spec.revision, (self.now)(), &mut |kid| {
                self.effects.release_key(ctx, kid)
            })?
        };
        if let Some(existing) = existing {
            ensure!(
                existing.manifest.images == accepted.manifest.images
                    && serde_json::to_vec(&existing.manifest.stateful_contract)?
                        == serde_json::to_vec(&accepted.manifest.stateful_contract)?,
                "release revision was already accepted with different images or stateful contract"
            );
            transaction::stateful_retry(p, spec.revision, spec.directory, &existing, || {
                self.initial_retry_allowed(ctx, p, spec.directory)
            })?;
            accepted = existing;
        } else {
            ctx.check()?;
            files::write_json(&path, &accepted)?
        }
        ctx.check()?;
        files::write_json(spec.output, &accepted)?;
        Ok(accepted)
    }
}
