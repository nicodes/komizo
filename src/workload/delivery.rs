//! Root-issued delivery permission binds one observed integration and a finite lifetime.
use super::policy::{Policy, commit_id, content_identity};
use crate::{wire::Time, wire_struct};
use anyhow::{Result, ensure};
use chrono::{DateTime, Duration, Utc};
wire_struct!(DeliveryAuthorization{version:"version":i64=>required,repository:"repository":String=>required,repository_id:"repository_id":String=>required,app:"app":String=>required,revision:"revision":String=>required,tree:"tree":String=>required,head:"head":String=>required,base:"base":String=>required,ci_run_id:"ci_run_id":i64=>required,ci_attempt:"ci_attempt":i64=>required,integration_artifact_id:"integration_artifact_id":i64=>required,inputs_sha256:"inputs_sha256":String=>required,kind:"kind":String=>required,scope:"scope":String=>required,issued_at:"issued_at":Time=>required,expires_at:"expires_at":Time=>required});
impl DeliveryAuthorization {
    pub fn check(&self, p: &Policy, revision: &str, now: DateTime<Utc>) -> Result<()> {
        ensure!(
            self.version == 1
                && self.repository == p.source_repository
                && self.repository_id == p.repository_id
                && self.app == p.app
                && self.revision == revision
                && commit_id(&self.revision)
                && commit_id(&self.tree)
                && commit_id(&self.head)
                && commit_id(&self.base)
                && self.ci_run_id > 0
                && self.ci_attempt > 0
                && self.integration_artifact_id > 0
                && content_identity(&self.inputs_sha256)
                && matches!(self.kind.as_str(), "merge" | "owner")
                && self.scope == "production-delivery"
                && self.issued_at.0 <= now
                && self.expires_at.0 > now
                && self.expires_at.0 > self.issued_at.0
                && self.expires_at.0 - self.issued_at.0 <= Duration::hours(4),
            "delivery authorization identity, scope or lifetime differs"
        );
        Ok(())
    }
}
