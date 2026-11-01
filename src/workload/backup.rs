//! Purpose-specific routine backup evidence cannot authorize delivery or restore.
use super::{
    policy::{Policy, commit_id, numeric_id},
    release::{self, ReleaseKey},
};
use crate::{wire::Time, wire_struct};
use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
wire_struct!(BackupManifest{version:"version":i64=>required,purpose:"purpose":String=>required,repository:"repository":String=>required,repository_id:"repository_id":String=>required,revision:"revision":String=>required,run_id:"run_id":String=>required,attempt:"attempt":String=>required});
wire_struct!(BackupAcceptance{manifest:"manifest":BackupManifest=>required,verified_at:"verified_at":Time=>required,expires_at:"expires_at":Time=>required,evidence_sha256:"evidence_sha256":String=>required});
pub fn verify_backup(
    body: &[u8],
    p: &Policy,
    serving: &str,
    now: DateTime<Utc>,
    key: &mut ReleaseKey<'_>,
) -> Result<BackupAcceptance> {
    p.check()?;
    let policy = p
        .routine_backup
        .as_ref()
        .ok_or_else(|| anyhow!("routine backup has no protected capability"))?;
    let envelope = release::read_envelope(body)?;
    let raw = release::decode_manifest(&envelope.manifest, "backup")?;
    let value = crate::strict::fields(
        release::strict_value(&raw)?,
        &[
            "version",
            "purpose",
            "repository",
            "repository_id",
            "revision",
            "run_id",
            "attempt",
        ],
    )?;
    let manifest: BackupManifest =
        serde_json::from_value(value).map_err(|_| anyhow!("invalid release fields"))?;
    ensure!(
        manifest.version == 1
            && manifest.purpose == "routine-backup"
            && manifest.repository == p.source_repository
            && manifest.repository_id == p.repository_id
            && commit_id(serving)
            && manifest.revision == serving
            && numeric_id(&manifest.run_id)
            && numeric_id(&manifest.attempt)
            && envelope.token.expose().len() <= 24 << 10,
        "backup identity differs from the accepted serving source and scope"
    );
    let claims = release::verify_actions(
        envelope.token.expose(),
        &format!("komizo-operation:sha256:{:x}", Sha256::digest(&raw)),
        now,
        key,
    )
    .map_err(|_| anyhow!("backup Actions identity verification failed"))?;
    let called = format!(
        "{}/.github/workflows/backup.yml@{}",
        policy.workflow_repository, policy.workflow_revision
    );
    let id = claims.string("jti");
    ensure!(
        claims.string("repository") == p.source_repository
            && claims.string("repository_id") == p.repository_id
            && claims.string("ref") == "refs/heads/main"
            && claims.string("sha") == serving
            && claims.string("workflow_ref")
                == format!(
                    "{}/.github/workflows/backup.yml@refs/heads/main",
                    p.source_repository
                )
            && claims.string("workflow_sha") == serving
            && claims.string("job_workflow_ref") == called
            && claims.string("job_workflow_sha") == policy.workflow_revision
            && claims.string("run_id") == manifest.run_id
            && claims.string("run_attempt") == manifest.attempt
            && matches!(
                claims.string("event_name"),
                "schedule" | "workflow_dispatch"
            )
            && claims.string("runner_environment") == "github-hosted"
            && claims.values.get("iat").is_some_and(|v| !v.is_null())
            && claims.not_before.is_some()
            && !id.is_empty()
            && id.len() <= 128
            && !id.contains(['\0', '\r', '\n'])
            && claims.expires > now
            && now - claims.issued <= Duration::minutes(10)
            && claims.expires - claims.issued <= Duration::minutes(10)
            && release::release_subject(claims.string("sub"), p),
        "backup Actions context is not the approved routine workflow"
    );
    Ok(BackupAcceptance {
        manifest,
        verified_at: Time(now.fixed_offset()),
        expires_at: Time(claims.expires.fixed_offset()),
        evidence_sha256: format!("{:x}", Sha256::digest(body)),
    })
}
