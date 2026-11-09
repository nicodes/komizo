//! Explicit owner enrollment of retained production data.
use super::{
    engine::Engine,
    model::ReleaseDocument,
    store::{self, Installed, ObjectRecord, Store},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub release_digest: String,
    pub volumes: BTreeMap<String, ObjectRecord>,
    pub created_at: i64,
    pub source: Source,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Source {
    Empty {
        confirmation: String,
    },
    Transfer {
        snapshot_sha256: String,
        verification_sha256: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub release_digest: String,
    pub volumes: BTreeMap<String, ObjectRecord>,
    pub snapshot_sha256: String,
    pub created_at: i64,
    pub checks: BTreeMap<String, String>,
    pub observations: serde_json::Map<String, serde_json::Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    kind: String,
    version: u32,
    operation_id: String,
    evidence_sha256: String,
    evidence: Evidence,
}
fn path(store: &Store, directory: &str, installed: &Installed) -> Result<PathBuf> {
    Ok(store.root.join(directory).join(format!(
        "{}.json",
        Store::instance_key(&installed.application, &installed.instance)?
    )))
}
fn same_volumes(
    left: &BTreeMap<String, ObjectRecord>,
    right: &BTreeMap<String, ObjectRecord>,
) -> Result<bool> {
    Ok(serde_json::to_vec(left)? == serde_json::to_vec(right)?)
}
pub fn validate(evidence: &Evidence, installed: &Installed, now: i64) -> Result<()> {
    ensure!(
        evidence.kind == "komizo.data-evidence"
            && evidence.version == 1
            && installed.instance == "production"
            && !installed.desired_running
            && evidence.application == installed.application
            && evidence.instance == installed.instance
            && evidence.release_digest == installed.release_digest
            && !evidence.volumes.is_empty()
            && same_volumes(&evidence.volumes, &installed.resources.volumes)?
            && now
                .checked_sub(evidence.created_at)
                .is_some_and(|age| (0..=86400).contains(&age)),
        "owner data evidence differs from the stopped installed data binding"
    );
    match &evidence.source {
        Source::Empty { confirmation } => ensure!(
            confirmation == "initialize-new-empty-application",
            "fresh initialization requires explicit owner intent"
        ),
        Source::Transfer {
            snapshot_sha256,
            verification_sha256,
        } => ensure!(
            digest(snapshot_sha256) && digest(verification_sha256),
            "transfer requires exact snapshot and verification identities"
        ),
    }
    Ok(())
}
pub fn validate_verification(report: &Verification, evidence: &Evidence, now: i64) -> Result<()> {
    let Source::Transfer {
        snapshot_sha256, ..
    } = &evidence.source
    else {
        return Err(anyhow!("verification is only valid for transfer"));
    };
    ensure!(
        report.kind == "komizo.data-verification"
            && report.version == 1
            && report.application == evidence.application
            && report.instance == evidence.instance
            && report.release_digest == evidence.release_digest
            && report.snapshot_sha256 == *snapshot_sha256
            && same_volumes(&report.volumes, &evidence.volumes)?
            && now
                .checked_sub(report.created_at)
                .is_some_and(|age| (0..=86400).contains(&age))
            && report.checks.len() == 3
            && ["database", "authorization", "files"]
                .iter()
                .all(|name| report
                    .checks
                    .get(*name)
                    .is_some_and(|status| status == "passed"))
            && !report.observations.is_empty(),
        "owner transfer report does not verify the exact snapshot, data, authorization and files"
    );
    Ok(())
}
fn owned_empty_volume(engine: &Engine, record: &ObjectRecord) -> Result<()> {
    let value = engine.owned_object("volume", record)?;
    let mountpoint = value["Mountpoint"]
        .as_str()
        .ok_or_else(|| anyhow!("volume mountpoint missing"))?;
    let expected = Path::new("/var/lib/containers/storage/volumes")
        .join(&record.name)
        .join("_data");
    ensure!(
        Path::new(mountpoint) == expected,
        "volume uses an unreviewed storage location"
    );
    let metadata = fs::symlink_metadata(&expected)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && fs::read_dir(expected)?.next().is_none(),
        "fresh initialization refuses nonempty or foreign data"
    );
    Ok(())
}
pub fn accept(
    store: &Store,
    installed: &Installed,
    expected: &str,
    operation_id: &str,
    now: i64,
    engine: &Engine,
) -> Result<()> {
    ensure!(
        digest(expected) && hex(operation_id, 32),
        "invalid owner data admission identity"
    );
    let destination = path(store, "data-admissions", installed)?;
    ensure!(
        !destination.try_exists()?,
        "retained data is already enrolled; explicit transfer recovery is required"
    );
    let body = store::read_protected(&path(store, "data-evidence", installed)?, 1 << 20)?;
    ensure!(
        document_digest(&body) == expected,
        "owner data evidence bytes changed"
    );
    let evidence: Evidence = serde_json::from_value(bounded_value(&body, 1 << 20)?)?;
    validate(&evidence, installed, now)?;
    for record in installed.resources.containers.values() {
        ensure!(
            !engine.exists("container", &record.name)?,
            "data admission requires stopped, never-started services"
        );
    }
    for record in installed.resources.volumes.values() {
        engine.owned_object("volume", record)?;
        let holders = engine.json(&[
            "ps",
            "--all",
            "--filter",
            &format!("volume={}", record.name),
            "--format=json",
        ])?;
        ensure!(
            holders.as_array().is_some_and(|values| values.is_empty()),
            "owner data admission refuses a volume still attached to a container"
        );
    }
    match &evidence.source {
        Source::Empty { .. } => {
            for record in installed.resources.volumes.values() {
                owned_empty_volume(engine, record)?;
            }
        }
        Source::Transfer {
            verification_sha256,
            ..
        } => {
            let report = store::read_protected(
                &store
                    .root
                    .join("data-evidence/reports")
                    .join(format!("{}.json", &verification_sha256[7..])),
                1 << 20,
            )?;
            ensure!(
                document_digest(&report) == *verification_sha256,
                "owner transfer report bytes changed"
            );
            validate_verification(
                &serde_json::from_value(bounded_value(&report, 1 << 20)?)?,
                &evidence,
                now,
            )?;
        }
    }
    store::atomic(
        &destination,
        &serde_json::to_vec(&Admission {
            kind: "komizo.data-admission".into(),
            version: 1,
            operation_id: operation_id.into(),
            evidence_sha256: expected.into(),
            evidence,
        })?,
        0o600,
    )
}
pub fn require(
    store: &Store,
    installed: &Installed,
    document: &ReleaseDocument,
    engine: &Engine,
) -> Result<()> {
    if installed.instance != "production" || document.release.workload.volumes.is_empty() {
        return Ok(());
    }
    let body = store::read_protected(&path(store, "data-admissions", installed)?, 1 << 20)
        .map_err(|_| {
            anyhow!("stateful production requires explicit owner data preparation and acceptance")
        })?;
    let record: Admission = serde_json::from_value(bounded_value(&body, 1 << 20)?)?;
    ensure!(
        record.kind == "komizo.data-admission"
            && record.version == 1
            && hex(&record.operation_id, 32)
            && digest(&record.evidence_sha256)
            && record.evidence.application == installed.application
            && record.evidence.instance == installed.instance
            && same_volumes(&record.evidence.volumes, &installed.resources.volumes)?,
        "accepted retained data identity changed"
    );
    super::native::retained_topology(&store.release(&record.evidence.release_digest)?, document)?;
    for volume in installed.resources.volumes.values() {
        engine.owned_object("volume", volume)?;
    }
    Ok(())
}
/// Only an explicitly accepted fresh store that is still physically empty may
/// omit the first logical backup. A partially initialized store needs capture.
pub fn fresh_empty(store: &Store, installed: &Installed, engine: &Engine) -> Result<bool> {
    let record: Admission = serde_json::from_value(bounded_value(
        &store::read_protected(&path(store, "data-admissions", installed)?, 1 << 20)?,
        1 << 20,
    )?)?;
    if !matches!(record.evidence.source, Source::Empty { .. }) {
        return Ok(false);
    }
    for volume in installed.resources.volumes.values() {
        if owned_empty_volume(engine, volume).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}
