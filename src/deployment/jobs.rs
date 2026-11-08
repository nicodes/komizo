use super::{
    model::*,
    store::{self, Installed, Store},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub identity: String,
    pub job: String,
    pub operation_id: String,
    pub release_digest: String,
    pub container_name: String,
    pub container_id: String,
    pub ownership: String,
    pub phase: String,
    pub exit_code: Option<i32>,
}

pub fn identity(document: &ReleaseDocument, job: &str, installed: &Installed) -> Result<String> {
    let container = document
        .release
        .workload
        .jobs
        .get(job)
        .ok_or_else(|| anyhow!("unknown one-shot job"))?;
    let secrets = container
        .environment_files
        .iter()
        .chain(container.secrets.iter().map(|s| &s.source))
        .map(|a| {
            installed
                .secret_snapshots
                .get(a)
                .map(|s| (a, s.generation.clone()))
                .ok_or_else(|| anyhow!("job secret generation is missing"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let volumes = container
        .volumes
        .iter()
        .map(|v| {
            installed
                .resources
                .volumes
                .get(&v.name)
                .map(|record| (&v.name, &record.id))
                .ok_or_else(|| anyhow!("job retained volume binding is missing"))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(document_digest(&canonical(
        &json!({"container":container,"artifact":document.release.artifacts[&container.artifact],"secrets":secrets,"volumes":volumes}),
    )?))
}
pub fn read(
    store: &Store,
    application: &str,
    instance: &str,
    identity: &str,
) -> Result<Option<Receipt>> {
    ensure!(
        name(application) && name(instance) && digest(identity),
        "invalid job receipt scope"
    );
    let namespace = super::units::namespace(application, instance)?;
    let path = store
        .root
        .join("jobs")
        .join(namespace)
        .join(format!("{}.json", &identity[7..]));
    if !path.try_exists()? {
        return Ok(None);
    }
    let receipt: Receipt = serde_json::from_value(crate::strict::value(
        &store::read_protected(&path, 64 << 10)?,
        64 << 10,
    )?)?;
    ensure!(
        receipt.kind == "komizo.job"
            && receipt.version == 1
            && receipt.application == application
            && receipt.instance == instance
            && receipt.identity == identity
            && name(&receipt.job)
            && hex(&receipt.operation_id, 32)
            && digest(&receipt.release_digest)
            && hex(&receipt.ownership, 32)
            && ["starting", "running", "completed", "failed", "uncertain"]
                .contains(&receipt.phase.as_str())
            && (receipt.phase != "completed" || receipt.exit_code == Some(0)),
        "invalid durable job receipt"
    );
    Ok(Some(receipt))
}
pub fn save(store: &Store, receipt: &Receipt) -> Result<()> {
    ensure!(
        digest(&receipt.identity) && name(&receipt.job),
        "invalid job receipt identity"
    );
    let namespace = super::units::namespace(&receipt.application, &receipt.instance)?;
    store::atomic(
        &store
            .root
            .join("jobs")
            .join(namespace)
            .join(format!("{}.json", &receipt.identity[7..])),
        &serde_json::to_vec(receipt)?,
        0o600,
    )
}
pub fn completed(
    store: &Store,
    document: &ReleaseDocument,
    job: &str,
    installed: &Installed,
) -> Result<bool> {
    Ok(read(
        store,
        &installed.application,
        &installed.instance,
        &identity(document, job, installed)?,
    )?
    .is_some_and(|r| r.job == job && r.phase == "completed" && r.exit_code == Some(0)))
}
