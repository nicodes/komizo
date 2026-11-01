//! Bounded root-owned inputs and synchronized atomic writes for privileged operations.
use crate::{
    statefile,
    workload::{
        activation::{ActivationRequest, ActivationResult},
        operation::Operation,
        policy::Policy,
        policy_read,
        release::ReleaseAcceptance,
    },
};
use anyhow::{Result, anyhow, ensure};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
pub fn owned(info: &fs::Metadata) -> bool {
    info.uid() == 0
}
pub fn protected(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_file() && info.mode() & 0o022 == 0 && owned(&info) && info.len() <= limit as u64,
        "activation input is not a bounded protected root file"
    );
    statefile::read(path, limit)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound).into())
}
pub fn read_policy(path: &Path) -> Result<Policy> {
    let info = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("workload policy must be a protected regular file"))?;
    ensure!(
        info.is_file() && info.mode() & 0o022 == 0,
        "workload policy must be a protected regular file"
    );
    ensure!(owned(&info), "workload policy must be root-owned");
    let body =
        statefile::read(path, 1 << 20)?.ok_or_else(|| anyhow!("workload policy unavailable"))?;
    policy_read::read_policy(&body)
}
pub trait Document: DeserializeOwned + Default {
    fn fields() -> &'static [&'static str];
    fn normalize(value: Value) -> Result<Value> {
        crate::strict::fields(value, Self::fields())
    }
}
macro_rules! document{($ty:ty,[$($field:literal),*$(,)?])=>{impl Document for $ty{fn fields()->&'static[&'static str]{&[$($field),*]}}};}
document!(
    Operation,
    [
        "operation_id",
        "started_at",
        "deadline",
        "version",
        "app",
        "candidate",
        "previous",
        "phase",
        "at"
    ]
);
document!(
    ActivationResult,
    [
        "version",
        "operation_id",
        "app",
        "candidate",
        "at",
        "phase",
        "ok",
        "scoped_generation",
        "started"
    ]
);
impl Document for ActivationRequest {
    fn fields() -> &'static [&'static str] {
        &[
            "version",
            "operation_id",
            "app",
            "candidate",
            "previous",
            "policy_sha256",
            "compose_sha256",
            "route_sha256",
            "route_path",
            "proxy",
            "deadline",
            "scoped_generation",
            "stage",
        ]
    }
    fn normalize(value: Value) -> Result<Value> {
        let mut value = crate::strict::fields(value, Self::fields())?;
        if let Some(value) = value.get_mut("stage") {
            *value = crate::strict::fields(
                value.take(),
                &["credential_sha256", "local_only", "generation"],
            )?;
        }
        Ok(value)
    }
}
impl Document for Policy {
    fn fields() -> &'static [&'static str] {
        &[]
    }
    fn normalize(value: Value) -> Result<Value> {
        Ok(serde_json::to_value(policy_read::read_policy(
            &serde_json::to_vec(&value)?,
        )?)?)
    }
}
impl Document for ReleaseAcceptance {
    fn fields() -> &'static [&'static str] {
        &["manifest", "verified_at", "authority", "evidence_sha256"]
    }
    fn normalize(value: Value) -> Result<Value> {
        let mut value = crate::strict::fields(value, Self::fields())?;
        if let Some(value) = value.get_mut("manifest") {
            *value = serde_json::to_value(crate::workload::release::read_manifest(
                &serde_json::to_vec(value)?,
            )?)?;
        }
        Ok(value)
    }
}
pub fn decode<T: Document>(body: &[u8], limit: usize) -> Result<T> {
    let value = crate::strict::value(body, limit)?;
    Ok(serde_json::from_value(T::normalize(value)?)?)
}
pub fn read_json<T: Document>(path: &Path) -> Result<T> {
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_file() && info.mode() & 0o022 == 0 && owned(&info),
        "accepted release must be a protected root-owned regular file"
    );
    let body = statefile::read(path, 64 << 10)
        .map_err(|_| anyhow!("accepted release is unreadable or oversized"))?
        .ok_or_else(|| anyhow!("accepted release is unreadable or oversized"))?;
    decode(&body, 64 << 10)
}
pub fn protected_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && crate::host::inventory::clean_path(&path.to_string_lossy())
                == path.to_string_lossy(),
        "release store must be absolute and canonical"
    );
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.mode() & 0o022 == 0 && owned(&info),
        "release store must be a protected root-owned directory"
    );
    Ok(())
}
pub fn write_atomic(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".komizo-retain-")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(mode))?;
    temporary.write_all(body)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_string_pretty(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}
pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    write_atomic(path, &json_bytes(value)?, 0o600)
}
pub fn create_private(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(body)?;
    file.sync_all()?;
    Ok(())
}
pub fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
pub fn activation_idle(directory: &Path) -> Result<()> {
    let upgrade = directory
        .parent()
        .unwrap_or(Path::new("."))
        .join("upgrades/pending.json");
    ensure!(
        fs::symlink_metadata(upgrade).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "platform operation requires completion or recovery before application deployment"
    );
    ensure!(
        fs::symlink_metadata(directory.join("pending.json"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "host activation is pending; wait for its durable result before staging another deployment"
    );
    Ok(())
}
