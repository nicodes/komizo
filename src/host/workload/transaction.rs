//! Durable deployment state and operation-private credential transport.
use super::files::{self, Document};
use crate::{
    wire::{Bytes, Secret, Slice},
    wire_struct,
    workload::{operation::Operation, policy::Policy, release::ReleaseAcceptance},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

wire_struct!(Credentials{registry:"registry":String=>required,user:"user":String=>required,password:"password":Secret=>required});
impl Credentials {
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty() && self.user.is_empty() && self.password.expose().is_empty()
    }
    pub fn check(&self, p: &Policy) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let username = (!self.user.is_empty()
            && self.user.len() <= 256
            && self
                .user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b)))
            || self.user == "github-actions[bot]";
        ensure!(
            self.registry == "ghcr.io"
                && p.image_prefix.starts_with("ghcr.io/")
                && username
                && !self.password.expose().is_empty()
                && self.password.expose().len() <= 16384
                && !self.password.expose().contains(['\0', '\r', '\n']),
            "invalid operation-private registry credential"
        );
        Ok(())
    }
}
impl Document for Credentials {
    fn fields() -> &'static [&'static str] {
        &["registry", "user", "password"]
    }
}
wire_struct!(StagedFile{path:"path":String=>required,body:"body":Bytes=>optional,exists:"exists":bool=>required,mode:"mode":u32=>required});
wire_struct!(Snapshot{version:"version":i64=>required,id:"operation_id":String=>required,files:"files":Slice<StagedFile> =>required});
impl Document for Snapshot {
    fn fields() -> &'static [&'static str] {
        &["version", "operation_id", "files"]
    }
    fn normalize(value: serde_json::Value) -> Result<serde_json::Value> {
        let mut value = crate::strict::fields(value, Self::fields())?;
        if let Some(serde_json::Value::Array(files)) = value.get_mut("files") {
            for file in files {
                *file = crate::strict::fields(file.take(), &["path", "body", "exists", "mode"])?
            }
        }
        Ok(value)
    }
}
pub fn hash(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(body))
}
pub fn credential_path(queue: &Path, id: &str) -> std::path::PathBuf {
    queue.join(format!("credentials-{id}/input.json"))
}
pub fn local_current_allowed(operation: &Operation, serving: &str) -> bool {
    operation.candidate == serving
        && matches!(
            operation.phase.as_str(),
            "ready" | "prepared_stopped" | "reconciled"
        )
}
pub fn deployment_version(body: &[u8]) -> Result<String> {
    let mut version = None;
    for line in String::from_utf8_lossy(body).split('\n') {
        if let Some(value) = line.strip_prefix("APP_VERSION=") {
            ensure!(version.is_none(), "duplicate installed revision");
            version = Some(value.to_owned());
        }
    }
    let version = version.unwrap_or_default();
    ensure!(
        version.is_empty() || crate::workload::policy::commit_id(&version),
        "installed revision is not a source identity"
    );
    Ok(version)
}
pub fn deployment_env(body: &[u8], version: &str) -> Result<Vec<u8>> {
    deployment_version(body)?;
    let body = String::from_utf8_lossy(body);
    let mut lines: Vec<String> = body
        .strip_suffix('\n')
        .unwrap_or(&body)
        .split('\n')
        .map(str::to_owned)
        .collect();
    let mut found = false;
    for line in &mut lines {
        if line.starts_with("APP_VERSION=") {
            *line = format!("APP_VERSION={version}");
            found = true
        }
    }
    if !found {
        lines.push(format!("APP_VERSION={version}"))
    }
    Ok(format!("{}\n", lines.join("\n")).into_bytes())
}
pub fn parse_retained(body: &[u8]) -> Result<(String, String)> {
    ensure!(body.len() <= 4096, "retention exceeds its bound");
    let body = String::from_utf8_lossy(body);
    let mut values = BTreeMap::new();
    for line in body.split('\n').filter(|line| !line.trim().is_empty()) {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid retained revisions"))?;
        ensure!(
            values.insert(key, value).is_none(),
            "invalid retained revisions"
        );
    }
    let current = values.get("CURRENT").copied().unwrap_or_default();
    ensure!(!current.is_empty(), "current revision unavailable");
    Ok((
        current.into(),
        values.get("PREVIOUS").copied().unwrap_or_default().into(),
    ))
}
pub fn retained(p: &Policy) -> Result<(String, String)> {
    parse_retained(&files::protected(
        &Path::new(&p.app_dir).join(".komizo-image-retention"),
        4096,
    )?)
}
pub fn rollback_allowed(p: &Policy, version: &str) -> bool {
    retained(p).is_ok_and(|(current, previous)| {
        version == current || !p.require_stateful_contract && version == previous
    })
}
pub fn stateful_retry(
    p: &Policy,
    version: &str,
    directory: &Path,
    candidate: &ReleaseAcceptance,
    initial: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !p.require_stateful_contract {
        return Ok(());
    }
    if fs::symlink_metadata(Path::new(&p.app_dir).join(".komizo-image-retention"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return initial();
    }
    let (current, _) = retained(p)?;
    if current == version {
        return Ok(());
    }
    let installed: ReleaseAcceptance =
        files::read_json(&directory.join(format!("{current}.json")))?;
    installed.check(p, &current)?;
    ensure!(
        !candidate.verified_at.is_zero()
            && !installed.verified_at.is_zero()
            && candidate.verified_at > installed.verified_at,
        "historical stateful release requires explicit verified post-write recovery; use a forward fix"
    );
    Ok(())
}
pub fn bootstrap_serving(compose: &[u8], environment: &[u8], retained: bool) -> Result<bool> {
    let version = deployment_version(environment)?;
    Ok(retained || !version.is_empty() || compose.trim_ascii() != b"services: {}")
}
pub fn check_bootstrap(
    base: &Policy,
    existing: &Policy,
    next: &Policy,
    has_operation: bool,
) -> Result<()> {
    ensure!(
        next.app == base.app
            && next.app_dir == base.app_dir
            && next.image_prefix == base.image_prefix
            && next.shared_network == base.shared_network,
        "bootstrap policy does not match registered authority"
    );
    let equal = |a: &Policy, b: &Policy| -> Result<bool> {
        Ok(serde_json::to_vec(a)? == serde_json::to_vec(b)?)
    };
    if equal(existing, next)? {
        return Ok(());
    }
    ensure!(
        !has_operation && equal(existing, base)?,
        "established policy cannot change through setup; review a platform authority migration"
    );
    Ok(())
}
pub fn write_deployment(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(info) => ensure!(
            info.is_file() && info.uid() == 0,
            "unsafe deployment destination"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    files::write_atomic(path, body, 0o600)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
pub type DeploymentWriter<'a> = dyn FnMut(&Path, &[u8], u32) -> Result<()> + 'a;
pub fn restore_snapshot(snapshot: &Snapshot, write: &mut DeploymentWriter<'_>) -> Result<()> {
    for file in snapshot.files.iter() {
        if file.exists {
            write(Path::new(&file.path), &file.body, file.mode)?
        } else {
            files::remove(Path::new(&file.path))?
        }
    }
    Ok(())
}
