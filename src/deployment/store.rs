use super::{model::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Store {
    pub root: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub kind: String,
    pub version: u32,
    pub operation_id: String,
    pub application: String,
    pub instance: String,
    pub release_digest: String,
    pub phase: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_release_digest: Option<String>,
    pub reconciliation_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<Backup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<Export>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

impl Operation {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.operation"
                && self.version == 1
                && hex(&self.operation_id, 32)
                && name(&self.application)
                && name(&self.instance)
                && (digest(&self.release_digest) || self.release_digest == "absent")
                && [
                    "admitted",
                    "staging",
                    "jobs",
                    "installing",
                    "activating",
                    "readiness",
                    "ready",
                    "prepared_stopped",
                    "failed",
                    "needs_reconciliation"
                ]
                .contains(&self.phase.as_str())
                && self.ok == ["ready", "prepared_stopped"].contains(&self.phase.as_str())
                && self.reconciliation_required == (self.phase == "needs_reconciliation")
                && self.previous_release_digest.as_deref().is_none_or(digest),
            "invalid durable operation state"
        );
        Ok(())
    }
    pub fn terminal(&self) -> bool {
        [
            "ready",
            "prepared_stopped",
            "failed",
            "needs_reconciliation",
        ]
        .contains(&self.phase.as_str())
    }
    pub fn transition(&mut self, phase: &str) -> Result<()> {
        let valid = match self.phase.as_str() {
            "admitted" => [
                "staging",
                "ready",
                "prepared_stopped",
                "failed",
                "needs_reconciliation",
            ]
            .contains(&phase),
            "staging" => ["jobs", "installing", "failed", "needs_reconciliation"].contains(&phase),
            "jobs" => ["installing", "failed", "needs_reconciliation"].contains(&phase),
            "installing" => [
                "activating",
                "prepared_stopped",
                "failed",
                "needs_reconciliation",
            ]
            .contains(&phase),
            "activating" => ["readiness", "failed", "needs_reconciliation"].contains(&phase),
            "readiness" => ["ready", "failed", "needs_reconciliation"].contains(&phase),
            _ => false,
        };
        ensure!(valid, "invalid durable operation transition");
        self.phase = phase.to_owned();
        self.ok = ["ready", "prepared_stopped"].contains(&phase);
        self.reconciliation_required = phase == "needs_reconciliation";
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub release_digest: String,
    pub operation_id: String,
    pub desired_running: bool,
    pub expires_at: Option<i64>,
    pub resources: Resources,
    pub secret_snapshots: BTreeMap<String, super::secrets::Snapshot>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub containers: BTreeMap<String, ContainerRecord>,
    pub networks: BTreeMap<String, ObjectRecord>,
    pub volumes: BTreeMap<String, ObjectRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRecord {
    pub name: String,
    pub id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerRecord {
    pub name: String,
    pub id: String,
    pub image: String,
    pub config_digest: String,
    pub release_digest: String,
    pub ownership: String,
    pub unit_sha256: String,
    pub volumes: BTreeMap<String, String>,
}

pub fn identity() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow!("operating system random source is unavailable"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn operation_identity(request: &Request) -> Result<String> {
    ensure!(
        name(&request.application) && name(&request.instance) && hex(&request.nonce, 32),
        "invalid proposed operation scope"
    );
    let hash = document_digest(
        format!(
            "komizo-operation-v1\0{}\0{}\0{}",
            request.application, request.instance, request.nonce
        )
        .as_bytes(),
    );
    Ok(hash[7..39].to_owned())
}

impl Store {
    pub fn unresolved(&self, application: &str, instance: &str) -> Result<Vec<Operation>> {
        Self::instance_key(application, instance)?;
        let mut result = Vec::new();
        for entry in fs::read_dir(self.root.join("operations"))? {
            let entry = entry?;
            let filename = entry.file_name();
            let id = filename
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .ok_or_else(|| anyhow!("invalid operation ledger path"))?;
            let operation = self.operation(id)?;
            if operation.application != application
                || operation.instance != instance
                || (!operation.reconciliation_required && operation.terminal())
            {
                continue;
            }
            let path = self.root.join("reconciliations").join(format!("{id}.json"));
            if path.try_exists()? {
                let value = super::validation::bounded_value(&read_protected(&path, 4096)?, 4096)?;
                let resolved = self.operation(
                    value["resolved_by"]
                        .as_str()
                        .ok_or_else(|| anyhow!("invalid reconciliation record"))?,
                )?;
                if resolved.application == application
                    && resolved.instance == instance
                    && resolved.ok
                {
                    continue;
                }
            }
            result.push(operation);
        }
        Ok(result)
    }
    pub fn create_operation(&self, operation: &Operation) -> Result<()> {
        operation.validate()?;
        ensure!(
            hex(&operation.operation_id, 32),
            "invalid operation identity"
        );
        let parent = self.root.join("operations");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent.join(format!("{}.json", operation.operation_id)))?;
        file.write_all(&serde_json::to_vec(operation)?)?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

pub fn protected_directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "protected directory must be absolute");
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "protected path crosses a non-directory"
                );
                // Shared system ancestors such as /tmp are permitted; Komizo's
                // own directory and all opened files carry independent checks.
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
        "protected directory is writable by another identity"
    );
    Ok(())
}

pub fn atomic(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing protected parent"))?;
    protected_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0,
            "refusing unsafe protected replacement"
        );
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(body)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn open_protected(path: &Path, maximum: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0
            && metadata.nlink() == 1
            && metadata.len() <= maximum,
        "unsafe or oversized protected file"
    );
    Ok(file)
}

pub fn read_protected(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = open_protected(path, maximum as u64)?;
    let mut body = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut body)?;
    ensure!(body.len() <= maximum, "protected file exceeds bounds");
    Ok(body)
}

pub struct Guard(File);
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Store {
    pub fn new(root: PathBuf) -> Result<Self> {
        protected_directory(&root)?;
        for name in [
            "operations",
            "releases",
            "instances",
            "nonces",
            "locks",
            "jobs",
            "exports",
        ] {
            protected_directory(&root.join(name))?;
        }
        Ok(Self { root })
    }
    pub fn instance_key(application: &str, instance: &str) -> Result<String> {
        ensure!(name(application) && name(instance), "invalid instance key");
        Ok(format!("{application}--{instance}"))
    }
    pub fn lock(&self, application: &str, instance: &str) -> Result<Guard> {
        let key = Self::instance_key(application, instance)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join("locks").join(key))?;
        ensure!(
            file.metadata()?.uid() == unsafe { libc::geteuid() }
                && file.metadata()?.mode() & 0o077 == 0,
            "unsafe instance lock"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "instance already has an active operation"
        );
        Ok(Guard(file))
    }
    pub fn reserve(
        &self,
        request: &Request,
        request_digest: &str,
        operation_id: &str,
    ) -> Result<()> {
        ensure!(
            hex(operation_id, 32) && hex(&request.nonce, 32) && digest(request_digest),
            "invalid admission record"
        );
        let key = Self::instance_key(&request.application, &request.instance)?;
        let parent = self.root.join("nonces").join(key);
        protected_directory(&parent)?;
        let body = serde_json::to_vec(
            &serde_json::json!({"request_digest":request_digest,"operation_id":operation_id,"expires_at":request.expires_at}),
        )?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent.join(&request.nonce))
            .map_err(|_| anyhow!("request nonce has already been used or cannot be reserved"))?;
        file.write_all(&body)?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn save_operation(&self, operation: &Operation) -> Result<()> {
        operation.validate()?;
        ensure!(
            hex(&operation.operation_id, 32),
            "invalid operation identity"
        );
        atomic(
            &self
                .root
                .join("operations")
                .join(format!("{}.json", operation.operation_id)),
            &serde_json::to_vec(operation)?,
            0o600,
        )
    }
    pub fn operation(&self, id: &str) -> Result<Operation> {
        ensure!(hex(id, 32), "invalid operation identity");
        let operation: Operation = serde_json::from_value(crate::strict::value(
            &read_protected(
                &self.root.join("operations").join(format!("{id}.json")),
                MAX_DOCUMENT_BYTES,
            )?,
            MAX_DOCUMENT_BYTES,
        )?)?;
        operation.validate()?;
        ensure!(
            operation.operation_id == id,
            "operation record identity differs from its protected path"
        );
        Ok(operation)
    }
    pub fn save_release(&self, document: &ReleaseDocument) -> Result<()> {
        let path = self
            .root
            .join("releases")
            .join(format!("{}.json", &document.digest[7..]));
        if path.exists() {
            ensure!(
                read_protected(&path, MAX_DOCUMENT_BYTES)? == document.canonical,
                "immutable release bytes changed"
            );
            return Ok(());
        }
        atomic(&path, &document.canonical, 0o600)
    }
    pub fn release(&self, digest_value: &str) -> Result<ReleaseDocument> {
        ensure!(digest(digest_value), "invalid release identity");
        let doc = read_release(&read_protected(
            &self
                .root
                .join("releases")
                .join(format!("{}.json", &digest_value[7..])),
            MAX_DOCUMENT_BYTES,
        )?)?;
        ensure!(
            doc.digest == digest_value,
            "stored release identity mismatch"
        );
        Ok(doc)
    }
    pub fn installed(&self, application: &str, instance: &str) -> Result<Option<Installed>> {
        let key = Self::instance_key(application, instance)?;
        let path = self.root.join("instances").join(format!("{key}.json"));
        if !path.try_exists()? {
            return Ok(None);
        }
        let record: Installed = serde_json::from_value(crate::strict::value(
            &read_protected(&path, MAX_DOCUMENT_BYTES)?,
            MAX_DOCUMENT_BYTES,
        )?)?;
        ensure!(
            record.kind == "komizo.installed"
                && record.version == 1
                && record.application == application
                && record.instance == instance
                && digest(&record.release_digest)
                && hex(&record.operation_id, 32),
            "invalid installed instance identity"
        );
        Ok(Some(record))
    }
    pub fn save_installed(&self, record: &Installed) -> Result<()> {
        let key = Self::instance_key(&record.application, &record.instance)?;
        atomic(
            &self.root.join("instances").join(format!("{key}.json")),
            &serde_json::to_vec(record)?,
            0o600,
        )
    }
    pub fn reconcile_interrupted(&self) -> Result<usize> {
        let mut count = 0;
        for file in fs::read_dir(self.root.join("operations"))? {
            let file = file?;
            let name = file.file_name();
            let id = name
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .ok_or_else(|| anyhow!("unexpected operation record"))?;
            let mut operation = self.operation(id)?;
            if !operation.terminal() {
                operation.transition("needs_reconciliation")?;
                self.save_operation(&operation)?;
                count += 1;
            }
        }
        Ok(count)
    }
}
