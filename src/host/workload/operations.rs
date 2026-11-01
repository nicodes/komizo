//! Named tasks and routine backups execute only protected operator-installed programs.
use super::{
    activation::Host,
    effects::Effects,
    files::{self, Document},
    transaction::{deployment_version, hash},
};
use crate::{
    wire::{Time, decode_base64},
    wire_struct,
    workload::{
        activation::Context,
        backup::{self, BackupAcceptance},
        operation::Operation,
        policy::Policy,
    },
};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::Ordering,
};
wire_struct!(BackupOperation{version:"version":i64=>required,phase:"phase":String=>required,accepted:"accepted":BackupAcceptance=>required,deadline:"deadline":Time=>required});
impl Document for BackupOperation {
    fn fields() -> &'static [&'static str] {
        &["version", "phase", "accepted", "deadline"]
    }
    fn normalize(value: Value) -> Result<Value> {
        let mut value = crate::strict::fields(value, Self::fields())?;
        if let Some(accepted) = value.get_mut("accepted") {
            *accepted = crate::strict::fields(
                accepted.take(),
                &["manifest", "verified_at", "expires_at", "evidence_sha256"],
            )?;
            if let Some(manifest) = accepted.get_mut("manifest") {
                *manifest = crate::strict::fields(
                    manifest.take(),
                    &[
                        "version",
                        "purpose",
                        "repository",
                        "repository_id",
                        "revision",
                        "run_id",
                        "attempt",
                    ],
                )?
            }
        }
        Ok(value)
    }
}
pub fn protected_path(path: &Path, directory: bool) -> Result<()> {
    for ancestor in path.ancestors() {
        let info = fs::symlink_metadata(ancestor)
            .map_err(|_| anyhow!("backup ancestry and files must be protected root authority"))?;
        ensure!(
            files::owned(&info)
                && !info.file_type().is_symlink()
                && info.mode() & 0o022 == 0
                && if ancestor != path || directory {
                    info.is_dir()
                } else {
                    info.is_file()
                },
            "backup ancestry and files must be protected root authority"
        );
    }
    Ok(())
}
pub fn claim_backup(path: &Path, operation: &BackupOperation) -> Result<()> {
    let mut body = serde_json::to_vec(operation)?;
    body.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| anyhow!("backup run already claimed; inspect before starting a new run"))?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}
pub fn serving_revision(app: &str, environment: &[u8], operation: &Operation) -> Result<String> {
    let version = deployment_version(environment)?;
    ensure!(
        operation.version == 1
            && operation.app == app
            && operation.phase == "ready"
            && operation.candidate == version,
        "backup requires the accepted ready serving operation"
    );
    Ok(version)
}
pub enum TaskAuthority<'a> {
    Owner,
    Ci(&'a [u8]),
}
impl<E: Effects> Host<E> {
    pub fn run_named(
        &mut self,
        ctx: &Context,
        p: &Policy,
        args: &[String],
        authority: TaskAuthority<'_>,
        input: Stdio,
    ) -> Result<()> {
        p.check()?;
        let proof = match authority {
            TaskAuthority::Ci(proof) if p.require_delivery_authorization => Some(proof),
            _ => None,
        };
        if let Some(proof) = proof {
            self.verify_task_release(ctx, p, proof)?;
        }
        let _lock = crate::host::locking::DeploymentLock::acquire(
            &self.root,
            &p.app,
            ctx.remaining()?,
            || ctx.cancelled.load(Ordering::Acquire),
        )?;
        if let Some(proof) = proof {
            self.verify_task_release(ctx, p, proof)?;
        }
        self.startup_capacity(p)?;
        let program = self.path(format!("/var/lib/komizo/tasks/{}.sh", p.app));
        for ancestor in program.ancestors() {
            let info = fs::symlink_metadata(ancestor)
                .map_err(|_| anyhow!("named task program is not protected"))?;
            ensure!(
                files::owned(&info) && !info.file_type().is_symlink() && info.mode() & 0o022 == 0,
                "named task program is not protected"
            );
            if ancestor == program {
                ensure!(
                    info.is_file()
                        && info.mode() & 0o777 == 0o700
                        && info.len() > 0
                        && info.len() <= 1 << 20,
                    "named task needs the operator's private regular executable"
                )
            } else {
                ensure!(info.is_dir(), "named task ancestry is not a directory")
            }
        }
        self.effects
            .program(ctx, &program, Path::new(&p.app_dir), args, input)
            .map_err(|_| {
                anyhow!("bounded named task failed; inspect its operation before retrying")
            })
    }
    fn backup_directory(&self, app: &str) -> Result<PathBuf> {
        let mut dir = self.path("/var/lib/komizo");
        protected_path(&dir, true)?;
        for name in ["backup-operations", app] {
            dir.push(name);
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            };
            protected_path(&dir, true)?;
            ensure!(
                fs::symlink_metadata(&dir)?.mode() & 0o777 == 0o700,
                "backup operation store must be private"
            );
        }
        Ok(dir)
    }
    fn verify_backup_input(
        &mut self,
        ctx: &Context,
        p: &Policy,
        body: &[u8],
    ) -> Result<BackupAcceptance> {
        files::activation_idle(&self.path(super::ACTIVATIONS))?;
        let env = Path::new(&p.app_dir).join(".env");
        protected_path(&env, false)?;
        let env = self.effects.read(&env, 1 << 20)?;
        let path = self.releases.join(&p.app).join("operation.json");
        protected_path(&path, false)?;
        let operation: Operation = self.read_json(&path)?;
        let serving = serving_revision(&p.app, &env, &operation)?;
        backup::verify_backup(body, p, &serving, (self.now)(), &mut |kid| {
            self.effects.release_key(ctx, kid)
        })
    }
    pub fn routine_backup(
        &mut self,
        parent: &Context,
        policy_path: &Path,
        p: &Policy,
        line: &[u8],
    ) -> Result<()> {
        p.check()?;
        let capability = p.routine_backup.as_ref().ok_or_else(|| {
            anyhow!("routine backup requires a protected capability and audience-bound proof")
        })?;
        let mut context = parent.clone();
        context.deadline = context.deadline.min(
            std::time::Instant::now()
                + std::time::Duration::from_secs(capability.timeout_seconds.try_into()?),
        );
        let ctx = &context;
        ctx.check()?;
        ensure!(
            line.len() <= 128 << 10,
            "backup requires a bounded authenticated operation proof line"
        );
        let raw = line.strip_prefix(b"komizo-operation/v1:").ok_or_else(|| {
            anyhow!("backup requires a bounded authenticated operation proof line")
        })?;
        let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
        let body = decode_base64(
            std::str::from_utf8(raw)
                .map_err(|_| anyhow!("invalid backup operation proof encoding"))?,
        )
        .map_err(|_| anyhow!("invalid backup operation proof encoding"))?;
        self.verify_backup_input(ctx, p, &body)?;
        let _lock = crate::host::locking::DeploymentLock::acquire(
            &self.root,
            &p.app,
            ctx.remaining()?,
            || ctx.cancelled.load(Ordering::Acquire),
        )?;
        let current = files::read_policy(policy_path)?;
        ensure!(
            serde_json::to_vec(p)? == serde_json::to_vec(&current)?,
            "backup authority changed while waiting"
        );
        self.startup_capacity(p)?;
        let accepted = self.verify_backup_input(ctx, p, &body)?;
        let program = self.path(format!("/usr/local/bin/export-{}-backup", p.app));
        protected_path(&program, false)?;
        let info = fs::symlink_metadata(&program)?;
        ensure!(
            matches!(info.mode() & 0o777, 0o700 | 0o755) && info.len() > 0 && info.len() <= 1 << 20,
            "backup exporter must be a bounded protected executable"
        );
        ensure!(
            hash(&self.effects.read(&program, 1 << 20)?) == capability.program_sha256,
            "backup exporter differs from protected authority"
        );
        let directory = self.backup_directory(&p.app)?;
        let path = directory.join(format!(
            "{}-{}.json",
            accepted.manifest.run_id, accepted.manifest.attempt
        ));
        let mut operation = BackupOperation {
            version: 1,
            phase: "claimed".into(),
            accepted,
            deadline: Time(
                ((self.now)() + chrono::Duration::from_std(ctx.remaining()?)?).fixed_offset(),
            ),
        };
        claim_backup(&path, &operation)?;
        let status = self
            .effects
            .program(ctx, &program, Path::new(&p.app_dir), &[], Stdio::null());
        operation.phase = if status.is_ok() {
            "complete"
        } else {
            "ambiguous"
        }
        .into();
        files::write_json(&path, &operation).map_err(|_| {
            anyhow!("backup outcome could not be recorded; inspect the durable claim")
        })?;
        status.map_err(|_| {
            anyhow!("bounded backup exporter failed; inspect its operation without replaying")
        })
    }
    pub fn inspect_backup(&self, app: &str, run: &str, attempt: &str) -> Result<BackupOperation> {
        for id in [run, attempt] {
            ensure!(
                crate::workload::policy::numeric_id(id),
                "backup inspection requires positive run and attempt identifiers"
            )
        }
        let path = self.path(format!(
            "/var/lib/komizo/backup-operations/{app}/{run}-{attempt}.json"
        ));
        protected_path(&path, false)?;
        self.read_json(&path)
    }
}
