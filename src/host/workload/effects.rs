//! Native subprocess and protected-file boundary of the privileged workload worker.
use super::{
    files,
    image_cache::{self, Cache},
    transaction::Credentials,
};
use crate::{
    host::Probe,
    process,
    workload::{activation::Context, archive},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
pub type ArchiveConsumer<'a> = dyn FnMut(&mut dyn Read) -> Result<()> + 'a;
pub trait Effects {
    fn owned(&self, info: &fs::Metadata) -> bool {
        files::owned(info)
    }
    fn probe(
        &mut self,
        ctx: &Context,
        client: &reqwest::blocking::Client,
        candidate: &str,
        probe: &crate::workload::policy::ReadinessProbe,
    ) -> Result<()> {
        crate::workload::readiness::probe_ready(ctx, client, candidate, probe)
    }
    fn docker(&mut self, ctx: &Context, args: &[&str]) -> Result<String>;
    fn archive(
        &mut self,
        ctx: &Context,
        args: &[&str],
        maximum: u64,
        consumer: &mut ArchiveConsumer<'_>,
    ) -> Result<()>;
    fn read(&self, path: &Path, maximum: usize) -> Result<Vec<u8>> {
        files::protected(path, maximum)
    }
    fn write(&mut self, path: &Path, body: &[u8], mode: u32) -> Result<()> {
        super::transaction::write_deployment(path, body, mode)
    }
    fn directory(&mut self, path: &Path, mode: u32) -> Result<()> {
        match fs::DirBuilder::new().mode(mode).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_dir() && info.mode() & 0o777 == mode && files::owned(&info),
            "unsafe static directory"
        );
        Ok(())
    }
    fn login(&mut self, ctx: &Context, credentials: &Credentials, directory: &Path) -> Result<()> {
        if credentials.registry.is_empty() {
            return Ok(());
        }
        let ctx = ctx.with_docker_config(directory.into());
        let mut command = docker_command(
            &ctx,
            &[
                "login",
                &credentials.registry,
                "--username",
                &credentials.user,
                "--password-stdin",
            ],
        );
        let captured = process::stream(
            &mut command,
            Some(credentials.password.expose().as_bytes()),
            8192,
            bounded(&ctx, 60)?,
            || ctx.cancelled.load(Ordering::Acquire),
            &mut std::io::sink(),
            &mut std::io::sink(),
        )
        .map_err(|_| anyhow!("operation-private registry login failed"))?;
        ensure!(
            captured.status.success(),
            "operation-private registry login failed"
        );
        Ok(())
    }
    fn scoped_check(&mut self, ctx: &Context, path: &Path, compose: &Path) -> Result<()> {
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_file() && info.mode() & 0o022 == 0 && files::owned(&info),
            "unsafe scoped checker"
        );
        let mut command = Command::new(path);
        command.arg("--check-compose").arg(compose);
        let captured = process::stream(
            &mut command,
            None,
            8192,
            ctx.deadline,
            || ctx.cancelled.load(Ordering::Acquire),
            &mut std::io::sink(),
            &mut std::io::sink(),
        )
        .map_err(|_| anyhow!("scoped mount validation failed"))?;
        ensure!(captured.status.success(), "scoped mount validation failed");
        Ok(())
    }
    fn checkpoint(&mut self, _name: &str) {}
}
fn bounded(ctx: &Context, seconds: u64) -> Result<Instant> {
    ctx.check()?;
    Ok(ctx
        .deadline
        .min(Instant::now() + Duration::from_secs(seconds)))
}
fn docker_command(ctx: &Context, args: &[&str]) -> Command {
    let mut command = Command::new("docker");
    command.args(args).env_remove("DOCKER_CONFIG");
    if let Some(path) = ctx.docker_config() {
        command.env("DOCKER_CONFIG", path);
    }
    command
}
pub struct Native {
    pub root: PathBuf,
}
impl Native {
    fn raw_docker(ctx: &Context, args: &[&str]) -> Result<String> {
        let captured = process::capture(
            &mut docker_command(ctx, args),
            None,
            2 << 20,
            bounded(ctx, 120)?,
            || ctx.cancelled.load(Ordering::Acquire),
        )
        .map_err(|_| anyhow!("bounded Docker operation failed or timed out"))?;
        ensure!(
            captured.status.success(),
            "bounded Docker operation failed or timed out"
        );
        Ok(String::from_utf8_lossy(&captured.stdout).into_owned())
    }
}
impl Effects for Native {
    fn docker(&mut self, ctx: &Context, args: &[&str]) -> Result<String> {
        if args.len() == 2 && matches!(args[0], "config-digest" | "local-config-image") {
            let directory = Probe {
                root: self.root.clone(),
            }
            .path(super::IMAGE_CONFIGS);
            let floors = Probe {
                root: self.root.clone(),
            }
            .path(crate::host::paths::DEPLOY_FLOORS_PATH);
            let mut space = |path: &Path| image_cache::space(path, &floors);
            let mut cache = Cache {
                root: &self.root,
                directory: &directory,
                owner: &files::owned,
                space: &mut space,
            };
            if args[0] == "local-config-image" {
                return cache.cached_image(ctx, args[1], &mut |image| {
                    let mut check = ctx.clone();
                    check.deadline = check.deadline.min(Instant::now() + Duration::from_secs(5));
                    let body = Self::raw_docker(&check, &["image", "inspect", image]);
                    body.ok()
                        .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
                        .is_some_and(|rows| {
                            rows.as_array()
                                .is_some_and(|rows| rows.len() == 1 && rows[0]["Id"] == image)
                        })
                });
            }
            return cache.config_digest(ctx, args[1], &mut |ctx, image| {
                process::consume(
                    &mut docker_command(ctx, &["image", "save", image]),
                    (2 << 30) + 1,
                    bounded(ctx, 90)?,
                    || ctx.cancelled.load(Ordering::Acquire),
                    |reader| archive::docker_archive_config_digest(reader),
                )
            });
        }
        Self::raw_docker(ctx, args)
    }
    fn archive(
        &mut self,
        ctx: &Context,
        args: &[&str],
        maximum: u64,
        consumer: &mut ArchiveConsumer<'_>,
    ) -> Result<()> {
        process::consume(
            &mut docker_command(ctx, args),
            maximum,
            bounded(ctx, 120)?,
            || ctx.cancelled.load(Ordering::Acquire),
            |reader| {
                consumer(reader)?;
                let mut padding = vec![];
                reader.take((1 << 20) + 1).read_to_end(&mut padding)?;
                ensure!(
                    padding.len() <= 1 << 20 && padding.iter().all(|b| *b == 0),
                    "unbounded or nonzero archive trailer"
                );
                Ok(())
            },
        )
    }
}
