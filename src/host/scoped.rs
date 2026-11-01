//! Startup checks credential generation metadata without reading credential bytes.
pub use super::types::ScopedDefinition;
use super::{
    locking::{DeploymentLock, HostLock},
    paths,
};
use crate::workload::policy::operation_identity;
use anyhow::{Result, anyhow, ensure};
use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt, path::Path, time::Duration};
pub fn valid_profile(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
pub fn parse_definition(
    profile: &str,
    schema: &str,
    files: &str,
) -> Result<Option<ScopedDefinition>> {
    if profile.is_empty() {
        ensure!(
            schema.is_empty() && files.is_empty(),
            "unscoped app has scoped metadata"
        );
        return Ok(None);
    }
    let schema = schema
        .parse::<i64>()
        .ok()
        .filter(|n| (1..=1_000_000).contains(n));
    ensure!(
        valid_profile(profile) && schema.is_some(),
        "scoped environment needs an explicit valid profile and schema"
    );
    let names: Vec<_> = files.split(',').map(str::to_owned).collect();
    ensure!(
        (1..=64).contains(&names.len()),
        "scoped environment needs a bounded file declaration"
    );
    let mut seen = BTreeSet::new();
    for name in &names {
        ensure!(
            !name.is_empty()
                && name.len() <= 80
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                && !matches!(name.as_str(), "." | ".." | "provenance")
                && seen.insert(name),
            "scoped environment has an unsafe or duplicate file declaration"
        );
    }
    Ok(Some(ScopedDefinition {
        profile: profile.into(),
        schema: schema.unwrap(),
        files: names.into(),
    }))
}
impl ScopedDefinition {
    pub fn marker(&self, generation: &str) -> Vec<u8> {
        format!(
            "profile={}\nschema={}\ngeneration={generation}\n",
            self.profile, self.schema
        )
        .into_bytes()
    }
}
fn definition(root: &Path, app: &str) -> Result<(paths::State, Option<ScopedDefinition>)> {
    let path = paths::app_state_path(root, app)?;
    let state = paths::read_state(&path)
        .map_err(|e| anyhow!("could not read the app record, so nothing was started: {e}"))?;
    let get = |key: &str| state.get(key).map(String::as_str).unwrap_or("");
    let definition =
        parse_definition(get("SCOPED_ENV"), get("SCOPED_SCHEMA"), get("SCOPED_FILES"))?;
    Ok((state, definition))
}
pub fn check_start(root: &Path, app: &str) -> Result<()> {
    let (state, definition) = definition(root, app)?;
    let Some(definition) = definition else {
        return Ok(());
    };
    let get = |key: &str| state.get(key).map(String::as_str).unwrap_or("");
    let id = get("SCOPED_GENERATION");
    let dir = Path::new(get("APP_DIR"));
    let ready = || anyhow!("scoped env is not ready, so nothing was started");
    ensure!(
        operation_identity(id) && !dir.as_os_str().is_empty() && dir.is_absolute(),
        "scoped env is not ready, so nothing was started"
    );
    let secrets = dir.join("secrets");
    let current = fs::read_link(secrets.join("current")).map_err(|_| ready())?;
    ensure!(
        current == Path::new(&format!("generations/{id}")),
        "scoped env is not ready, so nothing was started"
    );
    let generation = secrets.join("generations").join(id);
    for name in definition.files.iter() {
        let info = fs::symlink_metadata(generation.join(name)).map_err(|_| ready())?;
        ensure!(
            info.is_file() && info.mode() & 0o777 == 0o600,
            "scoped env is not ready, so nothing was started"
        );
    }
    let path = generation.join("provenance");
    let info = fs::symlink_metadata(&path).map_err(|_| ready())?;
    let expected = definition.marker(id);
    ensure!(
        info.is_file()
            && info.mode() & 0o777 == 0o400
            && info.uid() == 0
            && info.len() == expected.len() as u64,
        "scoped env is not ready, so nothing was started"
    );
    let actual = crate::statefile::read(&path, expected.len()).map_err(|_| ready())?;
    ensure!(
        actual.as_deref() == Some(expected.as_slice()),
        "scoped env is not ready, so nothing was started"
    );
    Ok(())
}
pub fn refuse_start(root: &Path, app: &str) -> Result<()> {
    if app.is_empty() {
        return Ok(());
    }
    if definition(root, app)?.1.is_none() {
        return Ok(());
    }
    let _lock = HostLock::acquire(root, &format!("deploy-{app}.lock"), Duration::ZERO, || {
        false
    })
    .map_err(|_| {
        anyhow!("scoped environment requires the shared app lock, so nothing was started")
    })?;
    check_start(root, app)
}
pub fn lock_for_start(
    root: &Path,
    app: &str,
    wait: Duration,
    cancelled: impl Fn() -> bool,
) -> Result<DeploymentLock> {
    let lock = DeploymentLock::acquire(root, app, wait, cancelled)?;
    check_start(root, app)?;
    Ok(lock)
}
