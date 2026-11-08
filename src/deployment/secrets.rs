use super::{
    model::*,
    store::{atomic, protected_directory, read_protected},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub generation: String,
    pub path: String,
    pub sha256: String,
}

pub fn environment_file(body: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(body)?;
    ensure!(
        !text.contains(['\0', '\r']) && body.len() <= 128 << 10,
        "invalid environment secret file"
    );
    let mut names = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("environment secret must contain explicit assignments"))?;
        ensure!(
            !key.is_empty()
                && key.as_bytes()[0].is_ascii_alphabetic()
                && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && names.insert(key)
                && safe_text(value, 16384),
            "invalid or duplicate environment secret assignment"
        );
    }
    Ok(())
}

pub fn grants<'a>(policy: &'a Policy, instance: &str) -> Result<&'a BTreeMap<String, SecretGrant>> {
    if instance == "production" {
        Ok(&policy.secrets)
    } else {
        Ok(&policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("preview secret authority missing"))?
            .secrets)
    }
}

pub fn stage(
    root: &Path,
    document: &ReleaseDocument,
    policy: &Policy,
    instance: &str,
) -> Result<BTreeMap<String, Snapshot>> {
    policy.admit(&document.release, instance)?;
    let grants = grants(policy, instance)?;
    let aliases = document
        .release
        .workload
        .services
        .values()
        .chain(document.release.workload.jobs.values())
        .flat_map(|c| {
            c.environment_files
                .iter()
                .chain(c.secrets.iter().map(|s| &s.source))
        })
        .collect::<BTreeSet<_>>();
    let namespace = super::units::namespace(&document.release.application, instance)?;
    let mut snapshots = BTreeMap::new();
    for alias in aliases {
        let grant = &grants[alias];
        let source = grant.path.replace("{instance}", instance);
        ensure!(
            absolute(&source),
            "secret reference did not resolve to a protected path"
        );
        let source = Path::new(&source);
        protected_directory(
            source
                .parent()
                .ok_or_else(|| anyhow!("secret parent missing"))?,
        )?;
        let metadata = fs::symlink_metadata(source)?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "secret source is not privately owned"
        );
        let body = read_protected(source, 128 << 10)?;
        if grant.environment_file {
            environment_file(&body)?;
        }
        let generation_key = document_digest(grant.generation.as_bytes());
        let path = root
            .join("secret-snapshots")
            .join(&namespace)
            .join(&generation_key[7..])
            .join(alias);
        if path.try_exists()? {
            ensure!(
                read_protected(&path, 128 << 10)? == body,
                "secret bytes changed without a new operator generation"
            );
        } else {
            atomic(&path, &body, 0o600)?;
        }
        snapshots.insert(
            alias.clone(),
            Snapshot {
                generation: grant.generation.clone(),
                path: path.to_str().unwrap().to_owned(),
                sha256: document_digest(&body),
            },
        );
    }
    for container in document
        .release
        .workload
        .services
        .values()
        .chain(document.release.workload.jobs.values())
    {
        let mut keys = container
            .environment
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        for alias in &container.environment_files {
            let body = read_protected(Path::new(&snapshots[alias].path), 128 << 10)?;
            for line in std::str::from_utf8(&body)?
                .lines()
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                let key = line
                    .split_once('=')
                    .ok_or_else(|| anyhow!("invalid staged environment assignment"))?
                    .0;
                ensure!(
                    keys.insert(key.to_owned()),
                    "secret environment reference shadows a declared or previously granted variable"
                );
            }
        }
    }
    Ok(snapshots)
}

pub fn mount_snapshot(
    root: &Path,
    service: &str,
    secret: &SecretMount,
    snapshot: &Snapshot,
) -> Result<String> {
    ensure!(
        name(service)
            && name(&secret.source)
            && absolute(&snapshot.path)
            && digest(&snapshot.sha256),
        "invalid mounted secret binding"
    );
    let key = document_digest(
        format!(
            "{}\0{service}\0{}\0{}\0{}",
            snapshot.path, secret.uid, secret.gid, secret.mode
        )
        .as_bytes(),
    );
    let path = root.join("mounted-secrets").join(&key[7..]);
    let body = read_protected(Path::new(&snapshot.path), 128 << 10)?;
    ensure!(
        document_digest(&body) == snapshot.sha256,
        "retained secret snapshot identity changed"
    );
    if !path.try_exists()? {
        atomic(&path, &body, 0o600)?;
        let encoded = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::chown(encoded.as_ptr(), secret.uid, secret.gid) } == 0,
            "cannot assign mounted secret ownership"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(secret.mode))?;
    }
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == secret.uid
            && metadata.gid() == secret.gid
            && metadata.mode() & 0o777 == secret.mode,
        "mounted secret ownership differs from admitted binding"
    );
    ensure!(
        metadata.len() == body.len() as u64
            && document_digest(&fs::read(&path)?) == snapshot.sha256,
        "mounted secret bytes differ from the retained generation"
    );
    Ok(path.to_str().unwrap().to_owned())
}

pub fn rotate(
    policy_path: &Path,
    policy: &mut Policy,
    update: &SecretUpdate,
    root: &Path,
) -> Result<String> {
    let grant = policy
        .secrets
        .get_mut(&update.reference)
        .ok_or_else(|| anyhow!("unknown owner secret reference"))?;
    ensure!(
        grant.generation == update.expected_generation
            && ((update.format == "environment-file" && grant.environment_file)
                || (update.format == "opaque" && grant.mount)),
        "secret generation or delivery format changed"
    );
    if update.format == "environment-file" {
        environment_file(update.value.as_bytes())?;
    }
    let generation = super::store::identity()?;
    let path: PathBuf = root
        .join("operator-secrets")
        .join(&policy.application)
        .join(&update.reference)
        .join(&generation);
    atomic(&path, update.value.as_bytes(), 0o600)?;
    grant.path = path.to_str().unwrap().to_owned();
    grant.generation = generation.clone();
    policy.validate()?;
    atomic(policy_path, &serde_json::to_vec(policy)?, 0o600)?;
    Ok(generation)
}
