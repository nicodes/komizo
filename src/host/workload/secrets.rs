//! Validated secret sets preserve unrelated bytes and publish private ownership atomically.
use super::files;
use crate::{
    wire::{Bytes, Secret},
    workload::yaml::MAX_BYTES,
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
};
#[derive(Clone, Debug, Default)]
pub struct SecretSet(pub BTreeMap<String, Bytes>);
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && (name.as_bytes()[0].is_ascii_alphanumeric() || name.starts_with('_'))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
impl SecretSet {
    pub fn from_strings(values: BTreeMap<String, Secret>) -> Self {
        Self(
            values
                .into_iter()
                .map(|(key, value)| (key, value.expose().as_bytes().to_vec().into()))
                .collect(),
        )
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            (1..=128).contains(&self.0.len()),
            "secret set needs bounded distinct names"
        );
        let mut total = 0;
        for (name, value) in &self.0 {
            ensure!(
                valid_name(name)
                    && !name.starts_with("GITHUB_")
                    && !name.starts_with("RUNNER_")
                    && name != "KOMIZO_DEPLOY_KEY"
                    && !value.is_empty()
                    && !value.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)),
                "invalid secret name or value"
            );
            total += name.len() + value.len() + 2;
        }
        ensure!(total <= MAX_BYTES, "secret set exceeds its bound");
        Ok(())
    }
    pub fn merge(&self, previous: &[u8]) -> Result<Vec<u8>> {
        self.check()?;
        ensure!(
            previous.len() <= MAX_BYTES,
            "existing secret set exceeds its bound"
        );
        let mut output = vec![];
        for line in previous.split(|b| *b == b'\n') {
            let key = line.split(|b| *b == b'=').next().unwrap_or_default();
            if !line.is_empty() && !self.0.keys().any(|name| name.as_bytes() == key) {
                output.extend_from_slice(line);
                output.push(b'\n')
            }
        }
        for (name, value) in &self.0 {
            output.extend_from_slice(name.as_bytes());
            output.push(b'=');
            output.extend_from_slice(value);
            output.push(b'\n')
        }
        ensure!(
            output.len() <= MAX_BYTES,
            "complete secret set exceeds its bound"
        );
        Ok(output)
    }
    pub fn write(&self, directory: &Path) -> Result<()> {
        self.check()?;
        let path = directory.join("secrets.env");
        let previous = match fs::symlink_metadata(&path) {
            Ok(info) => {
                ensure!(
                    info.is_file() && info.mode() & 0o077 == 0 && files::owned(&info),
                    "existing secret store is not protected"
                );
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)?
                    .take((MAX_BYTES + 1) as u64);
                let mut body = vec![];
                file.read_to_end(&mut body)?;
                ensure!(
                    body.len() <= MAX_BYTES,
                    "existing secret set exceeds its bound"
                );
                body
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e.into()),
        };
        write_file(&path, &self.merge(&previous)?, 0)
    }
}
pub fn write_file(path: &Path, body: &[u8], uid: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(info) => ensure!(info.is_file(), "secret destination is not a regular file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".secret-")
        .tempfile_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    ensure!(
        unsafe { libc::fchown(file.as_file().as_raw_fd(), uid, 0) } == 0,
        "private secret ownership could not be set"
    );
    file.write_all(body)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn decode_set(body: &[u8]) -> Result<SecretSet> {
    let value = crate::strict::fields(
        crate::strict::value(body, 2 * MAX_BYTES)?,
        &["version", "secrets"],
    )?;
    ensure!(value["version"] == 1, "invalid release secret set");
    let values: Option<BTreeMap<String, Option<Secret>>> =
        serde_json::from_value(value.get("secrets").cloned().unwrap_or_default())
            .map_err(|_| anyhow!("invalid release secret set"))?;
    let set = SecretSet::from_strings(
        values
            .unwrap_or_default()
            .into_iter()
            .map(|(key, value)| (key, value.unwrap_or_default()))
            .collect(),
    );
    set.check()?;
    Ok(set)
}
