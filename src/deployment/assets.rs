use super::{model::*, store::protected_directory, validation::*};
use anyhow::{Result, anyhow, ensure};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};

pub fn verify_file(path: &Path, expected: &str, size: u64) -> Result<()> {
    ensure!(digest(expected), "invalid expected artifact digest");
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() == size,
        "artifact size differs from admitted bytes"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut seen = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        seen = seen
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("artifact length overflow"))?;
        ensure!(seen <= size, "artifact grew during verification");
        hash.update(&buffer[..n]);
    }
    ensure!(
        seen == size && format!("sha256:{:x}", hash.finalize()) == expected,
        "artifact bytes differ from admitted digest"
    );
    Ok(())
}

/// Extract into a newly owned staging directory. No archive-selected host path,
/// link, device, mode, timestamp or identity is applied to the host filesystem.
pub fn extract(path: &Path, target: &Path, policy: &Policy) -> Result<()> {
    ensure!(
        !target.try_exists()?,
        "static staging target already exists"
    );
    protected_directory(
        target
            .parent()
            .ok_or_else(|| anyhow!("missing staging parent"))?,
    )?;
    fs::create_dir(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<()> {
        let mut decoder = GzDecoder::new(BufReader::new(File::open(path)?));
        let mut total = 0u64;
        let mut files = 0u32;
        let mut names = BTreeSet::new();
        {
            let mut archive = tar::Archive::new(&mut decoder);
            for entry in archive.entries()?.raw(true) {
                let mut entry = entry?;
                let raw = entry.path_bytes();
                let raw = std::str::from_utf8(&raw)?;
                let name = raw.trim_end_matches('/');
                ensure!(
                    !name.is_empty()
                        && name.len() <= 1024
                        && !name.starts_with('/')
                        && !name.contains(['\\', '\0'])
                        && Path::new(name)
                            .components()
                            .all(|c| matches!(c, Component::Normal(_)))
                        && !name.contains("//")
                        && names.insert(name.to_owned())
                        && names.len() <= 16384,
                    "unsafe or duplicate static archive path"
                );
                let kind = entry.header().entry_type();
                ensure!(
                    kind.is_file() || kind.is_dir(),
                    "static archive may contain only regular files and directories"
                );
                let size = entry.size();
                ensure!(
                    size <= policy.max_asset_file_bytes && (!kind.is_dir() || size == 0),
                    "static file exceeds its admitted bound"
                );
                total = total
                    .checked_add(size)
                    .ok_or_else(|| anyhow!("static size overflow"))?;
                ensure!(
                    total <= policy.max_asset_bytes,
                    "expanded static payload exceeds its admitted bound"
                );
                let destination = target.join(name);
                if kind.is_dir() {
                    fs::create_dir_all(&destination)?;
                    continue;
                }
                files += 1;
                fs::create_dir_all(destination.parent().unwrap())?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&destination)?;
                file.set_permissions(fs::Permissions::from_mode(0o444))?;
                let copied = std::io::copy(&mut entry, &mut file)?;
                ensure!(copied == size, "incomplete static archive member");
                file.flush()?;
                file.sync_all()?;
            }
        }
        // A tar stream may have block padding; it may not hide another payload.
        let mut padding = [0u8; 8192];
        let mut padding_bytes = 0usize;
        loop {
            let n = decoder.read(&mut padding)?;
            if n == 0 {
                break;
            }
            padding_bytes += n;
            ensure!(
                padding_bytes <= 1 << 20 && padding[..n].iter().all(|b| *b == 0),
                "unexpected data after static archive"
            );
        }
        ensure!(
            decoder.into_inner().fill_buf()?.is_empty() && files > 0,
            "static artifact has trailing compressed data or no files"
        );
        fn seal(path: &Path) -> Result<()> {
            for item in fs::read_dir(path)? {
                let item = item?;
                if item.file_type()?.is_dir() {
                    seal(&item.path())?;
                }
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            File::open(path)?.sync_all()?;
            Ok(())
        }
        seal(target)?;
        Ok(())
    })();
    if result.is_err() {
        fs::remove_dir_all(target)?;
    }
    result
}
