//! Fresh, immutable public trees reject links and path aliases before publication.
use super::policy::StaticLimits;
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, FileTimes, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{Duration, SystemTime},
};
pub const STATIC_ROOT: &str = "/srv/_public";
pub const STATIC_CONTAINER_ROOT: &str = "/srv/public";
pub const MAX_ENTRIES: usize = 4096;
fn identity(hashes: &BTreeMap<String, String>) -> String {
    let mut digest = Sha256::new();
    for (name, hash) in hashes {
        digest.update(name.as_bytes());
        digest.update(b"\0");
        digest.update(hash.as_bytes());
        digest.update(b"\n");
    }
    format!("{:x}", digest.finalize())
}
fn directories(root: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    out.push(root.into());
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            directories(&entry.path(), out)?;
        }
    }
    Ok(())
}
pub fn static_tree(input: impl Read, destination: &Path, limits: &StaticLimits) -> Result<String> {
    let (max_bytes, max_file) = limits.bounds()?;
    DirBuilder::new().mode(0o700).create(destination)?;
    let result = (|| -> Result<String> {
        let mut limited = input.take((max_bytes as u64) + (MAX_ENTRIES as u64) * 2048 + 1);
        let mut seen = BTreeSet::new();
        let mut hashes = BTreeMap::new();
        let mut total = 0u64;
        {
            let mut archive = tar::Archive::new(&mut limited);
            for (index, entry) in archive
                .entries()
                .map_err(|_| anyhow!("invalid public archive"))?
                .enumerate()
            {
                let mut entry = entry.map_err(|_| anyhow!("invalid public archive"))?;
                ensure!(index < MAX_ENTRIES, "public archive exceeds its envelope");
                let path = entry.path_bytes().into_owned();
                let raw = std::str::from_utf8(&path)
                    .map_err(|_| anyhow!("public archive path escapes its tree"))?;
                let raw = raw.strip_prefix("./").unwrap_or(raw);
                if matches!(raw, "." | "") && entry.header().entry_type().is_dir() {
                    continue;
                }
                let name = raw.strip_suffix('/').unwrap_or(raw);
                ensure!(
                    !name.is_empty()
                        && crate::host::inventory::clean_path(name) == name
                        && !name.starts_with('/')
                        && !name.contains(['\\', '\0', '\r', '\n']),
                    "public archive path escapes its tree"
                );
                for component in name.split('/') {
                    ensure!(
                        (!component.starts_with('.') || name == "_expo/.routes.json")
                            && !component.contains(':'),
                        "hidden or platform-sensitive public path"
                    );
                }
                ensure!(
                    seen.insert(name.to_lowercase()),
                    "duplicate public archive path"
                );
                let target = destination.join(name);
                if entry.header().entry_type().is_dir() {
                    fs::create_dir_all(&target)?;
                    continue;
                }
                let size = entry.size();
                ensure!(
                    entry.header().entry_type().is_file()
                        && size <= max_file as u64
                        && size <= max_bytes as u64 - total,
                    "unsupported or oversized public archive entry"
                );
                total += size;
                fs::create_dir_all(target.parent().unwrap())?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&target)?;
                let mut sum = Sha256::new();
                let mut copied = 0u64;
                let mut buffer = [0u8; 65536];
                loop {
                    let count = entry.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    file.write_all(&buffer[..count])?;
                    sum.update(&buffer[..count]);
                    copied += count as u64;
                }
                ensure!(copied == size, "incomplete public archive entry");
                file.sync_all()?;
                file.set_permissions(Permissions::from_mode(0o444))?;
                let modified =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(entry.header().mtime()?);
                file.set_times(
                    FileTimes::new()
                        .set_accessed(modified)
                        .set_modified(modified),
                )?;
                hashes.insert(name.to_owned(), format!("{:x}", sum.finalize()));
            }
        }
        ensure!(
            limited.limit() > 0 && hashes.contains_key("index.html"),
            "public archive lacks a bounded entry point"
        );
        let mut dirs = vec![];
        directories(destination, &mut dirs)?;
        for dir in dirs {
            fs::set_permissions(&dir, Permissions::from_mode(0o755))?;
            File::open(dir)?.sync_all()?;
        }
        Ok(identity(&hashes))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
    }
    result
}
pub fn static_tree_checksum(directory: &Path, limits: &StaticLimits) -> Result<String> {
    let (max_bytes, max_file) = limits.bounds()?;
    let mut hashes = BTreeMap::new();
    let mut total = 0u64;
    let mut entries = 0usize;
    fn walk(
        root: &Path,
        path: &Path,
        hashes: &mut BTreeMap<String, String>,
        total: &mut u64,
        entries: &mut usize,
        max_bytes: u64,
        max_file: u64,
    ) -> Result<()> {
        let info = fs::symlink_metadata(path)?;
        *entries += 1;
        ensure!(
            *entries <= MAX_ENTRIES + 1 && !info.file_type().is_symlink(),
            "cached public tree is linked or oversized"
        );
        if info.is_dir() {
            ensure!(
                info.permissions().mode() & 0o022 == 0,
                "cached public directory is writable"
            );
            let mut children = fs::read_dir(path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            children.sort();
            for child in children {
                walk(root, &child, hashes, total, entries, max_bytes, max_file)?;
            }
            return Ok(());
        }
        ensure!(
            info.is_file()
                && info.permissions().mode() & 0o222 == 0
                && info.len() <= max_file
                && info.len() <= max_bytes - *total,
            "cached public file is unsafe"
        );
        *total += info.len();
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?
            .take(max_file + 1);
        let mut sum = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            sum.update(&buffer[..count]);
        }
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .ok_or_else(|| anyhow!("invalid public path"))?;
        hashes.insert(relative.into(), format!("{:x}", sum.finalize()));
        Ok(())
    }
    if let Err(error) = walk(
        directory,
        directory,
        &mut hashes,
        &mut total,
        &mut entries,
        max_bytes as u64,
        max_file as u64,
    ) {
        return Err(anyhow!("{error}\ninvalid cached public entry point"));
    }
    ensure!(
        hashes.contains_key("index.html"),
        "invalid cached public entry point"
    );
    Ok(identity(&hashes))
}
