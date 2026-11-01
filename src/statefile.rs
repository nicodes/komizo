use anyhow::{Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
pub fn read(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "state file exceeds its bound or is not regular"
    );
    let mut bytes = vec![];
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "state file exceeds its bound");
    Ok(Some(bytes))
}
pub fn write_private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".komizo-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
