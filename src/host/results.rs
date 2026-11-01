use super::authority::{go_json, valid_command_id};
use super::{
    RESULT_VERSION, Result as CommandResult,
    store::{self, write_atomic},
};
use anyhow::{Context, Result};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
pub const DETAIL_MAX: usize = 4 << 10;
pub fn result_path(directory: &Path, id: &str) -> Result<PathBuf> {
    valid_command_id(id)?;
    Ok(directory.join(format!("{id}.json")))
}
pub fn trim_detail(value: &str) -> String {
    if value.len() <= DETAIL_MAX {
        return value.into();
    }
    format!(
        "…{}",
        String::from_utf8_lossy(&value.as_bytes()[value.len() - DETAIL_MAX..])
    )
}
pub fn write_result(directory: &Path, mut result: CommandResult) -> Result<()> {
    result.v = RESULT_VERSION;
    result.detail = trim_detail(&result.detail);
    let path = result_path(directory, &result.id)?;
    let mut body = go_json(&result)?;
    body.push(b'\n');
    write_atomic(&path, &mut body.as_slice(), 0o640, store::agent_group()?)
}
pub fn read_result(directory: &Path, id: &str) -> Result<Option<CommandResult>> {
    let path = result_path(directory, id)?;
    let Some(bytes) = crate::statefile::read(&path, 64 << 10)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
        format!("{} is not readable as a result", path.display())
    })?))
}
pub fn applied(directory: &Path, id: &str) -> bool {
    result_path(directory, id).is_ok_and(|p| fs::metadata(p).is_ok())
}
pub fn prune_results(directory: &Path, now: crate::wire::Time) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(modified) = entry.metadata().ok().and_then(|m| m.modified().ok()) else {
            continue;
        };
        let modified: chrono::DateTime<chrono::Utc> = modified.into();
        if now.utc().signed_duration_since(modified) > chrono::Duration::hours(24) {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {}
            }
        }
    }
    Ok(())
}
