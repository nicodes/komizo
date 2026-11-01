use super::{
    locking::HostLock,
    paths::{app_state_path, read_state},
    store::write_atomic,
};
use crate::wire::Time;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io, path::Path, time::Duration};
const STOPPED: &str = "STOPPED";
const STOPPED_BY: &str = "STOPPED_BY";
const STOPPED_AT: &str = "STOPPED_AT";
pub fn record_lock_name(app: &str) -> String {
    format!("state-{app}.lock")
}
pub fn state_revision(root: &Path, app: &str) -> Result<String> {
    let bytes = crate::statefile::read(&app_state_path(root, app)?, 1 << 20)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub fn is_stopped(root: &Path, app: &str) -> Result<bool> {
    match read_state(&app_state_path(root, app)?) {
        Ok(state) => Ok(state.get(STOPPED).is_some_and(|s| s == "1")),
        Err(e)
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
pub fn mark_stopped(root: &Path, app: &str, by: &str, at: Time) -> Result<()> {
    let at = Time(at.utc().fixed_offset());
    let time = serde_json::to_value(at)?.as_str().unwrap().to_owned();
    set_values(
        root,
        app,
        &BTreeMap::from([
            (STOPPED.into(), "1".into()),
            (STOPPED_BY.into(), by.into()),
            (STOPPED_AT.into(), time),
        ]),
        None,
    )
    .map(|_| ())
}
pub fn clear_stopped(root: &Path, app: &str) -> Result<()> {
    set_values(root, app, &clear_values(), None).map(|_| ())
}
pub fn clear_stopped_if_unchanged(root: &Path, app: &str, expected: &str) -> Result<bool> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid app state fingerprint"
    );
    set_values(root, app, &clear_values(), Some(expected))
}
fn clear_values() -> BTreeMap<String, String> {
    [STOPPED, STOPPED_BY, STOPPED_AT]
        .iter()
        .map(|s| (s.to_string(), String::new()))
        .collect()
}
fn set_values(
    root: &Path,
    app: &str,
    values: &BTreeMap<String, String>,
    expected: Option<&str>,
) -> Result<bool> {
    let path = app_state_path(root, app)?;
    for (key, value) in values {
        ensure!(
            !value.contains(['\n', '\r']),
            "{key} cannot contain a newline"
        );
        ensure!(value.len() <= 128, "{key} is longer than 128 bytes");
    }
    let _lock = HostLock::acquire(root, &record_lock_name(app), Duration::from_secs(5), || {
        false
    })
    .context("app record lock unavailable")?;
    let bytes = crate::statefile::read(&path, 1 << 20)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    if expected.is_some_and(|expected| format!("{:x}", Sha256::digest(&bytes)) != expected) {
        return Ok(false);
    }
    let body = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
    let mut output: Vec<_> = body
        .split('\n')
        .filter(|line| {
            !line
                .split_once('=')
                .is_some_and(|(key, _)| values.contains_key(key))
        })
        .map(str::to_owned)
        .collect();
    while output.last().is_some_and(|line| line.trim().is_empty()) {
        output.pop();
    }
    for (key, value) in values {
        if !value.is_empty() {
            output.push(format!("{key}={value}"));
        }
    }
    let body = output.join("\n") + "\n";
    write_atomic(&path, &mut body.as_bytes(), 0o640, None)?;
    Ok(true)
}
