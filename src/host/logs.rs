use super::{
    LogLine,
    store::{open_regular, write_atomic},
};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeSet,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
pub const LOGS_MAX: usize = 256 << 10;
pub const LOG_TAIL_MAX: usize = 2000;
pub fn log_path(dir: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty()
            && name.len() <= 100
            && !name.contains(['/', '.'])
            && !name.starts_with('_')
            && !name.contains('\0'),
        "not an app: {name:?}"
    );
    Ok(dir.join(format!("{name}.log")))
}
pub fn write_log(dir: &Path, name: &str, mut body: &[u8]) -> Result<()> {
    let path = log_path(dir, name)?;
    if body.len() > LOGS_MAX {
        body = &body[body.len() - LOGS_MAX..];
        if let Some(index) = body.iter().position(|b| *b == b'\n')
            && index + 1 < body.len()
        {
            body = &body[index + 1..];
        }
    }
    if crate::statefile::read(&path, LOGS_MAX)
        .ok()
        .flatten()
        .is_some_and(|old| old == body)
    {
        return Ok(());
    }
    write_atomic(&path, &mut body, 0o640, None)
}
pub fn read_log(dir: &Path, name: &str, count: usize) -> Result<String> {
    let path = log_path(dir, name)?;
    let mut file = open_regular(&path)?;
    let size = file.metadata()?.len();
    let seeked = size > LOGS_MAX as u64;
    if seeked {
        file.seek(SeekFrom::Start(size - LOGS_MAX as u64))?;
    }
    let mut bytes = vec![];
    file.take(LOGS_MAX as u64).read_to_end(&mut bytes)?;
    if seeked && let Some(first) = bytes.iter().position(|b| *b == b'\n') {
        bytes.drain(..=first);
    }
    let body = String::from_utf8_lossy(&bytes);
    let lines: Vec<_> = body.trim_end_matches('\n').split('\n').collect();
    let start = if count > 0 {
        lines.len().saturating_sub(count)
    } else {
        0
    };
    Ok(lines[start..].join("\n"))
}
pub fn parse_log(body: &str) -> Vec<LogLine> {
    body.strip_suffix('\n')
        .unwrap_or(body)
        .split('\n')
        .filter(|s| !s.is_empty())
        .map(|line| match line.split_once('\t') {
            Some((service, text)) => LogLine {
                service: service.into(),
                text: text.into(),
            },
            None => LogLine {
                service: String::new(),
                text: line.into(),
            },
        })
        .collect()
}
pub fn format_log(lines: &[LogLine]) -> String {
    let mut out = String::new();
    for line in lines {
        if !line.service.is_empty() {
            out.push_str(&line.service);
            out.push('\t');
        }
        out.push_str(&line.text);
        out.push('\n');
    }
    out
}
pub fn filter_log(lines: &[LogLine], service: &str) -> Vec<LogLine> {
    lines
        .iter()
        .filter(|line| service.is_empty() || line.service == service)
        .cloned()
        .collect()
}
pub fn log_services(lines: &[LogLine]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    lines
        .iter()
        .filter(|line| !line.service.is_empty() && seen.insert(line.service.clone()))
        .map(|line| line.service.clone())
        .collect()
}
pub fn valid_service(value: &str) -> bool {
    value.len() <= 100 && !value.chars().any(|c| c <= ' ' || c == '\x7f')
}
pub fn prune_logs(dir: &Path, keep: &[String]) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let live: BTreeSet<_> = keep.iter().map(|k| format!("{k}.log")).collect();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().is_ok_and(|t| !t.is_dir())
            && name.ends_with(".log")
            && !live.contains(&name)
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}
