//! Root writes observations; the reporting account receives only served data.
use super::{Metric, Metrics, Monitor, Poll, REPORT_VERSION, Report, Sample, Span};
use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
};
pub const HISTORY_MAX: u64 = 16 << 20;
pub const HISTORY_KEEP: usize = 20000;
pub const HISTORY_TAIL: u64 = 8 << 20;
pub const RECORD_MAX: usize = 4 << 20;

pub trait Document: DeserializeOwned {
    fn schema(&self) -> i64;
}
macro_rules! document { ($($name:ty),*)=>{$(impl Document for $name { fn schema(&self)->i64 { self.v } })*}; }
document!(Report, Poll, Monitor);
pub fn decode<T: Document>(bytes: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(bytes)?;
    let version = value.schema();
    ensure!(
        version != 0,
        "this is not something komizo-box wrote -- it states no schema version"
    );
    ensure!(
        version <= REPORT_VERSION,
        "this server speaks report schema v{version} and this komizo understands v{REPORT_VERSION} -- update komizo"
    );
    Ok(value)
}
impl Report {
    pub fn stale(&self, now: chrono::DateTime<chrono::Utc>, after: chrono::Duration) -> bool {
        self.at.is_zero() || now.signed_duration_since(self.at.utc()) > after
    }
}
impl Metric {
    pub fn total(&self) -> i64 {
        self.c2
            .wrapping_add(self.c3)
            .wrapping_add(self.c4)
            .wrapping_add(self.c5)
    }
}

pub fn read_report(path: &Path) -> Result<Report> {
    let bytes = crate::statefile::read(path, 16 << 20)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    decode(&bytes)
}
pub fn write_report(path: &Path, report: &Report) -> Result<()> {
    let mut bytes = serde_json::to_vec(report)?;
    bytes.push(b'\n');
    write_atomic(path, &mut bytes.as_slice(), 0o644, None)
}
pub fn write_metrics(path: &Path, metrics: &Metrics) -> Result<()> {
    write_atomic(
        path,
        &mut serde_json::to_vec(metrics)?.as_slice(),
        0o640,
        None,
    )
}
pub fn read_metrics(path: &Path, from: i64, to: i64) -> Result<Metrics> {
    let mut output = Metrics {
        rows: vec![].into(),
        ..Default::default()
    };
    let Some(bytes) = crate::statefile::read(path, 16 << 20)? else {
        return Ok(output);
    };
    let stored: Metrics = serde_json::from_slice(&bytes)?;
    output.rows = stored
        .rows
        .into_vec()
        .into_iter()
        .filter(|row| row.minute >= from && row.minute <= to)
        .collect::<Vec<_>>()
        .into();
    if let Some(span) = stored.span {
        let lo = span.from.max(from);
        let hi = span.to.min(to);
        if lo <= hi {
            output.span = Some(Span { from: lo, to: hi });
        }
    }
    Ok(output)
}
pub(crate) fn open_regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "served data is not a regular file"
    );
    Ok(file)
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn make_parent(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(parent(path))?;
    Ok(())
}

/// Set group on the unpublished temporary file, so a failed handoff cannot
/// create a replay record for work that has not run.
pub fn write_atomic(
    path: &Path,
    reader: &mut impl Read,
    mode: u32,
    gid: Option<libc::gid_t>,
) -> Result<()> {
    write_atomic_with(path, reader, mode, |file| give_to_group(file, gid))
}
pub fn write_atomic_with(
    path: &Path,
    reader: &mut impl Read,
    mode: u32,
    handoff: impl FnOnce(&File) -> Result<()>,
) -> Result<()> {
    make_parent(path)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempfile_in(parent(path))?;
    io::copy(reader, &mut temporary)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    handoff(temporary.as_file())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    File::open(parent(path))?.sync_all()?;
    Ok(())
}
pub(crate) fn give_to_group(file: &File, gid: Option<libc::gid_t>) -> Result<()> {
    if let Some(gid) = gid {
        // SAFETY: fchown uses a live descriptor; preserve the owner explicitly.
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), libc::getuid(), gid) } == 0,
            "could not give served file to komizo_monitor: {}",
            io::Error::last_os_error()
        );
    }
    Ok(())
}
pub fn agent_group() -> Result<Option<libc::gid_t>> {
    use std::mem::MaybeUninit;
    let mut capacity = 1024;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut group = MaybeUninit::<libc::group>::uninit();
        let mut result = std::ptr::null_mut();
        // SAFETY: buffers remain alive for the lookup and the returned pointer
        // is examined only after getgrnam_r reports success.
        let code = unsafe {
            libc::getgrnam_r(
                c"komizo_monitor".as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE && capacity < 1 << 20 {
            capacity *= 2;
            continue;
        }
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code).into());
        }
        return Ok(if result.is_null() {
            None
        } else {
            Some(unsafe { (*result).gr_gid })
        });
    }
}
pub fn prepare_served_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    if let Some(gid) = agent_group()? {
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), 0, gid) } == 0,
            "could not group served directory to komizo_monitor: {}",
            io::Error::last_os_error()
        );
    }
    file.set_permissions(fs::Permissions::from_mode(0o2750))?;
    Ok(())
}
pub fn append_sample(
    path: &Path,
    sample: &Sample,
    max: u64,
    keep: usize,
    gid: Option<libc::gid_t>,
) -> Result<()> {
    ensure!(
        max > 0 && keep > 0 && keep <= HISTORY_KEEP,
        "invalid history retention bounds"
    );
    let mut bytes = serde_json::to_vec(sample)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= max,
        "sample exceeds history byte limit"
    );
    make_parent(path)?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "history is not a regular file");
    give_to_group(&file, gid)?;
    file.write_all(&bytes)?;
    let size = file.metadata()?.len();
    drop(file);
    if size > max {
        trim_lines(path, keep, (max / 2).max(bytes.len() as u64))?;
    }
    Ok(())
}
/// Scanner-compatible bounded lines, including the byte count consumed.
fn next_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    let mut bytes = vec![];
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!bytes.is_empty()).then_some(bytes));
        }
        let end = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        ensure!(
            bytes.len() + end <= RECORD_MAX,
            "history record exceeds scanner bound"
        );
        let complete = available[end - 1] == b'\n';
        bytes.extend_from_slice(&available[..end]);
        reader.consume(end);
        if complete {
            return Ok(Some(bytes));
        }
    }
}
pub fn read_samples(path: &Path, from: i64, to: i64) -> Result<Option<Vec<Sample>>> {
    let mut file = match open_regular(path) {
        Ok(f) => f,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let size = file.metadata()?.len();
    let seeked = size > HISTORY_TAIL;
    if seeked {
        file.seek(SeekFrom::Start(size - HISTORY_TAIL))?;
    }
    let mut reader = BufReader::new(file);
    if seeked {
        next_line(&mut reader)?;
    }
    let mut output = vec![];
    while let Some(line) = next_line(&mut reader)? {
        if let Ok(sample) = serde_json::from_slice::<Sample>(&line) {
            let time = sample.at.utc().timestamp();
            if time >= from && time <= to {
                output.push(sample);
            }
        }
    }
    Ok((!output.is_empty()).then_some(output))
}
pub fn trim_lines(path: &Path, keep: usize, max_bytes: u64) -> Result<()> {
    ensure!(
        keep > 0 && keep <= HISTORY_KEEP && max_bytes > 0,
        "invalid history retention bounds"
    );
    let mut file = open_regular(path)?;
    let size = file.metadata()?.len();
    let mut start = size.saturating_sub(max_bytes);
    let partial = if start > 0 {
        file.seek(SeekFrom::Start(start - 1))?;
        let mut previous = [0u8; 1];
        file.read_exact(&mut previous)?;
        previous[0] != b'\n'
    } else {
        false
    };
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(file);
    if partial {
        loop {
            let available = reader.fill_buf()?;
            ensure!(
                !available.is_empty(),
                "history has no complete record within byte limit"
            );
            let end = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |n| n + 1);
            let complete = available[end - 1] == b'\n';
            start += end as u64;
            reader.consume(end);
            if complete {
                break;
            }
        }
    }
    let mut offsets = VecDeque::with_capacity(keep);
    let mut offset = start;
    while let Some(line) = next_line(&mut reader)? {
        if offsets.len() == keep {
            offsets.pop_front();
        }
        offsets.push_back(offset);
        offset += line.len() as u64;
    }
    let Some(start) = offsets.front().copied() else {
        bail!("history has no complete record within byte limit");
    };
    let mut file = reader.into_inner();
    file.seek(SeekFrom::Start(start))?;
    write_atomic(path, &mut file.take(size - start), 0o640, None)
        .context("replace retained history")
}
