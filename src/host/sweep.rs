use super::{
    Probe, SweepRecord,
    paths::{APPS_DIR, SRV_DIR},
};
use crate::wire::Time;
use anyhow::Result;
use chrono::{DateTime, FixedOffset};
use std::{collections::BTreeSet, path::Path};
pub const KNOB_PATH: &str = "/etc/komizo/disk-sweep";
pub const RECORD_PATH: &str = "/var/lib/komizo/served/sweep.json";
const HOUR: i64 = 3_600_000_000_000;
const DAY: i64 = 24 * HOUR;
#[derive(Clone, Debug)]
pub struct Knob {
    pub min_age_ns: i64,
    pub interval_ns: i64,
    pub disabled: bool,
}
impl Default for Knob {
    fn default() -> Self {
        Self {
            min_age_ns: 7 * DAY,
            interval_ns: 24 * HOUR,
            disabled: false,
        }
    }
}
pub fn parse_knob(body: &str) -> (Knob, String) {
    let get = |key: &str| {
        body.split('\n')
            .find_map(|line| {
                line.strip_prefix(&format!("{key}="))
                    .map(|v| v.trim_matches(['\r', ' ', '\t']))
            })
            .unwrap_or("")
    };
    let mut knob = Knob::default();
    let mut bad = vec![];
    for (key, unit, target, allow_zero) in [
        ("MIN_AGE_DAYS", DAY, &mut knob.min_age_ns, true),
        ("INTERVAL_HOURS", HOUR, &mut knob.interval_ns, false),
    ] {
        let value = get(key);
        if value.is_empty() {
            continue;
        }
        // Overflow must not turn a conservative age into a negative duration.
        if let Some(value) = value
            .parse::<i64>()
            .ok()
            .filter(|n| if allow_zero { *n >= 0 } else { *n > 0 })
            .and_then(|n| n.checked_mul(unit))
        {
            *target = value;
        } else {
            bad.push(format!("{key}={value}"));
        }
    }
    knob.disabled = get("DISABLED") == "1";
    let note = if bad.is_empty() {
        String::new()
    } else {
        format!(
            "ignoring non-numeric knob values, using defaults for them: {}",
            bad.join(", ")
        )
    };
    (knob, note)
}
pub fn read_knob(path: &Path) -> (Knob, String) {
    match std::fs::read_to_string(path) {
        Ok(body) => parse_knob(&body),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Knob::default(), String::new()),
        Err(e) => (
            Knob::default(),
            format!("could not read {}, using defaults: {e}", path.display()),
        ),
    }
}
#[derive(Clone, Debug)]
pub struct Image {
    pub id: String,
    pub repo: String,
    pub tag: String,
    pub created: DateTime<FixedOffset>,
    pub size_bytes: i64,
}
fn record(knob: &Knob, now: Time, note: String) -> SweepRecord {
    SweepRecord {
        v: 1,
        at: now,
        min_age_days: knob.min_age_ns / DAY,
        note,
        ..Default::default()
    }
}
pub fn sweep(
    knob: &Knob,
    now: Time,
    images: &[Image],
    refs: &BTreeSet<String>,
    state: &[String],
    mut remove: impl FnMut(&str) -> Result<()>,
) -> SweepRecord {
    let mut record = record(knob, now, String::new());
    if knob.disabled {
        record.note = format!("sweep disabled by {KNOB_PATH}");
        return record;
    }
    for image in images {
        if !image.tag.is_empty() && image.tag != "<none>" {
            continue;
        }
        let named = !image.repo.is_empty() && image.repo != "<none>";
        if refs.contains(&image.id)
            || (named && refs.contains(&format!("{}:{}", image.repo, image.tag)))
            || (named && state.iter().any(|s| s.contains(&image.repo)))
        {
            record.skipped += 1;
            continue;
        }
        if now
            .0
            .signed_duration_since(image.created)
            .num_nanoseconds()
            .unwrap_or(i64::MAX)
            < knob.min_age_ns
        {
            continue;
        }
        record.candidates += 1;
        if let Err(e) = remove(&image.id) {
            record.skipped += 1;
            if !record.note.is_empty() {
                record.note.push_str("; ");
            }
            record.note.push_str(&format!(
                "docker refused to remove {} (kept): {e}",
                image.id.chars().take(12).collect::<String>()
            ));
            continue;
        }
        record.removed += 1;
        record.reclaimed_bytes = record.reclaimed_bytes.wrapping_add(image.size_bytes);
    }
    if record.removed == 0 && record.note.is_empty() {
        record.note = "nothing to sweep".into();
    }
    record
}
pub fn parse_images(body: &str) -> Vec<Image> {
    body.split('\n')
        .filter_map(|line| {
            let f: Vec<_> = line.trim_end_matches('\r').split('\t').collect();
            if f.len() != 4 || f[0].is_empty() {
                return None;
            }
            // Docker's zone abbreviation is descriptive; its numeric offset owns the instant.
            let (stamp, _) = f[3].rsplit_once(' ')?;
            let created = DateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S %z").ok()?;
            Some(Image {
                id: f[0].into(),
                repo: f[1].into(),
                tag: f[2].into(),
                created,
                size_bytes: 0,
            })
        })
        .collect()
}
pub fn parse_refs(body: &str) -> BTreeSet<String> {
    body.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}
pub fn state_image_names(apps: &Path, srv: &Path) -> Vec<String> {
    let mut files = vec![];
    if let Ok(entries) = std::fs::read_dir(apps) {
        files.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|s| s == "env")),
        );
    }
    if let Ok(entries) = std::fs::read_dir(srv) {
        files.extend(entries.flatten().map(|e| e.path().join("compose.yml")));
    }
    files.sort();
    files
        .into_iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .collect()
}
pub fn docker_sweep(
    knob: &Knob,
    now: Time,
    probe: &Probe,
    mut run: impl FnMut(&[&str]) -> Result<String>,
) -> SweepRecord {
    let images = match run(&[
        "images",
        "--no-trunc",
        "--format",
        "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}",
    ]) {
        Ok(body) => body,
        Err(e) => {
            return record(
                knob,
                now,
                format!("could not list images (kept everything): {e}"),
            );
        }
    };
    let refs = match run(&["ps", "-a", "--no-trunc", "--format", "{{.Image}}"]) {
        Ok(body) => body,
        Err(e) => {
            return record(
                knob,
                now,
                format!("could not list containers (kept everything): {e}"),
            );
        }
    };
    let mut images = parse_images(&images);
    // Inspect every eligible size before allowing the first removal.
    for image in &mut images {
        if !image.tag.is_empty() && image.tag != "<none>" {
            continue;
        }
        let body = match run(&["image", "inspect", "--format", "{{.Size}}", &image.id]) {
            Ok(body) => body,
            Err(e) => {
                return record(
                    knob,
                    now,
                    format!("could not inspect image size (kept everything): {e}"),
                );
            }
        };
        match body.trim().parse::<i64>() {
            Ok(size) if size >= 0 => image.size_bytes = size,
            _ => return record(knob, now, "invalid image size (kept everything)".into()),
        }
    }
    sweep(
        knob,
        now,
        &images,
        &parse_refs(&refs),
        &state_image_names(&probe.path(APPS_DIR), &probe.path(SRV_DIR)),
        |id| run(&["image", "rm", id]).map(|_| ()),
    )
}
pub fn write_record(path: &Path, record: &SweepRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = crate::workload::json::compact(&serde_json::to_value(record)?)?;
    bytes.push(b'\n');
    super::store::write_atomic(path, &mut bytes.as_slice(), 0o644, None)
}
pub fn read_record(path: &Path) -> Option<SweepRecord> {
    serde_json::from_slice(&crate::statefile::read(path, 64 << 10).ok()??).ok()
}
