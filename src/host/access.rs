//! Access entries are reduced to counts before they leave the host.
use super::{Metric, Metrics, Probe, Span, paths::ACCESS_LOG, store::open_regular};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
};
const TAIL_BYTES: u64 = 4 << 20;
#[derive(Default, Deserialize)]
#[serde(default)]
struct Entry {
    ts: f64,
    status: i64,
    request: Request,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Request {
    host: String,
}
impl Probe {
    pub fn metrics(&self, from: i64, to: i64) -> Metrics {
        let mut owners = BTreeMap::new();
        for state in self.app_states() {
            if state.dir().is_empty() {
                continue;
            }
            for host in self.hosts(state.dir()) {
                owners.insert(host.name, (state.name.clone(), host.service));
            }
        }
        let Ok(mut file) = open_regular(&self.path(ACCESS_LOG)) else {
            return Metrics {
                rows: vec![].into(),
                ..Default::default()
            };
        };
        let Ok(metadata) = file.metadata() else {
            return Metrics {
                rows: vec![].into(),
                ..Default::default()
            };
        };
        let seeked = metadata.len() > TAIL_BYTES;
        if seeked
            && file
                .seek(SeekFrom::Start(metadata.len() - TAIL_BYTES))
                .is_err()
        {
            return Metrics {
                rows: vec![].into(),
                ..Default::default()
            };
        }
        metrics_from_reader(file.take(TAIL_BYTES), &owners, from, to, seeked)
    }
}
pub fn metrics_from_reader(
    reader: impl Read,
    owners: &BTreeMap<String, (String, String)>,
    from: i64,
    to: i64,
    drop_first: bool,
) -> Metrics {
    let mut reader = BufReader::new(reader);
    let mut first = drop_first;
    let mut counts: BTreeMap<(i64, String, String), Metric> = BTreeMap::new();
    let (mut oldest, mut newest) = (0, 0);
    loop {
        let mut bytes = vec![];
        let mut bounded = reader.by_ref().take(1 << 20);
        let Ok(n) = bounded.read_until(b'\n', &mut bytes) else {
            break;
        };
        if n == 0 || n == 1 << 20 {
            break;
        }
        if first {
            first = false;
            continue;
        }
        let Ok(entry) = serde_json::from_slice::<Entry>(&bytes) else {
            continue;
        };
        if !entry.ts.is_finite() {
            continue;
        }
        let time = entry.ts.floor() as i64;
        if time <= 0 {
            continue;
        }
        if oldest == 0 || time < oldest {
            oldest = time;
        }
        if time > newest {
            newest = time;
        }
        if time < from || time > to {
            continue;
        }
        let host = entry.request.host;
        let owner = owners.get(&host).or_else(|| {
            host.split_once('.')
                .and_then(|(_, rest)| owners.get(&format!("*.{rest}")))
        });
        let Some((app, service)) = owner else {
            continue;
        };
        let minute = time - time % 60;
        let row = counts
            .entry((minute, app.clone(), service.clone()))
            .or_insert_with(|| Metric {
                minute,
                app: app.clone(),
                service: service.clone(),
                ..Default::default()
            });
        match entry.status {
            500.. => row.c5 += 1,
            400..=499 => row.c4 += 1,
            300..=399 => row.c3 += 1,
            _ => row.c2 += 1,
        }
    }
    Metrics {
        span: (oldest > 0).then_some(Span {
            from: oldest,
            to: newest,
        }),
        rows: counts.into_values().collect::<Vec<_>>().into(),
    }
}
