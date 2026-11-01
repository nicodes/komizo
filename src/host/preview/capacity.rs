use super::knob::{Knob, get};
use crate::{
    host::PreviewHostResources,
    wire::{Slice, Time, null_default},
    wire_struct,
};
use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
wire_struct!(Floors{disk_bytes:"DiskBytes":i64=>required,mem_bytes:"MemBytes":i64=>required});
pub fn parse_floors(body: &str) -> Result<(Floors, bool)> {
    let mut floors = Floors::default();
    let mut present = false;
    for key in ["DISK_AVAILABLE_FLOOR_BYTES", "MEM_AVAILABLE_FLOOR_BYTES"] {
        let value = get(body, key);
        if value.is_empty() {
            continue;
        }
        let value = value
            .parse::<i64>()
            .map_err(|_| anyhow!("deploy-floors has a non-numeric {key}"))?;
        if key == "DISK_AVAILABLE_FLOOR_BYTES" {
            floors.disk_bytes = value;
        } else {
            floors.mem_bytes = value;
        }
        present = true;
    }
    Ok((floors, present))
}
pub struct Decision {
    pub refuse: String,
    pub warns: Slice<String>,
}
pub fn check_floors(floors: &Floors, present: bool, report: &[u8]) -> Result<Decision> {
    let mut decision = Decision {
        refuse: String::new(),
        warns: Slice::default(),
    };
    if !present {
        return Ok(decision);
    }
    ensure!(
        !report.is_empty(),
        "floors are set but report.json is missing or unreadable"
    );
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Available {
        #[serde(deserialize_with = "null_default")]
        available: i64,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct System {
        mem: Option<Available>,
        #[serde(deserialize_with = "null_default")]
        disks: Vec<Available>,
    }
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Report {
        #[serde(deserialize_with = "null_default")]
        system: System,
    }
    let report: Report = crate::wire::decode(
        std::str::from_utf8(report)
            .map_err(|_| anyhow!("floors are set but report.json is not readable"))?,
    )
    .map_err(|_| anyhow!("floors are set but report.json is not readable"))?;
    for (kind, floor, available) in [
        (
            "mem",
            floors.mem_bytes,
            report.system.mem.as_ref().map(|mem| mem.available),
        ),
        (
            "disk",
            floors.disk_bytes,
            report.system.disks.iter().map(|disk| disk.available).min(),
        ),
    ] {
        if floor <= 0 {
            continue;
        }
        let available = available
            .ok_or_else(|| anyhow!("floors are set but report.json lacks available fields"))?;
        if available < floor {
            return Ok(Decision {
                refuse: format!("{kind} available {available} bytes is below floor {floor} bytes"),
                warns: Slice::default(),
            });
        }
        if available < floor.wrapping_mul(2) {
            decision.warns.push(format!(
                "{kind} available {available} bytes is below twice the floor {floor} bytes"
            ));
        }
    }
    Ok(decision)
}
pub fn report_fresh(body: &[u8], now: DateTime<Utc>) -> Result<()> {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Report {
        at: Time,
    }
    let report = serde_json::from_slice::<Report>(body).ok();
    ensure!(
        report.as_ref().is_some_and(|r| !r.at.is_zero()
            && now - r.at.0.with_timezone(&Utc) <= Duration::minutes(2)
            && r.at.0 <= now + Duration::seconds(5)),
        "preview up requires a capacity report observed within two minutes"
    );
    Ok(())
}
impl Knob {
    pub fn production_reserve(&self, report: &[u8]) -> Result<()> {
        if self.production_reserve == 0 {
            return Ok(());
        }
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Memory {
            total: i64,
        }
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct System {
            mem: Option<Memory>,
        }
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Report {
            system: System,
        }
        let report = serde_json::from_slice::<Report>(report).ok();
        let total = report
            .and_then(|r| r.system.mem)
            .map(|m| m.total)
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                anyhow!("preview up requires measured physical RAM for PRODUCTION_RESERVE")
            })?;
        ensure!(
            self.memory_budget > 0
                && self.database_reserve > 0
                && self.production_reserve < total
                && i128::from(self.database_reserve)
                    <= i128::from(total) - i128::from(self.production_reserve)
                && i128::from(self.memory_budget)
                    <= i128::from(total)
                        - i128::from(self.production_reserve)
                        - i128::from(self.database_reserve),
            "preview up refused: preview/database budgets would consume the production reserve"
        );
        Ok(())
    }
    pub fn protect_envelope(&mut self, resources: Option<&PreviewHostResources>) -> Result<()> {
        let Some(p) = resources else { return Ok(()) };
        let remaining = i128::from(p.physical_memory_bytes)
            - i128::from(p.production_reserve_bytes)
            - i128::from(p.database_reserve_bytes);
        ensure!(
            p.memory_bytes >= 4 << 20
                && (1..=64000).contains(&p.milli_cp_us)
                && p.production_reserve_bytes >= 64 << 20
                && p.database_reserve_bytes >= 4 << 20
                && p.physical_memory_bytes > 0
                && p.production_reserve_bytes <= p.physical_memory_bytes
                && i128::from(p.database_reserve_bytes)
                    <= i128::from(p.physical_memory_bytes) - i128::from(p.production_reserve_bytes)
                && i128::from(p.memory_bytes) <= remaining,
            "preview up refused: invalid protected host resources"
        );
        let cpu = crate::workload::resources::parse_cpu(&self.cpu_limit);
        ensure!(
            cpu.is_some_and(|n| n.is_finite()
                && n > 0.0
                && (n * 1000.0).ceil() <= p.milli_cp_us as f64),
            "preview up refused: CPU_LIMIT exceeds the protected preview envelope"
        );
        self.cgroup_parent = "/komizo-previews".into();
        if self.memory_budget == 0 || self.memory_budget > p.memory_bytes {
            self.memory_budget = p.memory_bytes;
        }
        self.production_reserve = self.production_reserve.max(p.production_reserve_bytes);
        self.database_reserve = self.database_reserve.max(p.database_reserve_bytes);
        Ok(())
    }
}
