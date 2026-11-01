//! Reclaim only finite inactive control cache; validate every group before writing.
use super::HostResources;
use crate::{cgroupfs::Directory, wire::Slice, wire_struct};
use anyhow::{Result, anyhow, ensure};
use std::path::Path;
wire_struct!(ControlReclaim{name:"name":String=>required,before_bytes:"before_bytes":i64=>required,requested_bytes:"requested_bytes":i64=>required,after_bytes:"after_bytes":i64=>required});
fn counter(dir: &Directory) -> Result<i64> {
    let bytes = dir
        .read("memory.current", 64)
        .map_err(|_| anyhow!("control counter unavailable"))?
        .ok_or_else(|| anyhow!("control counter unavailable"))?;
    let value = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .ok_or_else(|| anyhow!("control counter invalid"))?;
    Ok(value)
}
impl HostResources {
    pub fn reclaim_control_cache(&self, root: &Path) -> (Slice<ControlReclaim>, Result<()>) {
        let mut rows = vec![];
        let mut directories = vec![];
        let preflight = (|| -> Result<()> {
            ensure!(
                (3..=4).contains(&self.controls.len()),
                "declared control resources required"
            );
            self.check_controls()?;
            let root = Directory::open(root).map_err(|_| anyhow!("control group unavailable"))?;
            for (name, control) in &self.controls {
                if name == "openrc.sshd" {
                    continue;
                }
                let dir = root
                    .directory(name, false)
                    .map_err(|_| anyhow!("control group unavailable"))?
                    .ok_or_else(|| anyhow!("control group unavailable"))?;
                let current = counter(&dir)?;
                let mut row = ControlReclaim {
                    name: name.clone(),
                    before_bytes: current,
                    after_bytes: current,
                    requested_bytes: 0,
                };
                if current > control.group.memory_bytes {
                    let amount = ((i128::from(current) - i128::from(control.group.memory_bytes)
                        + (8 << 20)
                        + (4 << 20)
                        - 1)
                        / (4 << 20))
                        * (4 << 20);
                    ensure!(
                        amount <= 64 << 20,
                        "control excess requires a larger reviewed drain"
                    );
                    let body = dir
                        .read("memory.stat", 65536)
                        .map_err(|_| anyhow!("inactive control cache unavailable"))?
                        .ok_or_else(|| anyhow!("inactive control cache unavailable"))?;
                    let mut inactive = -1i64;
                    for line in String::from_utf8_lossy(&body).lines() {
                        let fields: Vec<_> = line.split_whitespace().collect();
                        if fields.len() == 2 && fields[0] == "inactive_file" {
                            inactive = fields[1]
                                .parse()
                                .map_err(|_| anyhow!("invalid inactive cache counter"))?;
                            break;
                        }
                    }
                    ensure!(
                        i128::from(inactive) >= amount,
                        "insufficient inactive control cache; live memory cannot be forcibly drained"
                    );
                    ensure!(
                        dir.regular("memory.reclaim").unwrap_or(false),
                        "bounded kernel reclaim interface unavailable"
                    );
                    row.requested_bytes = amount as i64;
                }
                rows.push(row);
                directories.push(dir);
            }
            Ok(())
        })();
        if let Err(error) = preflight {
            return (Slice::default(), Err(error));
        }
        for (row, dir) in rows.iter_mut().zip(directories) {
            if row.requested_bytes == 0 {
                continue;
            }
            if dir
                .write_existing(
                    "memory.reclaim",
                    &format!("{} swappiness=0", row.requested_bytes),
                )
                .is_err()
            {
                return (
                    rows.into(),
                    Err(anyhow!(
                        "kernel reclaim incomplete; inspect retained receipt and current usage"
                    )),
                );
            }
            match counter(&dir) {
                Ok(value) => row.after_bytes = value,
                Err(error) => return (rows.into(), Err(error)),
            }
        }
        (rows.into(), Ok(()))
    }
}
