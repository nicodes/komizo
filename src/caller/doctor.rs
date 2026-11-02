use crate::{wire::Slice, wire_struct};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;
pub const SCRIPT: &str = include_str!("doctor.sh");
wire_struct!(Check{name:"name":String=>required,ok:"ok":bool=>required,detail:"detail":String=>required});
wire_struct!(Doctor{version:"version":i64=>required,host:"host":String=>required,supported:"supported":bool=>required,installed:"installed":bool=>required,checks:"checks":Slice<Check> =>required,facts:"facts":BTreeMap<String,String> =>required});
pub fn decode(host: &str, raw: &str) -> Result<Doctor> {
    let mut result = Doctor {
        version: 1,
        host: host.into(),
        supported: true,
        ..Default::default()
    };
    let allowed = [
        "os",
        "kernel",
        "arch",
        "uid",
        "memory_kib",
        "disk_kib",
        "inodes",
        "apk",
        "openrc",
        "cgroup_v2",
        "installed",
    ];
    ensure!(raw.len() <= 4096, "oversized prerequisite response");
    for line in raw.lines() {
        let Some((name, value)) = line.split_once('=') else {
            anyhow::bail!("invalid prerequisite response")
        };
        ensure!(
            allowed.contains(&name)
                && !result.facts.contains_key(name)
                && !value.is_empty()
                && value.len() <= 128,
            "invalid prerequisite response"
        );
        result.facts.insert(name.into(), value.into());
    }
    ensure!(
        result.facts.len() == allowed.len(),
        "incomplete prerequisite response"
    );
    let mut checks = vec![];
    let f = &result.facts;
    let os =
        f["os"] == "alpine" && f["kernel"] == "Linux" && f["apk"] == "yes" && f["openrc"] == "yes";
    checks.push(Check {
        name: "os".into(),
        ok: os,
        detail: "Alpine Linux with apk and OpenRC is required".into(),
    });
    checks.push(Check {
        name: "architecture".into(),
        ok: matches!(f["arch"].as_str(), "x86_64" | "aarch64"),
        detail: "amd64 or arm64 is required".into(),
    });
    checks.push(Check {
        name: "privileges".into(),
        ok: f["uid"] == "0",
        detail: "setup needs the host operator's root SSH access".into(),
    });
    for (name, key, minimum) in [
        ("memory", "memory_kib", 256 << 10),
        ("disk", "disk_kib", 1 << 20),
        ("inodes", "inodes", 4096),
    ] {
        checks.push(Check {
            name: name.into(),
            ok: !f[key].is_empty()
                && f[key].bytes().all(|b| b.is_ascii_digit())
                && f[key].parse::<u64>().is_ok_and(|v| v >= minimum),
            detail: format!(
                "minimum {minimum} {key}; this is setup admission, not application capacity"
            ),
        });
    }
    result.supported = checks.iter().all(|c| c.ok);
    result.installed = f["installed"] == "yes";
    for name in ["apk", "openrc", "cgroup_v2", "installed"] {
        ensure!(
            matches!(f[name].as_str(), "yes" | "no"),
            "invalid prerequisite boolean"
        );
    }
    result.checks = checks.into();
    Ok(result)
}
