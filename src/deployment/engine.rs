use super::{store::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub struct Engine {
    pub deadline: Instant,
}
pub fn normalize_id(value: &str) -> String {
    if value.starts_with("sha256:") {
        value.to_owned()
    } else {
        format!("sha256:{value}")
    }
}

pub fn workload_profile(value: &Value) -> Result<()> {
    ensure!(
        value["AppArmorProfile"] == super::bootstrap::WORKLOAD_PROFILE,
        "native workload is outside its protected AppArmor profile"
    );
    Ok(())
}

pub fn workload_label(label: &str) -> Result<()> {
    let profile = super::bootstrap::WORKLOAD_PROFILE;
    ensure!(
        label == format!("{profile} (enforce)")
            || label == format!("{profile}//&crun (enforce)")
            || label == format!("{profile}//&crun (mixed)"),
        "native workload has an unexpected or non-enforcing kernel AppArmor label"
    );
    Ok(())
}

impl Engine {
    fn capture(&self, arguments: &[&str]) -> Result<crate::process::Captured> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "native engine deadline expired");
        // The independent watchdog also survives controller death. Otherwise
        // an interrupted import could outlive the worker's userspace deadline.
        let mut command = Command::new("/usr/bin/timeout");
        command
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", "/root")
            .env("LANG", "C.UTF-8")
            .args(["--signal=TERM", "--kill-after=5s"])
            .arg(format!("{:.3}s", remaining.as_secs_f64().max(0.001)))
            .arg("/usr/bin/podman")
            .arg("--remote=false")
            .args(arguments);
        crate::process::capture(&mut command, None, 4 << 20, self.deadline, || false)
            .map_err(|_| anyhow!("native engine process failed or exceeded its deadline"))
    }
    pub fn run(&self, arguments: &[&str]) -> Result<Vec<u8>> {
        let output = self.capture(arguments)?;
        ensure!(
            output.status.success(),
            "native engine operation refused: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2048)
                .collect::<String>()
        );
        Ok(output.stdout)
    }
    pub fn health(&self, id: &str) -> Result<()> {
        ensure!(
            hex(id, 64),
            "native health probe requires an exact owned container ID"
        );
        let output = self.capture(&["healthcheck", "run", id])?;
        ensure!(
            matches!(output.status.code(), Some(0 | 1)),
            "native health probe could not complete"
        );
        Ok(())
    }
    pub fn json(&self, arguments: &[&str]) -> Result<Value> {
        crate::strict::value(&self.run(arguments)?, 4 << 20)
    }
    pub fn exists(&self, kind: &str, name_value: &str) -> Result<bool> {
        ensure!(
            ["container", "network", "volume", "secret", "image"].contains(&kind),
            "invalid engine object kind"
        );
        let output = self.capture(&[kind, "exists", name_value])?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(anyhow!("native engine object existence is uncertain")),
        }
    }
    pub fn preflight(&self) -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0
                && Path::new("/run/systemd/system").is_dir()
                && Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
            "host requires protected root execution, systemd and unified cgroup v2"
        );
        let os = std::fs::read_to_string("/etc/os-release")?;
        let field = |name: &str| {
            os.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .map(|v| v.trim_matches('"'))
                .unwrap_or("")
        };
        ensure!(
            field("ID") == "debian" && field("VERSION_ID") == "13",
            "host requires the supported Debian 13 baseline"
        );
        let info = self.json(&["info", "--format=json"])?;
        let host = &info["host"];
        ensure!(
            host["cgroupVersion"] == "v2"
                && host["cgroupManager"] == "systemd"
                && host["security"]["rootless"] == false
                && host["security"]["apparmorEnabled"] == true,
            "native engine has an unsupported authority or cgroup configuration"
        );
        let controllers = host["cgroupControllers"]
            .as_array()
            .ok_or_else(|| anyhow!("native cgroup controller evidence is unavailable"))?;
        ensure!(
            ["memory", "cpu", "pids"]
                .iter()
                .all(|c| controllers.iter().any(|v| v == c)),
            "host lacks required memory, CPU or PID controllers"
        );
        let version = self.run(&["version", "--format={{.Client.Version}}"])?;
        let parts = std::str::from_utf8(&version)?
            .trim()
            .split('.')
            .take(3)
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            parts.len() == 3 && (parts[0], parts[1], parts[2]) >= (5, 4, 2),
            "native engine requires version 5.4.2 or newer"
        );
        Ok(())
    }
    pub fn platform(&self) -> Result<String> {
        let info = self.json(&["info", "--format=json"])?;
        let arch = info["host"]["arch"]
            .as_str()
            .ok_or_else(|| anyhow!("native host architecture is unavailable"))?;
        ensure!(
            ["amd64", "arm64"].contains(&arch),
            "native host architecture is unsupported"
        );
        Ok(format!("linux/{arch}"))
    }
    pub fn inspect(&self, kind: &str, name: &str) -> Result<Value> {
        ensure!(
            ["container", "network", "volume", "image", "secret"].contains(&kind),
            "invalid inspection kind"
        );
        let value = self.json(&[kind, "inspect", name])?;
        let array = value
            .as_array()
            .ok_or_else(|| anyhow!("native engine returned ambiguous inspection"))?;
        ensure!(
            array.len() == 1,
            "native engine inspection did not select one object"
        );
        if kind == "container" {
            workload_profile(&array[0])?;
            if array[0]["State"]["Running"] == true {
                let pid = array[0]["State"]["Pid"]
                    .as_u64()
                    .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
                    .ok_or_else(|| anyhow!("live workload has no native PID"))?;
                let base = std::path::PathBuf::from(format!("/proc/{pid}/attr"));
                let named = base.join("apparmor/current");
                let path = if named.try_exists()? {
                    named
                } else {
                    base.join("current")
                };
                let label = std::fs::read_to_string(path)?;
                workload_label(label.trim())?;
            }
        }
        Ok(array[0].clone())
    }
    pub fn image(&self, reference: &str, config_digest: &str) -> Result<()> {
        let value = self.inspect("image", reference)?;
        ensure!(
            normalize_id(value["Id"].as_str().unwrap_or("")) == config_digest,
            "installed image differs from its admitted configuration"
        );
        Ok(())
    }
    pub fn import(&self, path: &Path, config_digest: &str) -> Result<()> {
        self.run(&[
            "load",
            "--input",
            path.to_str()
                .ok_or_else(|| anyhow!("invalid staged image path"))?,
        ])?;
        self.image(config_digest, config_digest)
    }
    pub fn owned_container(
        &self,
        record: &ContainerRecord,
        application: &str,
        instance: &str,
        service: &str,
    ) -> Result<Option<Value>> {
        if !self.exists("container", &record.name)? {
            return Ok(None);
        }
        let value = self.inspect("container", &record.name)?;
        let id = value["Id"].as_str().unwrap_or("");
        let labels = &value["Config"]["Labels"];
        ensure!(
            hex(id, 64)
                && hex(&record.ownership, 32)
                && labels["io.komizo.application"] == application
                && labels["io.komizo.instance"] == instance
                && labels["io.komizo.service"] == service
                && labels["io.komizo.release"] == record.release_digest
                && labels["io.komizo.ownership"] == record.ownership
                && normalize_id(value["Image"].as_str().unwrap_or("")) == record.config_digest,
            "container is outside its recorded immutable ownership"
        );
        // A supervised restart receives a new ID. It must retain the protected
        // unit's creation token, image and complete retained-volume bindings.
        ensure!(
            !record.id.is_empty(),
            "unrecorded preexisting container cannot be adopted"
        );
        let mounts = value["Mounts"]
            .as_array()
            .ok_or_else(|| anyhow!("container mount evidence missing"))?;
        let observed = mounts
            .iter()
            .filter(|m| m["Type"] == "volume")
            .map(|m| m["Name"].as_str().unwrap_or(""))
            .collect::<std::collections::BTreeSet<_>>();
        let expected = record
            .volumes
            .values()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        ensure!(
            observed == expected,
            "container retained-volume bindings changed"
        );
        Ok(Some(value))
    }
    pub fn owned_object(&self, kind: &str, record: &ObjectRecord) -> Result<Value> {
        ensure!(
            self.exists(kind, &record.name)?,
            "retained engine object is missing"
        );
        let value = self.inspect(kind, &record.name)?;
        let actual = if kind == "network" {
            value["id"].as_str().unwrap_or("").to_owned()
        } else if kind == "volume" {
            volume_identity(&value)?
        } else {
            return Err(anyhow!("invalid retained object kind"));
        };
        ensure!(
            actual == record.id,
            "engine object differs from retained ownership"
        );
        Ok(value)
    }
    pub fn wait_healthy(&self, name: &str, health: bool) -> Result<Value> {
        loop {
            ensure!(
                Instant::now() < self.deadline,
                "native service readiness deadline exceeded"
            );
            let value = self.inspect("container", name)?;
            ensure!(
                value["State"]["Running"] == true,
                "native service exited before readiness"
            );
            if !health || value["State"]["Health"]["Status"] == "healthy" {
                return Ok(value);
            }
            ensure!(
                value["State"]["Health"]["Status"] != "unhealthy",
                "native service healthcheck failed"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    pub fn stop_owned(
        &self,
        record: &ContainerRecord,
        application: &str,
        instance: &str,
        service: &str,
        timeout: u32,
    ) -> Result<()> {
        if let Some(value) = self.owned_container(record, application, instance, service)? {
            self.run(&[
                "stop",
                "--time",
                &timeout.to_string(),
                value["Id"].as_str().unwrap(),
            ])?;
        }
        Ok(())
    }
    pub fn prove_absent(&self, namespace: &str) -> Result<()> {
        for args in [
            vec!["container", "ls", "--all", "--format=json"],
            vec!["network", "ls", "--format=json"],
            vec!["volume", "ls", "--format=json"],
        ] {
            let value = self.json(&args)?;
            let array = value
                .as_array()
                .ok_or_else(|| anyhow!("absence inventory is ambiguous"))?;
            for object in array {
                let names = object
                    .get("Names")
                    .or_else(|| object.get("Name"))
                    .or_else(|| object.get("name"))
                    .ok_or_else(|| anyhow!("absence inventory omitted an object name"))?;
                let names = if let Some(s) = names.as_str() {
                    vec![s]
                } else {
                    names
                        .as_array()
                        .ok_or_else(|| anyhow!("invalid absence inventory names"))?
                        .iter()
                        .map(|n| {
                            n.as_str()
                                .ok_or_else(|| anyhow!("invalid absence inventory name"))
                        })
                        .collect::<Result<Vec<_>>>()?
                };
                ensure!(
                    names.iter().all(|n| !n.starts_with(namespace)),
                    "unreconciled instance resources prevent an absence assertion"
                );
            }
        }
        Ok(())
    }
}
pub fn volume_identity(value: &Value) -> Result<String> {
    ensure!(
        value["Name"].as_str().is_some()
            && value["CreatedAt"].as_str().is_some()
            && value["Driver"] == "local",
        "volume ownership evidence is unavailable"
    );
    Ok(document_digest(&canonical(
        &serde_json::json!({"Name":value["Name"],"CreatedAt":value["CreatedAt"],"Driver":value["Driver"],"Mountpoint":value["Mountpoint"],"Options":value["Options"]}),
    )?))
}

pub fn service_mounts(
    value: &Value,
    record: &ContainerRecord,
    container: &super::model::Container,
) -> Result<()> {
    let expected = container
        .volumes
        .iter()
        .map(|mount| {
            record
                .volumes
                .get(&mount.name)
                .map(|physical| (physical.as_str(), mount.target.as_str(), !mount.read_only))
                .ok_or_else(|| anyhow!("declared retained mount has no protected binding"))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let actual = value["Mounts"]
        .as_array()
        .ok_or_else(|| anyhow!("native retained mount evidence missing"))?
        .iter()
        .filter(|mount| mount["Type"] == "volume")
        .map(|mount| {
            Ok((
                mount["Name"]
                    .as_str()
                    .ok_or_else(|| anyhow!("native retained mount name missing"))?,
                mount["Destination"]
                    .as_str()
                    .ok_or_else(|| anyhow!("native retained mount target missing"))?,
                mount["RW"]
                    .as_bool()
                    .ok_or_else(|| anyhow!("native retained mount access missing"))?,
            ))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        actual == expected
            && value["Mounts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|mount| mount["Type"] == "volume")
                .count()
                == expected.len(),
        "native retained mount targets or access differ from the installed descriptor"
    );
    Ok(())
}
