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
pub fn workload_group(value: &Value, group: &super::cgroups::Group) -> Result<()> {
    super::workload_guard::verify(value, group)
}
pub fn workload_limits(
    value: &Value,
    group: &super::cgroups::Group,
    limits: &super::model::Limits,
) -> Result<()> {
    super::workload_guard::verify_limits(value, group, limits)
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
            || label == format!("{profile}//&crun (mixed)")
            || label == format!("crun//&{profile} (enforce)")
            || label == format!("crun//&{profile} (mixed)"),
        "native workload has an unexpected or non-enforcing kernel AppArmor label"
    );
    Ok(())
}

fn alpine_release(os: &str) -> Result<()> {
    let field = |name: &str| -> Result<&str> {
        let values = os
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{name}=")))
            .collect::<Vec<_>>();
        ensure!(values.len() == 1, "ambiguous host release identity");
        let value = values[0];
        if let Some(value) = value.strip_prefix('"') {
            value
                .strip_suffix('"')
                .filter(|value| !value.contains('"'))
                .ok_or_else(|| anyhow!("invalid quoted host release identity"))
        } else {
            ensure!(!value.contains('"'), "invalid quoted host release identity");
            Ok(value)
        }
    };
    let version = field("VERSION_ID")?.split('.').collect::<Vec<_>>();
    ensure!(
        field("ID")? == "alpine"
            && matches!(version.len(), 2 | 3)
            && version[0] == "3"
            && version[1] == "24"
            && version
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "host requires the supported Alpine 3.24 baseline"
    );
    Ok(())
}

fn cleanup_identity(actual: &Value, expected: &Value) -> Result<String> {
    let id = expected["Id"]
        .as_str()
        .filter(|id| hex(id, 64))
        .ok_or_else(|| anyhow!("owned cleanup requires an exact recorded container ID"))?;
    let labels = &expected["Config"]["Labels"];
    ensure!(
        expected["Config"].is_object()
            && expected["HostConfig"].is_object()
            && expected["Mounts"].is_array()
            && expected["Name"].is_string()
            && labels["io.komizo.application"].as_str().is_some_and(name)
            && labels["io.komizo.instance"].as_str().is_some_and(name)
            && labels["io.komizo.service"].as_str().is_some_and(name)
            && labels["io.komizo.release"].as_str().is_some_and(digest)
            && labels["io.komizo.ownership"]
                .as_str()
                .is_some_and(|value| hex(value, 32))
            && expected["Image"]
                .as_str()
                .is_some_and(|value| digest(&normalize_id(value)))
            && expected["AppArmorProfile"] == super::bootstrap::WORKLOAD_PROFILE
            && actual["Id"] == id
            && [
                "Config",
                "HostConfig",
                "Mounts",
                "Image",
                "Name",
                "AppArmorProfile",
                "OCIRuntime"
            ]
            .iter()
            .all(|key| actual[key] == expected[key]),
        "owned cleanup refused changed or incomplete immutable container identity"
    );
    Ok(id.to_owned())
}

impl Engine {
    /// Cleanup-only: never creates, starts or extends a workload's lifetime.
    /// A separately bounded caller may use this after its execution budget.
    pub fn kill_owned(&self, expected: &Value) -> Result<()> {
        let id = cleanup_identity(expected, expected)?;
        let inspect = || -> Result<Value> {
            let value = self.json(&["container", "inspect", &id])?;
            let entries = value
                .as_array()
                .filter(|entries| entries.len() == 1)
                .ok_or_else(|| anyhow!("owned cleanup inspection is ambiguous"))?;
            cleanup_identity(&entries[0], expected)?;
            Ok(entries[0].clone())
        };
        let terminal = |value: &Value| -> bool {
            value["State"]["Running"] == false
                && value["State"]["Paused"] == false
                && value["State"]["Pid"] == 0
                && value["State"]["Status"] == "exited"
        };
        let actual = inspect()?;
        if terminal(&actual) {
            return Ok(());
        }
        ensure!(
            actual["State"]["Running"] == true || actual["State"]["Paused"] == true,
            "owned cleanup refuses an unknown native execution state"
        );
        let killed = self
            .capture(&["kill", "--signal", "KILL", &id])?
            .status
            .success();
        loop {
            let current = inspect()?;
            if terminal(&current) {
                return Ok(());
            }
            ensure!(
                killed && Instant::now() < self.deadline,
                "owned container termination remains unproven"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    /// Finite jobs may exit between inspection and a captured proc read. Only
    /// that typed terminal race permits one same-CID immutable reinspection.
    /// Services use the strict free function during activation.
    pub fn workload_group(
        &self,
        value: &Value,
        group: &super::cgroups::Group,
    ) -> Result<Option<Value>> {
        self.finite_workload(value, group, None)
    }
    pub fn workload_limits(
        &self,
        value: &Value,
        group: &super::cgroups::Group,
        limits: &super::model::Limits,
    ) -> Result<Option<Value>> {
        self.finite_workload(value, group, Some(limits))
    }
    fn finite_workload(
        &self,
        value: &Value,
        group: &super::cgroups::Group,
        limits: Option<&super::model::Limits>,
    ) -> Result<Option<Value>> {
        let proof = if let Some(limits) = limits {
            workload_limits(value, group, limits)
        } else {
            workload_group(value, group)
        };
        match proof {
            Ok(()) => Ok(None),
            Err(error) if super::workload_guard::process_ended(&error) => {
                let id = value["Id"]
                    .as_str()
                    .filter(|id| hex(id, 64))
                    .ok_or_else(|| anyhow!("finite workload lacks an exact inspection ID"))?;
                let terminal = self.inspect("container", id)?;
                super::workload_guard::verify_terminal(&terminal, value, group)?;
                if let Some(limits) = limits {
                    super::workload_guard::configuration_limits(&terminal, limits)?;
                }
                Ok(Some(terminal))
            }
            Err(error) => Err(error),
        }
    }
    fn command(&self, arguments: &[&str]) -> Result<Command> {
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
            .arg("--signal=KILL")
            .arg(format!("{:.3}s", remaining.as_secs_f64().max(0.001)))
            .arg("/usr/bin/podman")
            .arg("--remote=false")
            .arg("--cgroup-manager=cgroupfs")
            .args(arguments);
        Ok(command)
    }
    fn capture(&self, arguments: &[&str]) -> Result<crate::process::Captured> {
        let mut command = self.command(arguments)?;
        crate::process::capture(&mut command, None, 4 << 20, self.deadline, || false)
            .map_err(|_| anyhow!("native engine process failed or exceeded its deadline"))
    }
    /// Bind this owned child and every forked monitor before either timeout or
    /// Podman executes. No existing process is selected or moved by PID.
    fn capture_in_group(
        &self,
        arguments: &[&str],
        group: &super::cgroups::Group,
    ) -> Result<crate::process::Captured> {
        #[cfg(target_os = "linux")]
        {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            let entry = super::cgroups::process_entry(group)?;
            let mut command = self.command(arguments)?;
            unsafe {
                command.pre_exec(move || {
                    if libc::write(entry.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            crate::process::capture(&mut command, None, 4 << 20, self.deadline, || false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (arguments, group);
            Err(anyhow!(
                "native process placement requires the supported Alpine host"
            ))
        }
    }
    pub fn start_in_group(&self, id: &str, monitor: &super::cgroups::Group) -> Result<()> {
        ensure!(
            hex(id, 64),
            "native start requires an exact owned container ID"
        );
        let output = self.capture_in_group(&["start", id], monitor)?;
        ensure!(
            output.status.success(),
            "native engine operation refused: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2048)
                .collect::<String>()
        );
        Ok(())
    }
    pub fn logs(&self, id: &str, maximum: usize) -> Result<(Vec<u8>, Vec<u8>)> {
        use std::{cell::RefCell, io::Write, rc::Rc};
        ensure!(
            hex(id, 64) && maximum > 0 && maximum <= 256 << 10,
            "native logs require an exact owned container ID and bounded tail"
        );
        // Podman sends container stdout and stderr on separate descriptors.
        // Keep both tails separate until each has passed secret redaction.
        struct Tail {
            bytes: Rc<RefCell<Vec<u8>>>,
            maximum: usize,
        }
        impl Write for Tail {
            fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
                let mut bytes = self.bytes.borrow_mut();
                if input.len() >= self.maximum {
                    bytes.clear();
                    bytes.extend_from_slice(&input[input.len() - self.maximum..]);
                } else {
                    let remove = (bytes.len() + input.len()).saturating_sub(self.maximum);
                    bytes.drain(..remove);
                    bytes.extend_from_slice(input);
                }
                Ok(input.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Rc::new(RefCell::new(Vec::new()));
        let errors = Rc::new(RefCell::new(Vec::new()));
        let mut stdout = Tail {
            bytes: output.clone(),
            maximum,
        };
        let mut stderr = Tail {
            bytes: errors.clone(),
            maximum,
        };
        let mut command = self.command(&["logs", "--tail", "200", id])?;
        let result = crate::process::stream(
            &mut command,
            None,
            maximum,
            self.deadline,
            || false,
            &mut stdout,
            &mut stderr,
        )?;
        ensure!(
            result.status.success(),
            "bounded native log observation failed"
        );
        drop(stdout);
        drop(stderr);
        let output = Rc::try_unwrap(output)
            .map_err(|_| anyhow!("log observation retained an unexpected writer"))?
            .into_inner();
        let errors = Rc::try_unwrap(errors)
            .map_err(|_| anyhow!("log observation retained an unexpected writer"))?
            .into_inner();
        Ok((output, errors))
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
    /// Charge the client, timeout and their descendants to this exact owned
    /// probe leaf before any executable or health effect can run.
    pub fn health_in_group(&self, id: &str, group: &super::cgroups::Group) -> Result<()> {
        ensure!(
            hex(id, 64),
            "native health probe requires an exact owned container ID"
        );
        let output = self.capture_in_group(&["healthcheck", "run", id], group)?;
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
                && Path::new("/run/openrc").is_dir()
                && Path::new("/sbin/supervise-daemon").is_file()
                && Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
            "host requires protected root execution, OpenRC and unified cgroup v2"
        );
        alpine_release(&std::fs::read_to_string("/etc/os-release")?)?;
        for (path, maximum) in [
            ("/usr/bin/podman", 128 << 20),
            ("/usr/bin/crun", 32 << 20),
            ("/usr/bin/conmon", 32 << 20),
        ] {
            super::bootstrap::public_root_file(Path::new(path), maximum, 0o755)?;
        }
        let info = self.json(&["info", "--format=json"])?;
        let host = &info["host"];
        ensure!(
            host["cgroupVersion"] == "v2"
                && host["cgroupManager"] == "cgroupfs"
                && host["security"]["rootless"] == false
                && host["security"]["apparmorEnabled"] == true
                && host["ociRuntime"]["name"] == "crun"
                && host["ociRuntime"]["path"] == "/usr/bin/crun"
                && host["conmon"]["path"] == "/usr/bin/conmon"
                && host["networkBackend"] == "netavark",
            "native engine has an unsupported authority or cgroup configuration"
        );
        let controllers = host["cgroupControllers"]
            .as_array()
            .ok_or_else(|| anyhow!("native cgroup controller evidence is unavailable"))?;
        ensure!(
            ["memory", "cpu", "pids", "io"]
                .iter()
                .all(|c| controllers.iter().any(|v| v == c)),
            "host lacks required memory, CPU, PID or I/O controllers"
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
    fn inspection(&self, kind: &str, name: &str) -> Result<Value> {
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
        Ok(array[0].clone())
    }
    pub fn inspect(&self, kind: &str, name: &str) -> Result<Value> {
        let value = self.inspection(kind, name)?;
        if kind == "container" {
            workload_profile(&value)?;
        }
        Ok(value)
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
    pub fn container_metadata(
        &self,
        record: &ContainerRecord,
        application: &str,
        instance: &str,
        service: &str,
    ) -> Result<Option<Value>> {
        if !self.exists("container", &record.name)? {
            return Ok(None);
        }
        let value = self.inspection("container", &record.name)?;
        workload_profile(&value)?;
        let id = value["Id"].as_str().unwrap_or("");
        let labels = &value["Config"]["Labels"];
        ensure!(
            hex(id, 64)
                && id == record.id
                && value["Name"]
                    .as_str()
                    .is_some_and(|actual| actual.strip_prefix('/').unwrap_or(actual) == record.name)
                && hex(&record.ownership, 32)
                && labels["io.komizo.application"] == application
                && labels["io.komizo.instance"] == instance
                && labels["io.komizo.service"] == service
                && labels["io.komizo.release"] == record.release_digest
                && labels["io.komizo.ownership"] == record.ownership
                && normalize_id(value["Image"].as_str().unwrap_or("")) == record.config_digest,
            "container is outside its recorded immutable ownership"
        );
        // The creation intent persists this CID before start. Supervisor
        // restarts reuse it; explicit recovery must persist its own candidate.
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
        super::workload_guard::configuration(
            &value,
            &super::cgroups::workload_group(
                application,
                instance,
                super::cgroups::WorkloadKind::Service,
                service,
                &record.ownership,
            )?,
        )?;
        Ok(Some(value))
    }
    pub fn owned_container(
        &self,
        record: &ContainerRecord,
        application: &str,
        instance: &str,
        service: &str,
    ) -> Result<Option<Value>> {
        let value = self.container_metadata(record, application, instance, service)?;
        if let Some(value) = &value {
            workload_group(
                value,
                &super::cgroups::workload_group(
                    application,
                    instance,
                    super::cgroups::WorkloadKind::Service,
                    service,
                    &record.ownership,
                )?,
            )?;
        }
        Ok(value)
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

#[cfg(test)]
mod host_tests {
    use super::*;
    #[test]
    fn scoped_start_refuses_names_and_delegated_branches_before_execution() {
        let engine = Engine {
            deadline: Instant::now() + Duration::from_secs(1),
        };
        let group = super::super::cgroups::root_group();
        for id in ["container-name", "", "../foreign", &"a".repeat(63)] {
            let error = engine.start_in_group(id, &group).unwrap_err();
            assert!(error.to_string().contains("exact owned container ID"));
        }
        let error = engine.start_in_group(&"a".repeat(64), &group).unwrap_err();
        #[cfg(target_os = "linux")]
        assert!(
            error
                .to_string()
                .contains("process cannot enter a delegated resource branch")
        );
        #[cfg(not(target_os = "linux"))]
        assert!(error.to_string().contains("supported Alpine host"));
    }
    #[test]
    fn alpine_baseline_accepts_patch_updates_but_not_another_distro_or_minor() {
        for version in ["3.24", "3.24.0", "3.24.3", "3.24.99"] {
            assert!(alpine_release(&format!("ID=alpine\nVERSION_ID=\"{version}\"\n")).is_ok());
        }
        for os in [
            "ID=debian\nVERSION_ID=13\n",
            "ID=alpine\nVERSION_ID=3.23.9\n",
            "ID=alpine\nVERSION_ID=3.25.0\n",
            "ID=alpine\nVERSION_ID=3.24.invalid\n",
            "ID=alpine\nVERSION_ID=3.24.3.extra\n",
            "ID=\"alpine\nVERSION_ID=3.24.3\n",
            "ID=alpine\nID=debian\nVERSION_ID=3.24.3\n",
        ] {
            assert!(alpine_release(os).is_err(), "{os:?}");
        }
    }
    #[test]
    fn cleanup_can_only_select_the_recorded_container_and_unchanged_immutable_bytes() {
        use serde_json::json;
        let expected = json!({"Id":"b".repeat(64),"Image":"sha256:".to_owned()+&"c".repeat(64),"Name":"kmz-fixed-job-fixed","AppArmorProfile":super::super::bootstrap::WORKLOAD_PROFILE,"OCIRuntime":"crun","HostConfig":{"CgroupParent":"/komizo/production/fixed"},"Mounts":[],"Config":{"Labels":{"io.komizo.application":"alpha","io.komizo.instance":"production","io.komizo.service":"migrate","io.komizo.release":"sha256:".to_owned()+&"d".repeat(64),"io.komizo.ownership":"a".repeat(32)}}});
        assert_eq!(
            cleanup_identity(&expected, &expected).unwrap(),
            "b".repeat(64)
        );
        for key in [
            "Id",
            "Image",
            "Name",
            "AppArmorProfile",
            "OCIRuntime",
            "HostConfig",
            "Mounts",
            "Config",
        ] {
            let mut foreign = expected.clone();
            foreign[key] = json!("foreign-private-sentinel");
            let error = cleanup_identity(&foreign, &expected).unwrap_err();
            assert!(!error.to_string().contains("foreign-private-sentinel"));
        }
        let mut incomplete = expected.clone();
        incomplete["Config"] = json!({});
        assert!(cleanup_identity(&incomplete, &incomplete).is_err());
    }
}
