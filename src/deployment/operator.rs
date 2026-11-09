//! Owner client. SSH authenticates the owner; the host still admits typed scope.
use super::{controller, model::*, store, validation::*};
use anyhow::{Result, anyhow, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    process::Command,
    time::{Duration, Instant},
};

pub const USAGE: &str = "komizo -- native owner client\n\n  komizo status --host HOST [--identity PATH]\n  komizo inspect|start|stop|restart|backup --host HOST --application APP [--instance production]\n  komizo logs --host HOST --application APP --service SERVICE_OR_JOB\n  komizo ui --host HOST [--port PORT]\n  komizo request --host HOST --file REQUEST.json\n  komizo capabilities\n  komizo version\n\nSSH uses the owner's root identity and strict known-host verification.\n";

fn options(args: &[String]) -> Result<BTreeMap<&str, &str>> {
    ensure!(
        args.len().is_multiple_of(2),
        "each owner option needs a value"
    );
    let mut result = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        ensure!(
            [
                "--host",
                "--identity",
                "--application",
                "--instance",
                "--file",
                "--service",
                "--port",
                "--operation",
                "--release"
            ]
            .contains(&pair[0].as_str())
                && !pair[1].is_empty()
                && safe_text(&pair[1], 4096)
                && result.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "invalid or duplicate owner option"
        );
    }
    Ok(result)
}
fn exchange(
    host: &str,
    identity: Option<&str>,
    command: &str,
    body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    ensure!(
        hostname(host) || host.parse::<std::net::IpAddr>().is_ok(),
        "owner host must be a literal hostname or address"
    );
    ensure!(
        ["komizo-box submit", "komizo-box status"].contains(&command) || {
            let words = command.split(' ').collect::<Vec<_>>();
            words.len() == 8
                && words[0..3] == ["komizo-box", "logs", "--application"]
                && words[4] == "--instance"
                && words[6] == "--service"
                && [words[3], words[5], words[7]]
                    .iter()
                    .all(|value| name(value))
        },
        "invalid fixed owner transport operation"
    );
    let mut process = Command::new("ssh");
    process.args([
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
    ]);
    if let Some(identity) = identity {
        process.args(["-i", identity]);
    }
    process.arg(format!("root@{host}")).arg(command);
    let context = crate::runtime::signal_context();
    let output = crate::process::capture(
        &mut process,
        body,
        MAX_DOCUMENT_BYTES,
        Instant::now() + Duration::from_secs(1560),
        || context.check().is_err(),
    )?;
    ensure!(
        output.status.success(),
        "owner transport did not confirm admission; inspect the proposed operation before retrying"
    );
    bounded_value(&output.stdout, MAX_DOCUMENT_BYTES)?;
    Ok(output.stdout)
}
fn request(application: &str, instance: &str, action: &str, release: &str) -> Result<Value> {
    ensure!(name(application) && name(instance), "invalid owner scope");
    let now = controller::now()?;
    Ok(
        json!({"kind":"komizo.request","version":1,"authority":"owner","application":application,"instance":instance,"action":action,"release_digest":release,"nonce":store::identity()?,"issued_at":now,"expires_at":now+120,"timeout_seconds":1500}),
    )
}
pub fn run(args: &[String], output: &mut dyn Write) -> Result<()> {
    let Some((action, flags)) = args.split_first() else {
        return Err(anyhow!("owner command required"));
    };
    if action == "version" {
        ensure!(flags.is_empty(), "version takes no options");
        writeln!(output, "komizo {}", super::VERSION)?;
        return Ok(());
    }
    if action == "capabilities" {
        ensure!(flags.is_empty(), "capabilities takes no options");
        serde_json::to_writer(
            &mut *output,
            &json!({"kind":"komizo.capabilities","version":1,"host":{"os":"debian","version":"13","engine":"podman","rootful":true},"commands":{"status":"read","inspect":"read","logs":"read","ui":"local","request":"typed","start":"effect","stop":"effect","restart":"effect","backup":"effect"}}),
        )?;
        output.write_all(b"\n")?;
        return Ok(());
    }
    ensure!(
        [
            "status", "request", "inspect", "start", "stop", "restart", "backup", "ui", "logs"
        ]
        .contains(&action.as_str()),
        "unsupported native owner command"
    );
    let options = options(flags)?;
    let host = *options
        .get("--host")
        .ok_or_else(|| anyhow!("owner host is required"))?;
    let identity = options.get("--identity").copied();
    if action == "ui" {
        ensure!(
            options
                .keys()
                .all(|key| ["--host", "--identity", "--port"].contains(key))
                && (hostname(host) || host.parse::<std::net::IpAddr>().is_ok()),
            "invalid local UI options"
        );
        let port = options
            .get("--port")
            .copied()
            .unwrap_or("8480")
            .parse::<u16>()?;
        ensure!(port > 0, "UI port must be nonzero");
        let mut args = vec![
            "ui".into(),
            "--host".into(),
            host.into(),
            "--owner-client".into(),
            std::env::current_exe()?
                .to_str()
                .ok_or_else(|| anyhow!("owner client path is not UTF8"))?
                .into(),
            "--port".into(),
            port.to_string(),
        ];
        if let Some(identity) = identity {
            args.extend(["--identity".into(), identity.into()]);
        }
        return crate::nativeapi::run(&crate::runtime::signal_context(), &args);
    }
    ensure!(
        !options.contains_key("--port"),
        "port only applies to the local UI"
    );
    let mut mutation = !["status", "inspect", "logs"].contains(&action.as_str());
    let result = if action == "status" {
        ensure!(
            !options.contains_key("--file")
                && !options.contains_key("--application")
                && !options.contains_key("--instance")
                && !options.contains_key("--service")
                && !options.contains_key("--operation")
                && !options.contains_key("--release"),
            "status does not take application options"
        );
        exchange(host, identity, "komizo-box status", None)?
    } else if action == "request" {
        ensure!(
            options
                .keys()
                .all(|key| ["--host", "--identity", "--file"].contains(key)),
            "request scope belongs inside the authenticated body"
        );
        let path = *options
            .get("--file")
            .ok_or_else(|| anyhow!("request file required"))?;
        let bytes = std::fs::read(path)?;
        let value = bounded_value(&bytes, MAX_DOCUMENT_BYTES)?;
        let request: Request = serde_json::from_value(value.clone())?;
        mutation = request.action != "inspect";
        ensure!(
            request.action != "export",
            "use the verified encrypted-backup export client for binary exports"
        );
        let proposed = store::operation_identity(&request)?;
        let body = canonical(&value)?;
        exchange(host, identity, "komizo-box submit", Some(&body)).map_err(|_| {
            anyhow!(
                "admission is unconfirmed; inspect proposed operation {proposed} before retrying"
            )
        })?
    } else if action == "logs" {
        ensure!(
            options.keys().all(|key| [
                "--host",
                "--identity",
                "--application",
                "--instance",
                "--service"
            ]
            .contains(key)),
            "invalid log options"
        );
        let application = *options
            .get("--application")
            .ok_or_else(|| anyhow!("log application required"))?;
        let instance = options.get("--instance").copied().unwrap_or("production");
        let service = *options
            .get("--service")
            .ok_or_else(|| anyhow!("log service required"))?;
        ensure!(
            [application, instance, service].iter().all(|n| name(n)),
            "invalid log scope"
        );
        exchange(
            host,
            identity,
            &format!(
                "komizo-box logs --application {application} --instance {instance} --service {service}"
            ),
            None,
        )?
    } else {
        ensure!(
            !options.contains_key("--file") && !options.contains_key("--service"),
            "owner action does not take a file"
        );
        let application = *options
            .get("--application")
            .ok_or_else(|| anyhow!("application is required"))?;
        let instance = options.get("--instance").copied().unwrap_or("production");
        let mut inspect = request(application, instance, "inspect", "current")?;
        if let Some(id) = options.get("--operation") {
            ensure!(
                action == "inspect" && hex(id, 32),
                "operation selector requires inspection"
            );
            let release = *options
                .get("--release")
                .ok_or_else(|| anyhow!("operation inspection needs its exact release digest"))?;
            ensure!(digest(release), "invalid inspected release digest");
            inspect["operation"] = json!(id);
            inspect["release_digest"] = json!(release);
        } else {
            ensure!(
                !options.contains_key("--release"),
                "release selector requires an operation identity"
            );
        }
        let observed = exchange(
            host,
            identity,
            "komizo-box submit",
            Some(&canonical(&inspect)?),
        )?;
        if action == "inspect" {
            observed
        } else {
            let value = bounded_value(&observed, MAX_DOCUMENT_BYTES)?;
            let target = if action == "start" && value.get("prepared").is_some() {
                "prepared"
            } else {
                "installed"
            };
            let release = value[target]["release_digest"]
                .as_str()
                .ok_or_else(|| anyhow!("instance is not installed"))?;
            let request = request(application, instance, action, release)?;
            let proposed = store::operation_identity(&serde_json::from_value(request.clone())?)?;
            exchange(host,identity,"komizo-box submit",Some(&canonical(&request)?)).map_err(|_|anyhow!("admission is unconfirmed; inspect proposed operation {proposed} before retrying"))?
        }
    };
    output.write_all(&result)?;
    let value = bounded_value(&result, MAX_DOCUMENT_BYTES)?;
    ensure!(
        value["kind"] != "komizo.error",
        "host did not confirm an accepted result; inspect the proposed operation before retrying"
    );
    ensure!(
        !mutation || value["kind"] != "komizo.operation" || value["ok"] == true,
        "operation did not reach an accepted state; inspect its recorded operation identity"
    );
    Ok(())
}

fn bounded_text(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take((64 << 10) + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 64 << 10 {
        return None;
    }
    String::from_utf8(bytes).ok()
}
fn cgroup_resources(root: &std::path::Path) -> Value {
    let number =
        |file: &str| bounded_text(&root.join(file)).and_then(|s| s.trim().parse::<u64>().ok());
    let cpu = bounded_text(&root.join("cpu.stat"));
    let stat = |name: &str| {
        cpu.as_ref().and_then(|s| {
            s.lines().find_map(|line| {
                let (key, value) = line.split_once(' ')?;
                (key == name).then(|| value.parse::<u64>().ok()).flatten()
            })
        })
    };
    json!({"memory_current_bytes":number("memory.current"),"memory_max_bytes":number("memory.max"),"memory_swap_current_bytes":number("memory.swap.current"),"memory_swap_max_bytes":number("memory.swap.max"),"cpu_usage_usec":stat("usage_usec"),"cpu_throttled_usec":stat("throttled_usec"),"pids_current":number("pids.current"),"pids_max":number("pids.max"),"cpu_quota":bounded_text(&root.join("cpu.max")).map(|s|s.trim().to_owned()),"memory_pressure":bounded_text(&root.join("memory.pressure")),"io_pressure":bounded_text(&root.join("io.pressure"))})
}
fn physical_resources() -> Value {
    let meminfo = bounded_text(std::path::Path::new("/proc/meminfo"));
    let number = |name: &str| {
        meminfo.as_ref().and_then(|s| {
            s.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key != name {
                    return None;
                }
                value
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()?
                    .checked_mul(1024)
            })
        })
    };
    json!({"memory_total_bytes":number("MemTotal"),"memory_available_bytes":number("MemAvailable"),"swap_total_bytes":number("SwapTotal"),"swap_free_bytes":number("SwapFree")})
}
fn storage_resources() -> Result<Value> {
    let path = std::ffi::CString::new("/var/lib/containers/storage")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "native storage observation unavailable"
    );
    let stat = unsafe { stat.assume_init() };
    Ok(
        json!({"total_bytes":u128::from(stat.f_blocks)*u128::from(stat.f_frsize),"free_bytes":u128::from(stat.f_bavail)*u128::from(stat.f_frsize),"total_inodes":stat.f_files,"free_inodes":stat.f_favail}),
    )
}

pub fn status() -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "host inventory requires the owner identity"
    );
    let store = store::Store::new(std::path::Path::new(super::observation::STATE).into())?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let engine = super::engine::Engine { deadline };
    let system = super::system::System { deadline };
    let mut instances = Vec::new();
    for observed in super::proxy::instances(&store)? {
        ensure!(
            Instant::now() < deadline,
            "host observation deadline expired"
        );
        let (installed, prepared) = store.view(&observed.application, &observed.instance)?;
        let installed = installed.ok_or_else(|| anyhow!("instance changed during observation"))?;
        let document = store.release(&installed.release_digest)?;
        let group = system
            .group(&super::units::slice(
                &installed.application,
                &installed.instance,
            )?)
            .ok();
        let resources = group.as_ref().map(|path| cgroup_resources(path));
        let mut services = BTreeMap::new();
        for (name, record) in &installed.resources.containers {
            let path = std::path::Path::new(super::system::QUADLETS).join(format!(
                "{}-{name}.container",
                super::units::namespace(&installed.application, &installed.instance)?
            ));
            super::system::verify_unit(
                &store,
                &path,
                &installed.application,
                &installed.instance,
                &record.unit_sha256,
            )?;
            let value = engine.owned_container(
                record,
                &installed.application,
                &installed.instance,
                name,
            )?;
            let mut service_resources = None;
            if let Some(value) = &value
                && let Some(pid) = value["State"]["Pid"]
                    .as_u64()
                    .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
                && let Some(cgroup) = bounded_text(std::path::Path::new(&format!(
                    "/proc/{pid}/cgroup"
                )))
                .and_then(|body| {
                    body.lines()
                        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
                })
            {
                ensure!(absolute(&cgroup), "service cgroup observation is invalid");
                let path =
                    std::path::Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
                ensure!(
                    group.as_ref().is_some_and(|group| path.starts_with(group)),
                    "service process escaped its owned instance allocation"
                );
                service_resources = Some(cgroup_resources(&path));
            }
            services.insert(name,json!({"container_id":value.as_ref().map(|v|&v["Id"]),"state":value.as_ref().map(|v|&v["State"]["Status"]),"health":value.as_ref().and_then(|v|v["State"]["Health"]["Status"].as_str()),"resources":service_resources}));
        }
        for record in installed.resources.networks.values() {
            engine.owned_object("network", record)?;
        }
        for record in installed.resources.volumes.values() {
            engine.owned_object("volume", record)?;
        }
        let mut operations = Vec::new();
        for id in store
            .history(&installed.application, &installed.instance)?
            .into_iter()
            .rev()
        {
            let operation = store.operation(&id)?;
            ensure!(
                operation.application == installed.application
                    && operation.instance == installed.instance,
                "operation history escaped its instance"
            );
            let mut value = serde_json::to_value(operation)?;
            let journal = store.root.join("journal").join(&id);
            let admission = journal.join("admission.json");
            if admission.try_exists()? {
                let record = bounded_value(&store::read_protected(&admission, 16384)?, 16384)?;
                value["action"] = record["action"].clone();
                value["admitted_at"] = record["evidence"]["admitted_at"].clone();
            }
            let failure = journal.join("failure.json");
            if failure.try_exists()? {
                value["failure"] = bounded_value(&store::read_protected(&failure, 16384)?, 16384)?;
            }
            operations.push(value);
        }
        let unresolved = store.unresolved(&installed.application, &installed.instance)?;
        let prepared=prepared.map(|record|->Result<Value>{let source=store.release(&record.release_digest)?.release.source;Ok(json!({"release_digest":record.release_digest,"operation_id":record.operation_id,"source":source}))}).transpose()?;
        let start = prepared
            .as_ref()
            .map_or(installed.release_digest.as_str(), |p| {
                p["release_digest"].as_str().unwrap()
            });
        let actions = json!({"start":{"release_digest":start},"stop":{"release_digest":installed.release_digest},"restart":{"release_digest":installed.release_digest},"backup":{"release_digest":installed.release_digest}});
        let generations = installed
            .secret_snapshots
            .iter()
            .map(|(alias, snapshot)| (alias, &snapshot.generation))
            .collect::<BTreeMap<_, _>>();
        let (policy, _) = controller::policy(
            std::path::Path::new(super::observation::POLICIES),
            &installed.application,
        )?;
        let available = super::secrets::grants(&policy, &installed.instance)?
            .iter()
            .map(|(alias, grant)| (alias, &grant.generation))
            .collect::<BTreeMap<_, _>>();
        instances.push(json!({"application":installed.application,"instance":installed.instance,"release_digest":installed.release_digest,"source":document.release.source,"routes":document.release.workload.routes.iter().map(|r|json!({"host":r.host,"path":r.path})).collect::<Vec<_>>(),"desired_running":installed.desired_running,"expires_at":installed.expires_at,"operation_id":installed.operation_id,"prepared":prepared,"actions":actions,"services":services,"log_targets":document.release.workload.services.keys().chain(document.release.workload.jobs.keys()).collect::<Vec<_>>(),"resources":resources,"volumes":installed.resources.volumes,"secret_generations":generations,"available_secret_generations":available,"unresolved_operations":unresolved,"operations":operations}));
    }
    Ok(
        json!({"kind":"komizo.status","version":1,"observed_at":controller::now()?,"host":{"boot_id":bounded_text(std::path::Path::new("/proc/sys/kernel/random/boot_id")).map(|s|s.trim().to_owned()),"resources":physical_resources(),"storage":storage_resources()?,"controller_resources":system.group("komizo-control.slice").ok().map(|p|cgroup_resources(&p)),"proxy_resources":system.group("komizo-proxy.slice").ok().map(|p|cgroup_resources(&p))},"instances":instances}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn invalid_owner_commands_refuse_before_any_transport_or_effect() {
        for values in [
            vec![
                "start",
                "--host",
                "-oProxyCommand=sh",
                "--application",
                "mailroom",
            ],
            vec![
                "start",
                "--host",
                "example.invalid",
                "--application",
                "../../host",
            ],
            vec![
                "start",
                "--host",
                "example.invalid",
                "--application",
                "mailroom",
                "--port",
                "22",
            ],
            vec![
                "inspect",
                "--host",
                "example.invalid",
                "--application",
                "mailroom",
                "--operation",
                "bad",
            ],
            vec!["capabilities", "--host", "example.invalid"],
            vec!["exec", "--host", "example.invalid"],
        ] {
            assert!(run(&args(&values), &mut Vec::new()).is_err());
        }
        assert!(exchange("example.invalid", None, "komizo-box status; id", None).is_err());
    }
    #[test]
    fn capabilities_are_finite_and_do_not_imply_remote_acceptance() {
        let mut output = Vec::new();
        run(&args(&["capabilities"]), &mut output).unwrap();
        let value = bounded_value(&output, 16384).unwrap();
        assert_eq!(value["kind"], "komizo.capabilities");
        assert_eq!(value["commands"]["ui"], "local");
        assert!(value.get("ready").is_none());
    }
}
