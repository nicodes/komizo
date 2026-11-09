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

pub const USAGE: &str = "komizo -- native owner client\n\n  komizo status --host HOST [--identity PATH]\n  komizo inspect|start|stop|restart|backup --host HOST --application APP [--instance production]\n  komizo request --host HOST --file REQUEST.json\n  komizo version\n\nSSH uses the owner's root identity and strict known-host verification.\n";

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
                "--file"
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
        ["komizo-box submit", "komizo-box status"].contains(&command),
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
    let output = crate::process::capture(
        &mut process,
        body,
        MAX_DOCUMENT_BYTES,
        Instant::now() + Duration::from_secs(1560),
        || false,
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
    ensure!(
        [
            "status", "request", "inspect", "start", "stop", "restart", "backup"
        ]
        .contains(&action.as_str()),
        "unsupported native owner command"
    );
    let options = options(flags)?;
    let host = *options
        .get("--host")
        .ok_or_else(|| anyhow!("owner host is required"))?;
    let identity = options.get("--identity").copied();
    let result = if action == "status" {
        ensure!(
            !options.contains_key("--file")
                && !options.contains_key("--application")
                && !options.contains_key("--instance"),
            "status does not take application options"
        );
        exchange(host, identity, "komizo-box status", None)?
    } else if action == "request" {
        ensure!(
            !options.contains_key("--application") && !options.contains_key("--instance"),
            "request scope belongs inside the authenticated body"
        );
        let path = *options
            .get("--file")
            .ok_or_else(|| anyhow!("request file required"))?;
        let bytes = std::fs::read(path)?;
        let value = bounded_value(&bytes, MAX_DOCUMENT_BYTES)?;
        let request: Request = serde_json::from_value(value.clone())?;
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
    } else {
        ensure!(
            !options.contains_key("--file"),
            "owner action does not take a file"
        );
        let application = *options
            .get("--application")
            .ok_or_else(|| anyhow!("application is required"))?;
        let instance = options.get("--instance").copied().unwrap_or("production");
        let inspect = request(application, instance, "inspect", "current")?;
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
            let release = value["installed"]["release_digest"]
                .as_str()
                .ok_or_else(|| anyhow!("instance is not installed"))?;
            let request = request(application, instance, action, release)?;
            let proposed = store::operation_identity(&serde_json::from_value(request.clone())?)?;
            exchange(host,identity,"komizo-box submit",Some(&canonical(&request)?)).map_err(|_|anyhow!("admission is unconfirmed; inspect proposed operation {proposed} before retrying"))?
        }
    };
    output.write_all(&result)?;
    Ok(())
}

pub fn status() -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "host inventory requires the owner identity"
    );
    let store = store::Store::new(std::path::Path::new(super::observation::STATE).into())?;
    let engine = super::engine::Engine {
        deadline: Instant::now() + Duration::from_secs(20),
    };
    let mut instances = Vec::new();
    for installed in super::proxy::instances(&store)? {
        let mut services = BTreeMap::new();
        for (name, record) in &installed.resources.containers {
            let value = engine.owned_container(
                record,
                &installed.application,
                &installed.instance,
                name,
            )?;
            services.insert(name,json!({"container_id":value.as_ref().map(|v|&v["Id"]),"state":value.as_ref().map(|v|&v["State"]["Status"]),"health":value.as_ref().and_then(|v|v["State"]["Health"]["Status"].as_str())}));
        }
        let unresolved = store.unresolved(&installed.application, &installed.instance)?;
        instances.push(json!({"application":installed.application,"instance":installed.instance,"release_digest":installed.release_digest,"desired_running":installed.desired_running,"expires_at":installed.expires_at,"operation_id":installed.operation_id,"services":services,"unresolved_operations":unresolved}));
    }
    Ok(json!({"kind":"komizo.status","version":1,"instances":instances}))
}
