//! Fixed native host commands; transport identity never grants application effects.
use super::{
    authority, bootstrap, commands,
    controller::{self, Coordinator},
    native, observation,
    store::Store,
    transport,
    validation::name,
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
    sync::Arc,
};

pub const USAGE: &str = "komizo-box -- native Komizo host\n\n  komizo-box install --authorized-keys /absolute/owner/public-keys\n  komizo-box daemon\n  komizo-box submit\n  komizo-box status\n  komizo-box proxy-guard\n  komizo-box guard|health|resource --application APP --instance INST --service SVC\n  komizo-box expire\n  komizo-box release validate|render FILE [render flags]\n  komizo-box application validate FILE\n  komizo-box policy validate POLICY RELEASE [--instance INST]\n  komizo-box version\n";

fn scope(args: &[String]) -> Result<(&str, &str, &str)> {
    ensure!(
        args.len() == 6,
        "service observation requires its exact application, instance and service"
    );
    let mut fields = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        ensure!(
            ["--application", "--instance", "--service"].contains(&pair[0].as_str())
                && name(&pair[1])
                && fields.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "invalid or duplicate native service scope"
        );
    }
    Ok((
        *fields
            .get("--application")
            .ok_or_else(|| anyhow!("missing application"))?,
        *fields
            .get("--instance")
            .ok_or_else(|| anyhow!("missing instance"))?,
        *fields
            .get("--service")
            .ok_or_else(|| anyhow!("missing service"))?,
    ))
}

fn ready() -> Result<()> {
    let Some(address) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::{
            linux::net::SocketAddrExt,
            unix::{
                ffi::OsStrExt,
                net::{SocketAddr, UnixDatagram},
            },
        };
        let bytes = address.as_bytes();
        ensure!(
            !bytes.is_empty() && bytes.len() < 108 && !bytes.contains(&0),
            "invalid service notification address"
        );
        let address = if bytes[0] == b'@' {
            SocketAddr::from_abstract_name(&bytes[1..])?
        } else {
            ensure!(
                bytes[0] == b'/',
                "notification address must be an absolute system socket"
            );
            SocketAddr::from_pathname(address)?
        };
        let socket = UnixDatagram::unbound()?;
        socket.connect_addr(&address)?;
        let message = b"READY=1\nSTATUS=Protected native admission ready";
        ensure!(
            socket.send(message)? == message.len(),
            "service notification was incomplete"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = address;
        Err(anyhow!("native host service notification requires Linux"))
    }
}

pub fn daemon() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native daemon requires the protected root identity"
    );
    let store = Store::new(Path::new(observation::STATE).into())?;
    let _lease = store.lock("platform", "daemon")?;
    let worker = native::Native::new()?;
    worker.startup(&store)?;
    let gid = transport::submission_gid(Path::new("/etc/komizo/controller.json"))?;
    let coordinator = Coordinator::new(
        store.root,
        Path::new(observation::POLICIES).into(),
        Arc::new(worker),
    )?;
    transport::serve_with_ready(
        Path::new(transport::SOCKET),
        gid,
        move |body, uid| {
            let mut keys = authority::github_key;
            coordinator.admit(body, uid, controller::now()?, &mut keys)
        },
        ready,
    )
}

pub fn run(args: &[String], input: &mut dyn Read, output: &mut dyn Write) -> Result<()> {
    let Some((mode, flags)) = args.split_first() else {
        return Err(anyhow!("native host command is required"));
    };
    match mode.as_str() {
        "release" | "application" | "policy" => commands::offline(args, output),
        "dns" => bootstrap::dns(flags, output),
        "task-run" | "task-watch" => {
            ensure!(
                flags.len() == 4 && flags[0] == "--operation" && flags[2] == "--task",
                "protected task execution requires its exact operation and task kind"
            );
            if mode == "task-watch" {
                native::task_watch(&flags[1], &flags[3])
            } else {
                native::task_run(&flags[1], &flags[3])
            }
        }
        "infrastructure-supervise" | "infrastructure-run" | "infrastructure-stop" => {
            ensure!(
                flags.len() == 1
                    && ["controller", "proxy", "dns", "expiry"].contains(&flags[0].as_str()),
                "infrastructure requires its fixed protected role"
            );
            match mode.as_str() {
                "infrastructure-supervise" => bootstrap::infrastructure_supervise(&flags[0]),
                "infrastructure-stop" => bootstrap::infrastructure_stop(&flags[0]),
                _ => bootstrap::infrastructure_run(&flags[0]),
            }
        }
        "dns-guard" => {
            ensure!(flags.is_empty(), "DNS guard does not accept arguments");
            bootstrap::dns_guard()
        }
        "install" => {
            ensure!(
                flags.len() == 2 && flags[0] == "--authorized-keys",
                "install requires its explicit owner public key file"
            );
            bootstrap::install(Path::new(&flags[1]))
        }
        "fence" | "guard" | "health" | "resource" | "logs" => {
            let (application, instance, service) = scope(flags)?;
            match mode.as_str() {
                "fence" => observation::fence(application, instance, service),
                "guard" => observation::guard(application, instance, service),
                "health" => observation::health(application, instance, service),
                "logs" => {
                    serde_json::to_writer(
                        &mut *output,
                        &observation::logs(application, instance, service)?,
                    )?;
                    output.write_all(b"\n")?;
                    Ok(())
                }
                _ => {
                    serde_json::to_writer(
                        &mut *output,
                        &observation::resource(application, instance, service)?,
                    )?;
                    output.write_all(b"\n")?;
                    Ok(())
                }
            }
        }
        "daemon" | "submit" | "expire" | "version" | "status" | "proxy-guard" => {
            ensure!(
                flags.is_empty(),
                "native host command does not accept arguments"
            );
            match mode.as_str() {
                "daemon" => daemon(),
                "submit" => transport::submit(input, output),
                "expire" => native::expire(),
                "proxy-guard" => bootstrap::proxy_guard(),
                "status" => {
                    serde_json::to_writer(&mut *output, &super::operator::status()?)?;
                    output.write_all(b"\n")?;
                    Ok(())
                }
                _ => {
                    writeln!(output, "{}", super::VERSION)?;
                    Ok(())
                }
            }
        }
        _ => Err(anyhow!("unsupported native host command")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn observation_scope_is_explicit_closed_and_not_a_command() {
        assert_eq!(
            scope(&args(&[
                "--service",
                "api",
                "--instance",
                "production",
                "--application",
                "mailroom"
            ]))
            .unwrap(),
            ("mailroom", "production", "api")
        );
        for value in [
            vec!["--application", "mailroom"],
            vec![
                "--application",
                "mailroom",
                "--instance",
                "production",
                "--exec",
                "id",
            ],
            vec![
                "--application",
                "mailroom",
                "--instance",
                "production",
                "--service",
                "../../host",
            ],
            vec![
                "--application",
                "mailroom",
                "--application",
                "other",
                "--service",
                "api",
            ],
        ] {
            assert!(scope(&args(&value)).is_err());
        }
    }
    #[test]
    fn legacy_and_raw_runtime_commands_have_no_native_frontdoor() {
        for value in [
            vec!["rootd"],
            vec!["workload", "exec"],
            vec!["app", "start"],
            vec!["podman", "ps"],
            vec!["submit", "id"],
            vec!["daemon", "--socket", "/tmp/other"],
            vec!["task-run", "--program", "/bin/sh"],
            vec!["task-run", "--operation", "../../host", "--task", "backup"],
            vec![
                "task-run",
                "--operation",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--task",
                "exec",
            ],
        ] {
            assert!(run(&args(&value), &mut &b""[..], &mut Vec::new()).is_err());
        }
    }
}
