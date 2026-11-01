use super::{
    client::{Cli, common},
    protocol, validate,
};
use crate::{
    flags::Flag,
    host::{Monitor, Report},
};
use anyhow::{Result, ensure};
use serde_json::json;
use std::time::Duration;
pub const USAGE: &str = "komizo -- operate an Alpine host over authenticated SSH\n\n  capabilities, version, doctor, status, report, list\n  setup, add, update, proxy, remove, start, stop, restart, logs\n  deploy, operation inspect|recover, preview, platform, workload\n  set-secret, unset-secret, reconcile, artifact, script, ui\n\nUse --help after a command for its flags. Prefix --json for the versioned machine protocol.\n";
pub fn run(cli: &mut Cli<'_>, name: &str, args: &[String]) -> Option<Result<()>> {
    Some(match name {
        "help" | "--help" | "-h" => cli.text(USAGE.as_bytes()),
        "version" | "--version" | "-v" => version(cli, args),
        "capabilities" => capabilities(cli, args),
        "doctor" => doctor(cli, args),
        "status" => status(cli, args),
        "report" => report(cli, args),
        "list" => list(cli, args),
        "ui" => ui(cli, args),
        _ => return None,
    })
}
fn version(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    ensure!(
        args.is_empty() || (args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h")),
        "version accepts no arguments"
    );
    if cli.machine {
        cli.emit(json!({"version":crate::runtime::VERSION}))
    } else {
        cli.text(format!("komizo {}\n", crate::runtime::VERSION).as_bytes())
    }
}
fn capabilities(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    ensure!(
        args.is_empty() || (args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h")),
        "capabilities accepts no arguments"
    );
    cli.emit(protocol::capabilities())
}
fn doctor(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let flags = cli.parse(&common(), args, "doctor accepts only flags")?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let raw = remote
        .quiet(&cli.context, super::doctor::SCRIPT)
        .map_err(|e| anyhow::anyhow!("cannot inspect server prerequisites: {e}"))?;
    let result = super::doctor::decode(&remote.target.addr(), &raw)?;
    let supported = result.supported;
    cli.emit(result)?;
    ensure!(
        supported,
        "server prerequisites failed; inspect doctor checks before setup"
    );
    Ok(())
}
fn status(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([Flag::text("directory", "."), Flag::text("app", "")]);
    let mut flags = cli.parse(&spec, args, "status accepts only flags")?;
    let directory = flags.text("directory").to_string();
    let remote = cli.bound_target(&mut flags, &directory)?;
    if !flags.text("app").is_empty() {
        validate::app(flags.text("app")).map_err(protocol::local)?;
    }
    cli.reachable(&remote, false)?;
    let report: Report = remote.fetch(&cli.context, &["report".into()])?;
    let app = flags.text("app");
    if app.is_empty() {
        return cli.emit(report);
    }
    let application =
        report.apps.iter().find(|a| a.name == app).ok_or_else(|| {
            anyhow::anyhow!("bound application is not registered on the target host")
        })?;
    cli.emit(json!({"version":1,"host":remote.target.addr(),"server":report.server,"application":application}))
}
fn report(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::boolean("json", false),
        Flag::boolean("cached", false),
        Flag::boolean("volumes", false),
        Flag::boolean("usage", false),
        Flag::boolean("known-hosts", false),
    ]);
    let flags = cli.parse(&spec, args, "report accepts only flags")?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let mut request = vec!["report".into()];
    if flags.boolean("cached") {
        request.push("--cached".into());
    }
    if flags.boolean("volumes") {
        request.push("--volumes".into());
    }
    let report: Report = remote.fetch(&cli.context, &request)?;
    if cli.machine || flags.boolean("json") {
        return cli.emit(report);
    }
    cli.text(
        format!(
            "{}: {}\n",
            remote.target.host,
            validate::scrub(&report.server.state)
        )
        .as_bytes(),
    )?;
    cli.text(&serde_json::to_vec_pretty(&report)?)?;
    cli.text(b"\n")?;
    if flags.boolean("known-hosts") {
        let keys: Vec<_> = report
            .server
            .host_keys
            .iter()
            .map(|k| (k.r#type.clone(), k.key.clone()))
            .collect();
        for app in report.apps.iter() {
            let mut target = remote.target.clone();
            target.aliases = app.known_as.to_vec();
            cli.text(
                format!(
                    "\n{} KOMIZO_KNOWN_HOSTS:\n{}\n",
                    validate::scrub(&app.name),
                    target.known_hosts(&keys)
                )
                .as_bytes(),
            )?;
        }
    }
    if flags.boolean("usage") {
        let now = chrono::Utc::now().timestamp();
        let args = [
            "monitor".into(),
            "--from".into(),
            (now - 4 * 3600).to_string(),
            "--to".into(),
            now.to_string(),
        ];
        match remote.fetch::<Monitor>(&cli.context, &args) {
            Ok(monitor) => {
                cli.text(b"\nUsage:\n")?;
                cli.text(&serde_json::to_vec_pretty(&monitor)?)?;
                cli.text(b"\n")?;
            }
            Err(error) => {
                cli.note(&format!("usage unavailable: {error}"))?;
            }
        }
    }
    Ok(())
}
fn list(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([Flag::boolean("json", false)]);
    let flags = cli.parse(&spec, args, "list accepts only flags")?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let report: Report = remote.fetch(&cli.context, &["report".into()])?;
    if cli.machine || flags.boolean("json") {
        return cli.emit(report.apps);
    }
    cli.text(b"APP\tSTATE\tVERSION\tDIRECTORY\n")?;
    for app in report.apps.iter() {
        cli.text(
            format!(
                "{}\t{}\t{}\t{}\n",
                validate::scrub(&app.name),
                validate::scrub(&app.runtime_state),
                validate::scrub(&app.version),
                validate::scrub(&app.dir)
            )
            .as_bytes(),
        )?;
    }
    if report.apps.is_empty() {
        cli.note("no applications are registered on this host")?;
    }
    Ok(())
}
fn ui(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = vec![Flag::text("bind", "127.0.0.1"), Flag::integer("port", 8480)];
    for name in [
        "hosts", "report", "history", "metrics", "results", "logs", "inbox", "apps",
    ] {
        spec.push(Flag::text(name, ""));
    }
    cli.parse(&spec, args, "ui accepts only flags")?;
    let mut argv = vec!["ui".into()];
    argv.extend_from_slice(args);
    crate::nativeapi::run(
        &crate::runtime::bounded(&cli.context, Duration::from_secs(365 * 24 * 3600)),
        &argv,
    )
}
