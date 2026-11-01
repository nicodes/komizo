use super::{
    client::{Cli, common},
    protocol,
};
use crate::{flags::Flag, scripts, workload::activation::Context};
use anyhow::{Result, ensure};
use std::{process::Command, time::Duration};
fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}
pub fn program(kind: &str) -> String {
    match kind {
        "maintenance" => scripts::MAINTENANCE_PREPARE.into(),
        "proxy" => format!(
            "import types\n_shared=types.ModuleType('komizo_platform_prepare')\nexec({},_shared.__dict__)\nrun,digest,protected_directory,HOST=_shared.run,_shared.digest,_shared.protected_directory,_shared.HOST\n_runtime=types.ModuleType('komizo_proxy_runtime')\nexec({},_runtime.__dict__)\nproxy_runtime_environment=_runtime.proxy_runtime_environment\n{}",
            quoted(scripts::PLATFORM_PREPARE),
            quoted(scripts::PLATFORM),
            scripts::PROXY_PREPARE
        ),
        "controls" => format!(
            "import types\n_shared=types.ModuleType('komizo_platform_prepare')\nexec({},_shared.__dict__)\nprepare,run,protected_directory,HOST=_shared.prepare,_shared.run,_shared.protected_directory,_shared.HOST\n_platform=types.ModuleType('komizo_platform')\nexec({},_platform.__dict__)\ncontrol_configuration,CONTROL_SERVICES=_platform.control_configuration,_platform.CONTROL_SERVICES\n{}",
            quoted(scripts::PLATFORM_PREPARE),
            quoted(scripts::PLATFORM),
            scripts::CONTROLS_PREPARE
        ),
        "workload" => format!(
            "_SOURCE={}\n{}",
            quoted(scripts::WORKLOAD_ACCEPTANCE),
            scripts::WORKLOAD_ACCEPTANCE
        ),
        _ => scripts::PLATFORM_PREPARE.into(),
    }
}
fn helper(
    cli: &mut Cli<'_>,
    source: &str,
    args: &[String],
    ctx: &Context,
    help: bool,
) -> Result<()> {
    let mut command = Command::new("/usr/bin/python3");
    command.args(["-I", "-c", source]).args(args);
    let mut output = protocol::Text::default();
    let writer: &mut dyn std::io::Write = if cli.machine { &mut output } else { cli.output };
    let result = crate::process::stream(
        &mut command,
        None,
        8192,
        ctx.deadline,
        || ctx.check().is_err(),
        writer,
        cli.progress,
    )?;
    ensure!(!output.truncated, "helper response exceeds 4 MiB");
    if cli.machine {
        if help && result.status.success() {
            cli.text(output.body())?;
            return Err(crate::flags::Help.into());
        }
        if !crate::wire::trim_space(output.body()).is_empty() {
            let decoded = cli.result.protocol(output.body());
            if result.status.success() {
                decoded?;
            }
        }
    }
    ensure!(result.status.success(), "helper failed: {}", result.status);
    Ok(())
}
pub fn run(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    if args
        .first()
        .is_some_and(|s| matches!(s.as_str(), "inspect" | "recover"))
    {
        return operation(cli, args);
    }
    let (kind, args) = if args
        .first()
        .is_some_and(|s| matches!(s.as_str(), "maintenance" | "proxy" | "controls"))
    {
        (args[0].as_str(), &args[1..])
    } else {
        ("platform", args)
    };
    ensure!(
        kind == "maintenance"
            || args
                .first()
                .is_some_and(|s| matches!(s.as_str(), "plan" | "apply")),
        "platform requires plan or apply"
    );
    let ctx = crate::runtime::bounded(
        &cli.context,
        Duration::from_secs(if kind == "maintenance" { 1200 } else { 900 }),
    );
    let help = args.iter().any(|s| matches!(s.as_str(), "--help" | "-h"));
    helper(cli, &program(kind), args, &ctx, help)
}
pub fn workload(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    ensure!(
        args.first().is_some_and(|s| s == "acceptance"),
        "workload requires acceptance --profile PATH --host root@HOST --output PATH"
    );
    let ctx = crate::runtime::bounded(&cli.context, Duration::from_secs(2100));
    helper(
        cli,
        &program("workload"),
        &args[1..],
        &ctx,
        args.iter().any(|s| matches!(s.as_str(), "--help" | "-h")),
    )
}
fn operation(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([Flag::text("stage", ""), Flag::text("expected-manifest", "")]);
    let flags = cli.parse(
        &spec,
        &args[1..],
        "platform inspection/recovery accepts only flags",
    )?;
    let stage = flags.text("stage");
    let digest = flags.text("expected-manifest");
    (|| -> Result<()> {
        let name = stage
            .strip_prefix("/var/lib/komizo/upgrades/")
            .unwrap_or("");
        ensure!(
            (1..=100).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && crate::workload::policy::content_identity(digest),
            "platform inspection/recovery requires an exact protected stage and manifest digest"
        );
        Ok(())
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    if remote.target.user != "root" {
        return Err(protocol::local(anyhow::anyhow!(
            "platform inspection/recovery requires the root operator"
        )));
    }
    cli.reachable(&remote, false)?;
    let body = remote.journey(
        &cli.context,
        &[
            "platform".into(),
            args[0].clone(),
            stage.into(),
            digest.into(),
        ],
        &[],
    )?;
    let result = crate::strict::value(&body, 4 << 20)?;
    ensure!(
        result["version"] == 1
            && result["manifest"] == digest
            && result["phase"].as_str().is_some_and(|s| [
                "prepared",
                "installing",
                "recovering",
                "complete",
                "recovered"
            ]
            .contains(&s)),
        "platform executor returned an invalid operation identity"
    );
    cli.emit(result)
}
