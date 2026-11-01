pub mod agent;
pub mod app;
pub mod daemon;
pub mod preview;
pub mod read;
use crate::{
    flags::{Flag, Flags},
    workload::activation::Context,
};
use anyhow::{Result, ensure};
use std::{io::Write, path::Path, process::Command};
pub fn emit(output: &mut dyn Write, value: &impl serde::Serialize) -> Result<()> {
    output.write_all(&crate::workload::json::compact(&serde_json::to_value(
        value,
    )?)?)?;
    output.write_all(b"\n")?;
    Ok(())
}
pub fn enter_read_budget() -> Result<()> {
    super::resource_authority::enter_read_budget(
        Path::new("/etc/komizo/resources.json"),
        Path::new("/sys/fs/cgroup"),
        std::process::id() as i32,
        unsafe { libc::geteuid() },
    )
}
pub fn platform(args: &[String], ctx: &Context) -> Result<()> {
    let (program, arguments) = if args.first().is_some_and(|s| s == "maintenance") {
        (
            format!(
                "import types\n_shared = types.ModuleType('komizo_platform')\nexec({}, _shared.__dict__)\nPlatform = _shared.Platform\n{}",
                serde_json::to_string(crate::scripts::PLATFORM)?,
                crate::scripts::MAINTENANCE
            ),
            &args[1..],
        )
    } else {
        ensure!(
            unsafe { libc::geteuid() } == 0
                && args.len() == 3
                && matches!(args[0].as_str(), "apply" | "recover" | "inspect"),
            "platform requires the root operator, apply/recover/inspect, protected stage and exact manifest digest"
        );
        (crate::scripts::PLATFORM.into(), args)
    };
    python(ctx, &program, arguments)
}
pub fn python(ctx: &Context, program: &str, args: &[String]) -> Result<()> {
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-I", "-c", program])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", "/root")
        .env("LC_ALL", "C")
        .current_dir("/");
    let result = crate::process::stream_input(
        &mut command,
        std::process::Stdio::inherit(),
        8192,
        ctx.deadline,
        || ctx.check().is_err(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )?;
    ensure!(
        result.status.success(),
        "operator program failed: {}",
        result.status
    );
    Ok(())
}
pub fn run(args: &[String], ctx: &Context, output: &mut dyn Write) -> Result<()> {
    let Some((mode, args)) = args.split_first() else {
        anyhow::bail!("komizo-box requires a mode")
    };
    match mode.as_str() {
        "version" => {
            writeln!(output, "{}", crate::runtime::VERSION)?;
            Ok(())
        }
        "workload" => super::workload::commands::run(args, ctx, output),
        "platform" => platform(args, ctx),
        "app" => app::run(args, ctx),
        "preview" => preview::run(args, ctx, output),
        "serve" => crate::nativeapi::run(
            ctx,
            &std::iter::once(String::from("serve"))
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        ),
        "rootd" => daemon::run(args, ctx),
        "agent" => agent::run(args, ctx),
        "enrol" => agent::enrol(args, ctx, output),
        "unenrol" => agent::unenrol(args, output),
        "report" | "poll" | "monitor" => read::run(mode, args, ctx, output),
        "preview-capabilities" => {
            ensure!(args.is_empty(), "preview-capabilities takes no arguments");
            emit(
                output,
                &serde_json::json!({"private_runtimes":true,"version":crate::runtime::VERSION}),
            )
        }
        _ => anyhow::bail!("unknown host mode {}", super::authority::quote(mode)),
    }
}
pub fn parse(spec: &[Flag], args: &[String], no_positionals: bool) -> Result<Flags> {
    let flags = Flags::parse(spec, args)?;
    if no_positionals && let Some(argument) = flags.args.first() {
        anyhow::bail!(
            "unexpected argument {} -- every input is a flag",
            super::authority::quote(argument)
        );
    }
    Ok(flags)
}
