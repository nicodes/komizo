//! One native entry point for interactive and typed machine invocations.
use super::{client::Cli, protocol};
use crate::{flags::Help, workload::activation::Context};
use anyhow::Result;
use std::{io::Write, time::Duration};
pub fn dispatch(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let Some((name, tail)) = args.split_first() else {
        return cli.text(super::read::USAGE.as_bytes());
    };
    // Help belongs to the same reviewed command surface as its native implementation.
    // Intercept only the syntactic help positions; a value containing --help is data.
    if protocol::help(args)
        && !matches!(
            name.as_str(),
            "version" | "--version" | "-v" | "capabilities" | "help" | "-h" | "--help"
        )
    {
        let key = args
            .iter()
            .take_while(|s| !s.starts_with('-'))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        let help: serde_json::Value = serde_json::from_str(include_str!("help.json"))?;
        if let Some(text) = help.get(&key).and_then(serde_json::Value::as_str) {
            cli.text(text.as_bytes())?;
            return Err(Help.into());
        }
    }
    if let Some(result) = super::read::run(cli, name, tail) {
        return result;
    }
    match name.as_str() {
        "setup" => super::provision::setup(cli, tail),
        "init" => super::provision::init(cli, tail),
        "add" => super::provision::add(cli, tail, true),
        "update" => super::provision::update(cli, tail),
        "proxy" => super::provision::proxy(cli, tail),
        "remove" => super::provision::remove(cli, tail),
        "script" => super::provision::script(cli, tail),
        "start" | "stop" | "restart" | "logs" => super::lifecycle::run(cli, name, tail),
        "set-secret" => super::secrets::set(cli, tail),
        "unset-secret" => super::secrets::unset(cli, tail),
        "deploy" => super::deployment::deploy(cli, tail),
        "operation" => super::deployment::operation(cli, tail),
        "artifact" => super::artifacts::run(cli, tail),
        "preview" => super::preview::run(cli, tail),
        "reconcile" => super::reconcile::run(cli, tail),
        "platform" => super::platform::run(cli, tail),
        "workload" => super::platform::workload(cli, tail),
        _ => Err(protocol::local(anyhow::anyhow!(
            "unknown command {name:?}; use komizo help"
        ))),
    }
}
pub fn run(args: &[String], base: &Context, out: &mut dyn Write, progress: &mut dyn Write) -> i32 {
    let mut args = args;
    let mut machine = false;
    let mut timeout = Duration::from_secs(1800);
    while let Some(head) = args.first() {
        match head.as_str() {
            "--json" => {
                machine = true;
                args = &args[1..];
            }
            "--timeout" => {
                let parsed = args
                    .get(1)
                    .and_then(|s| crate::flags::duration(s).ok())
                    .filter(|v| (1_000_000_000..=3_600_000_000_000).contains(v));
                let Some(nanos) = parsed else {
                    if machine {
                        let result = protocol::early_failure(
                            "",
                            "invalid_input",
                            "timeout must be between 1s and 1h",
                            false,
                        );
                        let _ = crate::host::commands::emit(out, &result);
                    } else {
                        let _ = writeln!(progress, "error: timeout must be between 1s and 1h");
                    }
                    return 1;
                };
                timeout = Duration::from_nanos(nanos as u64);
                args = &args[2..];
            }
            _ => break,
        }
    }
    let context = crate::runtime::bounded(base, timeout);
    if machine && (args.is_empty() || !protocol::known(protocol::command_name(args))) {
        let result = if args.is_empty() {
            protocol::early_failure(
                "",
                "invalid_input",
                "a command is required; use capabilities",
                false,
            )
        } else {
            protocol::early_failure(
                protocol::command_name(args),
                "unsupported_command",
                "use capabilities to discover machine commands",
                false,
            )
        };
        let _ = crate::host::commands::emit(out, &result);
        return result.exit_code as i32;
    }
    let mut cli = Cli {
        context: context.clone(),
        machine,
        output: out,
        progress,
        result: Default::default(),
        input: None,
    };
    let result = dispatch(&mut cli, args);
    if result.as_ref().is_err_and(|e| e.is::<Help>())
        && (!machine || cli.result.text.body().is_empty())
    {
        let words = args
            .iter()
            .take_while(|s| !s.starts_with('-'))
            .cloned()
            .collect::<Vec<_>>();
        let help: serde_json::Value =
            serde_json::from_str(include_str!("help.json")).expect("reviewed help");
        let text = (1..=words.len())
            .rev()
            .find_map(|n| {
                help.get(words[..n].join(" "))
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or(super::read::USAGE);
        let _ = cli.text(text.as_bytes());
    }
    if machine {
        let envelope = protocol::finish(&context, args, cli.result, result, false);
        let exit = envelope.exit_code as i32;
        if crate::host::commands::emit(out, &envelope).is_err() {
            return 1;
        }
        exit
    } else {
        match result {
            Ok(()) => 0,
            Err(e) if e.is::<Help>() => 0,
            Err(e) => {
                let _ = writeln!(progress, "error: {e}");
                protocol::exit_code(&e) as i32
            }
        }
    }
}
