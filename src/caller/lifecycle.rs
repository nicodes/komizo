use super::{
    client::{Cli, common},
    protocol,
    transport::ScrubWriter,
    validate,
};
use crate::{flags::Flag, host::authority::quote};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    cell::RefCell,
    io::{self, Write},
    rc::Rc,
};
struct Shared<'a, W: Write + ?Sized>(Rc<RefCell<&'a mut W>>);
impl<W: Write + ?Sized> Write for Shared<'_, W> {
    fn write(&mut self, body: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(body)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}
pub fn valid_service(value: &str) -> Result<()> {
    ensure!(
        !value.starts_with('-'),
        "--service {} is a flag, not a service name",
        quote(value)
    );
    ensure!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        "--service must be letters, digits, underscore, hyphen or dot; got {}",
        quote(value)
    );
    Ok(())
}
pub fn script(verb: &str, args: &[String]) -> String {
    format!(
        "/usr/local/bin/komizo-box app {}{}",
        crate::scripts::sh_quote(verb),
        args.iter()
            .map(|arg| format!(" {}", crate::scripts::sh_quote(arg)))
            .collect::<String>()
    )
}
pub fn run(cli: &mut Cli<'_>, verb: &str, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("app", ""),
        Flag::boolean("proxy", false),
        Flag::text("service", ""),
    ]);
    if verb == "logs" {
        spec.push(Flag::integer("tail", 40));
    }
    let flags = cli.parse(&spec, args, "every input must be a flag")?;
    let app = flags.text("app");
    let proxy = flags.boolean("proxy");
    let service = flags.text("service");
    (|| -> Result<()> {
        ensure!(
            proxy == app.is_empty(),
            "give exactly one of --app and --proxy"
        );
        if !proxy {
            validate::app(app)?;
        }
        valid_service(service)?;
        if verb == "logs" {
            ensure!(
                (1..=2000).contains(&flags.integer("tail")),
                "--tail must be between 1 and 2000"
            );
        }
        Ok(())
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let mut subject = if proxy {
        "the proxy".into()
    } else {
        app.to_string()
    };
    if !service.is_empty() {
        subject.push_str(&format!(" ({service})"));
    }
    let mut request = if proxy {
        vec!["--proxy".into()]
    } else {
        vec!["--app".into(), app.into()]
    };
    if !service.is_empty() {
        request.extend(["--service".into(), service.into()]);
    }
    if verb == "logs" {
        request.extend(["--tail".into(), flags.integer("tail").to_string()]);
    }
    if verb != "logs" {
        let message = format!("\n==> Running {verb} on {subject}\n");
        if cli.machine {
            cli.progress.write_all(message.as_bytes())?;
        } else {
            cli.text(message.as_bytes())?;
        }
    }
    let command = script(verb, &request);
    let ctx = cli.context.clone();
    let environment = Default::default();
    let heard = if cli.machine && verb != "logs" {
        let shared = Rc::new(RefCell::new(&mut *cli.progress));
        remote.script(
            &ctx,
            &command,
            &environment,
            &mut Shared(shared.clone()),
            &mut Shared(shared),
        )
    } else if verb == "logs" {
        let output: &mut dyn Write = if cli.machine {
            &mut cli.result.text
        } else {
            &mut *cli.output
        };
        let mut scrub = ScrubWriter::new(output);
        let heard = remote.script(&ctx, &command, &environment, &mut scrub, cli.progress);
        scrub.finish()?;
        heard
    } else {
        remote.script(&ctx, &command, &environment, cli.output, cli.progress)
    };
    if let Err(error) = heard.result {
        return Err(anyhow::anyhow!(
            "could not {verb} {subject} -- see the output above.\n\n    If the box says it does not know that mode, its agent predates this\n    command: run `komizo update --host {}`. {error}",
            remote.target.host
        ));
    }
    if cli.machine && verb != "logs" {
        return cli.receipt(verb, &remote, app, json!({"proxy":proxy,"service":service}));
    }
    let spoken = if verb == "logs" {
        heard.stdout
    } else {
        heard.stdout || heard.stderr
    };
    if !spoken {
        if verb == "logs" {
            writeln!(
                cli.progress,
                "\n==> {subject} has logged nothing\n    This command ran, and `docker compose logs` came back empty.\n    Either nothing has ever run under {subject}, or its containers have\n    written no output yet.\n    `komizo list --host {}` will say which of the two it is.",
                remote.target.addr()
            )?;
        } else {
            cli.text(format!("    Nothing happened -- compose names every container it acts on, and it\n    named none, so {verb} found nothing under {subject} to act on.\n").as_bytes())?;
        }
    }
    Ok(())
}
