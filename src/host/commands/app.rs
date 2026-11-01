use super::parse;
use crate::{
    flags::Flag,
    host::{
        application::{self, Runtime, Subject},
        authority::{Command as SignedCommand, quote},
        inbox::Executor,
        workload::{activation::Host, effects::Native},
    },
    workload::activation::Context,
};
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, path::Path, process::Command, time::Duration};
pub struct NativeRuntime {
    pub host: Host<Native>,
}
impl NativeRuntime {
    pub fn new() -> Result<Self> {
        Ok(Self {
            host: Host::new(
                Default::default(),
                Native {
                    root: Default::default(),
                },
            )?,
        })
    }
}
impl Runtime for NativeRuntime {
    fn owner_verb(
        &mut self,
        ctx: &Context,
        verb: &str,
        subject: &Subject,
        service: &str,
        actor: &str,
    ) -> Option<Result<()>> {
        self.host.owner_verb(ctx, verb, subject, service, actor)
    }
    fn compose(
        &mut self,
        ctx: &Context,
        subject: &Subject,
        args: &[String],
        capture: bool,
        maximum: usize,
    ) -> Result<String> {
        let ctx = crate::runtime::bounded(
            ctx,
            if capture {
                Duration::from_secs(60)
            } else {
                Duration::from_secs(600)
            },
        );
        let mut command = Command::new("docker");
        command
            .args(application::compose_base(&subject.dir, &subject.project))
            .args(args);
        let result = if capture {
            crate::process::capture(&mut command, None, maximum, ctx.deadline, || {
                ctx.check().is_err()
            })?
        } else {
            crate::process::stream(
                &mut command,
                None,
                8192,
                ctx.deadline,
                || ctx.check().is_err(),
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            )?
        };
        ensure!(
            result.status.success(),
            "{}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&result.stdout).into_owned())
    }
    fn provision(
        &mut self,
        ctx: &Context,
        script: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<()> {
        let ctx = crate::runtime::bounded(ctx, Duration::from_secs(600));
        let mut command = Command::new("/bin/sh");
        command
            .arg("-s")
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", "/root")
            .env("LC_ALL", "C")
            .envs(environment)
            .current_dir("/");
        let result = crate::process::stream(
            &mut command,
            Some(script.as_bytes()),
            8192,
            ctx.deadline,
            || ctx.check().is_err(),
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        )?;
        ensure!(
            result.status.success(),
            "provisioning failed: {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        );
        Ok(())
    }
}
impl Executor for NativeRuntime {
    fn perform(&mut self, ctx: &Context, command: &SignedCommand, actor: &str) -> Result<()> {
        application::perform(ctx, self, Path::new(""), command, actor)
    }
}
pub fn run(args: &[String], ctx: &Context) -> Result<()> {
    let Some((verb, args)) = args.split_first() else {
        anyhow::bail!("usage: komizo-box app <start|stop|restart|logs> --app NAME")
    };
    let flags = parse(
        &[
            Flag::text("app", ""),
            Flag::boolean("proxy", false),
            Flag::integer("tail", 40),
            Flag::text("service", ""),
        ],
        args,
        true,
    )?;
    ensure!(
        application::known_verb(verb),
        "{} is not something an app can be told to do",
        quote(verb)
    );
    ensure!(
        flags.boolean("proxy") == flags.text("app").is_empty(),
        "give exactly one of --app and --proxy"
    );
    ensure!(
        (1..=application::LOG_TAIL_MAX).contains(&flags.integer("tail")),
        "--tail must be between 1 and {}",
        application::LOG_TAIL_MAX
    );
    application::valid_service(flags.text("service"))?;
    let subject =
        application::resolve_subject(Path::new(""), flags.text("app"), flags.boolean("proxy"))?;
    application::run_verb(
        ctx,
        &mut NativeRuntime::new()?,
        verb,
        &subject,
        flags.integer("tail"),
        flags.text("service"),
        "cli",
    )
}
