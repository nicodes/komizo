//! SSH and signed commands share the same lifecycle and provisioning implementation.
use super::{
    authority::{Command, quote},
    paths, scoped, stopped,
};
use crate::{wire::Time, workload::activation::Context};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
pub const LOG_TAIL_MAX: i64 = 2000;
pub const PROXY_PROJECT: &str = "komizo-proxy";
#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub dir: String,
    pub project: String,
    pub app: String,
    pub root: PathBuf,
}
pub trait Runtime {
    fn owner_verb(
        &mut self,
        ctx: &Context,
        verb: &str,
        subject: &Subject,
        service: &str,
        actor: &str,
    ) -> Option<Result<()>>;
    fn compose(
        &mut self,
        ctx: &Context,
        subject: &Subject,
        args: &[String],
        capture: bool,
        maximum: usize,
    ) -> Result<String>;
    fn provision(
        &mut self,
        ctx: &Context,
        script: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<()>;
}
pub fn known_verb(verb: &str) -> bool {
    matches!(verb, "start" | "stop" | "restart" | "logs")
}
pub fn valid_service(service: &str) -> Result<()> {
    ensure!(
        !service.starts_with('-'),
        "{} is not a service name -- it is a flag",
        quote(service)
    );
    ensure!(
        service
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "{} is not a service name",
        quote(service)
    );
    Ok(())
}
pub fn resolve_subject(root: &Path, name: &str, proxy: bool) -> Result<Subject> {
    if proxy {
        return Ok(Subject {
            dir: paths::PROXY_DIR.into(),
            project: PROXY_PROJECT.into(),
            ..Default::default()
        });
    }
    let dir = paths::app_dir(root, name)?;
    ensure!(
        dir.starts_with('/'),
        "{} is not an absolute directory",
        quote(&dir)
    );
    Ok(Subject {
        dir,
        app: name.into(),
        root: root.into(),
        ..Default::default()
    })
}
pub fn compose_base(dir: &str, project: &str) -> Vec<String> {
    let mut args = vec![
        "compose".into(),
        "-f".into(),
        format!("{dir}/compose.yml"),
        "--project-directory".into(),
        dir.into(),
    ];
    if !project.is_empty() {
        args.extend(["-p".into(), project.into()]);
    }
    args
}
pub fn compose_args(verb: &str, tail: i64, service: &str) -> Vec<String> {
    let mut args: Vec<String> = match verb {
        "start" => vec!["up".into(), "-d".into()],
        "stop" => vec!["stop".into()],
        "restart" => vec!["restart".into()],
        "logs" => vec![
            "logs".into(),
            "--tail".into(),
            tail.to_string(),
            "--no-color".into(),
        ],
        _ => vec![],
    };
    if !service.is_empty() {
        args.extend(["--".into(), service.into()]);
    }
    args
}
pub fn run_verb(
    ctx: &Context,
    runtime: &mut impl Runtime,
    verb: &str,
    subject: &Subject,
    tail: i64,
    service: &str,
    actor: &str,
) -> Result<()> {
    run_verb_at(
        ctx,
        runtime,
        Lifecycle {
            verb,
            subject,
            tail,
            service,
            actor,
        },
        chrono::Utc::now(),
    )
}
pub struct Lifecycle<'a> {
    pub verb: &'a str,
    pub subject: &'a Subject,
    pub tail: i64,
    pub service: &'a str,
    pub actor: &'a str,
}
pub fn run_verb_at(
    ctx: &Context,
    runtime: &mut impl Runtime,
    request: Lifecycle<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let Lifecycle {
        verb,
        subject: sub,
        tail,
        service,
        actor,
    } = request;
    if let Some(result) = runtime.owner_verb(ctx, verb, sub, service, actor) {
        return result;
    }
    if verb == "restart" {
        let result = runtime.compose(ctx, sub, &["ps".into(), "-q".into()], true, 1 << 20);
        if result.is_err() && ctx.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            anyhow::bail!("cancelled -- nothing was restarted");
        }
        let output=result.map_err(|e|anyhow!("could not tell what is running here, so nothing was restarted -- start it instead if it is down: {e}"))?;
        ensure!(
            !output.trim().is_empty(),
            "nothing is running here -- start it instead"
        );
    }
    let marks = !sub.app.is_empty() && service.is_empty() && matches!(verb, "stop" | "start");
    if verb == "start" && !sub.app.is_empty() && !service.is_empty() {
        let recorded = stopped::is_stopped(&sub.root, &sub.app).map_err(|e| {
            anyhow!(
                "could not tell whether {} is recorded as stopped, so nothing was started: {e}",
                sub.app
            )
        })?;
        ensure!(
            !recorded,
            "{} is recorded as stopped, so starting one service would leave it marked stopped while it runs -- and an app in that state never pages again. Start the whole app first: komizo start --app {}",
            sub.app,
            sub.app
        );
    }
    if verb == "stop" && marks {
        stopped::mark_stopped(&sub.root, &sub.app, actor, Time(now.fixed_offset())).map_err(
            |e| {
                anyhow!(
                    "could not record that {} was stopped, so it was left running: {e}",
                    sub.app
                )
            },
        )?;
    }
    if matches!(verb, "start" | "restart") {
        scoped::refuse_start(&sub.root, &sub.app)?;
    }
    if let Err(error) =
        runtime.compose(ctx, sub, &compose_args(verb, tail, service), false, 1 << 20)
    {
        if verb == "stop" && marks {
            let _ = stopped::clear_stopped(&sub.root, &sub.app);
        }
        return Err(error);
    }
    if verb == "start" && marks {
        stopped::clear_stopped(&sub.root, &sub.app).map_err(|e| {
            anyhow!(
                "{} was started, but the box still has it recorded as stopped: {e}",
                sub.app
            )
        })?;
    }
    Ok(())
}
pub fn perform(
    ctx: &Context,
    runtime: &mut impl Runtime,
    root: &Path,
    command: &Command,
    actor: &str,
) -> Result<()> {
    match command.op.as_str() {
        "app.add" => {
            let spec = command.add_of()?;
            let mut environment = BTreeMap::from([
                ("APP_NAME".into(), spec.app),
                ("CI_PUBKEY".into(), spec.pubkey),
                ("CI_USER".into(), spec.user),
                ("CONFIG_IMAGE".into(), spec.config),
                ("KNOWN_AS".into(), spec.known_as.join(",")),
                (
                    "HARDEN_SSH".into(),
                    if spec.harden_ssh { "1" } else { "0" }.into(),
                ),
            ]);
            if !spec.app_dir.is_empty() {
                environment.insert("APP_DIR".into(), spec.app_dir);
            }
            runtime.provision(ctx, crate::scripts::alpine(), &environment)
        }
        "app.rotate" => {
            let (app, pubkey) = command.rotate_of()?;
            let state = paths::app_settings(root, app)?;
            let get = |key: &str| state.get(key).cloned().unwrap_or_default();
            for key in ["CI_USER", "CONFIG_IMAGE", "APP_DIR"] {
                ensure!(
                    !get(key).is_empty(),
                    "this box's record of {} has no {key}, so komizo cannot rotate its key without guessing the rest",
                    quote(app)
                );
            }
            runtime.provision(
                ctx,
                crate::scripts::alpine(),
                &BTreeMap::from([
                    ("APP_NAME".into(), app.into()),
                    ("CI_PUBKEY".into(), pubkey.into()),
                    ("CI_USER".into(), get("CI_USER")),
                    ("CONFIG_IMAGE".into(), get("CONFIG_IMAGE")),
                    ("APP_DIR".into(), get("APP_DIR")),
                    ("KNOWN_AS".into(), get("KNOWN_AS")),
                    ("HARDEN_SSH".into(), "0".into()),
                ]),
            )
        }
        op => {
            let verb = match op {
                "app.start" => "start",
                "app.stop" => "stop",
                "app.restart" => "restart",
                _ => anyhow::bail!("this box does not know how to {}", quote(op)),
            };
            let app = command.app_of()?;
            let subject = resolve_subject(root, app, false)?;
            run_verb(ctx, runtime, verb, &subject, 0, "", actor)
        }
    }
}
