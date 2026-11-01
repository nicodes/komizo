use super::{emit, parse};
use crate::{
    flags::Flag,
    host::{
        self,
        preview::{self, knob, runtime, store},
        resource_authority,
        workload::{files, transaction},
    },
    input::Input,
    workload::{activation::Context, host_resources::HostResources},
};
use anyhow::{Result, ensure};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
pub const REAP_PATH: &str = "/var/lib/komizo/served/preview-reap.json";
pub fn read_knob() -> (knob::Knob, String) {
    match std::fs::read_to_string(preview::KNOB_PATH) {
        Ok(body) => knob::parse(&body),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => knob::parse(""),
        Err(e) => {
            let (k, _) = knob::parse("");
            (
                k,
                format!("could not read {}, using defaults: {e}", preview::KNOB_PATH),
            )
        }
    }
}
pub fn docker(ctx: &Context, input: &str, args: &[&str]) -> Result<String> {
    let ctx = crate::runtime::bounded(ctx, Duration::from_secs(600));
    let mut command = Command::new("docker");
    command.args(args);
    let result = crate::process::capture(
        &mut command,
        if input.is_empty() {
            None
        } else {
            Some(input.as_bytes())
        },
        2 << 20,
        ctx.deadline,
        || ctx.check().is_err(),
    )?;
    ensure!(
        result.status.success(),
        "{}: {}",
        result.status,
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}
pub fn config(knob: knob::Knob) -> runtime::Config {
    runtime::Config {
        knob,
        root: PathBuf::new(),
        routes_dir: "/srv/_proxy/routes".into(),
        proxy: "komizo-proxy".into(),
        network: "edge".into(),
        floors_body: String::new(),
        report_json: vec![],
        report_path: None,
        host_resources: None,
        manage_idle_database: true,
    }
}
pub fn resources() -> Result<HostResources> {
    let bytes = files::protected(Path::new("/etc/komizo/resources.json"), 1 << 20)?;
    let resources = resource_authority::read_resources(&bytes)?;
    resources.check(
        resource_authority::host_memory(&host::Probe::default())?,
        resource_authority::measured_cpu() * 1000,
    )?;
    Ok(resources)
}
pub fn verify_controllers(resources: &HostResources, root: &Path) -> Result<()> {
    let p = &resources.previews;
    for (file, expected) in [
        ("memory.max", p.memory_bytes.to_string()),
        ("memory.swap.max", "0".into()),
        ("cpu.max", format!("{} 100000", p.milli_cpus * 100)),
        ("pids.max", p.pids.to_string()),
    ] {
        let body =
            std::fs::read_to_string(root.join("komizo-previews").join(file)).unwrap_or_default();
        ensure!(
            body.split_whitespace().collect::<Vec<_>>().join(" ") == expected,
            "preview up refused: protected preview controller drift ({file}); apply reviewed host resources first"
        );
    }
    Ok(())
}
pub fn response(mut record: preview::Record, knob: &knob::Knob) -> Result<serde_json::Value> {
    record.host = record.web_host(knob);
    record.api_host = record.public_api_host(knob);
    let domain = record
        .host
        .split_once('.')
        .map(|(_, domain)| domain.to_string())
        .unwrap_or_else(|| knob.domain_for(&record.app));
    let mut output = serde_json::to_value(record)?;
    output["domain"] = domain.into();
    Ok(output)
}
pub fn write_reap(record: &host::PreviewReap) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    host::store::write_atomic(Path::new(REAP_PATH), &mut bytes.as_slice(), 0o644, None)
}
pub fn run(args: &[String], ctx: &Context, output: &mut dyn std::io::Write) -> Result<()> {
    if args.first().is_some_and(|s| s == "configure") {
        return configure(&args[1..], ctx, output);
    }
    if args == ["database"] {
        return database(ctx);
    }
    let Some((verb, args)) = args.split_first() else {
        anyhow::bail!("preview what -- up, down, resolve, ls or gc")
    };
    let flags = parse(
        &[
            Flag::text("app", ""),
            Flag::integer("pr", 0),
            Flag::text("root", ""),
            Flag::text("routes", "/srv/_proxy/routes"),
            Flag::text("proxy", "komizo-proxy"),
            Flag::text("network", "edge"),
            Flag::text("floors", host::paths::DEPLOY_FLOORS_PATH),
            Flag::text("report", host::paths::REPORT_PATH),
        ],
        args,
        false,
    )?;
    let (knob, note) = read_knob();
    if !note.is_empty() {
        eprintln!("komizo-box preview: {note}");
    }
    let mut cfg = config(knob);
    cfg.root = flags.text("root").into();
    cfg.routes_dir = flags.text("routes").into();
    cfg.proxy = flags.text("proxy").into();
    cfg.network = flags.text("network").into();
    let app = flags.text("app");
    let pr = flags.integer("pr");
    match verb.as_str() {
        "resolve" => emit(output, &cfg.knob.resolve(app, pr, flags.args.len() > 1)?),
        "up" => {
            ensure!(
                !app.is_empty() && pr != 0,
                "preview up needs --app and --pr"
            );
            let r = resources()?;
            verify_controllers(&r, Path::new("/sys/fs/cgroup"))?;
            cfg.host_resources = Some(host::PreviewHostResources {
                memory_bytes: r.previews.memory_bytes,
                milli_cp_us: r.previews.milli_cpus,
                production_reserve_bytes: r.production.memory_bytes
                    + r.proxy.memory_bytes
                    + r.os_reserve_bytes,
                database_reserve_bytes: r.preview_database.memory_bytes,
                physical_memory_bytes: r.physical_memory_bytes,
            });
            cfg.floors_body = match std::fs::read_to_string(flags.text("floors")) {
                Ok(body) => body,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(_) => anyhow::bail!("cannot read {}", flags.text("floors")),
            };
            cfg.report_path = Some(flags.text("report").into());
            let record = runtime::up(
                ctx,
                &mut docker,
                &cfg,
                app,
                pr,
                &flags.args,
                chrono::Utc::now(),
            )?;
            emit(output, &response(record, &cfg.knob)?)
        }
        "down" => {
            ensure!(
                !app.is_empty() && pr != 0,
                "preview down needs --app and --pr"
            );
            let records = store::list(&cfg.root)?;
            let Some(record) = records.iter().find(|r| r.app == app && r.pr == pr) else {
                writeln!(
                    output,
                    "no preview of {app} PR #{pr} is recorded; nothing to take down."
                )?;
                return Ok(());
            };
            runtime::down(ctx, &mut docker, &cfg, record)?;
            writeln!(
                output,
                "preview {} is down: project, database {} and route removed.",
                record.project, record.db_name
            )?;
            Ok(())
        }
        "ls" => emit(output, &store::list(&cfg.root)?),
        "gc" => {
            let (reap, result) = runtime::gc(ctx, &mut docker, &cfg, chrono::Utc::now());
            result?;
            if let Err(e) = write_reap(&reap) {
                eprintln!("komizo-box preview: writing the reap record: {e}");
            }
            emit(output, &reap)
        }
        _ => anyhow::bail!(
            "preview what -- up, down, resolve, ls or gc, not {}",
            host::authority::quote(verb)
        ),
    }
}
fn configure(args: &[String], ctx: &Context, output: &mut dyn std::io::Write) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "preview configure requires the host operator"
    );
    let flags = parse(&[Flag::text("app", "")], args, true)?;
    let app = flags.text("app");
    ensure!(
        preview::profile::valid_name(app),
        "invalid registered application"
    );
    let native = super::app::NativeRuntime::new()?;
    let policy: crate::workload::policy::Policy = native
        .host
        .read_json(&Path::new(host::workload::POLICIES).join(format!("{app}.json")))?;
    ensure!(
        policy.app == app,
        "preview profile app differs from protected policy"
    );
    let body = Input::stdin()?.bounded(
        &crate::runtime::bounded(ctx, Duration::from_secs(10)),
        128 << 10,
    )?;
    preview::profile::configure(ctx, Path::new(""), app, &body)?;
    emit(
        output,
        &serde_json::json!({"configured":true,"app":app,"sha256":transaction::hash(&body)}),
    )
}
fn database(ctx: &Context) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "preview database requires the root operator"
    );
    super::enter_read_budget()?;
    let ctx = crate::runtime::bounded(ctx, Duration::from_secs(180));
    let _lock =
        host::locking::HostLock::acquire(Path::new(""), "previews.lock", ctx.remaining()?, || {
            ctx.check().is_err()
        })?;
    ensure!(
        store::list(Path::new(""))?.is_empty(),
        "preview database provisioning requires no active or retained preview records"
    );
    resources()?;
    let body = files::protected(Path::new("/etc/komizo/resources.json"), 1 << 20)?;
    let program = format!(
        "import types\n_shared = types.ModuleType('komizo_platform')\nexec({}, _shared.__dict__)\nPlatform = _shared.Platform\n{}",
        serde_json::to_string(crate::scripts::PLATFORM)?,
        crate::scripts::PREVIEW_DATABASE
    );
    super::python(&ctx, &program, &[transaction::hash(&body)])
}
