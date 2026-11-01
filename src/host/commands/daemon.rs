//! Root's independent timers share cancellation, never network-serving privileges.
use super::{app::NativeRuntime, parse, preview};
use crate::{
    flags::{Flag, Flags},
    host::{self, observer::Observer, paths::*, store, *},
    runtime,
    wire::Time,
    workload::activation::Context,
};
use anyhow::{Result, ensure};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Clone)]
pub struct Paths {
    pub report: PathBuf,
    pub history: PathBuf,
    pub metrics: PathBuf,
}
pub fn persist_tick(probe: &Probe, report: &Report, paths: &Paths) -> Vec<String> {
    let mut errors = vec![];
    if let Err(e) = store::write_report(&paths.report, report) {
        errors.push(format!("writing report: {e}"));
    }
    let sample = Sample {
        at: report.at,
        system: report.system.clone(),
    };
    if let Err(e) = store::append_sample(
        &paths.history,
        &sample,
        store::HISTORY_MAX,
        store::HISTORY_KEEP,
        None,
    ) {
        errors.push(format!("appending history: {e}"));
    }
    let to = report.at.utc().timestamp();
    let mut metrics = probe.metrics(to - METRICS_WINDOW, to);
    if let Some(span) = metrics.span.as_ref() {
        let lo = span.from.max(to - METRICS_WINDOW);
        let hi = span.to.min(to);
        metrics.span = if lo <= hi {
            Some(Span { from: lo, to: hi })
        } else {
            None
        };
    }
    if let Err(e) = store::write_metrics(&paths.metrics, &metrics) {
        errors.push(format!("writing metrics: {e}"));
    }
    errors
}
fn error(message: impl std::fmt::Display) {
    eprintln!("komizo-box: {message}");
}
fn tick(ctx: &Context, paths: &Paths, want_volumes: bool) {
    if ctx.check().is_err() {
        return;
    }
    let probe = Probe::default();
    let mut report = Observer::new(&probe, || ctx.check().is_err()).report(runtime::VERSION, None);
    if want_volumes && report.server.ready() {
        report.system.volumes = Observer::new(&probe, || ctx.check().is_err())
            .volumes("")
            .into();
    }
    if ctx.check().is_err() {
        return;
    }
    for message in persist_tick(&probe, &report, paths) {
        error(message);
    }
}
pub fn parse_flags(args: &[String]) -> Result<Flags> {
    let flags = parse(
        &[
            Flag::duration("interval", 60_000_000_000),
            Flag::text("config", credential::AGENT_CONF_PATH),
            Flag::text("inbox", inbox::INBOX_DIR),
            Flag::text("results", RESULTS_DIR),
            Flag::text("logs", LOGS_DIR),
            Flag::text("report", REPORT_PATH),
            Flag::text("history", HISTORY_PATH),
            Flag::text("metrics", METRICS_PATH),
            Flag::text("state", STATE_DIR),
            Flag::text("socket-dir", API_SOCKET_DIR),
            Flag::integer("volumes-every", 15),
            Flag::boolean("once", false),
            Flag::text("network", "edge"),
        ],
        args,
        false,
    )?;
    ensure!(
        !flags.duration("interval")?.is_zero(),
        "interval must be positive"
    );
    Ok(flags)
}
pub fn prepare(flags: &Flags) -> Result<Paths> {
    let paths = Paths {
        report: flags.text("report").into(),
        history: flags.text("history").into(),
        metrics: flags.text("metrics").into(),
    };
    let parent = paths
        .report
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    directories::prepare_state(Path::new(flags.text("state")))?;
    for path in [&paths.history, &paths.metrics] {
        store::prepare_served_dir(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
    }
    directories::prepare_inbox_or_socket(Path::new(flags.text("socket-dir")))?;
    directories::prepare_inbox_or_socket(Path::new(flags.text("inbox")))?;
    for name in ["results", "logs"] {
        store::prepare_served_dir(Path::new(flags.text(name)))?;
    }
    Ok(paths)
}
pub fn command_pass(
    ctx: &Context,
    configuration: &Path,
    inbox: &Path,
    results: &Path,
) -> Result<()> {
    let conf = credential::read_agent_conf(configuration)?;
    for message in
        host::inbox::apply_pending(ctx, &conf, inbox, results, &mut NativeRuntime::new()?)
    {
        error(message);
    }
    Ok(())
}
fn commands(ctx: &Context, flags: &Flags) {
    let mut executor = match NativeRuntime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            error(e);
            return;
        }
    };
    let mut prune = Instant::now() + Duration::from_secs(3600);
    while runtime::sleep(ctx, Duration::from_millis(500)) {
        if let Ok(conf) = credential::read_agent_conf(Path::new(flags.text("config"))) {
            for message in host::inbox::apply_pending(
                ctx,
                &conf,
                Path::new(flags.text("inbox")),
                Path::new(flags.text("results")),
                &mut executor,
            ) {
                error(message);
            }
        }
        if Instant::now() >= prune {
            let _ = results::prune_results(
                Path::new(flags.text("results")),
                Time(chrono::Utc::now().fixed_offset()),
            );
            prune = Instant::now() + Duration::from_secs(3600);
        }
    }
}
fn activations(ctx: &Context) {
    let mut host = match NativeRuntime::new() {
        Ok(runtime) => runtime.host,
        Err(e) => {
            error(e);
            return;
        }
    };
    let mut last_error = None;
    while runtime::sleep(ctx, Duration::from_millis(500)) {
        let result = host.activation_pass(ctx, Path::new(host::workload::ACTIVATIONS));
        if result.is_err()
            && last_error.is_none_or(|at: Instant| at.elapsed() > Duration::from_secs(60))
        {
            error("activation queue needs local operator inspection");
            last_error = Some(Instant::now());
        }
    }
}
fn logs(ctx: &Context, path: &Path) {
    let mut ticker = runtime::Ticker::new(Duration::from_secs(15));
    loop {
        let probe = Probe::default();
        Observer::new(&probe, || ctx.check().is_err()).collect_logs(path);
        if !ticker.wait(ctx) {
            return;
        }
    }
}
fn sweeps(ctx: &Context) {
    loop {
        let (knob, note) = sweep::read_knob(Path::new(sweep::KNOB_PATH));
        let mut record = sweep::docker_sweep(
            &knob,
            Time(chrono::Utc::now().fixed_offset()),
            &Probe::default(),
            |args| preview::docker(ctx, "", args),
        );
        if !note.is_empty() {
            record.note.push_str("; ");
            record.note.push_str(&note);
        }
        if let Err(e) = sweep::write_record(Path::new(sweep::RECORD_PATH), &record) {
            error(format!("writing the sweep record: {e}"));
        }
        let (knob, _) = sweep::read_knob(Path::new(sweep::KNOB_PATH));
        if !runtime::sleep(ctx, Duration::from_nanos(knob.interval_ns as u64)) {
            return;
        }
    }
}
fn preview_reaper(ctx: &Context, network: &str) {
    loop {
        let (knob, _) = preview::read_knob();
        let mut cfg = preview::config(knob);
        cfg.network = network.into();
        cfg.floors_body = fs::read_to_string(DEPLOY_FLOORS_PATH).unwrap_or_default();
        cfg.report_json = fs::read(REPORT_PATH).unwrap_or_default();
        let (reap, result) =
            host::preview::runtime::gc(ctx, &mut preview::docker, &cfg, chrono::Utc::now());
        if let Err(e) = result {
            error(format!("preview reap: {e}"));
        }
        if let Err(e) = preview::write_reap(&reap) {
            error(format!("writing the preview reap record: {e}"));
        }
        if !runtime::sleep(ctx, Duration::from_secs(3600)) {
            return;
        }
    }
}
fn preview_ask(ctx: &Context, network: &str) {
    let (knob, _) = preview::read_knob();
    let gateway = preview::docker(
        ctx,
        "",
        &[
            "network",
            "inspect",
            network,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ],
    );
    let gateway = match gateway {
        Ok(gateway) if !gateway.trim().is_empty() => gateway.trim().to_string(),
        _ => {
            error(format!(
                "the preview ask is not being served -- no gateway on {network}"
            ));
            return;
        }
    };
    if let Err(e) = crate::nativeapi::run(
        ctx,
        &[
            "preview-ask".into(),
            "--bind".into(),
            gateway,
            "--port".into(),
            knob.ask_port.to_string(),
            "--preview-knob".into(),
            host::preview::KNOB_PATH.into(),
        ],
    ) && ctx.check().is_ok()
    {
        error(format!("preview ask stopped: {e}"));
    }
}
pub fn run(args: &[String], ctx: &Context) -> Result<()> {
    let flags = parse_flags(args)?;
    let paths = prepare(&flags)?;
    let vol_every = flags.integer("volumes-every");
    tick(ctx, &paths, vol_every > 0);
    if flags.boolean("once") {
        return Ok(());
    }
    let interval = flags.duration("interval")?;
    std::thread::scope(|scope| {
        scope.spawn(|| commands(ctx, &flags));
        scope.spawn(|| activations(ctx));
        scope.spawn(|| logs(ctx, Path::new(flags.text("logs"))));
        scope.spawn(|| sweeps(ctx));
        scope.spawn(|| preview_reaper(ctx, flags.text("network")));
        scope.spawn(|| preview_ask(ctx, flags.text("network")));
        let mut n = 1i64;
        let mut ticker = runtime::Ticker::new(interval);
        while ticker.wait(ctx) {
            tick(ctx, &paths, vol_every > 0 && n % vol_every == 0);
            n = n.wrapping_add(1);
        }
    });
    Ok(())
}
