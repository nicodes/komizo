//! One host operation owns admission, effects and cleanup; failures retain cleanup records.
use super::{
    Record, RecordValues, capacity, compose,
    effects::{self, Run},
    knob::{Knob, memory_bytes, valid_cpu},
    profile, store,
};
use crate::{
    host::{
        PreviewHostResources, PreviewReap,
        locking::{HostLock, platform_idle},
    },
    wire::{Secret, Time},
    workload::activation::Context,
};
use anyhow::{Result, anyhow, ensure};
use chrono::{DateTime, Duration, Utc};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};
#[derive(Clone, Debug)]
pub struct Config {
    pub knob: Knob,
    pub root: PathBuf,
    pub routes_dir: PathBuf,
    pub proxy: String,
    pub network: String,
    pub floors_body: String,
    pub report_json: Vec<u8>,
    pub report_path: Option<PathBuf>,
    pub host_resources: Option<PreviewHostResources>,
    pub manage_idle_database: bool,
}
pub(super) fn lock(ctx: &Context, root: &Path, name: &str) -> Result<HostLock> {
    ctx.check()?;
    HostLock::acquire(
        root,
        name,
        ctx.remaining()?.min(StdDuration::from_secs(60)),
        || ctx.check().is_err(),
    )
}
pub(super) fn operation(ctx: &Context, root: &Path) -> Result<HostLock> {
    let lock = lock(ctx, root, "operation.lock")?;
    platform_idle(root)?;
    Ok(lock)
}
fn password() -> Result<Secret> {
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow!("preview credential generation unavailable"))?;
    Ok(Secret::new(
        bytes.iter().map(|b| format!("{b:02x}")).collect(),
    ))
}
fn valid_seed(seed: &Secret) -> bool {
    seed.expose().len() == 24
        && seed
            .expose()
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn port_range(value: &str) -> (i64, i64) {
    let (mut lo, mut hi) = (20000, 21000);
    if let Some((left, right)) = value.split_once('-') {
        if let Ok(value) = left.trim().parse() {
            lo = value;
        }
        let right = right.trim_start();
        let digits: String = right
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '+' || *c == '-')
            .collect();
        if let Ok(value) = digits.parse() {
            hi = value;
        }
    }
    (lo, hi)
}
pub fn up(
    ctx: &Context,
    run: &mut Run<'_>,
    cfg: &Config,
    app: &str,
    pr: i64,
    images: &[String],
    now: DateTime<Utc>,
) -> Result<Record> {
    up_with_seed(
        ctx,
        run,
        cfg,
        Request {
            app,
            pr,
            images,
            now,
        },
        password,
    )
}
pub struct Request<'a> {
    pub app: &'a str,
    pub pr: i64,
    pub images: &'a [String],
    pub now: DateTime<Utc>,
}
pub fn up_with_seed(
    ctx: &Context,
    run: &mut Run<'_>,
    cfg: &Config,
    request: Request<'_>,
    seed: impl FnOnce() -> Result<Secret>,
) -> Result<Record> {
    let Request {
        app,
        pr,
        images,
        now,
    } = request;
    let _operation = operation(ctx, &cfg.root)?;
    let mut cfg = cfg.clone();
    if let Some(path) = &cfg.report_path {
        cfg.report_json = crate::statefile::read(path, 16 << 20)
            .map_err(|e| anyhow!("cannot read current capacity report: {e}"))?
            .ok_or_else(|| anyhow!("cannot read current capacity report: file is missing"))?;
        capacity::report_fresh(&cfg.report_json, Utc::now())?;
    }
    ensure!(
        !cfg.knob.invalid_budget,
        "preview up refused: invalid capacity reservation"
    );
    cfg.knob.protect_envelope(cfg.host_resources.as_ref())?;
    ensure!(
        memory_bytes(&cfg.knob.mem_limit).is_ok() && valid_cpu(&cfg.knob.cpu_limit),
        "preview up requires positive bounded memory and CPU limits"
    );
    let target = cfg.knob.resolve(app, pr, images.len() > 1)?;
    ensure!(
        (1..=16).contains(&images.len()),
        "no images given -- a preview is images and nothing else"
    );
    for image in images {
        ensure!(
            !image.is_empty()
                && image
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:/_@=-".contains(&b)),
            "image {} contains characters that are not valid in an image reference",
            crate::host::authority::quote(image)
        );
    }
    if cfg.knob.profiles.is_none() {
        cfg.knob.profiles = Some(BTreeMap::from([(
            app.to_owned(),
            profile::read(&cfg.root, app)?,
        )]));
    }
    let profile = cfg.knob.profile(app);
    if let Some(profile) = profile {
        profile.validate_images(images)?;
        profile.validate_environment(
            &store::directory(&cfg.root, &super::project(app, pr)).join("stack.env"),
        )?;
    }
    let (floors, present) = capacity::parse_floors(&cfg.floors_body)?;
    let decision = capacity::check_floors(&floors, present, &cfg.report_json)?;
    ensure!(
        decision.refuse.is_empty(),
        "preview up refused by the capacity floors: {}",
        decision.refuse
    );
    let project = super::project(app, pr);
    let mut record = Record {
        values: RecordValues {
            v: 1,
            app: app.into(),
            pr,
            project: project.clone(),
            images: images.to_vec().into(),
            private_profile: profile.is_some(),
            created_at: Time(now.fixed_offset()),
            last_used: Time(now.fixed_offset()),
            route_file: format!("_preview-{project}.caddy"),
            host: target.host,
            api_host: target.api_host,
            base_path: target.base_path,
            ..Default::default()
        },
        ..Default::default()
    };
    if let Some(profile) = profile {
        record.profile_sha256 = profile.digest.clone();
    }
    record.memory_reserved_bytes = cfg.knob.memory_reservation(app, images)?;
    if !record.base_path.is_empty() {
        record.route_file = format!("_preview-pr-{pr}.{app}.route");
    }
    if images.len() > 1 && profile.is_none() {
        record.db_name = super::db_name(app, pr);
    }
    if !record.db_name.is_empty() || profile.is_some() {
        record.db_password = seed()?;
    }
    let _allocation = lock(ctx, &cfg.root, "previews.lock")?;
    let existing = store::list(&cfg.root)?;
    cfg.knob.production_reserve(&cfg.report_json)?;
    if cfg.knob.memory_budget > 0 {
        let mut reserved = i128::from(record.memory_reserved_bytes);
        for previous in &existing {
            if previous.project == project {
                continue;
            }
            ensure!(
                previous.memory_reserved_bytes > 0,
                "preview memory budget requires recorded reservations; drain or re-up legacy previews first"
            );
            reserved += i128::from(previous.memory_reserved_bytes);
            ensure!(
                previous.memory_reserved_bytes <= cfg.knob.memory_budget
                    && reserved <= i128::from(cfg.knob.memory_budget),
                "preview up exceeds MEM_BUDGET; existing previews and production were preserved"
            );
        }
        ensure!(
            reserved <= i128::from(cfg.knob.memory_budget),
            "preview up exceeds MEM_BUDGET; existing previews and production were preserved"
        );
    }
    let mut have = false;
    for previous in &existing {
        ensure!(
            previous.project != project || previous.base_path == record.base_path,
            "remove this preview before changing between hostname and path routing"
        );
        ensure!(
            previous.app != app
                || previous.base_path.is_empty()
                || (previous.host == record.host && previous.api_host == record.api_host),
            "drain the app's path previews before changing their hostnames"
        );
        if previous.project == project {
            have = true;
            ensure!(
                previous.private_profile == record.private_profile
                    && previous.profile_sha256 == record.profile_sha256,
                "drain the existing preview before changing its profile"
            );
            if profile.is_some() {
                ensure!(
                    previous.app == app && previous.pr == pr && valid_seed(&previous.db_password),
                    "the existing private preview has no valid credential seed"
                );
                record.db_password = previous.db_password.clone();
            }
        }
    }
    let (lo, hi) = port_range(&cfg.knob.port_range);
    let used: BTreeSet<_> = existing
        .iter()
        .filter(|r| r.project != project)
        .map(|r| r.gate_port)
        .collect();
    for previous in &existing {
        if previous.project == project
            && previous.gate_port >= lo
            && previous.gate_port <= hi
            && !used.contains(&previous.gate_port)
        {
            record.gate_port = previous.gate_port;
        }
    }
    if record.gate_port == 0 {
        record.gate_port = lo;
        while record.gate_port <= hi && used.contains(&record.gate_port) {
            record.gate_port = record
                .gate_port
                .checked_add(1)
                .ok_or_else(|| anyhow!("preview port range overflow"))?;
        }
        ensure!(record.gate_port <= hi, "no free gate ports in {lo}-{hi}");
    }
    if let Some(profile) = profile {
        let rendered = profile.compose(&record, &cfg.knob, &format!("{project}-ingress"))?;
        profile.validate_compose(&rendered, &record, &cfg.knob, &format!("{project}-ingress"))?;
    }
    if !have
        && existing.len() as i64 >= cfg.knob.max
        && let Some(previous) = existing.first()
    {
        down_inner(ctx, run, &cfg, previous).map_err(|e| {
            anyhow!(
                "evicting {} to stay within {} previews: {e}",
                previous.project,
                cfg.knob.max
            )
        })?;
    }
    store::write_record(&cfg.root, &record)?;
    let action = (|| -> Result<()> {
        let compose_path = store::directory(&cfg.root, &project).join("compose.yml");
        let stack_env =
            fs::metadata(store::directory(&cfg.root, &project).join("stack.env")).is_ok();
        let needs_database = !record.db_name.is_empty();
        let mut endpoint = "";
        if profile.is_none() && images.len() > 1 {
            effects::ensure_backend(ctx, run, &project, needs_database)?;
        }
        if needs_database {
            effects::ensure_database_ready(ctx, run, cfg.manage_idle_database)?;
            endpoint = super::DB_CONTAINER;
            effects::drop_database(ctx, run, &record.db_name).map_err(|e| {
                anyhow!(
                    "could not reclaim a leftover preview database in {}: {e}",
                    super::DB_CONTAINER
                )
            })?;
            effects::sql(
                ctx,
                run,
                &format!("CREATE ROLE {} LOGIN PASSWORD :'pw';", record.db_name),
                &["-v", &format!("pw={}", record.db_password.expose())],
            )
            .map_err(|e| {
                anyhow!(
                    "could not create the preview role {} in {}: {e}",
                    record.db_name,
                    super::DB_CONTAINER
                )
            })?;
            run(
                ctx,
                "",
                &[
                    "exec",
                    super::DB_CONTAINER,
                    "psql",
                    "-U",
                    super::DB_SUPERUSER,
                    "-d",
                    super::DB_MAINTENANCE,
                    "-c",
                    &format!(
                        "CREATE DATABASE {} OWNER {}",
                        record.db_name, record.db_name
                    ),
                ],
            )
            .map_err(|e| {
                anyhow!(
                    "could not create the preview database {} in {}: {e}",
                    record.db_name,
                    super::DB_CONTAINER
                )
            })?;
            effects::sql(ctx,run,&format!("REVOKE CONNECT ON DATABASE {} FROM PUBLIC;\nGRANT CONNECT ON DATABASE {} TO {};",record.db_name,record.db_name,record.db_name),&[]).map_err(|e|anyhow!("could not isolate the preview database {} from the other previews on {}: {e}",record.db_name,super::DB_CONTAINER))?;
        }
        let path = compose_path.to_string_lossy();
        if crate::statefile::read(&compose_path, 1 << 20)
            .ok()
            .flatten()
            .is_some_and(|body| String::from_utf8_lossy(&body).contains("\n  gate:\n"))
        {
            run(
                ctx,
                "",
                &[
                    "compose", "-p", &project, "-f", &path, "rm", "-s", "-f", "gate",
                ],
            )
            .map_err(|e| anyhow!("migrating this preview's gate alias: {e}"))?;
        }
        let ingress = effects::ensure_ingress(ctx, run, &project, &cfg.proxy)?;
        let body = compose::render(&record, &cfg.knob, &ingress, stack_env, endpoint)?;
        if let Some(profile) = profile {
            profile.validate_compose(&body, &record, &cfg.knob, &ingress)?;
        }
        fs::write(&compose_path, body)?;
        fs::set_permissions(&compose_path, fs::Permissions::from_mode(0o600))?;
        run(
            ctx,
            "",
            &[
                "compose",
                "-p",
                &project,
                "-f",
                &path,
                "up",
                "-d",
                "--remove-orphans",
            ],
        )
        .map_err(|e| anyhow!("the preview project did not come up: {e}"))?;
        effects::apply_record_route(ctx, run, &cfg.proxy, &cfg.routes_dir, &record, &cfg.knob)?;
        Ok(())
    })();
    if let Err(mut error) = action {
        if let Err(cleanup) = down_inner(ctx, run, &cfg, &record) {
            error =
                anyhow!("{error}\npreview cleanup incomplete; state retained for retry: {cleanup}");
        }
        return Err(error);
    }
    Ok(record)
}
pub fn down(ctx: &Context, run: &mut Run<'_>, cfg: &Config, r: &Record) -> Result<()> {
    let _operation = operation(ctx, &cfg.root)?;
    down_inner(ctx, run, cfg, r)
}
fn down_inner(ctx: &Context, run: &mut Run<'_>, cfg: &Config, r: &Record) -> Result<()> {
    let compose = store::directory(&cfg.root, &r.project).join("compose.yml");
    if let Err(error) = run(
        ctx,
        "",
        &[
            "compose",
            "-p",
            &r.project,
            "-f",
            &compose.to_string_lossy(),
            "down",
            "-v",
        ],
    ) && fs::metadata(&compose).is_ok()
    {
        return Err(anyhow!("could not take the preview project down: {error}"));
    }
    if !r.db_name.is_empty() {
        if cfg.manage_idle_database {
            effects::ensure_database_ready(ctx, run, true)
                .map_err(|e| anyhow!("preview database cleanup pending: {e}"))?;
        }
        let state = run(
            ctx,
            "",
            &[
                "inspect",
                super::DB_CONTAINER,
                "--format",
                "{{.State.Running}}",
            ],
        )
        .unwrap_or_default();
        ensure!(
            state.trim() == "true",
            "preview database cleanup pending: shared server unavailable"
        );
        effects::drop_database(ctx, run, &r.db_name)?;
    }
    effects::remove_route(ctx, run, &cfg.proxy, &cfg.routes_dir, &r.route_file)?;
    effects::remove_network(ctx, run, &r.project, &cfg.proxy, true, false)?;
    if !r.private_profile && r.images.len() > 1 {
        effects::remove_network(
            ctx,
            run,
            &r.project,
            &cfg.proxy,
            false,
            !r.db_name.is_empty(),
        )?;
    }
    let directory = store::directory(&cfg.root, &r.project);
    if directory.exists() {
        fs::remove_dir_all(directory)?;
    }
    stop_unused_database(ctx, run, cfg)
}
fn stop_unused_database(ctx: &Context, run: &mut Run<'_>, cfg: &Config) -> Result<()> {
    if !cfg.manage_idle_database {
        return Ok(());
    }
    if store::list(&cfg.root)?
        .iter()
        .any(|record| !record.db_name.is_empty())
    {
        return Ok(());
    }
    let Ok(state) = run(
        ctx,
        "",
        &[
            "inspect",
            super::DB_CONTAINER,
            "--format",
            "{{.State.Running}}",
        ],
    ) else {
        return Ok(());
    };
    if state.trim() == "false" {
        return Ok(());
    }
    ensure!(
        state.trim() == "true",
        "could not determine preview database state"
    );
    run(ctx, "", &["stop", "--time", "30", super::DB_CONTAINER])
        .map_err(|e| anyhow!("could not stop idle preview database: {e}"))?;
    Ok(())
}
pub fn gc(
    ctx: &Context,
    run: &mut Run<'_>,
    cfg: &Config,
    now: DateTime<Utc>,
) -> (PreviewReap, Result<()>) {
    let mut reap = PreviewReap {
        v: 1,
        at: Time(now.fixed_offset()),
        ..Default::default()
    };
    let action = (|| -> Result<()> {
        let _operation = operation(ctx, &cfg.root)?;
        let mut live = vec![];
        for record in store::list(&cfg.root)? {
            if now - record.last_used.0.with_timezone(&Utc) > Duration::nanoseconds(cfg.knob.ttl) {
                match down_inner(ctx, run, cfg, &record) {
                    Ok(()) => {
                        reap.reaped.push(record.project.clone());
                        continue;
                    }
                    Err(error) => {
                        if !reap.note.is_empty() {
                            reap.note.push_str("; ");
                        }
                        reap.note.push_str(&format!(
                            "could not reap {} (kept): {error}",
                            record.project
                        ));
                    }
                }
            }
            live.push(record);
        }
        while live.len() as i64 > cfg.knob.max {
            let Some(record) = live.first() else { break };
            if let Err(error) = down_inner(ctx, run, cfg, record) {
                if !reap.note.is_empty() {
                    reap.note.push_str("; ");
                }
                reap.note.push_str(&format!(
                    "could not evict {} (kept): {error}",
                    record.project
                ));
                break;
            }
            reap.reaped.push(record.project.clone());
            live.remove(0);
        }
        reap.kept = live.len() as i64;
        if let Err(error) = stop_unused_database(ctx, run, cfg) {
            if !reap.note.is_empty() {
                reap.note.push_str("; ");
            }
            reap.note.push_str(&error.to_string());
        }
        if reap.reaped.is_empty() && reap.note.is_empty() {
            reap.note = "nothing to reap".into();
        }
        Ok(())
    })();
    (reap, action)
}
