//! The reporting process only reads an observation file and posts it.
use super::parse;
use crate::{
    flags::Flag,
    host::{
        AgentConf, Probe, Report,
        credential::{self, AGENT_CONF_PATH},
        observer::Observer,
    },
    runtime,
    wire::{Secret, Slice},
    workload::activation::Context,
};
use anyhow::{Result, ensure};
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime},
};
#[derive(Debug)]
pub struct Revoked;
impl std::fmt::Display for Revoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this server's credential was refused")
    }
}
impl std::error::Error for Revoked {}
pub fn first_line(body: &[u8]) -> String {
    let end = body
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(body.len())
        .min(200);
    String::from_utf8_lossy(crate::wire::trim_space(&body[..end])).into_owned()
}
pub fn client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
pub fn post_report(
    ctx: &Context,
    client: &reqwest::blocking::Client,
    conf: &AgentConf,
    path: &Path,
) -> Result<()> {
    ctx.check()?;
    let body = crate::statefile::read(path, 16 << 20)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let response = client
        .post(conf.report_url())
        .timeout(ctx.remaining()?.min(Duration::from_secs(30)))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", conf.token.expose()))
        .header("User-Agent", format!("komizo-box/{}", runtime::VERSION))
        .body(body)
        .send()?;
    let status = response.status();
    let mut message = vec![];
    let _ = response.take(4096).read_to_end(&mut message);
    if matches!(status.as_u16(), 401 | 403) {
        return Err(Revoked.into());
    }
    ensure!(status.is_success(), "{status}: {}", first_line(&message));
    Ok(())
}
pub fn run(args: &[String], ctx: &Context) -> Result<()> {
    let flags = parse(
        &[
            Flag::text("config", AGENT_CONF_PATH),
            Flag::text("report", crate::host::paths::REPORT_PATH),
            Flag::duration("watch", 5_000_000_000),
            Flag::boolean("once", false),
        ],
        args,
        false,
    )?;
    let conf = credential::read_agent_conf(Path::new(flags.text("config")))?;
    if !conf.enrolled() {
        eprintln!("not enrolled -- nothing to report to");
        return Ok(());
    }
    let client = client()?;
    let path = Path::new(flags.text("report"));
    if flags.boolean("once") {
        return post_report(ctx, &client, &conf, path);
    }
    let watch = flags.duration("watch")?;
    ensure!(!watch.is_zero(), "watch must be positive");
    agent_loop(ctx, &client, &conf, path, watch)
}
pub fn agent_loop(
    ctx: &Context,
    client: &reqwest::blocking::Client,
    conf: &AgentConf,
    path: &Path,
    watch: Duration,
) -> Result<()> {
    let mut ticker = runtime::Ticker::new(watch);
    let mut last_sent = SystemTime::UNIX_EPOCH;
    let mut backoff = Duration::from_secs(5);
    while ctx.check().is_ok() {
        if let Ok(modified) = std::fs::metadata(path).and_then(|m| m.modified())
            && modified > last_sent
        {
            match post_report(ctx, client, conf, path) {
                Ok(()) => {
                    last_sent = modified;
                    backoff = Duration::from_secs(5);
                }
                Err(e) if e.is::<Revoked>() => {
                    eprintln!(
                        "stopping: this server is no longer enrolled. Re-enrol with `komizo enrol`, or remove the agent."
                    );
                    return Ok(());
                }
                Err(_) if ctx.check().is_err() => return Ok(()),
                Err(e) => {
                    eprintln!("could not report: {e}; retry in {backoff:?}");
                    if !runtime::sleep(ctx, backoff) {
                        return Ok(());
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(300));
                    continue;
                }
            }
        }
        if !ticker.wait(ctx) {
            break;
        }
    }
    Ok(())
}
pub fn carry_keys(
    previous: &[String],
    previous_server: &str,
    server: &str,
    added: &[String],
    forget: bool,
) -> (Slice<String>, usize) {
    let drop = forget || (!previous_server.is_empty() && previous_server != server);
    let mut keys = if drop { vec![] } else { previous.to_vec() };
    for key in added {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    (
        if keys.is_empty() {
            Slice::default()
        } else {
            keys.into()
        },
        if drop { previous.len() } else { 0 },
    )
}
pub fn exchange(
    ctx: &Context,
    client: &reqwest::blocking::Client,
    base: &str,
    token: &str,
    endpoint: &str,
    report: &Report,
) -> Result<AgentConf> {
    let mut body = serde_json::json!({"token":token,"report":report});
    if !endpoint.is_empty() {
        body["endpoint"] = endpoint.into();
    }
    let response = client
        .post(format!("{base}/v1/enrol"))
        .timeout(ctx.remaining()?.min(Duration::from_secs(30)))
        .header("User-Agent", format!("komizo-box/{}", runtime::VERSION))
        .json(&body)
        .send()?;
    let status = response.status();
    let mut raw = vec![];
    response.take(64 << 10).read_to_end(&mut raw)?;
    let source: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_default();
    let mut reply = serde_json::Map::new();
    if let Some(source) = source.as_object() {
        for (name, value) in source {
            for key in ["server_id", "agent_token", "registry_key", "message"] {
                if name.eq_ignore_ascii_case(key) {
                    reply.insert(key.into(), value.clone());
                }
            }
        }
    }
    let get = |key| reply.get(key).and_then(|v| v.as_str()).unwrap_or("");
    if !status.is_success() {
        if !get("message").is_empty() {
            anyhow::bail!("{}", get("message"));
        }
        anyhow::bail!("{status}: {}", first_line(&raw));
    }
    ensure!(
        !get("agent_token").is_empty() && !get("server_id").is_empty(),
        "the service accepted the enrolment but issued no credential"
    );
    Ok(AgentConf {
        api: base.into(),
        server_id: get("server_id").into(),
        token: Secret::new(get("agent_token").into()),
        registry_key: get("registry_key").into(),
        ..Default::default()
    })
}
pub fn enrol(args: &[String], ctx: &Context, output: &mut dyn std::io::Write) -> Result<()> {
    let flags = parse(
        &[
            Flag::text("api", ""),
            Flag::text("token", ""),
            Flag::text("config", AGENT_CONF_PATH),
            Flag::text("api-host", ""),
            Flag::list("device-key"),
            Flag::list("log-key"),
            Flag::boolean("forget-devices", false),
            Flag::boolean("forget-log-keys", false),
        ],
        args,
        false,
    )?;
    ensure!(
        !flags.text("api").is_empty() && !flags.text("token").is_empty(),
        "both --api and --token are required"
    );
    let base = credential::validate_api(flags.text("api"))?;
    let endpoint = flags.text("api-host");
    if !endpoint.is_empty() {
        credential::validate_api_host(endpoint)?;
    }
    for key in flags.list("device-key") {
        crate::host::authority::keys::parse_device_key(key)?;
    }
    for key in flags.list("log-key") {
        crate::host::authority::keys::parse_log_key(key)?;
    }
    let path = Path::new(flags.text("config"));
    let previous = credential::read_agent_conf(path)?;
    let probe = Probe::default();
    let report = Observer::new(&probe, || ctx.check().is_err()).report(runtime::VERSION, None);
    if !report.server.ready() {
        eprintln!(
            "warning: this box reports state {:?} -- enrolling anyway",
            report.server.state
        );
    }
    let mut conf = exchange(
        ctx,
        &client()?,
        &base,
        flags.text("token"),
        endpoint,
        &report,
    )?;
    let (keys, dropped) = carry_keys(
        &previous.operator_keys,
        &previous.server_id,
        &conf.server_id,
        &flags
            .list("device-key")
            .iter()
            .map(|key| key.trim().to_string())
            .collect::<Vec<_>>(),
        flags.boolean("forget-devices"),
    );
    conf.operator_keys = keys;
    let (keys, logs_dropped) = carry_keys(
        &previous.log_keys,
        &previous.server_id,
        &conf.server_id,
        &flags
            .list("log-key")
            .iter()
            .map(|key| key.trim().to_string())
            .collect::<Vec<_>>(),
        flags.boolean("forget-log-keys"),
    );
    conf.log_keys = keys;
    credential::write_agent_conf(path, &conf)
        .map_err(|e| anyhow::anyhow!("enrolled, but could not store the credential: {e}"))?;
    writeln!(output, "enrolled as {}", conf.server_id)?;
    writeln!(
        output,
        "{}",
        if conf.can_serve() {
            "this box can answer for itself; start komizo-api to serve it"
        } else {
            "this service issued no registry key, so this box reports but does not serve"
        }
    )?;
    for (kind, dropped, forget) in [
        ("device(s)", dropped, flags.boolean("forget-devices")),
        (
            "account(s) that could read its logs",
            logs_dropped,
            flags.boolean("forget-log-keys"),
        ),
    ] {
        if dropped > 0 {
            if forget {
                writeln!(output, "dropped {dropped} {kind}")?;
            } else {
                eprintln!(
                    "warning: this box now reports as {}, which differs from its previous server, so {dropped} {kind} were dropped",
                    conf.server_id
                );
            }
        }
    }
    if conf.operator_keys.is_empty() {
        writeln!(
            output,
            "no local command keys: observations only; manage root actions over SSH"
        )?;
    } else {
        writeln!(
            output,
            "root actions require one of these {} locally planted device(s):",
            conf.operator_keys.len()
        )?;
        for key in conf.operator_keys.iter() {
            writeln!(
                output,
                "    {}",
                crate::host::authority::keys::fingerprint(key)
            )?;
        }
    }
    if !conf.log_keys.is_empty() {
        writeln!(
            output,
            "{} account(s) may read this box's logs:",
            conf.log_keys.len()
        )?;
        for key in conf.log_keys.iter() {
            writeln!(
                output,
                "    {}",
                crate::host::authority::keys::fingerprint(key)
            )?;
        }
    } else if !conf.operator_keys.is_empty() {
        writeln!(
            output,
            "no log keys -- only the planted device(s) may read this box's logs."
        )?;
    } else {
        writeln!(
            output,
            "no log keys, so this box serves no logs. That is not a fault:\nkomizo cannot read them, which is the point -- set a log passphrase\nin the app, then re-run this with --log-key kmz_log_..."
        )?;
    }
    Ok(())
}
pub fn unenrol(args: &[String], output: &mut dyn std::io::Write) -> Result<()> {
    let flags = parse(&[Flag::text("config", AGENT_CONF_PATH)], args, false)?;
    match std::fs::remove_file(flags.text("config")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    };
    writeln!(
        output,
        "this box no longer reports to a komizo service\nrevoke its token on the dashboard as well -- removing the file does not"
    )?;
    Ok(())
}
