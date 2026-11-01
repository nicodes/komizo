//! Workstation provisioning preserves each app's recorded identity and authority.
use super::{
    artifacts,
    client::{Cli, common},
    doctor, keys, protocol, state,
    transport::Remote,
    validate,
};
use crate::{
    flags::Flag,
    host::{paths, types::Report},
    scripts,
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{IsTerminal, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};
pub const DEFAULT_PROXY: &str = "ghcr.io/nicodes/platform-proxy@sha256:25d6dabfad5ff85e7d2b449f1662a981e785d6d7d51772585e88e19e207c13a3";
pub fn bit(value: bool) -> String {
    if value { "1" } else { "0" }.into()
}
pub fn image(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-:/@".contains(&b))
}
pub fn proxy_env(
    network: &str,
    image_value: &str,
    ask: &str,
    directory: &str,
) -> Result<BTreeMap<String, String>> {
    ensure!(!network.is_empty(), "--network is required");
    validate::network(network)?;
    ensure!(image(image_value), "invalid proxy image");
    ensure!(
        ask.is_empty()
            || ((ask.starts_with("http://") || ask.starts_with("https://"))
                && ask
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:/_?=~%&-".contains(&b))),
        "invalid --tls-ask URL"
    );
    ensure!(
        directory.is_empty()
            || (directory.starts_with('/')
                && directory != "/"
                && !directory.ends_with('/')
                && !directory.contains("//")
                && !directory.contains("/../")
                && !directory.ends_with("/..")
                && directory
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))),
        "invalid --tls-config-dir"
    );
    Ok(BTreeMap::from([
        ("SHARED_NETWORK".into(), network.into()),
        ("PROXY_IMAGE".into(), image_value.into()),
        ("TLS_ASK".into(), ask.into()),
        ("TLS_CONFIG_DIR".into(), directory.into()),
        ("API_SOCKET_DIR".into(), paths::API_SOCKET_DIR.into()),
    ]))
}
fn initialize(cli: &mut Cli<'_>, remote: &Remote, network: &str, image: &str) -> Result<()> {
    cli.script(
        remote,
        scripts::ALPINE_INIT,
        &BTreeMap::from([("SHARED_NETWORK".into(), network.into())]),
    )?;
    artifacts::install(cli, remote)?;
    cli.script(
        remote,
        scripts::ALPINE_PROXY,
        &proxy_env(network, image, "", "")?,
    )
}
pub fn proxy(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("network", "edge"),
        Flag::text("image", DEFAULT_PROXY),
        Flag::text("tls-ask", ""),
        Flag::text("tls-config-dir", ""),
    ]);
    let flags = cli.parse(&spec, args, "proxy accepts only flags")?;
    let env = proxy_env(
        flags.text("network"),
        flags.text("image"),
        flags.text("tls-ask"),
        flags.text("tls-config-dir"),
    )
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    cli.script(&remote, scripts::ALPINE_PROXY, &env)?;
    cli.receipt(
        "proxy",
        &remote,
        "",
        json!({"network":flags.text("network"),"image":flags.text("image")}),
    )
}
pub fn init(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("network", "edge"),
        Flag::text("proxy-image", DEFAULT_PROXY),
    ]);
    let flags = cli.parse(&spec, args, "init accepts only flags")?;
    proxy_env(flags.text("network"), flags.text("proxy-image"), "", "").map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    initialize(
        cli,
        &remote,
        flags.text("network"),
        flags.text("proxy-image"),
    )?;
    cli.receipt(
        "init",
        &remote,
        "",
        json!({"network":flags.text("network")}),
    )
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct Record {
    pub name: String,
    pub user: String,
    pub config: String,
    pub dir: String,
}
pub fn records(body: &str) -> Vec<Record> {
    body.split('\n')
        .filter_map(|line| {
            let fields: Vec<_> = line.splitn(4, '\t').map(str::trim).collect();
            (fields.len() == 4).then(|| Record {
                name: fields[0].into(),
                user: fields[1].into(),
                config: fields[2].into(),
                dir: fields[3].into(),
            })
        })
        .collect()
}
impl Record {
    pub fn check(&self) -> Result<()> {
        validate::app(&self.name)
            .map_err(|_| anyhow::anyhow!("{} is not a valid app record filename", self.name))?;
        ensure!(!self.user.is_empty(), "record names no CI_USER");
        validate::user(&self.user)?;
        ensure!(!self.config.is_empty(), "record names no CONFIG_IMAGE");
        validate::config_image(&self.config)?;
        ensure!(!self.dir.is_empty(), "record names no APP_DIR");
        validate::app_dir(&self.dir)
    }
    pub fn environment(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("APP_NAME".into(), self.name.clone()),
            ("CI_USER".into(), self.user.clone()),
            ("CONFIG_IMAGE".into(), self.config.clone()),
            ("APP_DIR".into(), self.dir.clone()),
            ("CI_PUBKEY".into(), String::new()),
            ("KNOWN_AS".into(), String::new()),
            ("CLEAR_KNOWN_AS".into(), "0".into()),
            ("HARDEN_SSH".into(), "0".into()),
            ("DEFER_SSHD_RELOAD".into(), "1".into()),
        ])
    }
}
pub fn records_command() -> String {
    format!(
        r#"for f in {}/*.env; do
[ -f "$f" ] || continue
n="${{f##*/}}"; n="${{n%.env}}"
printf '%s\t%s\t%s\t%s\n' "$n" \
 "$(sed -n 's/^CI_USER=//p' "$f" | tr -d '\r' | head -n 1)" \
 "$(sed -n 's/^CONFIG_IMAGE=//p' "$f" | tr -d '\r' | head -n 1)" \
 "$(sed -n 's/^APP_DIR=//p' "$f" | tr -d '\r' | head -n 1)"
done"#,
        paths::APPS_DIR
    )
}
pub fn update(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("network", "edge"),
        Flag::text("proxy-image", DEFAULT_PROXY),
        Flag::boolean("proxy", false),
        Flag::boolean("no-proxy", false),
    ]);
    let flags = cli.parse(&spec, args, "update accepts only flags")?;
    (|| -> Result<()> {
        ensure!(
            !(flags.boolean("proxy") && flags.boolean("no-proxy")),
            "--proxy and --no-proxy ask for opposite things"
        );
        proxy_env(flags.text("network"), flags.text("proxy-image"), "", "")?;
        Ok(())
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let has_proxy = flags.boolean("proxy")
        || (!flags.boolean("no-proxy")
            && remote
                .fetch::<Report>(&cli.context, &["report".into()])
                .is_ok_and(|r| r.proxy.is_some()));
    cli.script(
        &remote,
        scripts::ALPINE_INIT,
        &BTreeMap::from([("SHARED_NETWORK".into(), flags.text("network").into())]),
    )?;
    artifacts::install(cli, &remote)?;
    let refreshed = (|| -> Result<()> {
        let records = records(&remote.quiet(&cli.context, &records_command())?);
        let mut failed = vec![];
        let mut successes = 0;
        for record in &records {
            let result = record
                .check()
                .and_then(|()| cli.script(&remote, scripts::alpine(), &record.environment()));
            if let Err(e) = result {
                cli.note(&format!("could not refresh {}: {e}", record.name))?;
                failed.push(record.name.clone());
            } else {
                successes += 1;
            }
        }
        if successes > 0
            && let Err(e) = cli.script(&remote, scripts::ALPINE_RELOAD_SSHD, &BTreeMap::new())
        {
            cli.note(&format!(
                "apps updated; sshd reload failed: {e}; rules take effect on the next reload"
            ))?;
        }
        ensure!(
            failed.is_empty(),
            "these apps still carry their previous deploy scripts: {}; inspect their records and rerun add",
            failed.join(", ")
        );
        Ok(())
    })();
    let proxy = if has_proxy && !flags.boolean("no-proxy") {
        cli.script(
            &remote,
            scripts::ALPINE_PROXY,
            &proxy_env(flags.text("network"), flags.text("proxy-image"), "", "")?,
        )
    } else {
        Ok(())
    };
    cli.receipt("update",&remote,"",json!({"apps_refreshed":refreshed.is_ok(),"proxy_updated":has_proxy&&!flags.boolean("no-proxy")&&proxy.is_ok()}))?;
    match (refreshed, proxy) {
        (Err(a), Err(b)) => Err(anyhow::anyhow!("{a}; {b}")),
        (Err(e), _) | (_, Err(e)) => Err(e),
        _ => Ok(()),
    }
}
fn write_key(path: &Path, pair: &keys::Keypair) -> Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    for (path, body, mode) in [
        (path.to_path_buf(), pair.private.to_vec(), 0o600),
        (
            path.with_file_name(format!(
                "{}.pub",
                path.file_name().unwrap_or_default().to_string_lossy()
            )),
            format!("{}\n", pair.public).into_bytes(),
            0o644,
        ),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    Ok(())
}
pub fn add(cli: &mut Cli<'_>, args: &[String], receipt: bool) -> Result<()> {
    let mut spec = common();
    for name in [
        "app",
        "config",
        "user",
        "app-dir",
        "key",
        "known-as",
        "task-script",
        "scoped-env",
        "scoped-env-spec",
    ] {
        spec.push(Flag::text(name, ""));
    }
    for name in [
        "preview",
        "harden-sshd",
        "rotate-key",
        "keep-key",
        "reuse-key",
        "no-instructions",
    ] {
        spec.push(Flag::boolean(name, false));
    }
    let flags = cli.parse(&spec, args, "add accepts only flags")?;
    let app = flags.text("app");
    let user = if flags.text("user").is_empty() {
        format!("komizo-{app}")
    } else {
        flags.text("user").into()
    };
    let rotate = flags.boolean("rotate-key");
    let keep = flags.boolean("keep-key");
    let reuse = flags.boolean("reuse-key");
    let path = flags.text("key");
    let scoped = (|| -> Result<Option<state::Scoped>> {
        validate::app(app)?;
        validate::user(&user)?;
        ensure!(user != "root", "the deploy user must not be root");
        validate::app_dir(flags.text("app-dir"))?;
        ensure!(
            !rotate || !keep,
            "--rotate-key and --keep-key ask for opposite things"
        );
        ensure!(
            !reuse || (!path.is_empty() && !rotate && !keep),
            "--reuse-key requires --key and cannot be combined with --rotate-key or --keep-key"
        );
        ensure!(
            !flags.boolean("no-instructions") || !path.is_empty() || keep,
            "--no-instructions requires --key or --keep-key"
        );
        ensure!(
            keep || !path.is_empty() || (!cli.machine && std::io::stdout().is_terminal()),
            "private deploy keys cannot be printed to a pipe; use --key PRIVATE_FILE or --keep-key"
        );
        if !rotate || !flags.text("config").is_empty() {
            validate::config_image(flags.text("config"))?;
        }
        if flags.text("scoped-env-spec").is_empty() {
            ensure!(
                flags.text("scoped-env").is_empty(),
                "--scoped-env requires --scoped-env-spec"
            );
            Ok(None)
        } else {
            let s = state::read_scoped(Path::new(flags.text("scoped-env-spec")))?;
            ensure!(
                !flags.seen.contains("scoped-env") || flags.text("scoped-env") == s.values.profile,
                "scoped profile differs from specification"
            );
            Ok(Some(s))
        }
    })()
    .map_err(protocol::local)?;
    let task = if flags.text("task-script").is_empty() {
        vec![]
    } else {
        let b = state::read_file(Path::new(flags.text("task-script")), 64 << 10, false)
            .map_err(protocol::local)?;
        ensure!(b.starts_with(b"#!"), "task script must have a shebang");
        b
    };
    let aliases: Vec<String> = flags
        .text("known-as")
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(String::from)
        .collect();
    for host in &aliases {
        validate::host(host).map_err(protocol::local)?;
    }
    let mut remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    if flags.boolean("harden-sshd") && !rotate {
        remote
            .quiet(&cli.context, "test -s /root/.ssh/authorized_keys")
            .map_err(|_| {
                anyhow::anyhow!("root has no authorized key; refusing global SSH hardening")
            })?;
    }
    let config = if flags.text("config").is_empty() {
        remote
            .quiet(
                &cli.context,
                &format!(
                    "sed -n 's/^CONFIG_IMAGE=//p' {} 2>/dev/null | head -n 1",
                    scripts::sh_quote(&format!("{}/{app}.env", paths::APPS_DIR))
                ),
            )?
            .trim()
            .to_string()
    } else {
        flags.text("config").into()
    };
    ensure!(
        !config.is_empty(),
        "could not read the current config image; is the app registered?"
    );
    validate::config_image(&config)?;
    let pair = if keep {
        None
    } else if reuse {
        Some(keys::read_existing(
            Path::new(path),
            &keys::comment(&user, &remote.target.host),
        )?)
    } else {
        let p = keys::generate(&keys::comment(&user, &remote.target.host))?;
        if !path.is_empty() {
            write_key(Path::new(path), &p)?;
        }
        Some(p)
    };
    let mut env = BTreeMap::from([
        ("APP_NAME".into(), app.into()),
        ("CI_USER".into(), user),
        ("CONFIG_IMAGE".into(), config.clone()),
        ("KNOWN_AS".into(), aliases.join(",")),
        (
            "CI_PUBKEY".into(),
            pair.as_ref().map(|p| p.public.clone()).unwrap_or_default(),
        ),
        (
            "HARDEN_SSH".into(),
            bit(flags.boolean("harden-sshd") && !rotate),
        ),
        ("TASKS_SET".into(), bit(flags.seen.contains("task-script"))),
        ("TASK_SCRIPT_B64".into(), STANDARD.encode(task)),
        (
            "SCOPED_ENV".into(),
            scoped
                .as_ref()
                .map(|s| s.values.profile.clone())
                .unwrap_or_else(|| flags.text("scoped-env").into()),
        ),
        (
            "SCOPED_ENV_SET".into(),
            bit(flags.seen.contains("scoped-env") || scoped.is_some()),
        ),
        ("SCOPED_SPEC_SET".into(), bit(scoped.is_some())),
        (
            "SCOPED_SCHEMA".into(),
            scoped
                .as_ref()
                .map(|s| s.values.schema.to_string())
                .unwrap_or_default(),
        ),
        (
            "SCOPED_FILES".into(),
            scoped
                .as_ref()
                .map(|s| s.values.files.join(","))
                .unwrap_or_default(),
        ),
        (
            "SCOPED_PROVISION_B64".into(),
            scoped
                .as_ref()
                .map(|s| STANDARD.encode(&s.provision))
                .unwrap_or_default(),
        ),
        (
            "SCOPED_STATUS_B64".into(),
            scoped
                .as_ref()
                .map(|s| STANDARD.encode(&s.status))
                .unwrap_or_default(),
        ),
        ("PREVIEW".into(), bit(flags.boolean("preview"))),
        ("PREVIEW_SET".into(), bit(flags.seen.contains("preview"))),
        (
            "CLEAR_KNOWN_AS".into(),
            bit(flags.seen.contains("known-as") && aliases.is_empty()),
        ),
    ]);
    if !flags.text("app-dir").is_empty() {
        env.insert("APP_DIR".into(), flags.text("app-dir").into());
    }
    cli.script(&remote, scripts::alpine(), &env)?;
    remote.target.aliases = aliases;
    let known_hosts = remote.read_known_hosts(&cli.context)?;
    if !receipt {
        return Ok(());
    }
    if cli.machine {
        return cli.emit(json!({"app":app,"host":remote.target.addr(),"registered":true,"key_file":path,"key_unchanged":keep,"known_hosts":known_hosts}));
    }
    if !flags.boolean("no-instructions") {
        cli.text(format!("\nRegistered {app} on {}\nKOMIZO_SERVER_URL={}\nKOMIZO_KNOWN_HOSTS:\n{known_hosts}\nConfig image: {config}\n",remote.target.addr(),remote.target.host).as_bytes())?;
        if let Some(pair) = pair {
            if path.is_empty() {
                cli.text(b"KOMIZO_SSH_KEY:\n")?;
                cli.text(&pair.private)?;
            } else {
                cli.text(format!("Deploy key: {path}\n").as_bytes())?;
            }
        }
    }
    Ok(())
}
pub fn remove(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("app", ""),
        Flag::boolean("yes", false),
        Flag::boolean("keep-data", false),
    ]);
    let flags = cli.parse(&spec, args, "remove accepts only flags")?;
    (|| -> Result<()> {
        validate::app(flags.text("app"))?;
        ensure!(
            flags.boolean("yes"),
            "remove stops and unregisters the app; review --keep-data and repeat with --yes"
        );
        Ok(())
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    cli.script(
        &remote,
        scripts::ALPINE_REMOVE,
        &BTreeMap::from([
            ("APP_NAME".into(), flags.text("app").into()),
            ("KEEP_DATA".into(), bit(flags.boolean("keep-data"))),
        ]),
    )?;
    cli.receipt(
        "remove",
        &remote,
        flags.text("app"),
        json!({"keep_data":flags.boolean("keep-data")}),
    )
}
pub fn script(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    ensure!(args.len() <= 1, "script accepts one script name");
    let body = match args.first().map(String::as_str).unwrap_or("add") {
        "add" => scripts::alpine(),
        "init" => scripts::ALPINE_INIT,
        "remove" => scripts::ALPINE_REMOVE,
        "unset-secret" => scripts::ALPINE_UNSET_SECRET,
        "proxy" => scripts::ALPINE_PROXY,
        _ => {
            return Err(protocol::local(anyhow::anyhow!(
                "unknown provisioning script"
            )));
        }
    };
    cli.text(body.as_bytes())
}
pub fn setup(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([Flag::text("definition", ""), Flag::text("key", "")]);
    let flags = cli.parse(&spec, args, "setup accepts only flags")?;
    ensure!(
        !flags.text("definition").is_empty() || flags.text("key").is_empty(),
        "--key requires --definition"
    );
    let definition = if flags.text("definition").is_empty() {
        None
    } else {
        Some(state::read_definition(Path::new(flags.text("definition"))).map_err(protocol::local)?)
    };
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let doctor = doctor::decode(
        &remote.target.addr(),
        &remote.quiet(&cli.context, doctor::SCRIPT)?,
    )?;
    if !doctor.supported {
        cli.emit(&doctor)?;
        anyhow::bail!("server prerequisites failed; setup made no installation changes");
    }
    if !doctor.installed {
        initialize(cli, &remote, "edge", DEFAULT_PROXY)?;
    }
    let report: Report = remote.fetch(&cli.context, &["report".into()])?;
    ensure!(
        report.server.state == "ready",
        "setup did not establish a ready host; inspect report before proceeding"
    );
    let mut result =
        json!({"version":1,"host":remote.target.addr(),"prepared":true,"app_registered":false});
    if let Some(d) = definition {
        let caps = remote
            .journey(
                &cli.context,
                &["workload".into(), "capabilities".into()],
                &[],
            )
            .and_then(|b| crate::strict::value(&b, 4 << 20));
        ensure!(
            caps.is_ok_and(|v| v["version"] == 1 && v["policy_bootstrap"] == true),
            "installed executor needs an explicit komizo upgrade before application setup; no registration or key change was made"
        );
        let existing = report.apps.iter().find(|a| a.name == d.app);
        if let Some(a) = existing {
            ensure!(
                a.config_image == d.config,
                "existing application configuration family differs; review a migration"
            );
        }
        let mut key = flags.text("key").to_string();
        if existing.is_none() {
            if key.is_empty() {
                let dir = state::target_path()?.parent().unwrap().join("keys");
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)?;
                let m = fs::symlink_metadata(&dir)?;
                ensure!(
                    m.is_dir() && m.mode() & 0o077 == 0,
                    "key directory must be private and regular"
                );
                let digest = format!(
                    "{:x}",
                    Sha256::digest(format!("{}:{}", remote.target.addr(), remote.target.port))
                );
                key = dir
                    .join(format!("{}-{}", d.app, &digest[..12]))
                    .to_string_lossy()
                    .into();
            }
            let mut add_args = vec![
                "--host".into(),
                remote.target.addr(),
                "--port".into(),
                remote.target.port.to_string(),
                "--app".into(),
                d.app.clone(),
                "--config".into(),
                d.config.clone(),
                "--key".into(),
                key.clone(),
                "--no-instructions".into(),
            ];
            match fs::symlink_metadata(&key) {
                Ok(_) => {
                    keys::read_existing(
                        Path::new(&key),
                        &keys::comment(&format!("komizo-{}", d.app), &remote.target.host),
                    )?;
                    add_args.push("--reuse-key".into());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            };
            add(cli, &add_args, false)?;
        }
        let body = remote.journey(
            &cli.context,
            &[
                "workload".into(),
                "policy-bootstrap".into(),
                "--app".into(),
                d.app.clone(),
            ],
            &serde_json::to_vec(&d.policy)?,
        )?;
        let authority = crate::strict::value(&body, 4 << 20)?;
        ensure!(
            authority["version"] == 1
                && authority["app"] == d.app
                && authority["installed"] == true
                && authority["deployment_enabled"] == true,
            "invalid bootstrap policy receipt"
        );
        result["app"] = d.app.clone().into();
        result["app_registered"] = true.into();
        result["key_unchanged"] = existing.is_some().into();
        result["authority"] = authority;
        if existing.is_none() {
            result["deploy_key_file"] = key.into();
        }
        if !d.policy.source_repository.is_empty()
            && let Err(e) = state::bind_target(
                &state::target_path()?,
                &d.policy.source_repository,
                &remote.target,
                &d.app,
            )
        {
            cli.emit(result)?;
            anyhow::bail!("host setup completed; local target binding needs attention: {e}");
        }
        result["next_action"] = json!([
            "komizo",
            "--json",
            "deploy",
            "--host",
            remote.target.addr(),
            "--port",
            remote.target.port.to_string(),
            "--app",
            d.app,
            "--version",
            "COMMIT"
        ]);
    }
    cli.emit(result)
}
