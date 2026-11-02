use super::{
    client::{Cli, common},
    protocol, state, validate,
};
use crate::{flags::Flag, host::authority::quote};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
pub fn set_command(app: &str, name: &str, uid: &str, file: bool) -> Result<String> {
    ensure!(!name.is_empty(), "--name is required: the secret to write");
    if file {
        ensure!(
            !matches!(name, "." | ".."),
            "--name {} is not a file name",
            quote(name)
        );
        ensure!(
            !name.starts_with(['.', '-']),
            "a file secret's name must not start with '.' or '-': {}",
            quote(name)
        );
        ensure!(
            !name.contains(['/', ' ', '\t', '\n']),
            "a file secret's name must not contain a slash or whitespace: {}",
            quote(name)
        );
        ensure!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "a file secret's name may use letters, digits, dot, underscore and hyphen: {}",
            quote(name)
        );
    } else {
        ensure!(
            uid.is_empty(),
            "--uid applies only to --file: an env value has no owner of its own"
        );
        ensure!(
            name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "an env secret's name may use letters, digits and underscore: {}.\n    A name like this usually wants --file.",
            quote(name)
        );
    }
    let mut command =
        format!("komizo-box workload owner-secret --policy /etc/komizo/workloads/{app}.json");
    if !uid.is_empty() {
        ensure!(
            uid.parse::<i64>().is_ok(),
            "--uid must be numeric: {}",
            quote(uid)
        );
        command.push_str(&format!(" --uid {uid}"));
    }
    if file {
        command.push_str(" --file");
    }
    command.push_str(&format!(" --name {name}"));
    Ok(command)
}
pub fn valid_name(app: &str, name: &str) -> bool {
    if let Some(name) = name.strip_prefix("file:") {
        set_command(app, name, "", true).is_ok()
    } else {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }
}
pub fn names(list: &str) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut result = vec![];
    for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        ensure!(
            valid_name("listing", name),
            "secret names are letters, digits and underscore, or file:NAME; got {}",
            quote(name)
        );
        if seen.insert(name) {
            result.push(name.into());
        }
    }
    ensure!(!result.is_empty(), "no secret names given");
    Ok(result)
}
pub fn unset_plan(
    app: &str,
    host: &str,
    wanted: &str,
    keep: &str,
    list: bool,
    yes: bool,
) -> Result<BTreeMap<String, String>> {
    ensure!(
        wanted.is_empty() || keep.is_empty(),
        "pass --name (what to remove) or --keep (what survives), not both"
    );
    ensure!(
        !list || (wanted.is_empty() && keep.is_empty()),
        "--list only reads; drop --name/--keep, or drop --list"
    );
    if list {
        return Ok(BTreeMap::from([
            ("APP_NAME".into(), app.into()),
            ("LIST".into(), "1".into()),
        ]));
    }
    ensure!(
        !wanted.is_empty() || !keep.is_empty(),
        "nothing to do -- pass --name, --keep, or --list to see what is there"
    );
    let parsed = names(if keep.is_empty() { wanted } else { keep })?;
    if !yes {
        let what = if keep.is_empty() {
            format!("removes {} from", parsed.join(", "))
        } else {
            format!("removes everything except {} from", parsed.join(", "))
        };
        anyhow::bail!(
            "this {what} /srv/{app}/secrets.env on {host}, and a deleted value may be the only copy.\n    The box keeps a dated root-only backup beside the file.\n    Re-run with --yes if that is what you want."
        );
    }
    ensure!(
        keep.is_empty() || parsed.iter().all(|name| !name.starts_with("file:")),
        "--keep accepts only environment secret names"
    );
    let mut environment = BTreeMap::from([
        ("APP_NAME".into(), app.into()),
        ("NAMES".into(), parsed.join(" ")),
    ]);
    if !keep.is_empty() {
        environment.insert("KEEP".into(), "1".into());
    }
    Ok(environment)
}
pub fn set(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("app", ""),
        Flag::text("name", ""),
        Flag::boolean("file", false),
        Flag::text("from", ""),
        Flag::text("uid", ""),
    ]);
    let flags = cli.parse(&spec, args, "every input must be a flag")?;
    let app = flags.text("app");
    validate::app(app).map_err(protocol::local)?;
    let command = set_command(
        app,
        flags.text("name"),
        flags.text("uid"),
        flags.boolean("file"),
    )
    .map_err(protocol::local)?;
    let value = if matches!(flags.text("from"), "" | "-") {
        cli.body(1 << 20)
    } else {
        state::read_file(Path::new(flags.text("from")), 1 << 20, false)
    }
    .map_err(protocol::local)?;
    ensure!(
        !value.is_empty(),
        "the value is empty -- refusing to write an empty secret.\n    If you mean to remove it, that is `komizo unset-secret`."
    );
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    cli.stream(&remote, &command, &value)?;
    cli.receipt(
        "set-secret",
        &remote,
        app,
        json!({"name":flags.text("name"),"file":flags.boolean("file")}),
    )
}
pub fn unset(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("app", ""),
        Flag::text("name", ""),
        Flag::text("keep", ""),
        Flag::boolean("list", false),
        Flag::boolean("yes", false),
    ]);
    let flags = cli.parse(&spec, args, "every input must be a flag")?;
    let app = flags.text("app");
    validate::app(app).map_err(protocol::local)?;
    let mut env = unset_plan(
        app,
        flags.text("host"),
        flags.text("name"),
        flags.text("keep"),
        flags.boolean("list"),
        flags.boolean("yes"),
    )
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    if cli.machine && flags.boolean("list") {
        env.insert("MACHINE_NAMES".into(), "1".into());
        let mut output = protocol::Text::with_limit(64 << 10);
        let heard = remote.script(
            &cli.context,
            crate::scripts::ALPINE_UNSET_SECRET,
            &env,
            &mut output,
            cli.progress,
        );
        heard.result?;
        ensure!(!output.truncated, "secret-name listing exceeds 64 KiB");
        let body = String::from_utf8(output.body().to_vec())?;
        let names: Vec<_> = body
            .strip_suffix('\n')
            .unwrap_or(&body)
            .split('\n')
            .filter(|name| !name.is_empty())
            .map(String::from)
            .collect();
        ensure!(
            names.iter().all(|name| valid_name(app, name)),
            "invalid secret-name response"
        );
        return cli.receipt(
            "unset-secret list",
            &remote,
            app,
            json!({"names":names,"values_omitted":true}),
        );
    }
    cli.script(&remote, crate::scripts::ALPINE_UNSET_SECRET, &env)?;
    cli.receipt("unset-secret",&remote,app,json!({"names":env.get("NAMES").map(|s|s.split_whitespace().collect::<Vec<_>>()).unwrap_or_default(),"keep":!flags.text("keep").is_empty()}))
}
