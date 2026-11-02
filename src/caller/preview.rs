use super::{
    client::{Cli, common},
    deployment, protocol, state, validate,
};
use crate::{
    flags::{Flag, Flags},
    host::preview::profile,
};
use anyhow::{Result, ensure};
use serde_json::json;
use std::path::Path;
pub fn run(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let (sub, args) = if args.first().is_some_and(|s| !s.starts_with('-')) {
        (args[0].as_str(), &args[1..])
    } else {
        ("up", args)
    };
    let mut spec = common();
    spec.extend([
        Flag::text("directory", "."),
        Flag::text("app", ""),
        Flag::text("profile-file", ""),
        Flag::integer("pr", 0),
    ]);
    let mut flags = Flags::parse(&spec, args).map_err(|e| {
        if e.is::<crate::flags::Help>() {
            e
        } else {
            protocol::local(e)
        }
    })?;
    let project = flags.text("host").is_empty();
    let directory = flags.text("directory").to_string();
    let mut images = flags.args.clone();
    let profile = (|| -> Result<Option<Vec<u8>>> {
        ensure!(
            ["up", "down", "resolve", "ls", "gc", "database", "configure"].contains(&sub),
            "unknown preview subcommand {sub}"
        );
        ensure!(
            sub != "database"
                || (flags.text("app").is_empty() && flags.integer("pr") == 0 && images.is_empty()),
            "preview database accepts only host connection flags"
        );
        if project {
            let d =
                state::default_target(Path::new(&directory), &state::target_path()?, &mut flags)?;
            if sub == "up" && images.is_empty() {
                let revision = deployment::revision(cli, &directory)?;
                for image in d.unwrap().images.iter() {
                    images.push(image.replace("{revision}", &revision));
                }
            }
        }
        if ["up", "down", "resolve"].contains(&sub) {
            validate::app(flags.text("app"))?;
            ensure!(flags.integer("pr") > 0, "--pr must be a positive integer");
        }
        ensure!(
            sub != "up" || !images.is_empty(),
            "preview up needs at least one image"
        );
        for image in &images {
            ensure!(
                !image.is_empty()
                    && image
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-:/@=".contains(&b)),
                "invalid image reference"
            );
        }
        if sub == "configure" {
            validate::app(flags.text("app"))?;
            ensure!(
                !flags.text("profile-file").is_empty()
                    && flags.integer("pr") == 0
                    && images.is_empty(),
                "preview configure requires --app and --profile-file only"
            );
            let body = state::read_file(Path::new(flags.text("profile-file")), 1 << 20, false)?;
            profile::parse(&body)?;
            Ok(Some(body))
        } else {
            ensure!(
                flags.text("profile-file").is_empty(),
                "--profile-file is only for preview configure"
            );
            Ok(None)
        }
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let mut request = vec!["preview".into(), sub.into()];
    if ["up", "down", "resolve", "configure"].contains(&sub) {
        request.extend(["--app".into(), flags.text("app").into()]);
    }
    if ["up", "down", "resolve"].contains(&sub) {
        request.extend(["--pr".into(), flags.integer("pr").to_string()]);
    }
    request.extend(images);
    if sub == "down" && cli.machine {
        cli.script(
            &remote,
            &super::reach::box_command(&request),
            &Default::default(),
        )?;
        return cli.receipt(
            "preview down",
            &remote,
            flags.text("app"),
            json!({"pr":flags.integer("pr")}),
        );
    }
    let body = remote.capture(
        &cli.context,
        &super::reach::box_command(&request),
        profile.as_deref(),
        protocol::MAX_OUTPUT,
    )?;
    if cli.machine {
        cli.result.protocol(&body)
    } else {
        cli.text(&body)
    }
}
