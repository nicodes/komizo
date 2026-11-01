//! Preview effects address only derived resources and restore rejected route changes.
use super::{Record, compose, knob::Knob};
use crate::workload::activation::Context;
use anyhow::{Result, anyhow, ensure};
use std::{
    fs::{self, File, Permissions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
};
pub type Run<'a> = dyn FnMut(&Context, &str, &[&str]) -> Result<String> + 'a;
pub const NETWORKS_FORMAT: &str =
    r#"{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}"#;
pub const OWNER_FORMAT: &str = r#"{{index .Labels "io.komizo.preview"}}"#;
fn owned_network(ctx: &Context, run: &mut Run<'_>, project: &str, ingress: bool) -> Result<String> {
    let kind = if ingress { "ingress" } else { "backend" };
    let network = format!("{project}-{kind}");
    match run(
        ctx,
        "",
        &["network", "inspect", &network, "--format", OWNER_FORMAT],
    ) {
        Ok(owner) => {
            if ingress {
                ensure!(
                    owner.trim() == project,
                    "preview ingress belongs to another workload"
                );
            } else {
                ensure!(
                    owner.trim() == project,
                    "preview backend name belongs to an unapproved network"
                );
            }
        }
        Err(_) => {
            let label = format!("io.komizo.preview={project}");
            let mut args = vec!["network", "create"];
            if ingress {
                args.push("--internal");
            }
            args.extend(["--label", &label, &network]);
            run(ctx, "", &args).map_err(|e| anyhow!("preview {kind} creation failed: {e}"))?;
        }
    }
    Ok(network)
}
pub fn ensure_ingress(
    ctx: &Context,
    run: &mut Run<'_>,
    project: &str,
    proxy: &str,
) -> Result<String> {
    let network = owned_network(ctx, run, project, true)?;
    let attached = run(ctx, "", &["inspect", proxy, "--format", NETWORKS_FORMAT])?;
    if !attached.split_whitespace().any(|name| name == network) {
        run(ctx, "", &["network", "connect", &network, proxy])?;
    }
    Ok(network)
}
pub fn ensure_backend(
    ctx: &Context,
    run: &mut Run<'_>,
    project: &str,
    database: bool,
) -> Result<()> {
    let network = owned_network(ctx, run, project, false)?;
    if database {
        let attached = run(
            ctx,
            "",
            &["inspect", super::DB_CONTAINER, "--format", NETWORKS_FORMAT],
        )?;
        if !attached.split_whitespace().any(|name| name == network) {
            run(
                ctx,
                "",
                &["network", "connect", &network, super::DB_CONTAINER],
            )
            .map_err(|e| anyhow!("preview database attachment failed: {e}"))?;
        }
    }
    Ok(())
}
pub fn remove_network(
    ctx: &Context,
    run: &mut Run<'_>,
    project: &str,
    proxy: &str,
    ingress: bool,
    database: bool,
) -> Result<()> {
    let kind = if ingress { "ingress" } else { "backend" };
    let network = format!("{project}-{kind}");
    let Ok(owner) = run(
        ctx,
        "",
        &["network", "inspect", &network, "--format", OWNER_FORMAT],
    ) else {
        return Ok(());
    };
    ensure!(
        owner.trim() == project,
        "preview {kind} removal refused: ownership differs"
    );
    if ingress || database {
        let container = if ingress { proxy } else { super::DB_CONTAINER };
        let attached = run(
            ctx,
            "",
            &["inspect", container, "--format", NETWORKS_FORMAT],
        )?;
        for name in attached.split_whitespace() {
            if name == network {
                run(
                    ctx,
                    "",
                    &["network", "disconnect", "--force", &network, container],
                )?;
            }
        }
    }
    run(ctx, "", &["network", "rm", &network])?;
    Ok(())
}
pub fn write_route(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".preview-route-")
        .tempfile_in(parent)?;
    file.as_file()
        .set_permissions(Permissions::from_mode(0o644))?;
    file.write_all(body)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn previous(path: &Path) -> Result<Option<Vec<u8>>> {
    crate::statefile::read(path, 1 << 20)
}
fn restore(path: &Path, previous: Option<&[u8]>) -> Result<()> {
    match previous {
        Some(body) => write_route(path, body),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        },
    }
}
fn caddy(ctx: &Context, run: &mut Run<'_>, proxy: &str, action: &str) -> Result<()> {
    run(
        ctx,
        "",
        &[
            "exec",
            proxy,
            "caddy",
            action,
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ],
    )?;
    Ok(())
}
pub fn apply_route(
    ctx: &Context,
    run: &mut Run<'_>,
    proxy: &str,
    directory: &Path,
    file: &str,
    content: &str,
) -> Result<()> {
    let path = directory.join(file);
    let original = previous(&path)?;
    write_route(&path, content.as_bytes())?;
    if let Err(error) = caddy(ctx, run, proxy, "validate") {
        restore(&path, original.as_deref())?;
        return Err(anyhow!(
            "the combined proxy config does not validate with the new route -- left as it was: {error}"
        ));
    }
    caddy(ctx, run, proxy, "reload")
        .map_err(|e| anyhow!("the route validates but the proxy did not reload: {e}"))
}
pub fn remove_route(
    ctx: &Context,
    run: &mut Run<'_>,
    proxy: &str,
    directory: &Path,
    file: &str,
) -> Result<()> {
    let path = directory.join(file);
    let Some(original) = previous(&path)? else {
        return Ok(());
    };
    fs::remove_file(&path)?;
    if let Err(error) = caddy(ctx, run, proxy, "validate") {
        write_route(&path, &original)?;
        return Err(anyhow!(
            "removing the route broke the combined config -- restored: {error}"
        ));
    }
    caddy(ctx, run, proxy, "reload")
        .map_err(|e| anyhow!("the route is gone but the proxy did not reload: {e}"))
}
pub fn apply_record_route(
    ctx: &Context,
    run: &mut Run<'_>,
    proxy: &str,
    directory: &Path,
    r: &Record,
    k: &Knob,
) -> Result<()> {
    if r.base_path.is_empty() {
        return apply_route(
            ctx,
            run,
            proxy,
            directory,
            &r.route_file,
            &compose::route(r, k),
        );
    }
    let path = directory.join(format!("_preview-path-{}.caddy", r.app));
    let original = previous(&path)?;
    let site = compose::path_site(r, k);
    if original
        .as_ref()
        .is_some_and(|body| body.as_slice() != site.as_bytes())
    {
        let suffix = format!(".{}.route", r.app);
        for entry in fs::read_dir(directory)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with("_preview-pr-") && name.ends_with(&suffix) && name != r.route_file {
                anyhow::bail!(
                    "path preview domain changed while another preview is running; drain the app's previews before changing its domain"
                );
            }
        }
    }
    write_route(&path, site.as_bytes())?;
    if let Err(error) = apply_route(
        ctx,
        run,
        proxy,
        directory,
        &r.route_file,
        &compose::path_route(r),
    ) {
        restore(&path, original.as_deref())?;
        return Err(error);
    }
    Ok(())
}
pub fn sql(ctx: &Context, run: &mut Run<'_>, sql: &str, args: &[&str]) -> Result<()> {
    let mut argv = vec![
        "exec",
        "-i",
        super::DB_CONTAINER,
        "psql",
        "-U",
        super::DB_SUPERUSER,
        "-d",
        super::DB_MAINTENANCE,
    ];
    argv.extend_from_slice(args);
    run(ctx, &format!("{sql}\n"), &argv)?;
    Ok(())
}
pub fn drop_database(ctx: &Context, run: &mut Run<'_>, name: &str) -> Result<()> {
    if name.is_empty() {
        return Ok(());
    }
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
            &format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
        ],
    )
    .map_err(|e| anyhow!("could not drop the preview database {name}: {e}"))?;
    sql(ctx, run, &format!("DROP ROLE IF EXISTS {name};"), &[])
        .map_err(|e| anyhow!("could not drop the preview role {name}: {e}"))
}
pub fn ensure_database_ready(ctx: &Context, run: &mut Run<'_>, allow_start: bool) -> Result<()> {
    let unavailable = || {
        anyhow!(
            "komizo's preview database server ({}) is not running -- run komizo setup for this host to provision it",
            super::DB_CONTAINER
        )
    };
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
    .map_err(|_| unavailable())?;
    if state.trim() != "true" {
        ensure!(allow_start && state.trim() == "false", "{}", unavailable());
        run(ctx, "", &["start", super::DB_CONTAINER])
            .map_err(|e| anyhow!("could not start the provisioned preview database: {e}"))?;
    }
    let mut last = anyhow!("not ready");
    for _ in 0..30 {
        ctx.check()?;
        match run(
            ctx,
            "",
            &[
                "exec",
                super::DB_CONTAINER,
                "pg_isready",
                "-U",
                super::DB_SUPERUSER,
                "-d",
                super::DB_MAINTENANCE,
            ],
        ) {
            Ok(_) => return Ok(()),
            Err(error) => last = error,
        }
        std::thread::sleep(std::time::Duration::from_secs(1).min(ctx.remaining()?));
    }
    Err(anyhow!(
        "komizo's preview database server ({}) is running but never accepted connections: {last}",
        super::DB_CONTAINER
    ))
}
