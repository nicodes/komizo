use super::{model::*, render, validation::*};
use anyhow::{Result, anyhow, ensure};
use std::{collections::BTreeMap, io::Write};

pub fn offline(args: &[String], out: &mut dyn Write) -> Result<()> {
    ensure!(
        args.len() >= 3,
        "expected release validate|render FILE or application validate FILE"
    );
    let body = std::fs::read(&args[2])?;
    ensure!(body.len() <= MAX_DOCUMENT_BYTES, "document exceeds bounds");
    match (args[0].as_str(), args[1].as_str()) {
        ("application", "validate") => {
            ensure!(args.len() == 3, "unexpected validation arguments");
            let application: Application = if args[2].ends_with(".toml") {
                toml::from_str(std::str::from_utf8(&body)?)?
            } else {
                serde_json::from_value(crate::strict::value(&body, MAX_DOCUMENT_BYTES)?)?
            };
            ensure!(
                application.kind == "komizo.application"
                    && application.version == 1
                    && name(&application.application),
                "invalid application identity"
            );
            application.workload.validate()?;
            writeln!(out, "{{\"ok\":true}}")?;
        }
        ("release", "validate") => {
            ensure!(args.len() == 3, "unexpected validation arguments");
            let document = read_release(&body)?;
            writeln!(
                out,
                "{{\"ok\":true,\"release_digest\":\"{}\"}}",
                document.digest
            )?;
        }
        ("release", "render") => {
            let document = read_release(&body)?;
            let mut root = None;
            let mut upstreams = BTreeMap::new();
            let mut http = false;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--assets-root" | "--upstreams" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| anyhow!("missing render argument"))?;
                        if args[i] == "--assets-root" {
                            ensure!(root.is_none(), "duplicate assets root");
                            root = Some(value.clone());
                        } else {
                            upstreams = serde_json::from_value(crate::strict::value(
                                &std::fs::read(value)?,
                                64 << 10,
                            )?)?;
                        }
                        i += 2;
                    }
                    "--http" => {
                        ensure!(!http, "duplicate HTTP fixture flag");
                        http = true;
                        i += 1;
                    }
                    _ => return Err(anyhow!("unknown render argument")),
                }
            }
            out.write_all(
                render::caddy(
                    &document,
                    root.as_deref()
                        .ok_or_else(|| anyhow!("render requires --assets-root"))?,
                    &upstreams,
                    http,
                )?
                .as_bytes(),
            )?;
        }
        _ => return Err(anyhow!("unsupported offline command")),
    }
    Ok(())
}
