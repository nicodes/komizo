//! Read-only joins of approved services, exact local image IDs and candidate routes.
use super::{
    activation::Context,
    policy::{Policy, ReadinessProbe, commit_id},
    release_bind::ImageRun,
    yaml::MAX_BYTES,
};
use crate::{
    host::health::{Desired, ready},
    wire::null_default,
};
use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, io::Read};
pub const INSPECT_FORMAT: &str = r#"{"Service":{{json (index .Config.Labels "com.docker.compose.service")}},"Project":{{json (index .Config.Labels "com.docker.compose.project")}},"Image":{{json .Image}},"Status":{{json .State.Status}},"ExitCode":{{json .State.ExitCode}},"Health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}}}"#;
#[derive(Default, Deserialize)]
#[serde(default)]
struct ReadyService {
    #[serde(deserialize_with = "null_default")]
    image: String,
    #[serde(flatten)]
    desired: Desired,
}
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct ReadyContainer {
    #[serde(deserialize_with = "null_default")]
    service: String,
    #[serde(deserialize_with = "null_default")]
    project: String,
    #[serde(deserialize_with = "null_default")]
    image: String,
    #[serde(deserialize_with = "null_default")]
    status: String,
    #[serde(deserialize_with = "null_default")]
    exit_code: i64,
    #[serde(deserialize_with = "null_default")]
    health: String,
}
pub type ProbeRun<'a> = dyn FnMut(&ReadinessProbe) -> Result<()> + 'a;
pub fn verify_readiness(
    run: &mut ImageRun<'_>,
    probe: &mut ProbeRun<'_>,
    p: &Policy,
    candidate: &str,
    compose_path: &str,
    compose: &[u8],
) -> Result<()> {
    ensure!(
        commit_id(candidate) && p.readiness.is_some(),
        "candidate readiness policy is required"
    );
    let readiness = p.readiness.as_ref().unwrap();
    readiness.check()?;
    ensure!(
        compose.len() <= MAX_BYTES,
        "approved workload exceeds limit"
    );
    #[derive(Default, Deserialize)]
    struct Projection {
        #[serde(default, deserialize_with = "null_default")]
        services: BTreeMap<String, ReadyService>,
    }
    let document: Projection = crate::wire::decode(
        std::str::from_utf8(compose).map_err(|_| anyhow!("invalid approved workload"))?,
    )
    .map_err(|_| anyhow!("invalid approved workload"))?;
    ensure!(
        (1..=32).contains(&document.services.len()),
        "invalid approved workload"
    );
    let ids = run(&[
        "compose",
        "--project-name",
        &p.app,
        "--project-directory",
        &p.app_dir,
        "--file",
        compose_path,
        "ps",
        "--all",
        "--quiet",
    ])
    .map_err(|_| anyhow!("candidate container inventory unavailable"))?;
    ensure!(
        ids.len() <= 4096,
        "candidate container inventory unavailable"
    );
    let mut containers = BTreeMap::new();
    for id in ids.split_whitespace() {
        ensure!(
            (12..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && containers.len() < 32,
            "invalid candidate container inventory"
        );
        let body = run(&["inspect", "--format", INSPECT_FORMAT, id])
            .map_err(|_| anyhow!("candidate container identity unavailable"))?;
        ensure!(
            body.len() <= 8192,
            "candidate container identity unavailable"
        );
        let container: ReadyContainer = crate::wire::decode(&body)
            .map_err(|_| anyhow!("candidate container identity unavailable"))?;
        ensure!(
            container.project == p.app,
            "candidate container identity unavailable"
        );
        ensure!(
            !containers.contains_key(&container.service),
            "duplicate candidate service"
        );
        containers.insert(container.service.clone(), container);
    }
    for (name, service) in document.services {
        let container = containers.get(&name);
        if container.is_none() && !service.desired.profiles.is_empty() {
            continue;
        }
        let container = container.ok_or_else(|| anyhow!("candidate service {name} is absent"))?;
        let id = run(&["image", "inspect", "--format", "{{.Id}}", &service.image])
            .map_err(|_| anyhow!("candidate service {name} serves a different image"))?;
        ensure!(
            id.trim() == container.image,
            "candidate service {name} serves a different image"
        );
        ensure!(
            ready(
                &service.desired,
                &container.status,
                container.exit_code,
                &container.health
            ),
            "candidate service {name} is unready"
        );
    }
    for request in readiness.probes.iter() {
        probe(request)?;
    }
    Ok(())
}
pub fn probe_ready(
    ctx: &Context,
    client: &reqwest::blocking::Client,
    candidate: &str,
    probe: &ReadinessProbe,
) -> Result<()> {
    let response = client
        .get(&probe.url)
        .header("Cache-Control", "no-cache")
        .timeout(ctx.remaining()?)
        .send()
        .map_err(|_| anyhow!("candidate route unavailable"))?;
    let status = response.status().as_u16();
    let revision = response
        .headers()
        .get("X-Komizo-Revision")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    ensure!(
        status == 200 && revision == candidate,
        "route does not identify the ready candidate"
    );
    let mut body = vec![];
    if !probe.revision_field.is_empty() {
        response
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| anyhow!("product readiness revision differs from candidate"))?;
    } else {
        response
            .take(512)
            .read_to_end(&mut body)
            .map_err(|_| anyhow!("candidate core read returned no content"))?;
    }
    check_route_response(status, &revision, &body, candidate, probe)
}
pub fn check_route_response(
    status: u16,
    revision: &str,
    body: &[u8],
    candidate: &str,
    probe: &ReadinessProbe,
) -> Result<()> {
    ensure!(
        status == 200 && revision == candidate,
        "route does not identify the ready candidate"
    );
    if !probe.revision_field.is_empty() {
        let document = serde_json::from_slice::<Value>(body).ok();
        ensure!(
            body.len() <= MAX_BYTES
                && document
                    .as_ref()
                    .and_then(|v| v.get(&probe.revision_field))
                    .and_then(Value::as_str)
                    == Some(candidate),
            "product readiness revision differs from candidate"
        );
    } else {
        ensure!(
            !String::from_utf8_lossy(&body[..body.len().min(512)])
                .trim()
                .is_empty(),
            "candidate core read returned no content"
        );
    }
    Ok(())
}
pub fn verify_static_readiness(
    run: &mut ImageRun<'_>,
    probe: &mut ProbeRun<'_>,
    p: &Policy,
    candidate: &str,
) -> Result<()> {
    ensure!(
        p.r#static.is_some() && p.readiness.is_some() && commit_id(candidate),
        "static readiness requires an explicit protected profile"
    );
    let status = run(&[
        "inspect",
        "--format",
        "{{.State.Status}}",
        &p.r#static.as_ref().unwrap().proxy,
    ])
    .map_err(|_| anyhow!("static serving proxy is not running"))?;
    ensure!(
        status.trim() == "running",
        "static serving proxy is not running"
    );
    for request in p.readiness.as_ref().unwrap().probes.iter() {
        probe(request)?;
    }
    Ok(())
}
