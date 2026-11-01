//! Immutable local image verification precedes every binding; it starts no service.
use super::{
    policy::Policy,
    release::{ReleaseAcceptance, ReleaseManifest, digest},
    yaml::MAX_BYTES,
};
use crate::wire::Time;
use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use serde_json::Value;
pub type ImageRun<'a> = dyn FnMut(&[&str]) -> Result<String> + 'a;
pub fn approved_map(body: &[u8]) -> Result<Value> {
    ensure!(
        body.len() <= MAX_BYTES && serde_json::from_slice::<Value>(body).is_ok(),
        "invalid approved workload"
    );
    let mut value = crate::strict::value(body, MAX_BYTES).map_err(|e| {
        let text = e.to_string();
        if text.starts_with("duplicate release JSON key") {
            anyhow!("duplicate release JSON key")
        } else if text.starts_with("release JSON exceeds nesting limit") {
            anyhow!("release JSON exceeds nesting limit")
        } else {
            e
        }
    })?;
    if !value.is_object() && !value.is_null() {
        let kind = match value {
            Value::Array(_) => "array",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            _ => "string",
        };
        bail!("json: cannot unmarshal {kind} into Go value of type map[string]interface {{}}");
    }
    fn floats(value: &mut Value) {
        match value {
            Value::Number(number) => {
                if let Some(float) = number.as_f64().and_then(serde_json::Number::from_f64) {
                    *number = float;
                }
            }
            Value::Array(values) => {
                for value in values {
                    floats(value);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    floats(value);
                }
            }
            _ => {}
        }
    }
    floats(&mut value);
    Ok(value)
}
pub fn json_image_references(body: &[u8]) -> Result<Vec<String>> {
    let document = approved_map(body)?;
    let services = document
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("image discovery requires bounded services"))?;
    ensure!(
        (1..=32).contains(&services.len()),
        "image discovery requires bounded services"
    );
    let mut refs = vec![];
    for service in services.values() {
        ensure!(service.is_object(), "invalid service for image discovery");
        let image = service
            .get("image")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("image discovery requires explicit references"))?;
        ensure!(
            !image.is_empty()
                && image.len() <= 1024
                && image
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._/:@-".contains(&b)),
            "image discovery requires explicit references"
        );
        refs.push(image.into());
    }
    refs.sort();
    Ok(refs)
}
fn verify_image(
    run: &mut ImageRun<'_>,
    manifest: &ReleaseManifest,
    image: &str,
    expected_ref: &str,
    pull: bool,
) -> Result<Value> {
    let expected = manifest
        .images
        .get(expected_ref)
        .ok_or_else(|| anyhow!("service image missing from authenticated release"))?;
    if pull {
        run(&["pull", "-q", image]).map_err(|_| anyhow!("release image pull failed"))?;
    }
    let body = run(&["image", "inspect", image])
        .map_err(|_| anyhow!("release image inspection failed"))?;
    let mismatch = || anyhow!("pulled image differs from authenticated Build evidence");
    let images: Vec<Value> = serde_json::from_str(&body).map_err(|_| mismatch())?;
    ensure!(
        images.len() == 1,
        "pulled image differs from authenticated Build evidence"
    );
    let info = images.into_iter().next().unwrap();
    let id = info.get("Id").and_then(Value::as_str).unwrap_or("");
    if id != expected {
        ensure!(
            digest(id)
                && info
                    .get("Descriptor")
                    .and_then(|v| v.get("Digest").or_else(|| v.get("digest")))
                    .and_then(Value::as_str)
                    == Some(id),
            "pulled image differs from authenticated Build evidence"
        );
        let actual = run(&["config-digest", id]).map_err(|_| mismatch())?;
        ensure!(
            actual.trim() == expected,
            "pulled image differs from authenticated Build evidence"
        );
    }
    Ok(info)
}
fn inspect_image(
    run: &mut ImageRun<'_>,
    manifest: &ReleaseManifest,
    image: &str,
    expected_ref: &str,
    pull: bool,
) -> Result<String> {
    let info = verify_image(run, manifest, image, expected_ref, pull)?;
    let repository = expected_ref
        .strip_suffix(&format!(":{}", manifest.revision))
        .unwrap_or(expected_ref);
    if let Some(refs) = info.get("RepoDigests").and_then(Value::as_array) {
        for value in refs {
            if let Some(value) = value.as_str()
                && let Some(id) = value.strip_prefix(&format!("{repository}@"))
                && digest(id)
            {
                ensure!(
                    !image.contains('@') || image == value,
                    "declared digest differs from authenticated image"
                );
                return Ok(value.into());
            }
        }
    }
    bail!("authenticated image has no registry digest: {expected_ref}")
}
pub fn bind_release(
    run: &mut ImageRun<'_>,
    p: &Policy,
    accepted: &ReleaseAcceptance,
    version: &str,
    config_image: &str,
    compose: &[u8],
    pull: bool,
) -> Result<Vec<u8>> {
    if !pull {
        ensure!(
            p.has_release_authority(),
            "local binding requires an authenticated source policy"
        );
    }
    ensure!(
        p.has_release_authority(),
        "release binding requires explicit protected admission authority"
    );
    accepted.check(p, version)?;
    let manifest = &accepted.manifest;
    if let Err(error) = verify_image(run, manifest, config_image, config_image, false) {
        let Some(expected) = manifest.images.get(config_image).filter(|_| !pull) else {
            return Err(error);
        };
        let Ok(original) = run(&["local-config-image", expected]) else {
            return Err(error);
        };
        ensure!(digest(original.trim()), "{error}");
        verify_image(run, manifest, original.trim(), config_image, false)?;
    }
    let mut document = approved_map(compose)?;
    let services = document
        .get_mut("services")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("approved workload has no services"))?;
    for service in services.values_mut() {
        let service = service
            .as_object_mut()
            .ok_or_else(|| anyhow!("invalid approved service"))?;
        let image = service
            .get("image")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("approved service has no image"))?;
        if !image.starts_with(&p.image_prefix) {
            continue;
        }
        let repository = image_repository(image);
        let expected_ref = format!("{repository}:{version}");
        let pinned = inspect_image(run, manifest, image, &expected_ref, pull)?;
        service.insert("image".into(), pinned.into());
    }
    super::json::compact(&document)
}
fn image_repository(image: &str) -> &str {
    let repository = image.split('@').next().unwrap();
    if let Some(colon) = repository.rfind(':')
        && repository.rfind('/').is_none_or(|slash| colon > slash)
    {
        &repository[..colon]
    } else {
        repository
    }
}
pub fn bootstrap_release(
    run: &mut ImageRun<'_>,
    p: &Policy,
    version: &str,
    config_image: &str,
    compose: &[u8],
    now: DateTime<Utc>,
) -> Result<ReleaseAcceptance> {
    let canonical = super::compose::validate(compose, p, version)?;
    let document: Value = serde_json::from_slice(&canonical)?;
    let mut refs = vec![config_image.to_owned()];
    for service in document["services"].as_object().unwrap().values() {
        let image = service["image"].as_str().unwrap();
        if image.starts_with(&p.image_prefix) {
            refs.push(image.into());
        }
    }
    let mut manifest = ReleaseManifest {
        version: 1,
        repository: p.source_repository.clone(),
        repository_id: p.repository_id.clone(),
        revision: version.into(),
        ..Default::default()
    };
    for image in refs {
        ensure!(
            image.starts_with(&p.image_prefix),
            "bootstrap image outside approved family"
        );
        let body = run(&["image", "inspect", &image])
            .map_err(|_| anyhow!("bootstrap image is not locally available"))?;
        let images: Vec<Value> = serde_json::from_str(&body)
            .map_err(|_| anyhow!("invalid local bootstrap image identity"))?;
        ensure!(images.len() == 1, "invalid local bootstrap image identity");
        let id = images[0].get("Id").and_then(Value::as_str).unwrap_or("");
        ensure!(digest(id), "invalid local bootstrap image identity");
        manifest
            .images
            .insert(format!("{}:{version}", image_repository(&image)), id.into());
    }
    let accepted = ReleaseAcceptance {
        manifest,
        authority: "operator-bootstrap".into(),
        verified_at: Time(now.fixed_offset()),
        ..Default::default()
    };
    accepted.check(p, version)?;
    Ok(accepted)
}
