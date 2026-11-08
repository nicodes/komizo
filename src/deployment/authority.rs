//! Request authority is independent of the transport account and artifact bytes.
use super::{model::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";
#[derive(Clone)]
pub struct PublicKey {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}
pub type KeyProvider<'a> = dyn FnMut(&str) -> Result<PublicKey> + 'a;

pub struct AdmittedRequest {
    pub request: Request,
    pub digest: String,
    pub release: Option<ReleaseDocument>,
    pub evidence: Value,
}

pub fn body_without_proof(value: &Value) -> Result<Vec<u8>> {
    let mut value = value.clone();
    value
        .as_object_mut()
        .ok_or_else(|| anyhow!("request must be an object"))?
        .remove("proof");
    canonical(&value)
}

pub fn jwks_key(body: &[u8], kid: &str) -> Result<PublicKey> {
    let value = crate::strict::value(body, 64 << 10)?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("invalid issuer key set"))?;
    ensure!(keys.len() <= 64, "issuer key set exceeds bounds");
    let mut found = None;
    for entry in keys {
        if entry.get("kid").and_then(Value::as_str) != Some(kid) {
            continue;
        }
        ensure!(
            found.is_none()
                && entry["kty"] == "RSA"
                && entry["use"] == "sig"
                && entry.get("alg").is_none_or(|v| v == "RS256"),
            "ambiguous or invalid issuer key"
        );
        let n = URL_SAFE_NO_PAD.decode(
            entry["n"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid issuer modulus"))?,
        )?;
        let e = URL_SAFE_NO_PAD.decode(
            entry["e"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid issuer exponent"))?,
        )?;
        ensure!(
            (256..=1024).contains(&n.len()) && (1..=4).contains(&e.len()),
            "invalid issuer key size"
        );
        let exponent = e.iter().fold(0u64, |n, b| (n << 8) + u64::from(*b));
        ensure!(
            exponent >= 3 && exponent % 2 == 1 && exponent <= i32::MAX as u64,
            "invalid issuer exponent"
        );
        found = Some(PublicKey {
            modulus: n,
            exponent: e,
        });
    }
    found.ok_or_else(|| anyhow!("issuer signing key is unavailable"))
}

pub fn github_key(kid: &str) -> Result<PublicKey> {
    ensure!(
        !kid.is_empty() && kid.len() <= 128 && safe_text(kid, 128),
        "invalid issuer key selector"
    );
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(format!("{ISSUER}/.well-known/jwks"))
        .send()?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "issuer signing keys are unavailable"
    );
    let mut body = vec![];
    response.take((64 << 10) + 1).read_to_end(&mut body)?;
    jwks_key(&body, kid)
}

pub fn verify_token(
    token: &str,
    audience: &str,
    now: i64,
    key: &mut KeyProvider<'_>,
) -> Result<Value> {
    ensure!(
        !token.is_empty() && token.len() <= 24 << 10,
        "missing or oversized identity proof"
    );
    let pieces: Vec<_> = token.split('.').collect();
    ensure!(pieces.len() == 3, "invalid identity proof encoding");
    let header = crate::strict::value(&URL_SAFE_NO_PAD.decode(pieces[0])?, 4096)?;
    ensure!(
        header["alg"] == "RS256" && header.get("crit").is_none(),
        "unapproved identity signing algorithm"
    );
    let kid = header["kid"]
        .as_str()
        .filter(|k| !k.is_empty() && safe_text(k, 128))
        .ok_or_else(|| anyhow!("identity signing key is missing"))?;
    let public = key(kid)?;
    RsaPublicKeyComponents {
        n: public.modulus,
        e: public.exponent,
    }
    .verify(
        &RSA_PKCS1_2048_8192_SHA256,
        format!("{}.{}", pieces[0], pieces[1]).as_bytes(),
        &URL_SAFE_NO_PAD.decode(pieces[2])?,
    )
    .map_err(|_| anyhow!("identity signature is invalid"))?;
    let claims = crate::strict::value(&URL_SAFE_NO_PAD.decode(pieces[1])?, 24 << 10)?;
    let date = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("identity has an invalid lifetime"))
    };
    let issued = date("iat")?;
    let before = date("nbf")?;
    let expires = date("exp")?;
    let audiences: Vec<&str> = match &claims["aud"] {
        Value::String(s) => vec![s],
        Value::Array(v) => v
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| anyhow!("invalid identity audience"))
            })
            .collect::<Result<_>>()?,
        _ => return Err(anyhow!("invalid identity audience")),
    };
    ensure!(
        claims["iss"] == ISSUER
            && audiences.len() <= 8
            && audiences.contains(&audience)
            && issued <= now + 5
            && issued >= now - 600
            && before <= now + 5
            && expires > now
            && expires <= issued + 600,
        "identity issuer, audience or lifetime does not match"
    );
    ensure!(
        claims["jti"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && safe_text(s, 256)),
        "identity nonce is missing"
    );
    Ok(claims)
}

fn string<'a>(claims: &'a Value, key: &str) -> &'a str {
    claims.get(key).and_then(Value::as_str).unwrap_or("")
}

fn check_workflow(
    claims: &Value,
    repository: &str,
    repository_id: &str,
    workflow: &str,
    reference: &str,
    environment: Option<&str>,
) -> Result<()> {
    ensure!(
        string(claims, "repository") == repository
            && string(claims, "repository_id") == repository_id
            && string(claims, "workflow_ref") == workflow
            && string(claims, "ref") == reference
            && hex(string(claims, "workflow_sha"), 40)
            && hex(string(claims, "sha"), 40)
            && string(claims, "sha") == string(claims, "workflow_sha")
            && matches!(
                string(claims, "runner_environment"),
                "github-hosted" | "self-hosted"
            )
            && matches!(
                string(claims, "event_name"),
                "push" | "workflow_dispatch" | "pull_request_target" | "schedule"
            ),
        "request is outside approved repository and workflow authority"
    );
    if let Some(environment) = environment {
        ensure!(
            string(claims, "sub")
                == format!(
                    "repo:{repository}:environment:{}",
                    environment.replace(':', "%3A")
                ),
            "request does not carry the protected environment identity"
        );
    }
    Ok(())
}

pub fn admit(
    body: &[u8],
    policy: &Policy,
    peer_uid: u32,
    now: i64,
    key: &mut KeyProvider<'_>,
) -> Result<AdmittedRequest> {
    policy.validate()?;
    let raw = bounded_value(body, MAX_DOCUMENT_BYTES)?;
    let request: Request = serde_json::from_value(raw.clone())?;
    ensure!(
        request.kind == "komizo.request"
            && request.version == 1
            && request.application == policy.application
            && name(&request.application)
            && name(&request.instance)
            && (digest(&request.release_digest)
                || (request.action == "inspect"
                    && request.release_digest == "current"
                    && request.operation.is_none())
                || (request.action == "backup" && request.release_digest == "absent"))
            && hex(&request.nonce, 32)
            && request.issued_at <= now + 5
            && request.issued_at >= now - 300
            && request.expires_at > now
            && request.expires_at > request.issued_at
            && request.expires_at <= request.issued_at + 300
            && (1..=1500).contains(&request.timeout_seconds),
        "invalid request scope, identity or lifetime"
    );
    ensure!(
        [
            "deploy",
            "start",
            "stop",
            "restart",
            "inspect",
            "recover",
            "backup",
            "remove",
            "secret-set",
            "export"
        ]
        .contains(&request.action.as_str()),
        "unsupported application action"
    );
    ensure!(
        request.operation.as_deref().is_none_or(|id| hex(id, 32)),
        "invalid operation identity"
    );
    ensure!(
        request.instance == "production"
            || request
                .instance
                .strip_prefix("pr-")
                .is_some_and(|n| n.parse::<u64>().is_ok_and(|v| v > 0 && v.to_string() == n)),
        "invalid application instance identity"
    );
    if request.action == "deploy" && request.instance != "production" {
        let preview = policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("previews are not admitted"))?;
        ensure!(
            request
                .ttl_seconds
                .is_some_and(|n| (60..=preview.max_ttl_seconds).contains(&n)),
            "preview deployment needs a bounded instance lifetime"
        );
    } else {
        ensure!(
            request.ttl_seconds.is_none(),
            "instance lifetime is only valid for preview deployment"
        );
    }
    ensure!(
        (request.action == "deploy") == request.release.is_some(),
        "only deployment submits a release body"
    );
    ensure!(
        request.action == "deploy" || request.release_proof.is_none(),
        "release proof is only valid for deployment"
    );
    ensure!(
        (request.action == "secret-set") == request.secret_update.is_some(),
        "secret update requires the owner secret operation"
    );
    if let Some(update) = &request.secret_update {
        ensure!(
            request.authority == "owner"
                && request.instance == "production"
                && name(&update.reference)
                && safe_text(&update.expected_generation, 128)
                && !update.value.is_empty()
                && update.value.len() <= 128 << 10
                && ["environment-file", "opaque"].contains(&update.format.as_str()),
            "invalid owner secret update"
        );
    }
    ensure!(
        (request.action == "export") == request.export_name.is_some(),
        "export requires an explicit admitted export name"
    );
    if let Some(export) = &request.export_name {
        ensure!(
            request.operation.is_some()
                && ["snapshot.cms", "receipt.json"].contains(&export.as_str()),
            "invalid backup export identity"
        );
    }
    ensure!(
        request.operation.is_none()
            || ["inspect", "recover", "export"].contains(&request.action.as_str()),
        "operation selector is invalid for this action"
    );
    ensure!(
        request.action != "remove"
            || request.instance != "production"
            || request.authority == "owner",
        "production removal needs explicit owner authority"
    );
    let unsigned = body_without_proof(&raw)?;
    ensure!(
        request.expected_secret_generations.len() <= 32
            && request
                .expected_secret_generations
                .iter()
                .all(|(a, g)| name(a) && hex(g, 32)),
        "invalid expected secret generation map"
    );
    let grants = if request.instance == "production" {
        &policy.secrets
    } else {
        &policy
            .previews
            .as_ref()
            .ok_or_else(|| anyhow!("previews are not admitted"))?
            .secrets
    };
    ensure!(
        request
            .expected_secret_generations
            .iter()
            .all(|(a, g)| grants.get(a).is_some_and(|v| &v.generation == g)),
        "expected secret generation differs from host policy"
    );
    let request_digest = document_digest(&unsigned);
    let release = if let Some(value) = &request.release {
        let document = read_release(&serde_json::to_vec(value)?)?;
        ensure!(
            document.digest == request.release_digest,
            "request release digest differs from the submitted bytes"
        );
        policy.admit(&document.release, &request.instance)?;
        Some(document)
    } else {
        None
    };
    if let Some(registry) = &request.registry {
        ensure!(
            !registry.server.is_empty()
                && registry.server.len() <= 253
                && !registry.server.contains(['/', '@'])
                && safe_text(&registry.server, 253)
                && safe_text(&registry.username, 256)
                && !registry.username.contains([':', ' '])
                && !registry.username.is_empty()
                && !registry.token.is_empty()
                && safe_text(&registry.token, 16384)
                && policy
                    .artifact_prefixes
                    .iter()
                    .any(|p| p.split('/').next() == Some(registry.server.as_str())),
            "registry credential is outside admitted artifact authority"
        );
    }
    let mut evidence = serde_json::json!({"authority":request.authority,"peer_uid":peer_uid,"admitted_at":now,"request_digest":request_digest,"nonce":request.nonce});
    match request.authority.as_str() {
        "owner" => {
            ensure!(
                peer_uid == 0 && request.proof.is_empty() && request.release_proof.is_none(),
                "owner authority requires the kernel authenticated root peer"
            );
            ensure!(
                request.action != "deploy" || matches!(policy.authority, Authority::Owner),
                "owner release admission requires explicit owner policy authority"
            );
        }
        "github" => {
            ensure!(
                request.secret_update.is_none() && request.action != "recover",
                "GitHub cannot update host secrets or approve owner recovery"
            );
            let Authority::Github {
                repository,
                repository_id,
                workflows,
                reference,
                environment,
                publisher_workflows,
            } = &policy.authority
            else {
                return Err(anyhow!("host policy does not admit GitHub authority"));
            };
            let action = if request.action == "export" {
                "backup"
            } else {
                request.action.as_str()
            };
            let scope = if request.instance == "production" {
                action.to_string()
            } else {
                format!("preview-{action}")
            };
            let claims = verify_token(
                &request.proof,
                &format!("komizo-request:{request_digest}"),
                now,
                key,
            )?;
            let workflow = if request.action == "inspect" {
                workflows
                    .values()
                    .find(|workflow| string(&claims, "workflow_ref") == *workflow)
            } else {
                workflows.get(&scope)
            }
            .ok_or_else(|| anyhow!("action has no approved workflow identity"))?;
            let environment = if request.instance == "production" {
                environment
            } else {
                &policy
                    .previews
                    .as_ref()
                    .ok_or_else(|| anyhow!("preview environment is not admitted"))?
                    .environment
            };
            check_workflow(
                &claims,
                repository,
                repository_id,
                workflow,
                reference,
                Some(environment),
            )?;
            for field in [
                "repository",
                "repository_id",
                "workflow_ref",
                "workflow_sha",
                "run_id",
                "run_attempt",
                "actor",
                "actor_id",
                "sub",
            ] {
                if let Some(value) = claims.get(field) {
                    ensure!(
                        value.as_str().is_some_and(|v| safe_text(v, 1024)),
                        "invalid identity audit field"
                    );
                    evidence[field] = value.clone();
                }
            }
            if let Some(release) = &release {
                if request.instance == "production" {
                    ensure!(
                        release.release.source.revision == string(&claims, "sha"),
                        "production release differs from the approved caller source"
                    );
                }
                {
                    let publisher_workflow = publisher_workflows
                        .get(&scope)
                        .ok_or_else(|| anyhow!("release has no immutable publisher authority"))?;
                    let proof = request.release_proof.as_ref().ok_or_else(|| {
                        anyhow!("deployment requires independent selected-source release proof")
                    })?;
                    ensure!(
                        proof.kind == "komizo.release-proof"
                            && proof.version == 1
                            && proof.release_digest == release.digest
                            && proof.source_revision == release.release.source.revision
                            && hex(&proof.source_revision, 40)
                            && !proof.run_id.is_empty()
                            && proof.run_id.bytes().all(|b| b.is_ascii_digit())
                            && !proof.run_attempt.is_empty()
                            && proof.run_attempt.bytes().all(|b| b.is_ascii_digit())
                            && proof.workflow_ref == *workflow
                            && hex(&proof.workflow_sha, 40),
                        "invalid selected-source release proof"
                    );
                    let value = serde_json::to_value(proof)?;
                    let hash = document_digest(&body_without_proof(&value)?);
                    let publisher =
                        verify_token(&proof.proof, &format!("komizo-release:{hash}"), now, key)?;
                    check_workflow(
                        &publisher,
                        repository,
                        repository_id,
                        workflow,
                        reference,
                        Some(environment),
                    )?;
                    ensure!(
                        string(&publisher, "repository") == repository
                            && string(&publisher, "repository_id") == repository_id
                            && string(&publisher, "ref") == reference
                            && string(&publisher, "workflow_ref") == proof.workflow_ref
                            && string(&publisher, "workflow_sha") == proof.workflow_sha
                            && string(&publisher, "sha") == proof.workflow_sha
                            && string(&publisher, "job_workflow_ref") == publisher_workflow
                            && string(&publisher, "run_id") == proof.run_id
                            && string(&publisher, "run_attempt") == proof.run_attempt,
                        "release proof is outside approved publisher authority"
                    );
                }
            }
        }
        _ => return Err(anyhow!("unknown request authority")),
    }
    Ok(AdmittedRequest {
        request,
        digest: request_digest,
        release,
        evidence,
    })
}
