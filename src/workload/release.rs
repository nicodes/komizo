//! Exact-byte Actions RS256 evidence and explicitly protected owner approval.
use super::{
    policy::{Policy, commit_id, content_identity, numeric_id},
    stateful::StatefulContract,
};
use crate::{
    wire::{Secret, Time},
    wire_struct,
};
use anyhow::{Result, anyhow, bail, ensure};
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, time::Duration as StdDuration};
pub const ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const MAX_BYTES: usize = 64 << 10;
wire_struct!(ReleaseManifest{version:"version":i64=>required,repository:"repository":String=>optional,repository_id:"repository_id":String=>optional,revision:"revision":String=>required,tested_commit:"tested_commit":String=>optional,run_id:"run_id":String=>optional,images:"images":BTreeMap<String,String> =>required,stateful_contract:"stateful_contract":Option<StatefulContract> =>optional});
wire_struct!(ReleaseEnvelope{manifest:"manifest":String=>required,token:"token":Secret=>required});
wire_struct!(ReleaseAcceptance{manifest:"manifest":ReleaseManifest=>required,verified_at:"verified_at":Time=>required,authority:"authority":String=>required,evidence_sha256:"evidence_sha256":String=>optional});
pub fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(content_identity)
}
impl ReleaseManifest {
    pub fn check(&self, policy: &Policy, version: &str) -> Result<()> {
        self.check_authority(policy, version, true)
    }
    pub fn check_authority(&self, p: &Policy, version: &str, actions: bool) -> Result<()> {
        ensure!(
            !p.require_stateful_contract || self.stateful_contract.is_some(),
            "stateful workload requires an audience-bound data and credential contract"
        );
        if let Some(contract) = &self.stateful_contract {
            contract.check(version)?;
        }
        ensure!(
            self.version == 1
                && self.repository == p.source_repository
                && self.repository_id == p.repository_id
                && self.revision == version
                && commit_id(version)
                && (2..=16).contains(&self.images.len()),
            "release identity does not match host policy and tested source"
        );
        if actions {
            ensure!(
                self.tested_commit == version && numeric_id(&self.run_id),
                "release has no matching tested workflow source"
            );
        } else {
            ensure!(
                self.tested_commit.is_empty() && self.run_id.is_empty(),
                "operator bootstrap must not claim Actions test evidence"
            );
        }
        for (image, id) in &self.images {
            ensure!(
                image.starts_with(&p.image_prefix)
                    && image.ends_with(&format!(":{version}"))
                    && digest(id),
                "release image identity outside approved family"
            );
            let component = image
                .strip_prefix(&p.image_prefix)
                .unwrap()
                .strip_suffix(&format!(":{version}"))
                .unwrap();
            ensure!(super::identifier(component), "invalid release component");
        }
        ensure!(
            self.images
                .contains_key(&format!("{}config:{version}", p.image_prefix)),
            "release has no configuration image"
        );
        Ok(())
    }
}
impl ReleaseAcceptance {
    pub fn check(&self, p: &Policy, version: &str) -> Result<()> {
        match self.authority.as_str() {
            ACTIONS_ISSUER => {
                ensure!(
                    !p.owner_approval && !p.source_repository.is_empty(),
                    "Actions evidence requires GitHub source authority"
                );
                self.manifest.check(p, version)
            }
            "owner-ssh" => {
                ensure!(
                    p.owner_approval && content_identity(&self.evidence_sha256),
                    "owner approval requires explicit protected host authority and an approval identity"
                );
                self.manifest.check_authority(p, version, false)
            }
            "operator-bootstrap" => self.manifest.check_authority(p, version, false),
            _ => bail!("unknown host release authority"),
        }
    }
}
// Declared-field normalization retains Go's case-insensitive decoding while rejecting unknown fields.
fn shape(value: Value, names: &[&str]) -> Result<Value> {
    crate::strict::fields(value, names)
}
fn contract_shape(value: Value) -> Result<Value> {
    let mut value = shape(
        value,
        &[
            "version",
            "source_revision",
            "schema",
            "data_revision",
            "credential_revision",
            "migrations",
            "recovery_action",
        ],
    )?;
    if let Some(value) = value.get_mut("schema") {
        *value = shape(value.take(), &["minimum", "maximum", "write"])?;
    }
    if let Some(values) = value.get_mut("migrations").and_then(Value::as_array_mut) {
        for value in values {
            *value = shape(value.take(), &["identity", "sha256"])?;
        }
    }
    Ok(value)
}
pub fn strict_value(body: &[u8]) -> Result<Value> {
    ensure!(
        body.len() <= MAX_BYTES && serde_json::from_slice::<Value>(body).is_ok(),
        "invalid bounded release JSON"
    );
    crate::strict::value(body, MAX_BYTES).map_err(|error| {
        let message = error.to_string();
        if message.starts_with("duplicate release JSON key") {
            anyhow!("duplicate release JSON key")
        } else if message.starts_with("release JSON exceeds nesting limit") {
            anyhow!("release JSON exceeds nesting limit")
        } else {
            error
        }
    })
}
pub fn read_envelope(body: &[u8]) -> Result<ReleaseEnvelope> {
    let value = shape(strict_value(body)?, &["manifest", "token"])?;
    serde_json::from_value(value).map_err(|_| anyhow!("invalid release fields"))
}
pub fn read_manifest(body: &[u8]) -> Result<ReleaseManifest> {
    let mut value = shape(
        strict_value(body)?,
        &[
            "version",
            "repository",
            "repository_id",
            "revision",
            "tested_commit",
            "run_id",
            "images",
            "stateful_contract",
        ],
    )?;
    if let Some(value) = value.get_mut("stateful_contract") {
        *value = contract_shape(value.take())?;
    }
    if let Some(values) = value.get_mut("images").and_then(Value::as_object_mut) {
        for value in values.values_mut() {
            if value.is_null() {
                *value = "".into();
            }
        }
    }
    serde_json::from_value(value).map_err(|_| anyhow!("invalid release fields"))
}
pub fn decode_manifest(value: &str, kind: &str) -> Result<Vec<u8>> {
    let filtered: Vec<_> = value
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    STANDARD
        .decode(filtered)
        .map_err(|_| anyhow!("invalid {kind} manifest encoding"))
}
#[derive(Clone, Debug)]
pub struct RsaKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}
pub type ReleaseKey<'a> = dyn FnMut(&str) -> Result<RsaKey> + 'a;
#[derive(Clone, Debug)]
pub struct ActionsClaims {
    pub values: Value,
    pub issued: DateTime<Utc>,
    pub expires: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
}
impl ActionsClaims {
    pub fn string(&self, name: &str) -> &str {
        self.values.get(name).and_then(Value::as_str).unwrap_or("")
    }
}
fn numeric_date(value: Option<&Value>) -> Result<Option<DateTime<Utc>>> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let number = value
        .as_f64()
        .ok_or_else(|| anyhow!("invalid numeric date"))?;
    ensure!(
        number.is_finite() && number >= i64::MIN as f64 && number < i64::MAX as f64,
        "invalid numeric date"
    );
    Ok(Some(
        DateTime::from_timestamp(number.trunc() as i64, 0)
            .ok_or_else(|| anyhow!("invalid numeric date"))?,
    ))
}
pub fn verify_actions(
    token: &str,
    audience: &str,
    now: DateTime<Utc>,
    key: &mut ReleaseKey<'_>,
) -> Result<ActionsClaims> {
    let parts: Vec<_> = token.split('.').collect();
    ensure!(parts.len() == 3, "invalid JWT segments");
    let decode = crate::host::authority::keys::decode;
    let header: Value = serde_json::from_slice(&decode(parts[0])?)?;
    let mut values: Value = serde_json::from_slice(&decode(parts[1])?)?;
    ensure!(values.is_object(), "invalid Actions claims");
    // JWT claims belong to the fixed issuer, not the protected policy schema.
    let names = [
        "iss",
        "aud",
        "sub",
        "exp",
        "nbf",
        "iat",
        "jti",
        "repository",
        "repository_id",
        "ref",
        "sha",
        "workflow_ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "job_workflow_ref",
        "job_workflow_sha",
        "event_name",
        "runner_environment",
    ];
    let mut normalized = serde_json::Map::new();
    for (name, value) in values.as_object().unwrap() {
        let canonical = names
            .iter()
            .find(|known| known.eq_ignore_ascii_case(name))
            .copied()
            .unwrap_or(name);
        normalized.insert(canonical.into(), value.clone());
    }
    values = normalized.into();
    for name in names
        .iter()
        .filter(|name| !matches!(**name, "aud" | "exp" | "nbf" | "iat"))
    {
        ensure!(
            values
                .get(*name)
                .is_none_or(|v| v.is_string() || v.is_null()),
            "invalid Actions claim type"
        );
    }
    let issued = numeric_date(values.get("iat"))?;
    let expires = numeric_date(values.get("exp"))?;
    let not_before = numeric_date(values.get("nbf"))?;
    let audiences = match values.get("aud") {
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| v.as_str().ok_or_else(|| anyhow!("invalid audience")))
            .collect::<Result<Vec<_>>>()?,
        None | Some(Value::Null) => vec![],
        _ => bail!("invalid audience"),
    };
    ensure!(
        header.get("alg").and_then(Value::as_str) == Some("RS256"),
        "unapproved Actions signing algorithm"
    );
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing Actions signing key"))?;
    ensure!(
        !kid.is_empty() && kid.len() <= 128,
        "missing Actions signing key"
    );
    let public = key(kid)?;
    RsaPublicKeyComponents {
        n: public.n,
        e: public.e,
    }
    .verify(
        &RSA_PKCS1_2048_8192_SHA256,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &decode(parts[2])?,
    )
    .map_err(|_| anyhow!("invalid Actions signature"))?;
    let expires = expires.ok_or_else(|| anyhow!("missing Actions expiry"))?;
    ensure!(
        now - Duration::seconds(5) < expires
            && not_before.is_none_or(|date| now + Duration::seconds(5) >= date)
            && issued.is_none_or(|date| now + Duration::seconds(5) >= date)
            && values.get("iss").and_then(Value::as_str) == Some(ACTIONS_ISSUER)
            && audiences.contains(&audience),
        "invalid Actions identity or lifetime"
    );
    Ok(ActionsClaims {
        values,
        issued: issued.unwrap_or_default(),
        expires,
        not_before,
    })
}
pub fn release_subject(subject: &str, p: &Policy) -> bool {
    for suffix in [
        ":ref:refs/heads/main",
        ":environment:production",
        ":environment:Production",
    ] {
        if subject == format!("repo:{}{suffix}", p.source_repository) {
            return true;
        }
        if let Some((owner, repo)) = p.source_repository.split_once('/') {
            let pattern = format!(
                r"^repo:{}@[1-9][0-9]*/{}@{}{}$",
                regex::escape(owner),
                regex::escape(repo),
                regex::escape(&p.repository_id),
                regex::escape(suffix)
            );
            if regex::Regex::new(&pattern).unwrap().is_match(subject) {
                return true;
            }
        }
    }
    false
}
pub fn verify_release(
    body: &[u8],
    p: &Policy,
    version: &str,
    now: DateTime<Utc>,
    key: &mut ReleaseKey<'_>,
) -> Result<ReleaseAcceptance> {
    let envelope = read_envelope(body)?;
    let raw = decode_manifest(&envelope.manifest, "release")?;
    let manifest = read_manifest(&raw)?;
    manifest.check(p, version)?;
    ensure!(
        envelope.token.expose().len() <= 24 << 10,
        "release token exceeds limit"
    );
    let claims = verify_actions(
        envelope.token.expose(),
        &format!("komizo-release:sha256:{:x}", Sha256::digest(&raw)),
        now,
        key,
    )
    .map_err(|_| anyhow!("release Actions identity verification failed"))?;
    ensure!(
        claims.string("repository") == p.source_repository
            && claims.string("repository_id") == p.repository_id
            && claims.string("ref") == "refs/heads/main"
            && claims.string("sha") == version
            && claims.string("workflow_ref")
                == format!(
                    "{}/.github/workflows/cd.yml@refs/heads/main",
                    p.source_repository
                )
            && claims.string("workflow_sha") == version
            && claims.string("run_id") == manifest.run_id
            && matches!(claims.string("event_name"), "push" | "workflow_dispatch")
            && matches!(
                claims.string("runner_environment"),
                "github-hosted" | "self-hosted"
            )
            && claims.values.get("iat").is_some_and(|v| !v.is_null())
            && claims.not_before.is_some()
            && now - claims.issued <= Duration::minutes(10)
            && claims.expires - claims.issued <= Duration::minutes(10)
            && release_subject(claims.string("sub"), p),
        "release Actions context is not the approved main workflow"
    );
    Ok(ReleaseAcceptance {
        manifest,
        verified_at: Time(now.fixed_offset()),
        authority: ACTIONS_ISSUER.into(),
        evidence_sha256: format!("{:x}", Sha256::digest(body)),
    })
}
pub fn approve_owner_release(
    body: &[u8],
    p: &Policy,
    version: &str,
    now: DateTime<Utc>,
) -> Result<ReleaseAcceptance> {
    p.check()?;
    ensure!(
        p.owner_approval && p.source_repository.is_empty() && p.repository_id.is_empty(),
        "host policy does not authorize owner SSH approval"
    );
    let manifest = read_manifest(body)?;
    manifest.check_authority(p, version, false)?;
    let accepted = ReleaseAcceptance {
        manifest,
        verified_at: Time(now.fixed_offset()),
        authority: "owner-ssh".into(),
        evidence_sha256: format!("{:x}", Sha256::digest(body)),
    };
    accepted.check(p, version)?;
    Ok(accepted)
}
pub fn github_release_key(kid: &str) -> Result<RsaKey> {
    github_release_key_with_timeout(kid, StdDuration::from_secs(10))
}
pub fn github_release_key_with_timeout(kid: &str, timeout: StdDuration) -> Result<RsaKey> {
    ensure!(!timeout.is_zero(), "Actions signing key deadline exceeded");
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout.min(StdDuration::from_secs(10)))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client
        .get(format!("{ACTIONS_ISSUER}/.well-known/jwks"))
        .send()
        .map_err(|_| anyhow!("Actions signing keys unavailable"))?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Actions signing keys unavailable"
    );
    let mut body = vec![];
    response
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| anyhow!("invalid Actions signing key response"))?;
    ensure!(
        body.len() <= MAX_BYTES,
        "invalid Actions signing key response"
    );
    parse_jwks(&body, kid)
}
pub fn parse_jwks(body: &[u8], kid: &str) -> Result<RsaKey> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| anyhow!("invalid Actions signing key set"))?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("invalid Actions signing key set"))?;
    ensure!(keys.len() <= 64, "invalid Actions signing key set");
    for jwk in keys {
        let string = |name: &str| jwk.get(name).and_then(Value::as_str).unwrap_or("");
        if string("kid") != kid
            || string("kty") != "RSA"
            || string("use") != "sig"
            || !matches!(string("alg"), "" | "RS256")
        {
            continue;
        }
        let decode = crate::host::authority::keys::decode;
        let n = decode(string("n")).map_err(|_| anyhow!("invalid Actions RSA key"))?;
        let e = decode(string("e")).map_err(|_| anyhow!("invalid Actions RSA key"))?;
        ensure!(
            (256..=1024).contains(&n.len()) && (1..=4).contains(&e.len()),
            "invalid Actions RSA key"
        );
        let exponent = e
            .iter()
            .fold(0u64, |value, byte| value * 256 + u64::from(*byte));
        ensure!(
            (3..=0x7fff_ffff).contains(&exponent) && exponent % 2 == 1,
            "invalid Actions RSA exponent"
        );
        return Ok(RsaKey { n, e });
    }
    bail!("Actions signing key not found")
}
