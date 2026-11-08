use super::{assets, model::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    media_type: String,
    artifact_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

pub struct Registry<'a> {
    client: Client,
    origin: Url,
    repository: String,
    credential: Option<&'a RegistryCredential>,
    bearer: Option<String>,
}
impl<'a> Registry<'a> {
    pub fn new(
        reference: &str,
        credential: Option<&'a RegistryCredential>,
        timeout: Duration,
    ) -> Result<(Self, String)> {
        ensure!(
            image_reference(reference),
            "invalid immutable registry reference"
        );
        let (name, hash) = reference.split_once('@').unwrap();
        let (server, repository) = name.split_once('/').unwrap();
        let origin = Url::parse(&format!("https://{server}/"))?;
        ensure!(
            origin.username().is_empty()
                && origin.password().is_none()
                && origin.host_str().is_some(),
            "invalid registry origin"
        );
        let credential = credential.filter(|c| c.server == server);
        let client = Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok((
            Self {
                client,
                origin,
                repository: repository.to_owned(),
                credential,
                bearer: None,
            },
            hash.to_owned(),
        ))
    }
    fn request(&self, url: &Url) -> Result<Response> {
        let mut request = self.client.get(url.clone()).header(
            reqwest::header::ACCEPT,
            "application/vnd.oci.image.manifest.v1+json",
        );
        if let Some(token) = &self.bearer {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        request
            .send()
            .map_err(|_| anyhow!("registry request failed"))
    }
    fn authorize(&mut self, challenge: &str) -> Result<()> {
        let values = challenge
            .strip_prefix("Bearer ")
            .ok_or_else(|| anyhow!("unapproved registry authentication scheme"))?;
        let pattern = regex::Regex::new(r#"(?:^|,\s*)([a-z]+)="([^"\r\n]*)""#)?;
        let mut attributes = BTreeMap::new();
        let mut consumed = 0usize;
        for captures in pattern.captures_iter(values) {
            ensure!(
                captures.get(0).unwrap().start() == consumed,
                "invalid registry challenge"
            );
            consumed = captures.get(0).unwrap().end();
            ensure!(
                attributes
                    .insert(captures[1].to_owned(), captures[2].to_owned())
                    .is_none(),
                "ambiguous registry challenge"
            );
        }
        ensure!(consumed == values.len(), "invalid registry challenge");
        let mut realm = Url::parse(
            attributes
                .get("realm")
                .ok_or_else(|| anyhow!("registry authentication realm missing"))?,
        )?;
        ensure!(
            realm.origin() == self.origin.origin()
                && realm.scheme() == "https"
                && realm.username().is_empty()
                && realm.password().is_none()
                && realm.query().is_none()
                && realm.fragment().is_none(),
            "registry authentication crossed its credential origin"
        );
        let service = attributes
            .get("service")
            .ok_or_else(|| anyhow!("registry authentication service missing"))?;
        ensure!(
            service == self.origin.host_str().unwrap(),
            "unapproved registry authentication service"
        );
        realm
            .query_pairs_mut()
            .append_pair("service", service)
            .append_pair("scope", &format!("repository:{}:pull", self.repository));
        let mut request = self.client.get(realm);
        if let Some(credential) = self.credential {
            request = request.basic_auth(&credential.username, Some(&credential.token));
        }
        let response = request
            .send()
            .map_err(|_| anyhow!("registry authentication failed"))?;
        ensure!(
            response.status().is_success(),
            "registry authentication refused"
        );
        let mut body = Vec::new();
        response.take((64 << 10) + 1).read_to_end(&mut body)?;
        let value = crate::strict::value(&body, 64 << 10)?;
        let token = value
            .get("token")
            .or_else(|| value.get("access_token"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("registry returned no bearer token"))?;
        ensure!(
            !token.is_empty() && safe_text(token, 32768),
            "invalid registry bearer token"
        );
        self.bearer = Some(token.to_owned());
        Ok(())
    }
    fn get(&mut self, kind: &str, hash: &str) -> Result<Response> {
        ensure!(
            ["manifests", "blobs"].contains(&kind) && digest(hash),
            "invalid registry object selector"
        );
        let url = self
            .origin
            .join(&format!("v2/{}/{kind}/{hash}", self.repository))?;
        let mut response = self.request(&url)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| anyhow!("registry omitted its authentication challenge"))?
                .to_owned();
            self.authorize(&challenge)?;
            response = self.request(&url)?;
        }
        // GHCR serves content-addressed blobs from its signed CDN. No bearer or
        // Basic credential is forwarded, and the received bytes remain hashed.
        if response.status() == reqwest::StatusCode::TEMPORARY_REDIRECT
            && kind == "blobs"
            && self.origin.host_str() == Some("ghcr.io")
        {
            let location = Url::parse(
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow!("registry blob redirect omitted its destination"))?,
            )?;
            ensure!(
                location.scheme() == "https"
                    && location.host_str() == Some("pkg-containers.githubusercontent.com")
                    && location.port_or_known_default() == Some(443)
                    && location.username().is_empty()
                    && location.password().is_none()
                    && location.fragment().is_none(),
                "unapproved registry blob redirect"
            );
            response = self
                .client
                .get(location)
                .send()
                .map_err(|_| anyhow!("registry blob transfer failed"))?;
        }
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "registry object is unavailable"
        );
        Ok(response)
    }
    fn bytes(&mut self, kind: &str, hash: &str, maximum: usize) -> Result<Vec<u8>> {
        let response = self.get(kind, hash)?;
        let mut body = Vec::new();
        response
            .take(maximum as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| anyhow!("registry body transfer failed"))?;
        ensure!(
            body.len() <= maximum && document_digest(&body) == hash,
            "registry object differs from its immutable identity"
        );
        Ok(body)
    }
    pub fn static_archive(
        &mut self,
        manifest_digest: &str,
        artifact: &Artifact,
        target: &Path,
        policy: &Policy,
    ) -> Result<()> {
        let Artifact::Archive {
            digest: payload,
            size_bytes,
            media_type,
            ..
        } = artifact
        else {
            return Err(anyhow!("static transfer requires an archive artifact"));
        };
        ensure!(
            *size_bytes <= policy.max_asset_bytes,
            "compressed static object exceeds its admitted bound"
        );
        let body = self.bytes("manifests", manifest_digest, 256 << 10)?;
        let manifest: Manifest = serde_json::from_value(crate::strict::value(&body, 256 << 10)?)?;
        ensure!(
            manifest.schema_version == 2
                && manifest.media_type == "application/vnd.oci.image.manifest.v1+json"
                && manifest.artifact_type == "application/vnd.komizo.static.v1"
                && manifest.config.media_type == "application/vnd.oci.empty.v1+json"
                && manifest.config.digest == document_digest(b"{}")
                && manifest.config.size == 2
                && manifest.config.annotations.is_empty()
                && manifest.layers.len() == 1
                && manifest.annotations.len() <= 32,
            "invalid static OCI manifest"
        );
        ensure!(
            self.bytes("blobs", &manifest.config.digest, 2)? == b"{}",
            "invalid empty static OCI configuration"
        );
        let layer = &manifest.layers[0];
        ensure!(
            &layer.media_type == media_type
                && &layer.digest == payload
                && layer.size == *size_bytes
                && layer.annotations.is_empty(),
            "static OCI payload differs from admitted bytes"
        );
        let mut response = self.get("blobs", payload)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(target)?;
        let mut hash = Sha256::new();
        let mut seen = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = response
                .read(&mut buffer)
                .map_err(|_| anyhow!("static blob transfer failed"))?;
            if n == 0 {
                break;
            }
            seen = seen
                .checked_add(n as u64)
                .ok_or_else(|| anyhow!("static blob length overflow"))?;
            ensure!(
                seen <= *size_bytes,
                "static blob exceeded its admitted size"
            );
            file.write_all(&buffer[..n])?;
            hash.update(&buffer[..n]);
        }
        ensure!(
            seen == *size_bytes && format!("sha256:{:x}", hash.finalize()) == *payload,
            "static blob differs from its admitted identity"
        );
        file.sync_all()?;
        assets::verify_file(target, payload, *size_bytes)
    }
}
