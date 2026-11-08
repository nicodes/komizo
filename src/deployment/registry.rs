use super::{assets, model::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize, Serialize)]
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
    deadline: Instant,
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
                deadline: Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(|| anyhow!("invalid registry deadline"))?,
            },
            hash.to_owned(),
        ))
    }
    fn remaining(&self) -> Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!left.is_zero(), "registry operation exceeded its deadline");
        Ok(left)
    }
    fn request(&self, url: &Url) -> Result<Response> {
        let mut request = self
            .client
            .get(url.clone())
            .timeout(self.remaining()?)
            .header(
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
        let mut request = self.client.get(realm).timeout(self.remaining()?);
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
        let value = super::validation::bounded_value(&body, 64 << 10)?;
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
                .timeout(self.remaining()?)
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
    /// Stage one exact OCI closure. Import and activation remain separate owned
    /// effects; no layer expansion or registry access is deferred to boot.
    pub fn image_archive(
        &mut self,
        manifest_digest: &str,
        artifact: &Artifact,
        target: &Path,
        policy: &Policy,
    ) -> Result<()> {
        ensure!(
            image_reference(artifact.reference()),
            "invalid image transfer reference"
        );
        let (name, identity) = artifact.reference().split_once('@').unwrap();
        let (server, repository) = name.split_once('/').unwrap();
        let origin = Url::parse(&format!("https://{server}/"))?;
        ensure!(
            origin.origin() == self.origin.origin()
                && repository == self.repository
                && identity == manifest_digest,
            "image transfer differs from its registry scope"
        );
        let body = self.bytes("manifests", manifest_digest, IMAGE_METADATA)?;
        let deadline = self.deadline;
        stage_image(
            &body,
            manifest_digest,
            artifact,
            target,
            policy,
            deadline,
            |descriptor| self.get("blobs", &descriptor.digest),
        )
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
        let manifest: Manifest =
            serde_json::from_value(super::validation::bounded_value(&body, 256 << 10)?)?;
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

const IMAGE_METADATA: usize = 1 << 20;
const IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const IMAGE_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ImageManifest {
    schema_version: u32,
    media_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

fn image_deadline(deadline: Instant) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "OCI image staging exceeded its deadline"
    );
    Ok(())
}
fn image_descriptor(value: &Descriptor, maximum: u64) -> Result<()> {
    ensure!(
        digest(&value.digest)
            && value.size > 0
            && value.size <= maximum
            && value.annotations.len() <= 32
            && value
                .annotations
                .iter()
                .all(|(key, value)| safe_text(key, 1024) && safe_text(value, 4096)),
        "OCI image descriptor exceeds its identity or metadata bound"
    );
    Ok(())
}
fn image_copy<R: Read, W: Write>(
    mut source: R,
    mut target: W,
    descriptor: &Descriptor,
    deadline: Instant,
) -> Result<()> {
    let mut hash = Sha256::new();
    let mut seen = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        image_deadline(deadline)?;
        let n = source.read(&mut buffer[..((descriptor.size - seen).min(65535) + 1) as usize])?;
        if n == 0 {
            break;
        }
        seen = seen
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("OCI image size overflow"))?;
        ensure!(
            seen <= descriptor.size,
            "OCI blob exceeded its declared size"
        );
        hash.update(&buffer[..n]);
        target.write_all(&buffer[..n])?;
    }
    ensure!(
        seen == descriptor.size && format!("sha256:{:x}", hash.finalize()) == descriptor.digest,
        "OCI blob differs from its admitted digest or size"
    );
    Ok(())
}
fn expanded_layer(
    path: &Path,
    descriptor: &Descriptor,
    maximum: u64,
    deadline: Instant,
) -> Result<(String, u64)> {
    if descriptor.media_type == LAYER_TAR {
        ensure!(
            descriptor.size <= maximum,
            "OCI layers exceed their expanded bound"
        );
        return Ok((descriptor.digest.clone(), descriptor.size));
    }
    let mut decoder = flate2::bufread::GzDecoder::new(BufReader::new(File::open(path)?));
    let mut seen = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        image_deadline(deadline)?;
        let n = decoder.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        seen = seen
            .checked_add(n as u64)
            .ok_or_else(|| anyhow!("OCI expansion overflow"))?;
        ensure!(seen <= maximum, "OCI layers exceed their expanded bound");
        hash.update(&buffer[..n]);
    }
    ensure!(
        decoder.get_mut().fill_buf()?.is_empty(),
        "OCI gzip layer contains concatenated or trailing payload"
    );
    Ok((format!("sha256:{:x}", hash.finalize()), seen))
}
struct ImageReader<R> {
    source: R,
    deadline: Instant,
}
impl<R: Read> Read for ImageReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "OCI staging deadline exceeded",
            ));
        }
        self.source.read(buffer)
    }
}
fn image_entry<W: Write, R: Read>(
    archive: &mut tar::Builder<W>,
    name: &str,
    size: u64,
    source: R,
    deadline: Instant,
) -> Result<()> {
    image_deadline(deadline)?;
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, name, ImageReader { source, deadline })?;
    Ok(())
}

fn stage_image<F, R>(
    body: &[u8],
    manifest_digest: &str,
    artifact: &Artifact,
    target: &Path,
    policy: &Policy,
    deadline: Instant,
    mut fetch: F,
) -> Result<()>
where
    F: FnMut(&Descriptor) -> Result<R>,
    R: Read,
{
    image_deadline(deadline)?;
    let Artifact::Image {
        digest: accepted_manifest,
        config_digest,
        platform,
        ..
    } = artifact
    else {
        return Err(anyhow!("image transfer requires an image artifact"));
    };
    ensure!(
        digest(manifest_digest)
            && manifest_digest == accepted_manifest
            && document_digest(body) == manifest_digest,
        "OCI manifest differs from the accepted image artifact"
    );
    ensure!(
        policy.max_image_bytes > 0 && policy.max_image_bytes <= 8u64 << 30,
        "invalid image staging bound"
    );
    ensure!(
        target.is_absolute()
            && target
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "image archive target is not an absolute canonical path"
    );
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("image staging parent missing"))?;
    super::store::protected_directory(parent)?;
    ensure!(
        fs::metadata(parent)?.mode() & 0o077 == 0,
        "image staging parent is not private"
    );
    ensure!(
        !target.try_exists()? && fs::symlink_metadata(target).is_err(),
        "image archive target already exists"
    );
    let manifest: ImageManifest =
        serde_json::from_value(super::validation::bounded_value(body, IMAGE_METADATA)?)?;
    ensure!(
        manifest.schema_version == 2
            && manifest.media_type == IMAGE_MANIFEST
            && manifest.layers.len() <= 128
            && manifest.annotations.len() <= 32,
        "unsupported OCI image manifest"
    );
    image_descriptor(&manifest.config, IMAGE_METADATA as u64)?;
    ensure!(
        manifest.config.media_type == IMAGE_CONFIG && &manifest.config.digest == config_digest,
        "OCI image configuration differs from the accepted artifact"
    );
    let mut raw_total = body.len() as u64 + manifest.config.size;
    for layer in &manifest.layers {
        image_descriptor(layer, policy.max_image_bytes)?;
        ensure!(
            [LAYER_TAR, LAYER_GZIP].contains(&layer.media_type.as_str()),
            "unsupported OCI image layer media type"
        );
        raw_total = raw_total
            .checked_add(layer.size)
            .ok_or_else(|| anyhow!("OCI image size overflow"))?;
    }
    ensure!(
        raw_total <= policy.max_image_bytes,
        "OCI image exceeds its admitted raw byte bound"
    );
    let mut configuration = Vec::new();
    image_copy(
        fetch(&manifest.config)?,
        &mut configuration,
        &manifest.config,
        deadline,
    )?;
    let config = super::validation::bounded_value(&configuration, IMAGE_METADATA)?;
    ensure!(
        config.is_object()
            && config.get("os").and_then(serde_json::Value::as_str) == Some("linux")
            && config
                .get("architecture")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|arch| platform == &format!("linux/{arch}"))
            && ["linux/amd64", "linux/arm64"].contains(&platform.as_str()),
        "OCI image platform differs from the accepted artifact"
    );
    let rootfs = config
        .get("rootfs")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("OCI image rootfs missing"))?;
    let diffs = rootfs
        .get("diff_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("OCI image diff IDs missing"))?;
    ensure!(
        rootfs.len() == 2
            && rootfs.get("type").and_then(serde_json::Value::as_str) == Some("layers")
            && diffs.len() == manifest.layers.len()
            && diffs.iter().all(|value| value.as_str().is_some_and(digest)),
        "OCI image has no complete ordered RootFS identity"
    );
    let staging = tempfile::Builder::new()
        .prefix(".oci-image-")
        .tempdir_in(parent)?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
    let mut layers = BTreeMap::<String, (Descriptor, PathBuf, String, u64)>::new();
    let mut expanded = 0u64;
    for (layer, diff) in manifest.layers.iter().zip(diffs) {
        image_deadline(deadline)?;
        if !layers.contains_key(&layer.digest) {
            let path = staging.path().join(&layer.digest[7..]);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            image_copy(fetch(layer)?, &mut file, layer, deadline)?;
            file.sync_all()?;
            let (identity, size) =
                expanded_layer(&path, layer, policy.max_image_bytes - expanded, deadline)?;
            layers.insert(layer.digest.clone(), (layer.clone(), path, identity, size));
        }
        let (record, _, identity, size) = &layers[&layer.digest];
        ensure!(
            record.size == layer.size
                && record.media_type == layer.media_type
                && Some(identity.as_str()) == diff.as_str(),
            "OCI image layer differs from its immutable config RootFS"
        );
        expanded = expanded
            .checked_add(*size)
            .ok_or_else(|| anyhow!("OCI image expansion overflow"))?;
        ensure!(
            expanded <= policy.max_image_bytes,
            "OCI layers exceed their expanded bound"
        );
    }
    let index = serde_json::to_vec(
        &serde_json::json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
        "manifests":[{"mediaType":IMAGE_MANIFEST,"digest":manifest_digest,"size":body.len()}]}),
    )?;
    let layout = b"{\"imageLayoutVersion\":\"1.0.0\"}";
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    output.set_permissions(fs::Permissions::from_mode(0o600))?;
    let owned = output.metadata()?;
    let result = (|| -> Result<()> {
        {
            let mut archive = tar::Builder::new(&mut output);
            image_entry(
                &mut archive,
                "oci-layout",
                layout.len() as u64,
                layout.as_slice(),
                deadline,
            )?;
            image_entry(
                &mut archive,
                "index.json",
                index.len() as u64,
                index.as_slice(),
                deadline,
            )?;
            image_entry(
                &mut archive,
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                body.len() as u64,
                body,
                deadline,
            )?;
            image_entry(
                &mut archive,
                &format!("blobs/sha256/{}", &config_digest[7..]),
                configuration.len() as u64,
                configuration.as_slice(),
                deadline,
            )?;
            for (identity, (descriptor, path, _, _)) in &layers {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)?;
                ensure!(
                    file.metadata()?.is_file() && file.metadata()?.len() == descriptor.size,
                    "staged OCI layer changed"
                );
                image_entry(
                    &mut archive,
                    &format!("blobs/sha256/{}", &identity[7..]),
                    descriptor.size,
                    file,
                    deadline,
                )?;
            }
            archive.finish()?;
        }
        ensure!(
            output.metadata()?.len() <= policy.max_image_bytes,
            "OCI archive exceeds its admitted byte bound"
        );
        image_deadline(deadline)?;
        output.sync_all()?;
        Ok(())
    })();
    if result.is_err()
        && fs::symlink_metadata(target)
            .is_ok_and(|current| current.dev() == owned.dev() && current.ino() == owned.ino())
    {
        fs::remove_file(target)?;
    }
    result
}

#[cfg(test)]
mod image_tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::Cursor;
    struct Fixture {
        body: Vec<u8>,
        artifact: Artifact,
        blobs: BTreeMap<String, Vec<u8>>,
    }
    fn private_root() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
    fn policy() -> Policy {
        serde_json::from_value(json!({"kind":"komizo.policy","version":1,"application":"example","authority":{"kind":"owner"},
            "artifact_prefixes":["ghcr.io/example/app"],"hostnames":["app.example"],
            "limits":{"memory_bytes":1048576,"memory_swap_bytes":1048576,"milli_cpus":100,"pids":32},
            "max_image_bytes":1048576})).unwrap()
    }
    fn desc(bytes: &[u8], media: &str) -> Value {
        json!({"mediaType":media,"digest":document_digest(bytes),"size":bytes.len()})
    }
    fn encoded(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut stream = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        stream.write_all(bytes).unwrap();
        stream.finish().unwrap()
    }
    fn layer(body: &[u8]) -> Vec<u8> {
        let mut output = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        output.append_data(&mut header, "data/value", body).unwrap();
        output.into_inner().unwrap()
    }
    fn fixture(parts: &[(Vec<u8>, bool)]) -> Fixture {
        let mut blobs = BTreeMap::new();
        let mut layers = vec![];
        let mut diffs = vec![];
        for (body, compressed) in parts {
            let bytes = if *compressed {
                gzip(body)
            } else {
                body.clone()
            };
            let row = desc(&bytes, if *compressed { LAYER_GZIP } else { LAYER_TAR });
            blobs.insert(row["digest"].as_str().unwrap().into(), bytes);
            layers.push(row);
            diffs.push(document_digest(body));
        }
        let config = encoded(
            &json!({"os":"linux","architecture":"amd64","config":{"User":"10001:10001"},"rootfs":{"type":"layers","diff_ids":diffs}}),
        );
        let config_row = desc(&config, IMAGE_CONFIG);
        blobs.insert(config_row["digest"].as_str().unwrap().into(), config);
        let body = encoded(
            &json!({"schemaVersion":2,"mediaType":IMAGE_MANIFEST,"config":config_row,"layers":layers}),
        );
        let identity = document_digest(&body);
        let artifact = Artifact::Image {
            reference: format!("ghcr.io/example/app@{identity}"),
            digest: identity,
            config_digest: config_row["digest"].as_str().unwrap().into(),
            platform: "linux/amd64".into(),
        };
        Fixture {
            body,
            artifact,
            blobs,
        }
    }
    fn mutate_manifest(fixture: &mut Fixture, change: impl FnOnce(&mut Value)) {
        let mut value: Value = serde_json::from_slice(&fixture.body).unwrap();
        change(&mut value);
        fixture.body = encoded(&value);
        if let Artifact::Image {
            reference, digest, ..
        } = &mut fixture.artifact
        {
            *digest = document_digest(&fixture.body);
            *reference = format!("ghcr.io/example/app@{digest}");
        }
    }
    fn mutate_config(fixture: &mut Fixture, change: impl FnOnce(&mut Value)) {
        let manifest: Value = serde_json::from_slice(&fixture.body).unwrap();
        let mut value: Value =
            serde_json::from_slice(&fixture.blobs[manifest["config"]["digest"].as_str().unwrap()])
                .unwrap();
        change(&mut value);
        let bytes = encoded(&value);
        let row = desc(&bytes, IMAGE_CONFIG);
        fixture
            .blobs
            .insert(row["digest"].as_str().unwrap().into(), bytes);
        if let Artifact::Image { config_digest, .. } = &mut fixture.artifact {
            *config_digest = row["digest"].as_str().unwrap().into();
        }
        mutate_manifest(fixture, |value| value["config"] = row);
    }
    fn stage(fixture: &Fixture, target: &Path, policy: &Policy) -> Result<()> {
        stage_image(
            &fixture.body,
            fixture.artifact.digest(),
            &fixture.artifact,
            target,
            policy,
            Instant::now() + Duration::from_secs(10),
            |descriptor| {
                Ok(Cursor::new(
                    fixture
                        .blobs
                        .get(&descriptor.digest)
                        .ok_or_else(|| anyhow!("fixture blob missing"))?
                        .clone(),
                ))
            },
        )
    }
    #[test]
    fn single_oci_image_preserves_exact_manifest_config_layers_and_private_metadata() {
        let first = layer(b"first");
        let second = layer(b"second");
        let fixture = fixture(&[(first, false), (second, true)]);
        let root = private_root();
        let target = root.path().join("image.oci.tar");
        stage(&fixture, &target, &policy()).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        let mut archive = tar::Archive::new(File::open(&target).unwrap());
        let mut observed = BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            assert!(entry.header().entry_type().is_file());
            assert_eq!(entry.header().mode().unwrap(), 0o600);
            assert_eq!(entry.header().uid().unwrap(), 0);
            assert_eq!(entry.header().gid().unwrap(), 0);
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut bytes = vec![];
            entry.read_to_end(&mut bytes).unwrap();
            assert!(observed.insert(name, bytes).is_none());
        }
        assert_eq!(
            observed.remove("oci-layout").unwrap(),
            b"{\"imageLayoutVersion\":\"1.0.0\"}"
        );
        let index: Value = serde_json::from_slice(&observed.remove("index.json").unwrap()).unwrap();
        assert_eq!(index["manifests"].as_array().unwrap().len(), 1);
        assert_eq!(index["manifests"][0]["digest"], fixture.artifact.digest());
        assert_eq!(
            observed
                .remove(&format!("blobs/sha256/{}", &fixture.artifact.digest()[7..]))
                .unwrap(),
            fixture.body
        );
        for (identity, bytes) in &fixture.blobs {
            assert_eq!(
                observed
                    .remove(&format!("blobs/sha256/{}", &identity[7..]))
                    .unwrap(),
                *bytes
            );
        }
        assert!(observed.is_empty());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
    #[test]
    fn mismatched_manifest_config_platform_and_diff_ids_never_leave_an_archive() {
        for invalid in ["manifest", "config", "platform", "diff", "duplicate-json"] {
            let mut fixture = fixture(&[(layer(b"value"), true)]);
            match invalid {
                "manifest" => fixture.body.push(b' '),
                "config" => {
                    if let Artifact::Image { config_digest, .. } = &mut fixture.artifact {
                        *config_digest = format!("sha256:{}", "0".repeat(64));
                    }
                }
                "platform" => {
                    mutate_config(&mut fixture, |value| value["architecture"] = json!("arm64"))
                }
                "diff" => mutate_config(&mut fixture, |value| {
                    value["rootfs"]["diff_ids"][0] = json!(format!("sha256:{}", "0".repeat(64)))
                }),
                _ => {
                    fixture.body = b"{\"schemaVersion\":2,\"schemaVersion\":2}".to_vec();
                    if let Artifact::Image { digest, .. } = &mut fixture.artifact {
                        *digest = document_digest(&fixture.body);
                    }
                }
            }
            let root = private_root();
            let target = root.path().join("image.oci.tar");
            assert!(stage(&fixture, &target, &policy()).is_err(), "{invalid}");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0, "{invalid}");
        }
    }
    #[test]
    fn descriptor_urls_foreign_media_types_layer_counts_and_declared_size_bombs_refuse_before_fetch()
     {
        for invalid in ["url", "type", "count", "size"] {
            let mut fixture = fixture(&[(layer(b"value"), false)]);
            mutate_manifest(&mut fixture, |value| match invalid {
                "url" => value["layers"][0]["urls"] = json!(["https://foreign.test/layer"]),
                "type" => value["layers"][0]["mediaType"] = json!("application/octet-stream"),
                "count" => value["layers"] = json!(vec![value["layers"][0].clone(); 129]),
                _ => value["layers"][0]["size"] = json!(1048577),
            });
            let root = private_root();
            let mut called = false;
            let result = stage_image(
                &fixture.body,
                fixture.artifact.digest(),
                &fixture.artifact,
                &root.path().join("image"),
                &policy(),
                Instant::now() + Duration::from_secs(1),
                |_| {
                    called = true;
                    Ok(Cursor::new(vec![]))
                },
            );
            assert!(result.is_err(), "{invalid}");
            assert!(!called, "{invalid}");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn corrupt_truncated_oversized_and_missing_raw_blobs_never_leave_partial_output() {
        for invalid in ["changed", "short", "long", "missing"] {
            let mut fixture = fixture(&[(layer(b"value"), true)]);
            let manifest: Value = serde_json::from_slice(&fixture.body).unwrap();
            let identity = manifest["layers"][0]["digest"].as_str().unwrap();
            match invalid {
                "changed" => fixture.blobs.get_mut(identity).unwrap()[0] ^= 1,
                "short" => {
                    fixture.blobs.get_mut(identity).unwrap().pop();
                }
                "long" => fixture.blobs.get_mut(identity).unwrap().push(0),
                _ => {
                    fixture.blobs.remove(identity);
                }
            }
            let root = private_root();
            assert!(
                stage(&fixture, &root.path().join("image"), &policy()).is_err(),
                "{invalid}"
            );
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn compressed_expansion_repeated_layers_and_gzip_trailers_cannot_bypass_one_budget() {
        for invalid in ["expansion", "repeated", "trailer"] {
            let mut fixture = if invalid == "expansion" {
                fixture(&[(vec![0; 32769], true)])
            } else if invalid == "repeated" {
                fixture(&[(vec![0; 20000], true), (vec![0; 20000], true)])
            } else {
                fixture(&[(layer(b"value"), true)])
            };
            if invalid == "trailer" {
                let manifest: Value = serde_json::from_slice(&fixture.body).unwrap();
                let mut bytes =
                    fixture.blobs[manifest["layers"][0]["digest"].as_str().unwrap()].clone();
                bytes.extend(b"trailing");
                let row = desc(&bytes, LAYER_GZIP);
                fixture
                    .blobs
                    .insert(row["digest"].as_str().unwrap().into(), bytes);
                mutate_manifest(&mut fixture, |value| value["layers"][0] = row);
            }
            let mut policy = policy();
            policy.max_image_bytes = 32768;
            let root = private_root();
            assert!(
                stage(&fixture, &root.path().join("image"), &policy).is_err(),
                "{invalid}"
            );
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }
    #[test]
    fn existing_targets_linked_ancestors_and_archive_padding_failure_preserve_owned_siblings() {
        let fixture = fixture(&[(layer(b"value"), false)]);
        let root = private_root();
        let target = root.path().join("image");
        fs::write(&target, b"keep").unwrap();
        assert!(stage(&fixture, &target, &policy()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        std::os::unix::fs::symlink(root.path(), root.path().join("alias")).unwrap();
        assert!(stage(&fixture, &root.path().join("alias/other"), &policy()).is_err());
        let mut tiny = policy();
        tiny.max_image_bytes = fixture.body.len() as u64
            + fixture
                .blobs
                .values()
                .map(|value| value.len() as u64)
                .sum::<u64>();
        assert!(stage(&fixture, &root.path().join("new"), &tiny).is_err());
        assert!(!root.path().join("new").exists());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }
    #[test]
    fn expired_image_staging_cannot_fetch_or_create_a_target() {
        let fixture = fixture(&[(layer(b"value"), false)]);
        let root = private_root();
        let mut called = false;
        assert!(
            stage_image(
                &fixture.body,
                fixture.artifact.digest(),
                &fixture.artifact,
                &root.path().join("image"),
                &policy(),
                Instant::now() - Duration::from_secs(1),
                |_| {
                    called = true;
                    Ok(Cursor::new(vec![]))
                }
            )
            .is_err()
        );
        assert!(!called);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
