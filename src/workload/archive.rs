//! Bounded archive readers never extract configuration or Docker image paths.
use super::yaml::MAX_BYTES;
use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, copy, sink},
};
pub fn read_configuration(input: impl Read) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut limited = input.take((4 << 20) + 1);
    let mut compose = vec![];
    let mut hostnames = vec![];
    let mut seen = BTreeSet::new();
    {
        let mut archive = tar::Archive::new(&mut limited);
        for entry in archive
            .entries()
            .map_err(|_| anyhow!("invalid configuration archive"))?
        {
            let mut entry = entry.map_err(|_| anyhow!("invalid configuration archive"))?;
            let path = entry.path_bytes();
            let raw = std::str::from_utf8(&path)
                .map_err(|_| anyhow!("unsafe configuration archive path"))?;
            let raw = raw.strip_prefix("./").unwrap_or(raw);
            let raw = if raw.is_empty() && entry.header().entry_type().is_dir() {
                "."
            } else {
                raw
            };
            let name = crate::host::inventory::clean_path(raw);
            ensure!(
                (raw == name || raw == format!("{name}/"))
                    && !name.starts_with('/')
                    && name != ".."
                    && !name.starts_with("../"),
                "unsafe configuration archive path"
            );
            if entry.header().entry_type().is_dir() && matches!(name.as_str(), "config" | ".") {
                continue;
            }
            let name = name.strip_prefix("config/").unwrap_or(&name).to_owned();
            ensure!(
                entry.header().entry_type().is_file()
                    && seen.insert(name.clone())
                    && matches!(name.as_str(), "compose.yml" | "hostnames"),
                "configuration archive contains an unsupported entry"
            );
            let limit = if name == "hostnames" {
                16 << 10
            } else {
                MAX_BYTES
            };
            let size = entry.size();
            ensure!(size <= limit as u64, "configuration file exceeds its bound");
            let mut body = vec![];
            entry
                .read_to_end(&mut body)
                .map_err(|_| anyhow!("incomplete configuration file"))?;
            ensure!(body.len() as u64 == size, "incomplete configuration file");
            if name == "compose.yml" {
                compose = body;
            } else {
                hostnames = body;
            }
        }
    }
    ensure!(
        limited.limit() > 0 && !compose.is_empty(),
        "configuration archive exceeds its bound or has no compose file"
    );
    Ok((compose, hostnames))
}
pub fn docker_archive_config_digest(input: impl Read) -> Result<String> {
    let mut limited = input.take((2 << 30) + 1);
    let mut hashes = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut config = String::new();
    {
        let mut archive = tar::Archive::new(&mut limited);
        for entry in archive
            .entries()
            .map_err(|_| anyhow!("invalid local image archive"))?
        {
            let mut entry = entry.map_err(|_| anyhow!("invalid local image archive"))?;
            ensure!(
                seen.len() < 4096 && entry.size() <= 2 << 30,
                "invalid local image archive"
            );
            let path = entry.path_bytes();
            let mut name = std::str::from_utf8(&path)
                .map_err(|_| anyhow!("ambiguous local image archive"))?
                .to_owned();
            if entry.header().entry_type().is_dir() && name.ends_with('/') {
                name.pop();
            }
            ensure!(
                !name.starts_with('/')
                    && crate::host::inventory::clean_path(&name) == name
                    && !name.starts_with("../")
                    && seen.insert(name.clone()),
                "ambiguous local image archive"
            );
            if !entry.header().entry_type().is_file() || entry.size() > 1 << 20 {
                continue;
            }
            let mut body = vec![];
            entry.read_to_end(&mut body)?;
            ensure!(hashes.len() < 256, "too many local image metadata files");
            hashes.insert(name.clone(), format!("sha256:{:x}", Sha256::digest(&body)));
            if name == "manifest.json" {
                let value = crate::strict::value(&body, 1 << 20)
                    .map_err(|_| anyhow!("local image export must contain one image"))?;
                let values = value
                    .as_array()
                    .ok_or_else(|| anyhow!("local image export must contain one image"))?;
                ensure!(
                    values.len() == 1,
                    "local image export must contain one image"
                );
                config = values[0]
                    .get("Config")
                    .or_else(|| values[0].get("config"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .into();
                ensure!(
                    !config.is_empty(),
                    "local image export must contain one image"
                );
            }
        }
    }
    copy(&mut limited, &mut sink()).map_err(|_| anyhow!("local image archive exceeds limit"))?;
    ensure!(limited.limit() > 0, "local image archive exceeds limit");
    ensure!(
        config != "manifest.json" && hashes.contains_key(&config),
        "local image configuration missing"
    );
    Ok(hashes.remove(&config).unwrap())
}
pub fn static_gate(compose: &[u8], app: &str) -> Result<String> {
    // No evaluation of Compose expressions, includes or environment is permitted.
    let value = serde_json::from_slice::<serde_json::Value>(compose)
        .map_err(|_| anyhow!("static profile requires one gate-only service"))?;
    let services = value
        .get("services")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("static profile requires one gate-only service"))?;
    ensure!(
        services.len() == 1,
        "static profile requires one gate-only service"
    );
    let image = services
        .get(&format!("{app}-gate"))
        .and_then(|v| v.get("image"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    ensure!(
        image.contains("@sha256:"),
        "static profile requires the admitted immutable gate image"
    );
    Ok(image.into())
}
