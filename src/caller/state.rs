//! Deployment identity stays in the operator's private targets file.
use super::{transport::Target, validate};
use crate::{
    flags::{Flags, Value as FlagValue},
    wire::Slice,
    wire_struct,
    workload::{policy::Policy, policy_read},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
wire_struct!(Binding{host:"host":String=>required,port:"port":i64=>required,app:"app":String=>required});
wire_struct!(Targets{version:"version":i64=>required,projects:"projects":BTreeMap<String,Binding> =>required});
wire_struct!(Deployment{version:"version":i64=>required,repository:"repository":String=>required,images:"images":Slice<String> =>optional});
wire_struct!(Definition{version:"version":i64=>required,app:"app":String=>required,config:"config":String=>required,policy:"policy":Policy=>required});
wire_struct!(ScopedValues{version:"version":i64=>required,profile:"profile":String=>required,schema:"schema":i64=>required,files:"files":Slice<String> =>required,provision_script:"provision_script":String=>required,status_script:"status_script":String=>required});
pub struct Scoped {
    pub values: ScopedValues,
    pub provision: Vec<u8>,
    pub status: Vec<u8>,
}
pub fn read_file(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.len() <= limit as u64 && (!private || info.mode() & 0o077 == 0),
        "input must be a bounded regular file; credential files must be private"
    );
    let mut body = vec![];
    file.take(limit as u64 + 1).read_to_end(&mut body)?;
    ensure!(body.len() <= limit, "input exceeds its bound");
    Ok(body)
}
pub fn repository_slug(value: &str) -> bool {
    let Some((owner, repo)) = value.split_once('/') else {
        return false;
    };
    [owner, repo].iter().all(|v| {
        !v.is_empty()
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    })
}
pub fn decode_targets(body: &[u8]) -> Result<Targets> {
    let mut value = crate::strict::fields(
        crate::strict::value(body, 1 << 20)?,
        &["version", "projects"],
    )?;
    if value.is_null() {
        value = json!({"version":1,"projects":{}});
    }
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid private project targets"))?;
    if object.get("version").is_none_or(Value::is_null) {
        object.insert("version".into(), 1.into());
    }
    if !object.contains_key("projects") {
        object.insert("projects".into(), json!({}));
    }
    ensure!(
        !object["projects"].is_null(),
        "invalid private project targets"
    );
    if let Some(projects) = object.get_mut("projects").and_then(Value::as_object_mut) {
        for binding in projects.values_mut() {
            *binding = crate::strict::fields(binding.take(), &["host", "port", "app"])?;
        }
    }
    let config: Targets = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("invalid private project targets"))?;
    ensure!(config.version == 1, "invalid private project targets");
    for (repository, binding) in &config.projects {
        ensure!(
            repository_slug(repository)
                && validate::app(&binding.app).is_ok()
                && (1..=65535).contains(&binding.port),
            "invalid private project binding"
        );
        let target = Target::parse(&binding.host)?;
        validate::host(&target.host)?;
    }
    Ok(config)
}
pub fn read_targets(path: &Path) -> Result<Targets> {
    match read_file(path, 1 << 20, true) {
        Ok(body) => decode_targets(&body),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(Targets {
                version: 1,
                ..Default::default()
            })
        }
        Err(e) => Err(e),
    }
}
pub fn bind_target(path: &Path, repository: &str, target: &Target, app: &str) -> Result<()> {
    ensure!(
        repository_slug(repository) && validate::app(app).is_ok(),
        "invalid repository binding"
    );
    let mut config = read_targets(path)?;
    let binding = Binding {
        host: target.addr(),
        port: target.port,
        app: app.into(),
    };
    if let Some(previous) = config.projects.get(repository) {
        ensure!(
            previous.host == binding.host
                && previous.port == binding.port
                && previous.app == binding.app,
            "existing private project target differs; review the target file before moving an application"
        );
    }
    config.projects.insert(repository.into(), binding);
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(directory)?;
    let info = parent.metadata()?;
    ensure!(
        info.is_dir() && info.mode() & 0o077 == 0,
        "target directory must be private and regular"
    );
    crate::statefile::write_private_json(path, &config)
}
pub fn decode_deployment(body: &[u8]) -> Result<Deployment> {
    let value = crate::strict::fields(
        crate::strict::value(body, 1 << 20)?,
        &["version", "repository", "images"],
    )?;
    let config:Deployment=serde_json::from_value(value).map_err(|_|anyhow::anyhow!("komizo.json must contain only a version-1 deployment repository and optional image references"))?;
    ensure!(
        config.version == 1 && repository_slug(&config.repository) && config.images.len() <= 16,
        "komizo.json must contain only a version-1 deployment repository and optional image references"
    );
    let mut seen = std::collections::BTreeSet::new();
    for image in config.images.iter() {
        let resolved = image.replace("{revision}", &"a".repeat(40));
        ensure!(
            !image.is_empty()
                && seen.insert(image)
                && image.len() <= 2048
                && resolved
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-:/@=".contains(&b)),
            "deployment images require distinct valid references with only an optional {{revision}} template"
        );
    }
    Ok(config)
}
pub fn read_deployment(directory: &Path) -> Result<Deployment> {
    let path = directory.join("komizo.toml");
    ensure!(
        path.exists() || !directory.join("komizo.json").exists(),
        "legacy komizo.json requires explicit conversion to komizo.toml; legacy JSON v1 must be converted manually; no automatic import"
    );
    let bytes = read_file(&path, 1 << 20, false)
        .map_err(|e| anyhow::anyhow!("read deployment configuration: {e}"))?;
    let value =
        crate::source_toml::parse(std::str::from_utf8(&bytes)?).map_err(anyhow::Error::msg)?;
    // The existing strict deployment policy is also the explicit v1 JSON protocol codec.
    decode_deployment(&serde_json::to_vec(&value)?)
}
pub fn default_target(
    directory: &Path,
    path: &Path,
    flags: &mut Flags,
) -> Result<Option<Deployment>> {
    if !flags.text("host").is_empty() {
        return Ok(None);
    }
    let deployment = read_deployment(directory)?;
    let config = read_targets(path)?;
    let binding=config.projects.get(&deployment.repository).ok_or_else(||anyhow::anyhow!("no private target for this repository; an operator must run komizo setup --host HOST --definition FILE, or supply --host and --app explicitly"))?;
    ensure!(
        flags.text("app").is_empty() || flags.text("app") == binding.app,
        "application differs from the private repository binding"
    );
    ensure!(
        !flags.seen.contains("port") || flags.integer("port") == binding.port,
        "SSH port differs from the private deployment binding; select the host explicitly to override it"
    );
    flags
        .values
        .insert("host".into(), FlagValue::Text(binding.host.clone()));
    flags
        .values
        .insert("app".into(), FlagValue::Text(binding.app.clone()));
    if !flags.seen.contains("port") {
        flags
            .values
            .insert("port".into(), FlagValue::Int(binding.port));
        flags.seen.insert("port".into());
    }
    Ok(Some(deployment))
}
pub fn decode_definition(body: &[u8]) -> Result<Definition> {
    let mut value = crate::strict::fields(
        crate::strict::value(body, 1 << 20)?,
        &["version", "app", "config", "policy"],
    )?;
    // Reuse the complete nested policy decoder; an envelope cannot weaken it.
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("definition must be one versioned JSON document"))?;
    let policy = policy_read::read_policy(&serde_json::to_vec(
        object.get("policy").unwrap_or(&Value::Null),
    )?)?;
    object.insert("policy".into(), serde_json::to_value(policy)?);
    let definition: Definition = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("definition must be one versioned JSON document"))?;
    ensure!(
        definition.version == 1,
        "unsupported application definition version"
    );
    validate::app(&definition.app)?;
    validate::config_image(&definition.config)?;
    let base = Policy::new(
        &definition.app,
        &format!("/srv/{}", definition.app),
        &definition.config,
        "edge",
    )?;
    let p = &definition.policy;
    ensure!(
        p.app == base.app
            && p.app_dir == base.app_dir
            && p.image_prefix == base.image_prefix
            && p.shared_network == base.shared_network,
        "definition policy does not match its app, configuration family or default network"
    );
    p.check()?;
    ensure!(
        p.has_release_authority() && p.resources.is_some() && p.readiness.is_some(),
        "definition needs explicit trusted source, finite resources and readiness"
    );
    Ok(definition)
}
pub fn read_definition(path: &Path) -> Result<Definition> {
    decode_definition(&read_file(path, 1 << 20, false)?)
}
pub fn read_scoped(path: &Path) -> Result<Scoped> {
    let body = read_file(path, 65536, false).map_err(|_| {
        anyhow::anyhow!("scoped environment specification unavailable or oversized")
    })?;
    let value = crate::strict::fields(
        crate::strict::value(&body, 65536)?,
        &[
            "version",
            "profile",
            "schema",
            "files",
            "provision_script",
            "status_script",
        ],
    )?;
    let values: ScopedValues = serde_json::from_value(value)?;
    ensure!(
        values.version == 1,
        "one versioned scoped environment specification is required"
    );
    ensure!(
        !values.profile.is_empty()
            && crate::host::scoped::parse_definition(
                &values.profile,
                &values.schema.to_string(),
                &values.files.join(",")
            )
            .is_ok(),
        "scoped environment specification requires an explicit valid definition"
    );
    let read = |name: &str| -> Result<Vec<u8>> {
        ensure!(
            Path::new(name).file_name().and_then(|v| v.to_str()) == Some(name)
                && !matches!(name, "." | "..")
                && name.ends_with(".sh"),
            "scoped adapter must be a sibling shell script"
        );
        let body = read_file(
            &path.parent().unwrap_or(Path::new(".")).join(name),
            64 << 10,
            false,
        )
        .map_err(|_| anyhow::anyhow!("scoped adapter must be a bounded regular file"))?;
        ensure!(body.starts_with(b"#!"), "scoped adapter requires a shebang");
        Ok(body)
    };
    let provision = read(&values.provision_script)?;
    let status = read(&values.status_script)?;
    ensure!(
        provision.len() + status.len() <= 64 << 10,
        "combined scoped adapters exceed transport bound"
    );
    Ok(Scoped {
        values,
        provision,
        status,
    })
}
pub fn target_path() -> Result<PathBuf> {
    if let Some(directory) = std::env::var_os("KOMIZO_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        ensure!(
            directory.is_absolute(),
            "KOMIZO_CONFIG_DIR must be absolute"
        );
        return Ok(directory.join("targets.json"));
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let directory = if cfg!(target_os = "macos") {
        home.map(|home| home.join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|home| home.join(".config")))
    }
    .ok_or_else(|| anyhow::anyhow!("no user configuration directory"))?;
    ensure!(
        directory.is_absolute(),
        "configuration directory must be absolute"
    );
    Ok(directory.join("komizo/targets.json"))
}
