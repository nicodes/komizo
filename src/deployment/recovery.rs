//! Owner reconciliation observes protected effects; it never recreates data.
use super::{
    engine::Engine,
    native::{self, ObjectIntent},
    store::{self, Installed, ObjectRecord, Store},
    system, units,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRemoval {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub instance: String,
    pub operation_id: String,
    pub release_digest: String,
    pub object_kind: String,
    pub logical: String,
    pub name: String,
    pub identity: String,
}
fn journal(store: &Store, operation: &str) -> Result<Vec<PathBuf>> {
    ensure!(
        hex(operation, 32),
        "invalid object reconciliation operation"
    );
    let path = store.root.join("journal").join(operation);
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    store::protected_directory(&path)?;
    let mut selected = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(path)? {
        count += 1;
        ensure!(
            count <= 16384,
            "operation journal exceeds reconciliation bound"
        );
        let path = entry?.path();
        let name = path.file_name().and_then(|p| p.to_str()).unwrap_or("");
        if name.starts_with("object-") && name.ends_with(".json") {
            selected.push(path)
        }
    }
    selected.sort();
    Ok(selected)
}
fn scope(
    application: &str,
    instance: &str,
    release: &str,
    operation: &str,
    installed: &Installed,
    target: &str,
) -> Result<()> {
    ensure!(
        name(application)
            && name(instance)
            && digest(release)
            && installed.kind == "komizo.installed"
            && installed.version == 1
            && application == installed.application
            && instance == installed.instance
            && release == installed.release_digest
            && operation == target
            && hex(target, 32),
        "object intent differs from its exact staged scope"
    );
    Ok(())
}
fn record_map<'a>(
    installed: &'a mut Installed,
    kind: &str,
) -> Result<&'a mut std::collections::BTreeMap<String, ObjectRecord>> {
    match kind {
        "network" => Ok(&mut installed.resources.networks),
        "volume" => Ok(&mut installed.resources.volumes),
        _ => Err(anyhow!("unknown retained object kind")),
    }
}
pub fn reconcile_objects(
    store: &Store,
    installed: &mut Installed,
    operation_id: &str,
    engine: &Engine,
) -> Result<()> {
    reconcile_objects_with(store, installed, operation_id, |kind, name| {
        if engine.exists(kind, name)? {
            Ok(Some(engine.inspect(kind, name)?))
        } else {
            Ok(None)
        }
    })
}
pub fn reconcile_objects_with(
    store: &Store,
    installed: &mut Installed,
    operation_id: &str,
    inspect: impl Fn(&str, &str) -> Result<Option<Value>>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for path in journal(store, operation_id)? {
        let value = crate::strict::value(&store::read_protected(&path, 1 << 20)?, 1 << 20)?;
        if value["kind"] != "komizo.object-intent" {
            continue;
        }
        let mut intent: ObjectIntent = serde_json::from_value(value)?;
        scope(
            &intent.application,
            &intent.instance,
            &intent.release_digest,
            &intent.operation_id,
            installed,
            operation_id,
        )?;
        ensure!(
            seen.insert((intent.object_kind.clone(), intent.logical.clone())),
            "duplicate object creation authority"
        );
        ensure!(
            intent.version == 1
                && hex(&intent.ownership, 32)
                && ((intent.object_kind == "network"
                    && intent.internal.is_some()
                    && intent.identity.as_deref().is_none_or(|id| hex(id, 64)))
                    || (intent.object_kind == "volume"
                        && intent.internal.is_none()
                        && intent.identity.as_deref().is_none_or(digest))),
            "invalid protected object creation intent"
        );
        ensure!(
            name(&intent.logical)
                && intent.name
                    == units::object_name(
                        &intent.application,
                        &intent.instance,
                        &intent.object_kind,
                        &intent.logical
                    )?,
            "invalid object intent name"
        );
        let actual = inspect(&intent.object_kind, &intent.name)?;
        let map = record_map(installed, &intent.object_kind)?;
        let Some(actual) = actual else {
            ensure!(
                intent.identity.is_none() && !map.contains_key(&intent.logical),
                "recorded retained object disappeared; owner transfer evidence required"
            );
            continue;
        };
        let record = native::object_evidence(&intent, &actual)?;
        if let Some(old) = map.get(&intent.logical) {
            ensure!(
                old.name == record.name && old.id == record.id,
                "installed retained object differs from creation intent"
            )
        }
        intent.identity = Some(record.id.clone());
        // Persist the observed exact ID before advancing the installed ledger.
        store::atomic(&path, &serde_json::to_vec(&intent)?, 0o600)?;
        map.insert(intent.logical, record);
        store.save_installed(installed)?;
    }
    Ok(())
}
pub fn reconcile_object_removals(
    store: &Store,
    installed: &mut Installed,
    operation_id: &str,
    engine: &Engine,
) -> Result<()> {
    reconcile_object_removals_with(store, installed, operation_id, |kind, name| {
        if engine.exists(kind, name)? {
            Ok(Some(engine.inspect(kind, name)?))
        } else {
            Ok(None)
        }
    })
}
pub fn reconcile_object_removals_with(
    store: &Store,
    installed: &mut Installed,
    operation_id: &str,
    inspect: impl Fn(&str, &str) -> Result<Option<Value>>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for path in journal(store, operation_id)? {
        let value = crate::strict::value(&store::read_protected(&path, 1 << 20)?, 1 << 20)?;
        if value["kind"] != "komizo.object-removal" {
            continue;
        }
        let intent: ObjectRemoval = serde_json::from_value(value)?;
        scope(
            &intent.application,
            &intent.instance,
            &intent.release_digest,
            &intent.operation_id,
            installed,
            operation_id,
        )?;
        ensure!(
            intent.version == 1
                && name(&intent.logical)
                && ["network", "volume"].contains(&intent.object_kind.as_str())
                && intent.name
                    == units::object_name(
                        &intent.application,
                        &intent.instance,
                        &intent.object_kind,
                        &intent.logical
                    )?
                && (if intent.object_kind == "network" {
                    hex(&intent.identity, 64)
                } else {
                    digest(&intent.identity)
                })
                && seen.insert((intent.object_kind.clone(), intent.logical.clone())),
            "invalid or duplicate exact object removal authority"
        );
        let actual = inspect(&intent.object_kind, &intent.name)?;
        let map = record_map(installed, &intent.object_kind)?;
        if let Some(previous) = map.get(&intent.logical) {
            ensure!(
                previous.name == intent.name && previous.id == intent.identity,
                "removal intent differs from installed object identity"
            );
        }
        if let Some(actual) = actual {
            let identity = if intent.object_kind == "network" {
                actual["id"].as_str().unwrap_or("").to_owned()
            } else {
                super::engine::volume_identity(&actual)?
            };
            ensure!(
                identity == intent.identity && map.contains_key(&intent.logical),
                "existing retained object changed after removal intent"
            );
            // The authorized removal has not happened. Preserve it; never replay rm.
            continue;
        }
        map.remove(&intent.logical);
        store.save_installed(installed)?;
    }
    Ok(())
}
pub fn reconcile_units(
    store: &Store,
    application: &str,
    instance: &str,
    operation_id: &str,
) -> Result<()> {
    system::reconcile_unit_intents(store, application, instance, operation_id)
}
