//! Release retention: reclaim what superseded releases left on a host.
//!
//! Komizo stages three kinds of physical state per release: an extracted asset
//! tree under the assets root, Podman images (named only by image ID) and
//! exited one-shot job containers. Nothing else removes them, so a host
//! eventually refuses staging for lack of disk. This module computes the set of
//! releases that must stay (see [`keep_set`]) and removes everything outside it
//! in a fixed order: asset trees, job containers, then images.
//!
//! Collection must never race `stage()`. `stage()` holds the host-wide staging
//! lock for its whole run; [`collect`] demands a [`Lease`] on that same lock, so
//! it can only run from inside staging (the capacity gate), after a deploy, or
//! from the owner command, and the owner command cannot run during staging.

use super::{
    engine::{Engine, normalize_id},
    jobs,
    model::*,
    proxy,
    store::{self, Guard, Installed, Operation, Store},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

/// Prefix of the same-filesystem name an asset tree is renamed to before it is
/// removed. It is never a release name, so a crash cannot leave a partial tree
/// under one; the next run removes whatever is left.
pub const TRASH_PREFIX: &str = ".komizo-trash-";

/// Proof that the caller holds the staging lock for the host.
pub struct Lease {
    _guard: Guard,
}

pub fn try_lease(store: &Store) -> Result<Option<Lease>> {
    Ok(store
        .try_lock("platform", "retention")?
        .map(|guard| Lease { _guard: guard }))
}

/// Held by `stage()` for its whole run, so the owner command cannot collect
/// while artifacts are being fetched, extracted or imported.
pub fn staging_lease(store: &Store, deadline: Instant) -> Result<Lease> {
    loop {
        if let Some(lease) = try_lease(store)? {
            return Ok(lease);
        }
        ensure!(
            Instant::now() < deadline,
            "release collection held the staging lock past the operation deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Releases that must keep their physical state, with the reasons they do.
#[derive(Debug, Default)]
pub struct Keep(BTreeMap<String, BTreeSet<&'static str>>);

impl Keep {
    pub fn contains(&self, release: &str) -> bool {
        self.0.contains_key(release)
    }
    pub fn releases(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }
    pub fn reasons(&self, release: &str) -> Vec<&'static str> {
        self.0
            .get(release)
            .map(|r| r.iter().copied().collect())
            .unwrap_or_default()
    }
    fn add(&mut self, release: &str, reason: &'static str) {
        if digest(release) {
            self.0.entry(release.to_owned()).or_default().insert(reason);
        }
    }
}

/// The action an operation was admitted with, when its journal records one.
fn action(store: &Store, operation: &str) -> Result<Option<String>> {
    let path = store
        .root
        .join("journal")
        .join(operation)
        .join("admission.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(&store::read_protected(&path, MAX_DOCUMENT_BYTES)?)?;
    Ok(value["action"].as_str().map(str::to_owned))
}

/// Compute the keep set across every installed instance and application.
///
/// Per instance that is not a removed tombstone: its current release, a
/// prepared (stopped) release, the previous release (the most recent earlier
/// successful deploy in its history with a different release) and the newest
/// failed deploy (a retry candidate). Host-wide: every release named by an
/// operation that is non-terminal or awaits reconciliation.
pub fn keep_set(store: &Store) -> Result<Keep> {
    let mut keep = Keep::default();
    for installed in proxy::instances(store)? {
        if installed.removed {
            // A tombstone keeps its records but owns nothing physical.
            continue;
        }
        keep.add(&installed.release_digest, "current");
        if let Some(prepared) = store.prepared(&installed.application, &installed.instance)? {
            keep.add(&prepared.release_digest, "prepared");
        }
        let (mut previous, mut failed) = (None, None);
        for id in store
            .history(&installed.application, &installed.instance)?
            .iter()
            .rev()
        {
            let operation = store.operation(id)?;
            if !digest(&operation.release_digest) {
                continue;
            }
            // Records without a journal entry count: keeping more is safe.
            if action(store, id)?.is_some_and(|a| a != "deploy") {
                continue;
            }
            if previous.is_none()
                && operation.ok
                && operation.release_digest != installed.release_digest
            {
                previous = Some(operation.release_digest.clone());
            }
            if failed.is_none() && operation.phase == "failed" {
                failed = Some(operation.release_digest.clone());
            }
        }
        if let Some(release) = previous {
            keep.add(&release, "previous");
        }
        if let Some(release) = failed {
            keep.add(&release, "failed");
        }
    }
    for operation in store.unresolved_all()? {
        keep.add(&operation.release_digest, "unresolved");
    }
    Ok(keep)
}

/// Image IDs (`sha256:` form) a release stages.
fn images_of(store: &Store, release: &str) -> Result<BTreeSet<String>> {
    Ok(store
        .release(release)?
        .release
        .artifacts
        .values()
        .filter_map(|artifact| match artifact {
            Artifact::Image { config_digest, .. } => Some(config_digest.clone()),
            Artifact::Archive { .. } => None,
        })
        .collect())
}

#[derive(Clone, Debug, Serialize)]
pub struct Image {
    pub id: String,
    pub bytes: u64,
}

/// What collection needs from the container engine. The native implementation
/// is `NativeRuntime`; tests substitute a recording fake.
pub trait Runtime {
    /// Every image on the engine.
    fn images(&self) -> Result<Vec<Image>>;
    /// The image ID of every container, in any state, one entry per container.
    fn container_images(&self) -> Result<Vec<String>>;
    /// The image of a job's container when it is present.
    fn job_container_image(&self, receipt: &jobs::Receipt) -> Result<Option<String>>;
    fn remove_job_container(
        &self,
        store: &Store,
        installed: &Installed,
        receipt: &jobs::Receipt,
    ) -> Result<()>;
    /// Remove one image by its exact ID. Never a prune, never forced.
    fn remove_image(&self, id: &str) -> Result<()>;
}

pub struct NativeRuntime {
    pub engine: Engine,
}

impl NativeRuntime {
    fn deadline(&self) -> Instant {
        self.engine.deadline
    }
}

impl Runtime for NativeRuntime {
    fn images(&self) -> Result<Vec<Image>> {
        let value = self
            .engine
            .json(&["image", "ls", "--all", "--format=json"])?;
        value
            .as_array()
            .ok_or_else(|| anyhow!("image inventory is ambiguous"))?
            .iter()
            .map(|image| {
                let id = image["Id"]
                    .as_str()
                    .map(normalize_id)
                    .filter(|id| digest(id))
                    .ok_or_else(|| anyhow!("image inventory omitted an image ID"))?;
                Ok(Image {
                    id,
                    bytes: image["Size"].as_u64().unwrap_or(0),
                })
            })
            .collect()
    }
    fn container_images(&self) -> Result<Vec<String>> {
        let value = self
            .engine
            .json(&["container", "ls", "--all", "--format=json"])?;
        value
            .as_array()
            .ok_or_else(|| anyhow!("container inventory is ambiguous"))?
            .iter()
            .map(|container| {
                container["ImageID"]
                    .as_str()
                    .map(normalize_id)
                    .filter(|id| digest(id))
                    .ok_or_else(|| anyhow!("container inventory omitted an image ID"))
            })
            .collect()
    }
    fn job_container_image(&self, receipt: &jobs::Receipt) -> Result<Option<String>> {
        if !jobs::finished_present(receipt, self.deadline())? {
            return Ok(None);
        }
        let value = self.engine.inspect("container", &receipt.container_name)?;
        Ok(Some(normalize_id(value["Image"].as_str().unwrap_or(""))))
    }
    fn remove_job_container(
        &self,
        store: &Store,
        installed: &Installed,
        receipt: &jobs::Receipt,
    ) -> Result<()> {
        jobs::remove_finished(store, installed, receipt, self.deadline())
    }
    fn remove_image(&self, id: &str) -> Result<()> {
        ensure!(digest(id), "image removal requires an exact image ID");
        let hex = &id[7..];
        self.engine.run(&["image", "rm", "--", hex])?;
        ensure!(
            !self.engine.exists("image", hex)?,
            "image removal remains uncertain"
        );
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct Item {
    pub id: String,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub kind: &'static str,
    pub version: u32,
    pub dry_run: bool,
    pub keep: BTreeMap<String, Vec<&'static str>>,
    pub trash: Vec<Item>,
    pub asset_trees: Vec<Item>,
    pub containers: Vec<Item>,
    pub images: Vec<Item>,
    /// Bytes of trash, trees and images (containers carry no size).
    pub bytes: u64,
    pub errors: Vec<String>,
}

pub struct Context<'a> {
    pub store: &'a Store,
    pub assets: &'a Path,
    /// The caller's own operation, when collection runs inside one.
    pub own_operation: Option<&'a str>,
    pub dry_run: bool,
}

/// Refuse while another operation is live. Inside an operation (the capacity
/// gate or the end of a deploy) the single effect worker is ours, so another
/// operation can only be queued and not yet executing: phase `admitted`. Its
/// release is in the keep set already. The owner command accepts no live
/// operation at all.
fn quiescent(store: &Store, own: Option<&str>) -> Result<()> {
    for operation in store.live_operations_at(SystemTime::now())? {
        if Some(operation.operation_id.as_str()) == own {
            continue;
        }
        ensure!(
            own.is_some() && operation.phase == "admitted",
            "operation {} is {}; release collection refuses to race it",
            operation.operation_id,
            operation.phase
        );
    }
    Ok(())
}

fn tree_bytes(path: &Path) -> u64 {
    let Ok(info) = fs::symlink_metadata(path) else {
        return 0;
    };
    let mut total = info.blocks() * 512;
    if info.is_dir()
        && let Ok(entries) = fs::read_dir(path)
    {
        for entry in entries.flatten() {
            total = total.saturating_add(tree_bytes(&entry.path()));
        }
    }
    total
}

struct Tree {
    path: PathBuf,
    id: String,
    bytes: u64,
}

/// Classify the assets root. Only a directory named exactly 64 lowercase hex
/// is a release tree, and only a directory named with the trash prefix plus
/// 64 lowercase hex is leftover trash. Everything else is left alone.
fn scan_assets(assets: &Path, keep: &Keep) -> Result<(Vec<Tree>, Vec<Tree>)> {
    let (mut trees, mut trash) = (Vec::new(), Vec::new());
    if !assets.try_exists()? {
        return Ok((trees, trash));
    }
    for entry in fs::read_dir(assets)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let (target, release) = if hex(&name, 64) {
            (&mut trees, Some(name.as_str()))
        } else if name.strip_prefix(TRASH_PREFIX).is_some_and(|h| hex(h, 64)) {
            (&mut trash, None)
        } else {
            continue;
        };
        let info = fs::symlink_metadata(entry.path())?;
        if !info.is_dir() {
            continue;
        }
        if release.is_some_and(|hex| keep.contains(&format!("sha256:{hex}"))) {
            continue;
        }
        target.push(Tree {
            bytes: tree_bytes(&entry.path()),
            id: name,
            path: entry.path(),
        });
    }
    trees.sort_by(|a, b| a.id.cmp(&b.id));
    trash.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((trees, trash))
}

/// Rename to trash on the same filesystem, then remove.
fn remove_tree(assets: &Path, tree: &Tree) -> Result<()> {
    let trash = assets.join(format!("{TRASH_PREFIX}{}", tree.id));
    if fs::symlink_metadata(&trash).is_ok() {
        fs::remove_dir_all(&trash)?;
    }
    fs::rename(&tree.path, &trash)?;
    fs::File::open(assets)?.sync_all()?;
    fs::remove_dir_all(&trash)?;
    Ok(())
}

fn multiset_subtract(used: &mut Vec<String>, id: &str) {
    if let Some(position) = used.iter().position(|u| u == id) {
        used.swap_remove(position);
    }
}

/// Collect everything outside the keep set. `_lease` proves the caller holds
/// the staging lock. Per-item failures are reported, not fatal.
pub fn collect(context: &Context, _lease: &Lease, runtime: &dyn Runtime) -> Result<Report> {
    let store = context.store;
    quiescent(store, context.own_operation)?;
    let keep = keep_set(store)?;
    let mut report = Report {
        kind: "komizo.retention",
        version: 1,
        dry_run: context.dry_run,
        keep: keep
            .releases()
            .map(|r| (r.clone(), keep.reasons(r)))
            .collect(),
        trash: Vec::new(),
        asset_trees: Vec::new(),
        containers: Vec::new(),
        images: Vec::new(),
        bytes: 0,
        errors: Vec::new(),
    };

    // 1. Asset trees (and trash a crash left behind).
    let (trees, trash) = scan_assets(context.assets, &keep)?;
    for (trees, into_trash) in [(trash, true), (trees, false)] {
        for tree in trees {
            if !context.dry_run {
                let result = if into_trash {
                    fs::remove_dir_all(&tree.path).map_err(Into::into)
                } else {
                    remove_tree(context.assets, &tree)
                };
                if let Err(error) = result {
                    report
                        .errors
                        .push(format!("asset tree {}: {error:#}", tree.id));
                    continue;
                }
            }
            report.bytes = report.bytes.saturating_add(tree.bytes);
            let item = Item {
                release: (!into_trash).then(|| format!("sha256:{}", tree.id)),
                id: tree.id,
                bytes: tree.bytes,
            };
            if into_trash {
                report.trash.push(item);
            } else {
                report.asset_trees.push(item);
            }
        }
    }

    // 2. Exited job containers of releases outside the keep set.
    let mut planned_images = Vec::new();
    for installed in proxy::instances(store)? {
        let receipts = match jobs::finished_outside(store, &installed, |r| keep.contains(r)) {
            Ok(receipts) => receipts,
            Err(error) => {
                report.errors.push(format!(
                    "job receipts {}--{}: {error:#}",
                    installed.application, installed.instance
                ));
                continue;
            }
        };
        for receipt in receipts {
            let image = match runtime.job_container_image(&receipt) {
                Ok(Some(image)) => image,
                Ok(None) => continue,
                Err(error) => {
                    report.errors.push(format!(
                        "job container {}: {error:#}",
                        receipt.container_name
                    ));
                    continue;
                }
            };
            if !context.dry_run
                && let Err(error) = runtime.remove_job_container(store, &installed, &receipt)
            {
                report.errors.push(format!(
                    "job container {}: {error:#}",
                    receipt.container_name
                ));
                continue;
            }
            planned_images.push(image);
            report.containers.push(Item {
                id: receipt.container_name.clone(),
                bytes: 0,
                release: Some(receipt.release_digest.clone()),
            });
        }
    }

    // 3. Images no kept release references and no container uses.
    if let Err(error) = collect_images(context, runtime, &keep, planned_images, &mut report) {
        report.errors.push(format!("images: {error:#}"));
    }
    Ok(report)
}

fn collect_images(
    context: &Context,
    runtime: &dyn Runtime,
    keep: &Keep,
    planned_images: Vec<String>,
    report: &mut Report,
) -> Result<()> {
    let store = context.store;
    // An unreadable kept release hides images it needs: remove none.
    let mut kept = BTreeSet::new();
    for release in keep.releases() {
        kept.extend(images_of(store, release)?);
    }
    // Only images a stored release names are Komizo's to remove.
    let mut known = BTreeSet::new();
    for release in store.release_digests()? {
        match images_of(store, &release) {
            Ok(images) => known.extend(images),
            Err(error) => report.errors.push(format!("release {release}: {error:#}")),
        }
    }
    let mut used = runtime.container_images()?;
    if context.dry_run {
        for image in &planned_images {
            multiset_subtract(&mut used, image);
        }
    }
    let mut images = runtime.images()?;
    images.sort_by(|a, b| a.id.cmp(&b.id));
    for image in images {
        if !known.contains(&image.id) || kept.contains(&image.id) || used.contains(&image.id) {
            continue;
        }
        if !context.dry_run
            && let Err(error) = runtime.remove_image(&image.id)
        {
            report.errors.push(format!("image {}: {error:#}", image.id));
            continue;
        }
        report.bytes = report.bytes.saturating_add(image.bytes);
        report.images.push(Item {
            id: image.id,
            bytes: image.bytes,
            release: None,
        });
    }
    Ok(())
}

/// Journal what a non-owner collection did, as a non-fatal finding.
pub fn record(
    store: &Store,
    operation: &Operation,
    stage: &str,
    result: &Result<Report>,
) -> Result<()> {
    let body = match result {
        Ok(report) => {
            json!({"kind":"komizo.retention","version":1,"operation_id":operation.operation_id,"stage":stage,"outcome":if report.errors.is_empty() {"collected"} else {"partial"},"report":report})
        }
        Err(error) => {
            json!({"kind":"komizo.retention","version":1,"operation_id":operation.operation_id,"stage":stage,"outcome":"refused","context":format!("{error:#}").chars().take(2048).collect::<String>()})
        }
    };
    store::atomic(
        &store
            .root
            .join("journal")
            .join(&operation.operation_id)
            .join(format!("retention-{stage}.json")),
        &serde_json::to_vec(&body)?,
        0o600,
    )
}

/// After a deploy is ready: collect under a short budget. Any failure is
/// journalled and never changes the deploy's outcome.
pub fn after_deploy(store: &Store, operation: &Operation, deadline: Instant) {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(120));
    let result = (|| {
        let lease = try_lease(store)?.ok_or_else(|| anyhow!("staging lock is held elsewhere"))?;
        collect(
            &Context {
                store,
                assets: Path::new(super::system::ASSETS),
                own_operation: Some(&operation.operation_id),
                dry_run: false,
            },
            &lease,
            &NativeRuntime {
                engine: Engine { deadline },
            },
        )
    })();
    let _ = record(store, operation, "after-deploy", &result);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fixture {
        _directory: tempfile::TempDir,
        store: Store,
        assets: PathBuf,
        counter: RefCell<u128>,
    }

    fn sorted<const N: usize>(mut values: [String; N]) -> Vec<String> {
        values.sort();
        values.to_vec()
    }
    fn id(tag: char) -> String {
        tag.to_string().repeat(64)
    }
    fn image(tag: char) -> String {
        format!("sha256:{}", id(tag))
    }

    impl Fixture {
        fn new() -> Self {
            let directory =
                tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
            let store = Store::new(directory.path().join("state")).unwrap();
            let assets = directory.path().join("assets");
            fs::create_dir(&assets).unwrap();
            Self {
                _directory: directory,
                store,
                assets,
                counter: RefCell::new(0),
            }
        }

        /// A stored release whose digest is derived from `tag`. Its image has
        /// the config digest `image(tag)`.
        fn release(&self, tag: char) -> ReleaseDocument {
            let mut source: Value = serde_json::from_slice(include_bytes!(
                "../../tests/fixtures/deployment/release.json"
            ))
            .unwrap();
            source["source"]["revision"] = json!(tag.to_string().repeat(40));
            source["artifacts"]["api"]["config_digest"] = json!(image(tag));
            let document = read_release(&serde_json::to_vec(&source).unwrap()).unwrap();
            self.store.save_release(&document).unwrap();
            document
        }

        fn install(&self, instance: &str, document: &ReleaseDocument, removed: bool) {
            self.store
                .save_installed(&Installed {
                    kind: "komizo.installed".into(),
                    version: 1,
                    application: "mailroom".into(),
                    instance: instance.into(),
                    release_digest: document.digest.clone(),
                    operation_id: "a".repeat(32),
                    desired_running: !removed,
                    removed,
                    expires_at: None,
                    resources: store::Resources::default(),
                    secret_snapshots: BTreeMap::new(),
                })
                .unwrap();
        }

        fn operation(
            &self,
            instance: &str,
            document: &ReleaseDocument,
            action: &str,
            phase: &str,
        ) -> String {
            let mut counter = self.counter.borrow_mut();
            *counter += 1;
            let operation_id = format!("{:032x}", *counter);
            let mut operation = Operation {
                kind: "komizo.operation".into(),
                version: 1,
                operation_id: operation_id.clone(),
                application: "mailroom".into(),
                instance: instance.into(),
                release_digest: document.digest.clone(),
                phase: "admitted".into(),
                ok: false,
                previous_release_digest: None,
                reconciliation_required: false,
                backup: None,
            };
            if phase != "admitted" {
                // Walk the real transition table to a legal phase.
                let path: &[&str] = match phase {
                    "ready" => &["ready"],
                    "failed" => &["failed"],
                    "staging" => &["staging"],
                    "needs_reconciliation" => &["needs_reconciliation"],
                    _ => panic!("unmodelled phase"),
                };
                for step in path {
                    operation.transition(step).unwrap();
                }
            }
            self.store.create_operation(&operation).unwrap();
            store::atomic(
                &self
                    .store
                    .root
                    .join("journal")
                    .join(&operation_id)
                    .join("admission.json"),
                &serde_json::to_vec(&json!({"action":action})).unwrap(),
                0o600,
            )
            .unwrap();
            operation_id
        }

        fn tree(&self, name: &str) -> PathBuf {
            let path = self.assets.join(name);
            fs::create_dir_all(path.join("web")).unwrap();
            fs::write(path.join("web/index.html"), b"0123456789").unwrap();
            path
        }

        fn keep(&self) -> Vec<String> {
            keep_set(&self.store).unwrap().releases().cloned().collect()
        }

        fn run(&self, runtime: &Fake, own: Option<&str>, dry_run: bool) -> Result<Report> {
            let lease = try_lease(&self.store)?.unwrap();
            collect(
                &Context {
                    store: &self.store,
                    assets: &self.assets,
                    own_operation: own,
                    dry_run,
                },
                &lease,
                runtime,
            )
        }
    }

    #[derive(Default)]
    struct Fake {
        images: Vec<Image>,
        containers: Vec<String>,
        jobs: BTreeMap<String, String>,
        removed_images: RefCell<Vec<String>>,
        removed_jobs: RefCell<Vec<String>>,
    }

    impl Runtime for Fake {
        fn images(&self) -> Result<Vec<Image>> {
            let gone = self.removed_images.borrow();
            Ok(self
                .images
                .iter()
                .filter(|i| !gone.contains(&i.id))
                .cloned()
                .collect())
        }
        fn container_images(&self) -> Result<Vec<String>> {
            let gone = self.removed_jobs.borrow();
            let mut all = self.containers.clone();
            all.extend(
                self.jobs
                    .iter()
                    .filter(|(name, _)| !gone.contains(name))
                    .map(|(_, image)| image.clone()),
            );
            Ok(all)
        }
        fn job_container_image(&self, receipt: &jobs::Receipt) -> Result<Option<String>> {
            Ok(self
                .jobs
                .get(&receipt.container_name)
                .filter(|_| !self.removed_jobs.borrow().contains(&receipt.container_name))
                .cloned())
        }
        fn remove_job_container(
            &self,
            _: &Store,
            _: &Installed,
            receipt: &jobs::Receipt,
        ) -> Result<()> {
            self.removed_jobs
                .borrow_mut()
                .push(receipt.container_name.clone());
            Ok(())
        }
        fn remove_image(&self, id: &str) -> Result<()> {
            self.removed_images.borrow_mut().push(id.to_owned());
            Ok(())
        }
    }

    fn receipt(f: &Fixture, instance: &str, document: &ReleaseDocument, n: char) -> jobs::Receipt {
        let identity = format!("sha256:{}", n.to_string().repeat(64));
        let namespace = super::super::units::namespace("mailroom", instance).unwrap();
        let receipt = jobs::Receipt {
            kind: "komizo.job".into(),
            version: 1,
            application: "mailroom".into(),
            instance: instance.into(),
            identity: identity.clone(),
            job: "migrate".into(),
            operation_id: "b".repeat(32),
            release_digest: document.digest.clone(),
            container_name: format!("{namespace}-job-{}", &identity[7..27]),
            container_id: "c".repeat(64),
            ownership: "d".repeat(32),
            native_timeout_seconds: 60,
            phase: "completed".into(),
            exit_code: Some(0),
        };
        jobs::save(&f.store, &receipt).unwrap();
        receipt
    }

    /// Four deploys, the newest one failed. Previous is the successful deploy
    /// before the current one; the older one is collectable.
    #[test]
    fn keep_set_has_current_previous_and_newest_failed() {
        let f = Fixture::new();
        let (r1, r2, r3, r4) = (
            f.release('1'),
            f.release('2'),
            f.release('3'),
            f.release('4'),
        );
        f.operation("production", &r1, "deploy", "ready");
        f.operation("production", &r2, "deploy", "ready");
        f.operation("production", &r3, "deploy", "ready");
        f.operation("production", &r4, "deploy", "failed");
        f.install("production", &r3, false);
        assert_eq!(
            f.keep(),
            sorted([r2.digest.clone(), r3.digest.clone(), r4.digest.clone()])
        );
        let keep = keep_set(&f.store).unwrap();
        assert!(!keep.contains(&r1.digest));
        assert_eq!(keep.reasons(&r3.digest), ["current"]);
    }

    #[test]
    fn previous_skips_redeploys_of_current_and_non_deploy_operations() {
        let f = Fixture::new();
        let (r1, r2, r3) = (f.release('1'), f.release('2'), f.release('3'));
        f.operation("production", &r1, "deploy", "ready");
        f.operation("production", &r2, "deploy", "ready");
        f.operation("production", &r3, "deploy", "ready");
        f.operation("production", &r3, "deploy", "ready");
        // A successful restart that names an old release is not a deploy.
        f.operation("production", &r1, "restart", "ready");
        f.install("production", &r3, false);
        assert_eq!(f.keep(), sorted([r2.digest, r3.digest]));
    }

    #[test]
    fn unresolved_and_non_terminal_operations_keep_their_release() {
        let f = Fixture::new();
        let (r1, r2, r3, r4) = (
            f.release('1'),
            f.release('2'),
            f.release('3'),
            f.release('4'),
        );
        f.install("production", &r1, false);
        f.operation("production", &r1, "deploy", "ready");
        f.operation("preview", &r2, "deploy", "staging");
        f.operation("other", &r3, "deploy", "needs_reconciliation");
        let resolved = f.operation("other", &r4, "deploy", "needs_reconciliation");
        let fix = f.operation("other", &r1, "deploy", "ready");
        store::atomic(
            &f.store
                .root
                .join("reconciliations")
                .join(format!("{resolved}.json")),
            &serde_json::to_vec(&json!({"resolved_by":fix})).unwrap(),
            0o600,
        )
        .unwrap();
        let keep = keep_set(&f.store).unwrap();
        assert!(
            keep.contains(&r1.digest) && keep.contains(&r2.digest) && keep.contains(&r3.digest)
        );
        assert!(!keep.contains(&r4.digest));
        assert_eq!(keep.reasons(&r2.digest), ["unresolved"]);
    }

    #[test]
    fn shared_digests_across_instances_are_kept_once_for_either_owner() {
        let f = Fixture::new();
        let (r1, r2, r3) = (f.release('1'), f.release('2'), f.release('3'));
        for instance in ["production", "pr-7"] {
            f.operation(instance, &r1, "deploy", "ready");
            f.operation(instance, &r2, "deploy", "ready");
            f.install(instance, &r2, false);
        }
        // The preview moves on; the production instance still owns r2 and r1.
        f.operation("pr-7", &r3, "deploy", "ready");
        f.install("pr-7", &r3, false);
        let keep = keep_set(&f.store).unwrap();
        assert_eq!(
            keep.releases().cloned().collect::<Vec<_>>(),
            sorted([r1.digest.clone(), r2.digest.clone(), r3.digest.clone()])
        );
        assert_eq!(keep.reasons(&r2.digest), ["current", "previous"]);
    }

    #[test]
    fn removed_instance_tombstones_contribute_nothing() {
        let f = Fixture::new();
        let (r1, r2, r3) = (f.release('1'), f.release('2'), f.release('3'));
        f.operation("pr-9", &r1, "deploy", "ready");
        f.operation("pr-9", &r2, "deploy", "ready");
        f.operation("pr-9", &r3, "deploy", "failed");
        f.install("pr-9", &r2, true);
        assert!(f.keep().is_empty());
        // Its records stay: the release document is still readable.
        assert!(f.store.release(&r2.digest).is_ok());
    }

    #[test]
    fn a_prepared_release_is_kept() {
        let f = Fixture::new();
        let (r1, r2) = (f.release('1'), f.release('2'));
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        // A stopped instance with a prepared successor.
        let mut stopped = f
            .store
            .installed("mailroom", "production")
            .unwrap()
            .unwrap();
        stopped.desired_running = false;
        f.store.save_installed(&stopped).unwrap();
        store::atomic(
            &f.store.root.join("prepared/mailroom--production.json"),
            &serde_json::to_vec(&Installed {
                release_digest: r2.digest.clone(),
                ..stopped
            })
            .unwrap(),
            0o600,
        )
        .unwrap();
        assert_eq!(f.keep(), sorted([r1.digest, r2.digest]));
    }

    #[test]
    fn only_exact_release_names_are_trees_and_trash_is_cleaned() {
        let f = Fixture::new();
        let (r1, r2) = (f.release('1'), f.release('2'));
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        let kept = f.tree(&r1.digest[7..]);
        let stale = f.tree(&r2.digest[7..]);
        let upper = f.tree(&"A".repeat(64));
        let short = f.tree(&"3".repeat(63));
        let long = f.tree(&"3".repeat(65));
        let named = f.tree("web");
        let near_trash = f.tree(&format!("{TRASH_PREFIX}short"));
        let leftover = f.tree(&format!("{TRASH_PREFIX}{}", id('9')));
        let file = f.assets.join(id('4'));
        fs::write(&file, b"not a tree").unwrap();
        let link = f.assets.join(id('5'));
        std::os::unix::fs::symlink(&kept, &link).unwrap();
        let twin = f
            .store
            .root
            .join(format!("releases/{}.json", &r2.digest[7..]));
        let report = f.run(&Fake::default(), None, false).unwrap();
        assert!(kept.is_dir() && !stale.exists() && !leftover.exists());
        for survivor in [&upper, &short, &long, &named, &near_trash, &file, &link] {
            assert!(survivor.symlink_metadata().is_ok(), "{survivor:?}");
        }
        assert!(kept.join("web/index.html").is_file());
        assert!(twin.is_file(), "release documents are never removed");
        assert_eq!(
            report.asset_trees.iter().map(|i| &i.id).collect::<Vec<_>>(),
            [&r2.digest[7..].to_owned()]
        );
        assert_eq!(report.trash.len(), 1);
        assert!(report.errors.is_empty() && report.bytes > 0);
    }

    #[test]
    fn dry_run_reports_bytes_and_removes_nothing() {
        let f = Fixture::new();
        let (r1, r2) = (f.release('1'), f.release('2'));
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        let stale = f.tree(&r2.digest[7..]);
        let fake = Fake {
            images: vec![
                Image {
                    id: image('2'),
                    bytes: 700,
                },
                Image {
                    id: image('1'),
                    bytes: 500,
                },
            ],
            ..Fake::default()
        };
        let report = f.run(&fake, None, true).unwrap();
        assert!(stale.is_dir() && fake.removed_images.borrow().is_empty());
        assert_eq!(report.images.len(), 1);
        assert!(report.dry_run && report.bytes >= 700);
        assert_eq!(report.keep[&r1.digest], ["current"]);
        let _ = r2;
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["kind"], "komizo.retention");
    }

    #[test]
    fn kept_releases_lose_no_container_and_no_image() {
        let f = Fixture::new();
        let (r1, r2, r3) = (f.release('1'), f.release('2'), f.release('3'));
        f.operation("production", &r1, "deploy", "ready");
        f.operation("production", &r2, "deploy", "ready");
        f.install("production", &r2, false);
        let kept_job = receipt(&f, "production", &r2, 'a');
        let previous_job = receipt(&f, "production", &r1, 'b');
        let old_job = receipt(&f, "production", &r3, 'c');
        let failed_old = {
            let mut r = receipt(&f, "production", &r3, 'd');
            r.phase = "failed".into();
            r.exit_code = Some(2);
            jobs::save(&f.store, &r).unwrap();
            r
        };
        let mut running = receipt(&f, "production", &r3, 'e');
        running.phase = "running".into();
        running.exit_code = None;
        jobs::save(&f.store, &running).unwrap();
        let fake = Fake {
            images: vec![
                Image {
                    id: image('1'),
                    bytes: 1,
                },
                Image {
                    id: image('2'),
                    bytes: 2,
                },
                Image {
                    id: image('3'),
                    bytes: 3,
                },
                Image {
                    id: format!("sha256:{}", id('9')),
                    bytes: 9,
                },
            ],
            containers: vec![],
            jobs: [&kept_job, &previous_job, &old_job, &failed_old, &running]
                .into_iter()
                .map(|r| (r.container_name.clone(), image('3')))
                .chain([(kept_job.container_name.clone(), image('2'))])
                .collect(),
            ..Fake::default()
        };
        let report = f.run(&fake, None, false).unwrap();
        let removed = fake.removed_jobs.borrow().clone();
        assert!(removed.contains(&old_job.container_name));
        assert!(removed.contains(&failed_old.container_name));
        // Kept releases and a still-running job are untouched.
        assert!(!removed.contains(&kept_job.container_name));
        assert!(!removed.contains(&previous_job.container_name));
        assert!(!removed.contains(&running.container_name));
        // Image 3 is still used by the running job's container; 1 and 2 are
        // kept; the unknown image is not Komizo's.
        assert!(fake.removed_images.borrow().is_empty(), "{report:?}");
    }

    #[test]
    fn unreferenced_images_go_by_exact_id_but_foreign_used_and_kept_ones_stay() {
        let f = Fixture::new();
        let (r1, r2, r3, r4) = (
            f.release('1'),
            f.release('2'),
            f.release('3'),
            f.release('4'),
        );
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        let _ = (r2, r4);
        let old_job = receipt(&f, "production", &r3, 'c');
        let fake = Fake {
            images: vec![
                Image {
                    id: image('1'),
                    bytes: 10,
                },
                Image {
                    id: image('2'),
                    bytes: 20,
                },
                Image {
                    id: image('3'),
                    bytes: 30,
                },
                Image {
                    id: image('4'),
                    bytes: 40,
                },
                Image {
                    id: format!("sha256:{}", id('9')),
                    bytes: 99,
                },
            ],
            // A container of any kind pins image 4; the old job pins 3 until
            // its container is removed in the same run.
            containers: vec![image('4')],
            jobs: [(old_job.container_name.clone(), image('3'))].into(),
            ..Fake::default()
        };
        let report = f.run(&fake, None, false).unwrap();
        let mut gone = fake.removed_images.borrow().clone();
        gone.sort();
        assert_eq!(gone, [image('2'), image('3')]);
        assert_eq!(fake.removed_jobs.borrow().len(), 1);
        assert_eq!(report.bytes, 50);
    }

    #[test]
    fn dry_run_counts_images_freed_by_the_containers_it_would_remove() {
        let f = Fixture::new();
        let (r1, r3) = (f.release('1'), f.release('3'));
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        let old_job = receipt(&f, "production", &r3, 'c');
        let fake = Fake {
            images: vec![Image {
                id: image('3'),
                bytes: 30,
            }],
            jobs: [(old_job.container_name.clone(), image('3'))].into(),
            ..Fake::default()
        };
        let report = f.run(&fake, None, true).unwrap();
        assert_eq!(report.images.len(), 1);
        assert!(fake.removed_jobs.borrow().is_empty());
    }

    #[test]
    fn collection_refuses_to_race_live_operations_and_the_staging_lock() {
        let f = Fixture::new();
        let r1 = f.release('1');
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        let staging = f.operation("preview", &r1, "deploy", "staging");
        let queued = f.operation("other", &r1, "deploy", "admitted");
        let fake = Fake::default();
        // The owner command accepts no live operation.
        assert!(f.run(&fake, None, false).is_err());
        // A staging operation of someone else refuses even inside a worker.
        assert!(f.run(&fake, Some(&queued), false).is_err());
        // The caller's own staging operation, with another one merely queued.
        assert!(f.run(&fake, Some(&staging), false).is_ok());
        // The lock `stage()` holds excludes a second holder.
        let held = try_lease(&f.store).unwrap().unwrap();
        assert!(try_lease(&f.store).unwrap().is_none());
        assert!(staging_lease(&f.store, Instant::now() + Duration::from_millis(120)).is_err());
        drop(held);
        assert!(try_lease(&f.store).unwrap().is_some());
    }

    #[test]
    fn a_failing_item_is_reported_and_does_not_stop_collection() {
        struct Broken(Fake);
        impl Runtime for Broken {
            fn images(&self) -> Result<Vec<Image>> {
                self.0.images()
            }
            fn container_images(&self) -> Result<Vec<String>> {
                self.0.container_images()
            }
            fn job_container_image(&self, r: &jobs::Receipt) -> Result<Option<String>> {
                self.0.job_container_image(r)
            }
            fn remove_job_container(
                &self,
                _: &Store,
                _: &Installed,
                _: &jobs::Receipt,
            ) -> Result<()> {
                Err(anyhow!("engine refused"))
            }
            fn remove_image(&self, id: &str) -> Result<()> {
                self.0.remove_image(id)
            }
        }
        let f = Fixture::new();
        let (r1, r3) = (f.release('1'), f.release('3'));
        f.operation("production", &r1, "deploy", "ready");
        f.install("production", &r1, false);
        let stale = f.tree(&r3.digest[7..]);
        let job = receipt(&f, "production", &r3, 'c');
        let broken = Broken(Fake {
            images: vec![Image {
                id: image('3'),
                bytes: 30,
            }],
            jobs: [(job.container_name.clone(), image('3'))].into(),
            ..Fake::default()
        });
        let lease = try_lease(&f.store).unwrap().unwrap();
        let report = collect(
            &Context {
                store: &f.store,
                assets: &f.assets,
                own_operation: None,
                dry_run: false,
            },
            &lease,
            &broken,
        )
        .unwrap();
        assert!(!stale.exists());
        assert_eq!(report.errors.len(), 1);
        // The container still pins its image: it is not removed.
        assert!(broken.0.removed_images.borrow().is_empty());
    }
}
