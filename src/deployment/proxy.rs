//! One protected ingress configuration, assembled from installed ownership.
use super::{
    engine::Engine,
    model::*,
    render,
    store::{self, Installed, Store},
    system,
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub kind: String,
    pub version: u32,
    pub trusted_proxies: Vec<String>,
}

pub fn globals() -> Result<String> {
    let p: Policy = serde_json::from_slice(&store::read_protected(
        Path::new("/etc/komizo/proxy.json"),
        16384,
    )?)?;
    ensure!(
        p.kind == "komizo.proxy" && p.version == 1 && p.trusted_proxies.len() <= 64,
        "invalid host ingress policy"
    );
    for cidr in &p.trusted_proxies {
        let (ip, bits) = cidr
            .split_once('/')
            .ok_or_else(|| anyhow!("trusted proxy requires an explicit CIDR"))?;
        let ip: IpAddr = ip.parse()?;
        let bits: u32 = bits.parse()?;
        ensure!(
            bits > 0 && bits <= if ip.is_ipv4() { 32 } else { 128 },
            "unbounded trusted proxy range"
        );
    }
    let mut out = String::from(
        "{\nadmin unix//run/komizo-proxy/admin.sock\nstorage file_system /var/lib/komizo-proxy/data\nservers {\n",
    );
    if !p.trusted_proxies.is_empty() {
        out.push_str(&format!("trusted_proxies static {}\ntrusted_proxies_strict\nclient_ip_headers X-Forwarded-For\n", p.trusted_proxies.join(" ")));
    }
    out.push_str("}\n}\n");
    Ok(out)
}

pub fn asset_root(document: &ReleaseDocument) -> PathBuf {
    Path::new(system::ASSETS).join(&document.digest[7..])
}

pub fn instances(store: &Store) -> Result<Vec<Installed>> {
    let mut records = Vec::new();
    for entry in fs::read_dir(store.root.join("instances"))? {
        let path = entry?.path();
        if store::pending(&path, MAX_DOCUMENT_BYTES as u64)? {
            continue;
        }
        let record: Installed =
            serde_json::from_slice(&store::read_protected(&path, MAX_DOCUMENT_BYTES)?)?;
        ensure!(
            path.file_name().and_then(|p| p.to_str())
                == Some(&format!(
                    "{}.json",
                    Store::instance_key(&record.application, &record.instance)?
                )),
            "instance ledger scope changed"
        );
        records.push(
            store
                .installed(&record.application, &record.instance)?
                .ok_or_else(|| anyhow!("instance ledger disappeared"))?,
        );
    }
    Ok(records)
}

pub fn upstreams(
    engine: &Engine,
    installed: &Installed,
    document: &ReleaseDocument,
) -> Result<BTreeMap<String, String>> {
    upstreams_from(installed, document, |record, name| {
        engine.owned_container(record, &installed.application, &installed.instance, name)
    })
}

fn upstreams_from(
    installed: &Installed,
    document: &ReleaseDocument,
    mut observe: impl FnMut(&store::ContainerRecord, &str) -> Result<Option<serde_json::Value>>,
) -> Result<BTreeMap<String, String>> {
    let mut upstreams = BTreeMap::new();
    for route in &document.release.workload.routes {
        let Some(RouteTarget::Service { name, port }) = &route.target else {
            continue;
        };
        let target = format!("{name}:{port}");
        if upstreams.contains_key(&target) {
            continue;
        }
        let record = installed
            .resources
            .containers
            .get(name)
            .ok_or_else(|| anyhow!("route service has no creation record"))?;
        let value = observe(record, name)?.ok_or_else(|| anyhow!("route service is absent"))?;
        ensure!(
            value["State"]["Running"] == true,
            "route service is stopped"
        );
        let networks = value["NetworkSettings"]["Networks"]
            .as_object()
            .ok_or_else(|| anyhow!("route bridge evidence missing"))?;
        let address = document.release.workload.services[name]
            .networks
            .iter()
            .find_map(|network| {
                let physical = &installed.resources.networks.get(network)?.name;
                networks.get(physical)?["IPAddress"]
                    .as_str()?
                    .parse::<IpAddr>()
                    .ok()
            })
            .ok_or_else(|| anyhow!("service has no owned private bridge address"))?;
        ensure!(
            !address.is_unspecified() && !address.is_loopback() && !address.is_multicast(),
            "route bridge address is invalid"
        );
        upstreams.insert(target, SocketAddr::new(address, *port).to_string());
    }
    Ok(upstreams)
}

pub fn refresh(store: &Store, deadline: Instant) -> Result<()> {
    let _lock = super::controller::resource_lease(store, "platform", "proxy", deadline)?;
    refresh_locked(store, deadline)
}

pub fn refresh_background(store: &Store, deadline: Instant) -> Result<()> {
    let Some(_lock) = super::controller::maintenance_lease(store, "platform", "proxy")? else {
        return Ok(());
    };
    refresh_locked(store, deadline)
}

fn refresh_locked(store: &Store, deadline: Instant) -> Result<()> {
    system::reconcile_framework_units(store, "platform", "proxy")?;
    let engine = Engine { deadline };
    let mut body = globals()?;
    let mut hosts = BTreeMap::new();
    for installed in instances(store)?.into_iter().filter(|r| r.desired_running) {
        if store
            .unresolved(&installed.application, &installed.instance)?
            .iter()
            .any(|op| op.reconciliation_required)
        {
            continue;
        }
        let document = store.release(&installed.release_digest)?;
        super::tls::require(store, &document, &installed.instance)?;
        for host in document
            .release
            .workload
            .routes
            .iter()
            .map(|r| &r.host)
            .collect::<BTreeSet<_>>()
        {
            ensure!(
                hosts
                    .insert(host.clone(), installed.application.clone())
                    .is_none(),
                "ingress hostname belongs to multiple instances"
            );
        }
        // Boot/restart may be between container creation and observation. Fail
        // closed for this instance while preserving all other installed sites.
        let Ok(upstreams) = upstreams(&engine, &installed, &document) else {
            continue;
        };
        // The cache is root-owned and the proxy has read-only access. Full
        // byte verification happens at staging and controller startup; route
        // refreshes only check the protected accepted-tree inventory.
        if !document.release.workload.assets.is_empty() {
            let record = store
                .root
                .join("assets")
                .join(format!("{}.json", &document.digest[7..]));
            let recorded: BTreeMap<String, String> =
                serde_json::from_slice(&store::read_protected(&record, 1 << 20)?)?;
            ensure!(
                recorded.keys().eq(document.release.workload.assets.keys())
                    && recorded.values().all(|hash| digest(hash)),
                "public asset inventory differs from installed ownership"
            );
        }
        body.push_str(&render::sites(
            &document,
            asset_root(&document).to_str().unwrap(),
            &upstreams,
            false,
        )?);
    }
    body.push_str(&render::catchall());
    let path = Path::new(system::PROXY_CONFIG);
    if store::read_protected(path, 1 << 20)? == body.as_bytes() {
        return Ok(());
    }
    let staged = store.root.join("proxy-staged.caddy");
    store::atomic(&staged, body.as_bytes(), 0o600)?;
    system::caddy_validate(&staged, deadline)?;
    let previous = store::read_protected(path, 1 << 20)?;
    system::install(store, path, "platform", "proxy", body.as_bytes())?;
    if let Err(error) = system::caddy_reload(deadline) {
        system::install(store, path, "platform", "proxy", &previous)?;
        return Err(error);
    }
    Ok(())
}

pub fn tree(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<String, String>) -> Result<()> {
        let info = fs::symlink_metadata(path)?;
        ensure!(
            !info.file_type().is_symlink() && info.uid() == 0 && info.mode() & 0o022 == 0,
            "public asset ownership changed"
        );
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .ok_or_else(|| anyhow!("non UTF8 asset path"))?
            .to_owned();
        if info.is_dir() {
            entries.insert(relative, "directory".into());
            for entry in fs::read_dir(path)? {
                visit(root, &entry?.path(), entries)?;
            }
        } else {
            ensure!(
                info.is_file() && info.nlink() == 1 && info.mode() & 0o777 == 0o444,
                "public assets contain a non-file or hardlink"
            );
            let digest = super::native::file_hash(fs::File::open(path)?)?;
            entries.insert(relative, digest);
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(path, path, &mut entries)?;
    Ok(document_digest(&canonical(&serde_json::to_value(
        entries,
    )?)?))
}

pub fn seal_assets(store: &Store, document: &ReleaseDocument) -> Result<()> {
    let root = asset_root(document);
    let record = store
        .root
        .join("assets")
        .join(format!("{}.json", &document.digest[7..]));
    let mut identities = BTreeMap::new();
    for name in document.release.workload.assets.keys() {
        identities.insert(name, tree(&root.join(name))?);
    }
    let bytes = canonical(&serde_json::to_value(identities)?)?;
    if record.try_exists()? {
        ensure!(
            store::read_protected(&record, 1 << 20)? == bytes,
            "immutable public asset tree changed"
        );
    } else {
        store::atomic(&record, &bytes, 0o600)?;
    }
    Ok(())
}
pub fn verify_assets(store: &Store, document: &ReleaseDocument) -> Result<()> {
    if document.release.workload.assets.is_empty() {
        return Ok(());
    }
    let path = store
        .root
        .join("assets")
        .join(format!("{}.json", &document.digest[7..]));
    ensure!(
        path.try_exists()?,
        "public asset tree has no protected identity"
    );
    seal_assets(store, document)
}

pub fn verify_asset_inventory(store: &Store, document: &ReleaseDocument) -> Result<()> {
    if document.release.workload.assets.is_empty() {
        return Ok(());
    }
    let path = store
        .root
        .join("assets")
        .join(format!("{}.json", &document.digest[7..]));
    let raw = store::read_protected(&path, 1 << 20)?;
    let recorded: BTreeMap<String, String> =
        serde_json::from_value(crate::strict::value(&raw, 1 << 20)?)?;
    ensure!(
        recorded.keys().eq(document.release.workload.assets.keys())
            && recorded.values().all(|hash| digest(hash))
            && canonical(&serde_json::to_value(&recorded)?)? == raw,
        "public asset inventory differs from installed ownership"
    );
    Ok(())
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Installed, ReleaseDocument, serde_json::Value) {
        let mut source: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/deployment/release.json"))
                .unwrap();
        let first = source["workload"]["routes"][1].clone();
        let mut duplicate = first.clone();
        duplicate["host"] = json!("mail.example");
        duplicate["path"] = json!("/api/*");
        let mut other_port = first.clone();
        other_port["path"] = json!("/other/*");
        other_port["target"]["port"] = json!(8081);
        source["workload"]["routes"]
            .as_array_mut()
            .unwrap()
            .extend([duplicate, other_port]);
        let document = read_release(&serde_json::to_vec(&source).unwrap()).unwrap();
        let record = store::ContainerRecord {
            name: "owned-api".into(),
            id: "a".repeat(64),
            image: "unused".into(),
            config_digest: format!("sha256:{}", "b".repeat(64)),
            release_digest: document.digest.clone(),
            ownership: "c".repeat(32),
            unit_sha256: format!("sha256:{}", "d".repeat(64)),
            volumes: Default::default(),
        };
        let installed = Installed {
            kind: "komizo.installed".into(),
            version: 1,
            application: "mailroom".into(),
            instance: "production".into(),
            release_digest: document.digest.clone(),
            operation_id: "e".repeat(32),
            desired_running: true,
            removed: false,
            expires_at: None,
            resources: store::Resources {
                containers: BTreeMap::from([("api".into(), record)]),
                networks: BTreeMap::from([(
                    "backend".into(),
                    store::ObjectRecord {
                        name: "owned-network".into(),
                        id: "f".repeat(64),
                    },
                )]),
                ..Default::default()
            },
            secret_snapshots: Default::default(),
        };
        let metadata = json!({"State":{"Running":true},"NetworkSettings":{"Networks":{"owned-network":{"IPAddress":"10.42.0.5"}}}});
        (installed, document, metadata)
    }
    #[test]
    fn repeated_route_targets_share_one_fresh_observation_per_call() {
        let (installed, document, value) = fixture();
        let mut calls = 0;
        for round in 1..=2 {
            let upstreams = upstreams_from(&installed, &document, |record, name| {
                assert_eq!(record.id, installed.resources.containers["api"].id);
                assert_eq!(name, "api");
                calls += 1;
                Ok(Some(value.clone()))
            })
            .unwrap();
            assert_eq!(
                calls,
                round * 2,
                "two ports are distinct; repeated origins are not"
            );
            assert_eq!(
                upstreams,
                BTreeMap::from([
                    ("api:8080".into(), "10.42.0.5:8080".into()),
                    ("api:8081".into(), "10.42.0.5:8081".into())
                ])
            );
        }
    }
    #[test]
    fn upstream_reuse_never_turns_missing_stopped_or_invalid_native_proofs_into_routes() {
        let (installed, document, value) = fixture();
        assert!(upstreams_from(&installed, &document, |_, _| Ok(None)).is_err());
        assert!(
            upstreams_from(&installed, &document, |_, _| Err(anyhow!(
                "ownership refused"
            )))
            .is_err()
        );
        let mut stopped = value.clone();
        stopped["State"]["Running"] = json!(false);
        assert!(upstreams_from(&installed, &document, |_, _| Ok(Some(stopped.clone()))).is_err());
        for ip in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "not-an-address"] {
            let mut bad = value.clone();
            bad["NetworkSettings"]["Networks"]["owned-network"]["IPAddress"] = json!(ip);
            assert!(
                upstreams_from(&installed, &document, |_, _| Ok(Some(bad.clone()))).is_err(),
                "{ip}"
            );
        }
    }
}
