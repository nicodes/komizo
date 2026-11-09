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
    let mut upstreams = BTreeMap::new();
    for route in &document.release.workload.routes {
        let Some(RouteTarget::Service { name, port }) = &route.target else {
            continue;
        };
        let record = installed
            .resources
            .containers
            .get(name)
            .ok_or_else(|| anyhow!("route service has no creation record"))?;
        let value = engine
            .owned_container(record, &installed.application, &installed.instance, name)?
            .ok_or_else(|| anyhow!("route service is absent"))?;
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
        upstreams.insert(
            format!("{name}:{port}"),
            SocketAddr::new(address, *port).to_string(),
        );
    }
    Ok(upstreams)
}

pub fn refresh(store: &Store, deadline: Instant) -> Result<()> {
    let _lock = store.lock("platform", "proxy")?;
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
