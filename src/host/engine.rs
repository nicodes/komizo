//! Docker's local metadata protocol uses one connection and one shared budget.
use super::inventory::{ContainerInfo, DOCKER_API, Inventory, Mount, parse_stamp};
use crate::{wire::Slice, wire_struct};
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
wire_struct!(EngineVersion{version:"Version":String=>required,git_commit:"GitCommit":String=>required,api_version:"ApiVersion":String=>required,min_api_version:"MinAPIVersion":String=>required});
wire_struct!(ListRow{id:"Id":String=>required,state:"State":String=>required,status:"Status":String=>required,image:"Image":String=>required,names:"Names":Slice<String> =>required,labels:"Labels":BTreeMap<String,String> =>required});
wire_struct!(Details{id:"Id":String=>required,config:"Config":EngineConfig=>required,state:"State":Option<EngineState> =>required,network_settings:"NetworkSettings":NetworkSettings=>required,mounts:"Mounts":Slice<EngineMount> =>required});
wire_struct!(EngineConfig{tty:"Tty":bool=>required});
wire_struct!(EngineState{status:"Status":String=>required,started_at:"StartedAt":String=>required,finished_at:"FinishedAt":String=>required,exit_code:"ExitCode":Option<i64> =>required,pid:"Pid":Option<i64> =>required,health:"Health":Option<EngineHealth> =>required});
wire_struct!(EngineHealth{status:"Status":String=>required});
wire_struct!(NetworkSettings{networks:"Networks":BTreeMap<String,Endpoint> =>required});
wire_struct!(Endpoint{aliases:"Aliases":Slice<String> =>required});
wire_struct!(EngineMount{r#type:"Type":String=>required,name:"Name":String=>required,source:"Source":String=>required});
wire_struct!(NetworkDetails{driver:"Driver":String=>required,ipam:"IPAM":Ipam=>required});
wire_struct!(Ipam{config:"Config":Slice<Subnet> =>required});
wire_struct!(Subnet{subnet:"Subnet":String=>required});
pub trait Metadata {
    fn read(&mut self, path: &str, maximum: usize) -> Result<Value>;
}
pub struct Engine {
    client: reqwest::blocking::Client,
    pub version: EngineVersion,
    pub available: bool,
    remaining: usize,
    deadline: Instant,
}
impl Engine {
    /// None means an unsupported protocol; an unavailable compatible daemon
    /// remains selected, so failure does not trigger a second CLI observation.
    pub fn connect(socket: &Path, deadline: Instant) -> Result<Option<Self>> {
        let client = reqwest::blocking::Client::builder()
            .unix_socket(socket.to_owned())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(1)
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(8))
            .build()?;
        let mut engine = Self {
            client,
            version: EngineVersion::default(),
            available: false,
            remaining: 64 << 20,
            deadline,
        };
        let version = engine
            .read("/version", 64 << 10)
            .and_then(|v| serde_json::from_value::<EngineVersion>(v).map_err(Into::into));
        let Ok(version) = version else {
            return Ok(Some(engine));
        };
        engine.version = version;
        if !api_contains(
            &engine.version.min_api_version,
            &engine.version.api_version,
            DOCKER_API,
        ) {
            return Ok(None);
        }
        let version = &engine.version;
        if version.version.is_empty()
            || version.version.len() > 128
            || version.git_commit.len() > 128
            || version.version.contains(['\r', '\n', '\t'])
            || version.git_commit.contains(['\r', '\n', '\t'])
        {
            return Ok(Some(engine));
        }
        engine.available = true;
        Ok(Some(engine))
    }
    pub fn read_bytes(&mut self, path: &str, maximum: usize) -> Result<Vec<u8>> {
        let maximum = maximum.min(self.remaining);
        ensure!(
            maximum > 0,
            "Docker metadata reading exhausted its byte budget"
        );
        let timeout = self.deadline.saturating_duration_since(Instant::now());
        ensure!(!timeout.is_zero(), "Docker metadata unavailable");
        let response = self
            .client
            .get(format!("http://docker{path}"))
            .timeout(timeout)
            .send()
            .map_err(|_| anyhow!("Docker metadata unavailable"))?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "Docker metadata request refused"
        );
        let mut bytes = vec![];
        let result = response.take(maximum as u64 + 1).read_to_end(&mut bytes);
        self.remaining = self.remaining.saturating_sub(bytes.len());
        ensure!(
            result.is_ok() && bytes.len() <= maximum,
            "Docker metadata response exceeds its bound or was interrupted"
        );
        Ok(bytes)
    }
    pub fn remaining(&self) -> usize {
        self.remaining
    }
    pub fn inventory(&mut self) -> Inventory {
        read_inventory(self)
    }
    pub fn network(&mut self, name: &str) -> Result<String> {
        read_network(self, name)
    }
}
impl Metadata for Engine {
    fn read(&mut self, path: &str, maximum: usize) -> Result<Value> {
        serde_json::from_slice(&self.read_bytes(path, maximum)?)
            .map_err(|_| anyhow!("Docker metadata response is invalid"))
    }
}
pub fn api_contains(minimum: &str, maximum: &str, target: &str) -> bool {
    fn parse(value: &str) -> Option<i32> {
        let (major, minor) = value.split_once('.')?;
        if major != "1" {
            return None;
        }
        minor.parse::<i32>().ok().filter(|n| (0..=999).contains(n))
    }
    matches!((parse(minimum),parse(maximum),parse(target)),(Some(lo),Some(hi),Some(want)) if hi>=lo&&want>=lo&&want<=hi)
}
pub fn read_inventory(reader: &mut impl Metadata) -> Inventory {
    let rows = reader
        .read(&format!("/v{DOCKER_API}/containers/json?all=1"), 8 << 20)
        .and_then(|v| serde_json::from_value::<Slice<ListRow>>(v).map_err(Into::into));
    let Ok(rows) = rows else {
        return Inventory::unavailable("list_unavailable");
    };
    if rows.len() > 1024 {
        return Inventory::unavailable("list_unavailable");
    }
    let mut inv = Inventory::default();
    for row in rows.into_vec() {
        if row.id.len() != 64
            || !row
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || row.names.is_empty()
            || inv.contains(&row.id)
        {
            return Inventory::unavailable("list_invalid");
        }
        inv.insert(ContainerInfo {
            inspection_unavailable: true,
            id: row.id,
            name: row.names[0]
                .strip_prefix('/')
                .unwrap_or(&row.names[0])
                .to_owned(),
            state: row.state,
            status: row.status,
            image: row.image,
            service: row
                .labels
                .get("com.docker.compose.service")
                .cloned()
                .unwrap_or_default(),
            working_dir: row
                .labels
                .get("com.docker.compose.project.working_dir")
                .cloned()
                .unwrap_or_default(),
            ..Default::default()
        });
    }
    let ids: Vec<_> = inv.sorted().iter().map(|c| c.id.clone()).collect();
    for id in ids {
        let details = reader
            .read(&format!("/v{DOCKER_API}/containers/{id}/json"), 4 << 20)
            .and_then(|v| serde_json::from_value::<Details>(v).map_err(Into::into));
        let Ok(details) = details else {
            inv.partial("inspection_unavailable");
            continue;
        };
        let Some(state) = details.state.filter(|s| {
            s.exit_code.is_some() && s.pid.is_some() && !s.status.is_empty() && details.id == id
        }) else {
            inv.partial("inspection_unavailable");
            continue;
        };
        let container = inv.by_id_mut(&id).unwrap();
        container.inspection_unavailable = false;
        container.tty = details.config.tty;
        container.state = state.status;
        container.started_at = parse_stamp(&state.started_at);
        container.finished_at = parse_stamp(&state.finished_at);
        container.exit_code = state.exit_code.unwrap();
        container.pid = state.pid.unwrap();
        if let Some(health) = state.health {
            container.health = health.status;
        }
        container.networks = details
            .network_settings
            .networks
            .into_iter()
            .map(|(name, network)| (name, network.aliases))
            .collect();
        let mounts: Vec<_> = details
            .mounts
            .into_vec()
            .into_iter()
            .filter(|m| m.r#type == "volume")
            .map(|m| Mount {
                name: m.name,
                source: m.source,
            })
            .collect();
        if !mounts.is_empty() {
            container.mounts = mounts.into();
        }
    }
    inv
}
pub fn read_network(reader: &mut impl Metadata, name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name != "."
            && name != ".."
            && name.len() <= 256
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')),
        "Docker network metadata name is invalid"
    );
    let details: NetworkDetails =
        serde_json::from_value(reader.read(&format!("/v{DOCKER_API}/networks/{name}"), 1 << 20)?)?;
    Ok(details.driver
        + "\t"
        + &details
            .ipam
            .config
            .iter()
            .map(|c| c.subnet.as_str())
            .collect::<String>())
}
pub fn default_context(path: &Path) -> bool {
    let bytes = match crate::statefile::read(path, 1 << 20) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return true,
        Err(_) => return false,
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    if value.is_null() {
        return true;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut current = "";
    for (key, value) in object {
        if key.eq_ignore_ascii_case("CurrentContext") {
            if value.is_null() {
                continue;
            }
            let Some(value) = value.as_str() else {
                return false;
            };
            current = value;
        }
    }
    current.is_empty() || current == "default"
}
pub fn local_engine_eligible(probe: &super::Probe) -> bool {
    if !cfg!(target_os = "linux") || !probe.root.as_os_str().is_empty() {
        return false;
    }
    if [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_API_VERSION",
        "DOCKER_CONFIG",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some_and(|v| !v.is_empty()))
    {
        return false;
    }
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("docker"))
            .find(|p| {
                p.metadata()
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
    }) else {
        return false;
    };
    if path != Path::new("/usr/bin/docker") && path != Path::new("/usr/local/bin/docker") {
        return false;
    }
    let mut magic = [0u8; 4];
    if std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_err()
        || magic != *b"\x7fELF"
    {
        return false;
    }
    std::env::var_os("HOME")
        .is_some_and(|home| default_context(&Path::new(&home).join(".docker/config.json")))
}
