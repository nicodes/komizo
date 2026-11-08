use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const MAX_DOCUMENT_BYTES: usize = 4 << 20;
pub const STATIC_MEDIA_TYPE: &str = "application/vnd.komizo.static.v1.tar+gzip";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<Providers>,
    pub artifacts: BTreeMap<String, Artifact>,
    pub workload: Workload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stateful_contract: Option<StatefulContract>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Providers {
    pub cookbook_revision: String,
    pub tools_revision: String,
    pub core_revision: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub workload: Workload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub repository: String,
    pub repository_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Artifact {
    Image {
        reference: String,
        digest: String,
        config_digest: String,
        platform: String,
    },
    Archive {
        reference: String,
        digest: String,
        size_bytes: u64,
        media_type: String,
    },
}

impl Artifact {
    pub fn reference(&self) -> &str {
        match self {
            Self::Image { reference, .. } | Self::Archive { reference, .. } => reference,
        }
    }
    pub fn digest(&self) -> &str {
        match self {
            Self::Image { digest, .. } | Self::Archive { digest, .. } => digest,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    #[serde(default)]
    pub services: BTreeMap<String, Container>,
    #[serde(default)]
    pub jobs: BTreeMap<String, Container>,
    #[serde(default)]
    pub assets: BTreeMap<String, Asset>,
    #[serde(default)]
    pub networks: BTreeMap<String, Network>,
    #[serde(default)]
    pub volumes: BTreeMap<String, Volume>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub readiness: Vec<Readiness>,
}

fn yes() -> bool {
    true
}
fn stop_timeout() -> u32 {
    30
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    pub artifact: String,
    pub user: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub environment_files: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<SecretMount>,
    #[serde(default)]
    pub volumes: Vec<Mount>,
    #[serde(default)]
    pub tmpfs: BTreeMap<String, Tmpfs>,
    #[serde(default)]
    pub networks: Vec<String>,
    pub limits: Limits,
    #[serde(default)]
    pub health: Option<Health>,
    #[serde(default)]
    pub needs: BTreeMap<String, Condition>,
    #[serde(default = "yes")]
    pub read_only: bool,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub init: bool,
    #[serde(default)]
    pub working_directory: Option<String>,
    #[serde(default = "stop_timeout")]
    pub stop_timeout_seconds: u32,
    #[serde(default)]
    pub timeout_seconds: Option<u32>,
    #[serde(default)]
    pub ulimits: BTreeMap<String, Ulimit>,
    #[serde(default)]
    pub sysctls: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    Started,
    Healthy,
    Completed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub memory_bytes: u64,
    pub memory_swap_bytes: u64,
    pub milli_cpus: u32,
    pub pids: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub command: Vec<String>,
    pub interval_seconds: u32,
    pub timeout_seconds: u32,
    pub retries: u32,
    #[serde(default)]
    pub start_period_seconds: u32,
    #[serde(default)]
    pub start_interval_seconds: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMount {
    pub source: String,
    pub target: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub name: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tmpfs {
    pub size_bytes: u64,
    pub mode: u32,
    #[serde(default)]
    pub executable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ulimit {
    pub soft: u64,
    pub hard: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub artifact: String,
    pub serving: Serving,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Serving {
    #[serde(default)]
    pub route_rules: Vec<RouteRule>,
    #[serde(default)]
    pub not_found: Option<String>,
    #[serde(default)]
    pub fallbacks: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub header_rules: Vec<HeaderRule>,
    #[serde(default)]
    pub precompressed: Vec<String>,
    #[serde(default)]
    pub encode: Vec<String>,
    #[serde(default)]
    pub encode_content_types: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    pub pattern: String,
    pub replacement: String,
    #[serde(default)]
    pub redirect_status: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRule {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub except_paths: Vec<String>,
    #[serde(default)]
    pub path_regexp: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub existing_file: bool,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub internal: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub target: Option<RouteTarget>,
    #[serde(default)]
    pub redirect: Option<Redirect>,
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub proxy: Option<ProxyOptions>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyOptions {
    #[serde(default)]
    pub encode: Vec<String>,
    #[serde(default)]
    pub encode_content_types: Vec<String>,
    #[serde(default)]
    pub dial_timeout_seconds: Option<u32>,
    #[serde(default)]
    pub response_header_timeout_seconds: Option<u32>,
    #[serde(default)]
    pub error_status: Option<u16>,
    #[serde(default)]
    pub error_body: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum RouteTarget {
    Asset { name: String },
    Service { name: String, port: u16 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    pub to: String,
    pub status: u16,
    #[serde(default)]
    pub preserve_uri: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readiness {
    pub url: String,
    pub status: u16,
    #[serde(default)]
    pub revision_field: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatefulContract {
    pub version: u32,
    pub source_revision: String,
    pub schema: SchemaRange,
    pub data_revision: String,
    pub credential_revision: String,
    pub migrations: Vec<Migration>,
    pub recovery_action: RecoveryAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRange {
    pub minimum: u64,
    pub maximum: u64,
    pub write: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub identity: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    ForwardOnly,
    ImageRollback,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub kind: String,
    pub version: u32,
    pub application: String,
    pub authority: Authority,
    pub artifact_prefixes: Vec<String>,
    pub hostnames: Vec<String>,
    pub limits: Limits,
    #[serde(default)]
    pub aggregate_mode: AggregateMode,
    #[serde(default)]
    pub service_limits: Option<Limits>,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretGrant>,
    #[serde(default)]
    pub readiness: Vec<Readiness>,
    #[serde(default)]
    pub require_stateful_contract: bool,
    #[serde(default = "default_archive_bytes")]
    pub max_asset_bytes: u64,
    #[serde(default = "default_file_bytes")]
    pub max_asset_file_bytes: u64,
    #[serde(default = "default_operation_seconds")]
    pub operation_timeout_seconds: u32,
    #[serde(default)]
    pub previews: Option<PreviewPolicy>,
    #[serde(default)]
    pub backup: Option<ProtectedTask>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AggregateMode {
    #[default]
    Sum,
    Cgroup,
}

fn default_archive_bytes() -> u64 {
    256 << 20
}
fn default_file_bytes() -> u64 {
    128 << 20
}
fn default_operation_seconds() -> u32 {
    1500
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Authority {
    Owner,
    Github {
        repository: String,
        repository_id: String,
        workflows: BTreeMap<String, String>,
        reference: String,
        environment: String,
        #[serde(default)]
        publisher_workflow: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrant {
    pub path: String,
    pub services: Vec<String>,
    #[serde(default)]
    pub environment_file: bool,
    #[serde(default)]
    pub mount: bool,
    pub generation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicy {
    pub hostname_suffix: String,
    pub max_instances: u32,
    pub max_ttl_seconds: u32,
    pub limits: Limits,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretGrant>,
    #[serde(default)]
    pub api_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedTask {
    pub program: String,
    pub sha256: String,
    pub timeout_seconds: u32,
    pub max_export_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub kind: String,
    pub version: u32,
    pub authority: String,
    pub application: String,
    pub instance: String,
    pub action: String,
    pub release_digest: String,
    pub nonce: String,
    pub issued_at: i64,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_proof: Option<ReleaseProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_update: Option<SecretUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub expected_secret_generations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("application", &self.application)
            .field("instance", &self.instance)
            .field("action", &self.action)
            .field("release_digest", &self.release_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretUpdate {
    pub reference: String,
    pub expected_generation: String,
    pub format: String,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCredential {
    pub server: String,
    pub username: String,
    pub token: String,
}
impl std::fmt::Debug for RegistryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryCredential")
            .field("server", &self.server)
            .field("username", &"[redacted]")
            .field("token", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProof {
    pub kind: String,
    pub version: u32,
    pub release_digest: String,
    pub source_revision: String,
    pub run_id: String,
    pub run_attempt: String,
    pub workflow_ref: String,
    pub workflow_sha: String,
    pub proof: String,
}
impl std::fmt::Debug for ReleaseProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseProof")
            .field("release_digest", &self.release_digest)
            .field("source_revision", &self.source_revision)
            .field("proof", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ReleaseDocument {
    pub release: Release,
    pub canonical: Vec<u8>,
    pub digest: String,
}
