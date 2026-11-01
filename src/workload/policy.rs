//! Host-owned authority is validated before repository configuration is read.
use super::{identifier, resources::ResourcePolicy};
use crate::{
    host::{authority::quote, inventory::clean_path},
    wire::Slice,
    wire_struct,
};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
macro_rules! matcher {
    ($name:ident,$pattern:literal) => {
        pub fn $name(value: &str) -> bool {
            static RE: OnceLock<regex::Regex> = OnceLock::new();
            RE.get_or_init(|| regex::Regex::new($pattern).unwrap())
                .is_match(value)
        }
    };
}
matcher!(repository_name, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$");
matcher!(numeric_id, r"^[1-9][0-9]{0,19}$");
matcher!(content_identity, r"^[a-f0-9]{64}$");
matcher!(commit_id, r"^[a-f0-9]{40}$");
matcher!(operation_identity, r"^[a-f0-9]{32}$");
matcher!(image_repository, r"^[a-z0-9][a-z0-9./_-]+$");
matcher!(
    static_hostname,
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$"
);
wire_struct!(Policy{version:"version":i64=>required,app:"app":String=>required,app_dir:"app_dir":String=>required,image_prefix:"image_prefix":String=>required,shared_network:"shared_network":String=>required,source_repository:"source_repository":String=>optional,owner_approval:"owner_approval":bool=>optional,repository_id:"repository_id":String=>optional,resources:"resources":Option<ResourcePolicy> =>optional,readiness:"readiness":Option<ReadinessPolicy> =>optional,ingress_network:"ingress_network":String=>optional,require_stateful_contract:"require_stateful_contract":bool=>optional,require_delivery_authorization:"require_delivery_authorization":bool=>optional,r#static:"static":Option<StaticPolicy> =>optional,deployment:"deployment":Option<DeploymentPolicy> =>optional,routine_backup:"routine_backup":Option<BackupPolicy> =>optional});
wire_struct!(ReadinessPolicy{probes:"probes":Slice<ReadinessProbe> =>required});
wire_struct!(ReadinessProbe{url:"url":String=>required,revision_field:"revision_field":String=>optional});
wire_struct!(DeploymentPolicy{route_path:"route_path":String=>required,proxy:"proxy":String=>required,proxy_dir:"proxy_dir":String=>required});
wire_struct!(DeploymentStage{credential_sha256:"credential_sha256":String=>required,local_only:"local_only":bool=>optional,generation:"generation":String=>optional});
wire_struct!(BackupPolicy{workflow_repository:"workflow_repository":String=>required,workflow_revision:"workflow_revision":String=>required,program_sha256:"program_sha256":String=>required,timeout_seconds:"timeout_seconds":i64=>required});
wire_struct!(StaticPolicy{image_directory:"image_directory":String=>required,limits:"limits":StaticLimits=>required,serving:"serving":StaticServingOptions=>required,gate_config_sha:"gate_config_sha256":String=>required,proxy:"proxy":String=>required,hostnames:"hostnames":Slice<String> =>required});
wire_struct!(StaticLimits{max_bytes:"max_bytes":i64=>optional,max_file_bytes:"max_file_bytes":i64=>optional});
wire_struct!(StaticServingOptions{fallbacks:"fallbacks":Slice<String> =>optional,deny_paths:"deny_paths":Slice<String> =>optional,headers:"headers":BTreeMap<String,String> =>optional,header_rules:"header_rules":Slice<StaticHeaderRule> =>optional,precompressed:"precompressed":Slice<String> =>optional,encode:"encode":Slice<String> =>optional,encode_content_types:"encode_content_types":Slice<String> =>optional});
wire_struct!(StaticHeaderRule{paths:"paths":Slice<String> =>optional,except_paths:"except_paths":Slice<String> =>optional,path_regexp:"path_regexp":String=>optional,methods:"methods":Slice<String> =>optional,existing_file:"existing_file":bool=>optional,headers:"headers":BTreeMap<String,String> =>required});
pub fn isolated_ingress(app: &str) -> String {
    let app = if app.len() > 40 {
        format!(
            "{}-{}",
            String::from_utf8_lossy(&app.as_bytes()[..40]),
            &format!("{:x}", Sha256::digest(app.as_bytes()))[..6]
        )
    } else {
        app.into()
    };
    format!("komizo-{app}-ingress")
}
impl ReadinessPolicy {
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.probes.is_empty() && self.probes.len() <= 8,
            "readiness requires 1..8 operator-owned probes"
        );
        for probe in self.probes.iter() {
            let parsed = reqwest::Url::parse(&probe.url).ok();
            ensure!(
                parsed
                    .as_ref()
                    .is_some_and(|u| probe.url.starts_with("https://")
                        && !probe
                            .url
                            .split_once("://")
                            .unwrap()
                            .1
                            .split(['/', '?', '#'])
                            .next()
                            .unwrap_or_default()
                            .contains('@')
                        && u.scheme() == "https"
                        && u.host_str().is_some()
                        && u.username().is_empty()
                        && u.password().is_none()
                        && u.query().is_none_or(|q| q.is_empty())
                        && u.fragment().is_none_or(|f| f.is_empty()))
                    && (probe.revision_field.is_empty() || identifier(&probe.revision_field)),
                "invalid operator readiness probe"
            );
        }
        Ok(())
    }
}
impl DeploymentPolicy {
    pub fn check(&self, app: &str) -> Result<()> {
        ensure!(
            identifier(&self.proxy)
                && self.proxy_dir.starts_with('/')
                && clean_path(&self.proxy_dir) == self.proxy_dir
                && self.proxy_dir != "/"
                && self.route_path == clean_path(&format!("{}/routes/{app}.caddy", self.proxy_dir)),
            "invalid operator deployment authority"
        );
        Ok(())
    }
}
impl DeploymentStage {
    pub fn check(&self) -> Result<()> {
        ensure!(
            content_identity(&self.credential_sha256)
                && (self.generation.is_empty() || operation_identity(&self.generation)),
            "invalid deployment staging request"
        );
        Ok(())
    }
}
impl BackupPolicy {
    pub fn check(&self) -> Result<()> {
        ensure!(
            repository_name(&self.workflow_repository)
                && commit_id(&self.workflow_revision)
                && content_identity(&self.program_sha256)
                && (1..=900).contains(&self.timeout_seconds),
            "backup authority needs an immutable reusable workflow, fixed program and finite deadline"
        );
        Ok(())
    }
}
impl StaticLimits {
    pub fn bounds(&self) -> Result<(i64, i64)> {
        let total = if self.max_bytes == 0 {
            64 << 20
        } else {
            self.max_bytes
        };
        let file = if self.max_file_bytes == 0 {
            16 << 20
        } else {
            self.max_file_bytes
        };
        ensure!(
            (1..=1 << 30).contains(&total) && (1..=128 << 20).contains(&file) && file <= total,
            "static archive bounds exceed the protected envelope"
        );
        Ok((total, file))
    }
}
fn static_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.contains(['{', '}'])
        && !value.chars().any(|c| c < ' ' || c == '\x7f')
}
fn static_patterns(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.len() <= 32
        && values
            .iter()
            .all(|v| static_text(v, 1024) && !v.contains([' ', '\t', '\\', '"']) && seen.insert(v))
}
fn static_headers(headers: &BTreeMap<String, String>) -> bool {
    let mut seen = BTreeSet::new();
    headers.len() <= 32
        && headers.iter().all(|(name, value)| {
            let lower = name.to_lowercase();
            !name.is_empty()
                && name.len() <= 100
                && name.as_bytes()[0].is_ascii_alphabetic()
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && static_text(value, 4096)
                && seen.insert(lower.clone())
                && !matches!(
                    lower.as_str(),
                    "x-komizo-revision" | "content-length" | "transfer-encoding" | "connection"
                )
        })
}
fn go_regex(pattern: &str) -> bool {
    use regex_syntax::ast::{Ast, RepetitionKind, RepetitionRange};
    fn children(ast: &Ast) -> Vec<&Ast> {
        match ast {
            Ast::Repetition(r) => vec![&r.ast],
            Ast::Group(g) => vec![&g.ast],
            Ast::Alternation(a) => a.asts.iter().collect(),
            Ast::Concat(c) => c.asts.iter().collect(),
            _ => vec![],
        }
    }
    fn bounded(ast: &Ast, mut budget: u32) -> bool {
        if let Ast::Repetition(r) = ast
            && let RepetitionKind::Range(range) = &r.op.kind
        {
            let maximum = match range {
                RepetitionRange::Exactly(n) | RepetitionRange::AtLeast(n) => *n,
                RepetitionRange::Bounded(_, n) => *n,
            };
            if maximum == 0 {
                return true;
            }
            if maximum > budget {
                return false;
            }
            budget /= maximum;
        }
        children(ast).iter().all(|child| bounded(child, budget))
    }
    fn parsed(ast: &Ast) -> bool {
        bounded(ast, 1000) && children(ast).iter().all(|child| parsed(child))
    }
    regex::RegexBuilder::new(pattern)
        .nest_limit(1000)
        .build()
        .is_ok()
        && regex_syntax::ast::parse::ParserBuilder::new()
            .nest_limit(1000)
            .build()
            .parse(pattern)
            .is_ok_and(|ast| parsed(&ast))
}
impl StaticServingOptions {
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.fallbacks.len() <= 16
                && static_patterns(&self.deny_paths)
                && static_headers(&self.headers)
                && self.header_rules.len() <= 32,
            "invalid bounded static serving settings"
        );
        for value in self.fallbacks.iter() {
            let path = value.replace("{path}", "/request");
            ensure!(
                static_patterns(std::slice::from_ref(&path))
                    && path.starts_with('/')
                    && !path.contains(".."),
                "invalid static fallback path"
            );
        }
        static REPETITION: OnceLock<regex::Regex> = OnceLock::new();
        let expression =
            REPETITION.get_or_init(|| regex::Regex::new(r"\{[0-9]+(?:,[0-9]*)?\}").unwrap());
        for rule in self.header_rules.iter() {
            ensure!(
                static_patterns(&rule.paths)
                    && static_patterns(&rule.except_paths)
                    && !rule.headers.is_empty()
                    && static_headers(&rule.headers)
                    && rule.methods.len() <= 8
                    && (rule.paths.len()
                        + rule.except_paths.len()
                        + rule.path_regexp.len()
                        + rule.methods.len()
                        > 0
                        || rule.existing_file),
                "invalid static header selector"
            );
            for method in rule.methods.iter() {
                ensure!(
                    matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"),
                    "unsupported static request method"
                );
            }
            if !rule.path_regexp.is_empty() {
                ensure!(
                    rule.path_regexp.len() <= 1024
                        && !rule.path_regexp.contains(['\0', '\r', '\n'])
                        && !expression
                            .replace_all(&rule.path_regexp, "")
                            .contains(['{', '}'])
                        && go_regex(&rule.path_regexp),
                    "invalid static path expression"
                );
            }
        }
        for values in [&self.precompressed, &self.encode] {
            ensure!(values.len() <= 3, "too many static encoders");
            let mut seen = BTreeSet::new();
            for value in values.iter() {
                ensure!(
                    matches!(value.as_str(), "br" | "gzip" | "zstd") && seen.insert(value),
                    "unsupported or duplicate static encoding"
                );
            }
        }
        ensure!(
            !self.encode.iter().any(|v| v == "br"),
            "Brotli requires precompressed sidecars"
        );
        ensure!(
            (self.encode_content_types.is_empty() || !self.encode.is_empty())
                && static_patterns(&self.encode_content_types),
            "invalid static compression selectors"
        );
        Ok(())
    }
}
impl StaticPolicy {
    pub fn check(&self) -> Result<()> {
        ensure!(
            content_identity(&self.gate_config_sha)
                && identifier(&self.proxy)
                && self.image_directory.starts_with('/')
                && clean_path(&self.image_directory) == self.image_directory
                && self.image_directory != "/"
                && !self.image_directory.contains(['\0', '\r', '\n', ':', '\\']),
            "invalid protected static serving identity"
        );
        self.limits.bounds()?;
        self.serving.check()?;
        ensure!(
            !self.hostnames.is_empty() && self.hostnames.len() <= 16,
            "static profiles require reviewed exact hostnames"
        );
        let mut seen = BTreeSet::new();
        for host in self.hostnames.iter() {
            ensure!(
                static_hostname(host) && host.len() <= 253 && seen.insert(host),
                "invalid or duplicate static hostname"
            );
        }
        Ok(())
    }
}
impl Policy {
    pub fn has_release_authority(&self) -> bool {
        !self.source_repository.is_empty() || self.owner_approval
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.owner_approval
                || (self.source_repository.is_empty()
                    && self.repository_id.is_empty()
                    && !self.require_delivery_authorization
                    && self.routine_backup.is_none()),
            "owner approval and GitHub source/delivery/backup authority are mutually exclusive"
        );
        if let Some(backup) = &self.routine_backup {
            ensure!(
                !self.source_repository.is_empty(),
                "routine backup requires authenticated source authority"
            );
            backup.check()?;
        }
        if let Some(profile) = &self.r#static {
            ensure!(
                self.has_release_authority()
                    && !self.require_stateful_contract
                    && self.readiness.is_some(),
                "static serving requires authenticated gate-only releases and explicit readiness"
            );
            profile.check()?;
        }
        if let Some(deployment) = &self.deployment {
            ensure!(
                self.has_release_authority(),
                "typed deployment requires authenticated source authority"
            );
            deployment.check(&self.app)?;
        }
        ensure!(
            (!self.require_stateful_contract || self.has_release_authority())
                && (!self.require_delivery_authorization || !self.source_repository.is_empty()),
            "stateful contracts require authenticated release source authority"
        );
        ensure!(
            self.ingress_network.is_empty() || self.ingress_network == isolated_ingress(&self.app),
            "ingress network must belong to this app"
        );
        if let Some(readiness) = &self.readiness {
            readiness.check()?;
        }
        if let Some(resources) = &self.resources {
            ensure!(
                !resources.cgroup_parent.starts_with("/komizo-production/")
                    || resources.cgroup_parent == format!("/komizo-production/{}", self.app),
                "application cgroup must belong to this app"
            );
            resources.check()?;
        }
        ensure!(
            self.source_repository.is_empty() && self.repository_id.is_empty()
                || repository_name(&self.source_repository) && numeric_id(&self.repository_id),
            "invalid workload source identity"
        );
        ensure!(
            self.version == 1
                && identifier(&self.app)
                && identifier(&self.shared_network)
                && self.app_dir.starts_with('/')
                && clean_path(&self.app_dir) == self.app_dir
                && self.app_dir != "/"
                && image_repository(&self.image_prefix)
                && self.image_prefix.ends_with('-'),
            "invalid host workload policy"
        );
        Ok(())
    }
    pub fn new(app: &str, dir: &str, config_image: &str, network: &str) -> Result<Self> {
        ensure!(
            config_image.ends_with("-config"),
            "configuration repository must end in -config"
        );
        let policy = Self {
            version: 1,
            app: app.into(),
            app_dir: dir.into(),
            image_prefix: config_image.strip_suffix("config").unwrap().into(),
            shared_network: network.into(),
            ..Default::default()
        };
        policy.check()?;
        Ok(policy)
    }
}
pub fn check_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    where_: &str,
    allowed: &[&str],
) -> Result<()> {
    for field in object.keys() {
        ensure!(
            allowed.contains(&field.as_str()),
            "unsupported {where_} field {}",
            quote(field)
        );
    }
    Ok(())
}
