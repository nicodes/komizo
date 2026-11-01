use super::{Target, preview_host, valid_app, validate_args};
use crate::wire_struct;
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ops::{Deref, DerefMut},
};
wire_struct!(KnobValues{shared_domain:"SharedDomain":String=>required,domain:"Domain":String=>required,ttl:"TTL":i64=>required,max:"Max":i64=>required,mem_limit:"MemLimit":String=>required,cpu_limit:"CPULimit":String=>required,production_reserve:"ProductionReserve":i64=>required,database_reserve:"DatabaseReserve":i64=>required,memory_budget:"MemoryBudget":i64=>required,invalid_budget:"InvalidBudget":bool=>required,ask_port:"AskPort":i64=>required,port_range:"PortRange":String=>required});
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Knob {
    #[serde(flatten)]
    pub values: KnobValues,
    #[serde(skip)]
    pub body: String,
    #[serde(skip)]
    pub cgroup_parent: String,
    #[serde(skip)]
    pub profiles: Option<std::collections::BTreeMap<String, Option<super::profile::Profile>>>,
}
impl Deref for Knob {
    type Target = KnobValues;
    fn deref(&self) -> &KnobValues {
        &self.values
    }
}
impl DerefMut for Knob {
    fn deref_mut(&mut self) -> &mut KnobValues {
        &mut self.values
    }
}
impl Default for Knob {
    fn default() -> Self {
        Self {
            values: KnobValues {
                ttl: 72 * 3_600_000_000_000,
                max: 5,
                mem_limit: "512m".into(),
                cpu_limit: "0.75".into(),
                ask_port: 8487,
                port_range: "20000-21000".into(),
                ..Default::default()
            },
            body: String::new(),
            cgroup_parent: String::new(),
            profiles: None,
        }
    }
}
pub fn get<'a>(body: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    body.split('\n')
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .map(|value| value.trim_matches(['\r', ' ', '\t']))
        })
        .unwrap_or("")
}
pub fn memory_bytes(value: &str) -> Result<i64> {
    let value = value.to_ascii_lowercase();
    let raw = value.strip_suffix('b').unwrap_or(&value);
    let (number, multiplier) = match raw.as_bytes().last() {
        Some(b'k') => (&raw[..raw.len() - 1], 1024u64),
        Some(b'm') => (&raw[..raw.len() - 1], 1 << 20),
        Some(b'g') => (&raw[..raw.len() - 1], 1 << 30),
        Some(b't') => (&raw[..raw.len() - 1], 1 << 40),
        _ => (raw, 1),
    };
    ensure!(
        !number.is_empty()
            && number.as_bytes()[0].is_ascii_digit()
            && number.as_bytes()[0] != b'0'
            && number.bytes().all(|b| b.is_ascii_digit()),
        "memory must be positive bytes or k/m/g units"
    );
    let number = number.parse::<u64>().ok();
    let bytes = number
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| (6 << 20..=64 << 30).contains(n))
        .ok_or_else(|| anyhow!("memory must be between 6 MiB and 64 GiB"))?;
    Ok(bytes as i64)
}
pub fn valid_cpu(value: &str) -> bool {
    let mut dots = 0;
    let mut count = 0;
    for byte in value.bytes() {
        if byte == b'.' {
            if count == 0 || dots > 0 {
                return false;
            }
            dots += 1;
            count = 0;
        } else if byte.is_ascii_digit() {
            count += 1;
        } else {
            return false;
        }
    }
    count > 0 && value.parse::<f64>().is_ok_and(|n| n > 0.0 && n <= 64.0)
}
pub fn parse(body: &str) -> (Knob, String) {
    let mut k = Knob {
        body: body.into(),
        ..Default::default()
    };
    k.shared_domain = get(body, "SHARED_DOMAIN").into();
    let mut bad = vec![];
    let value = get(body, "DOMAIN");
    if !value.is_empty() {
        k.domain = value.into();
    }
    for key in ["TTL_HOURS", "MAX_PREVIEWS"] {
        let value = get(body, key);
        if value.is_empty() {
            continue;
        }
        if let Ok(number) = value.parse::<i64>()
            && number > 0
        {
            if key == "TTL_HOURS" {
                k.ttl = number.wrapping_mul(3_600_000_000_000);
            } else {
                k.max = number;
            }
        } else {
            bad.push(format!("{key}={value}"));
        }
    }
    for key in ["MEM_LIMIT", "CPU_LIMIT"] {
        let value = get(body, key);
        if value.is_empty() {
            continue;
        }
        let valid = if key == "MEM_LIMIT" {
            memory_bytes(value).is_ok()
        } else {
            valid_cpu(value)
        };
        if valid {
            if key == "MEM_LIMIT" {
                k.mem_limit = value.into();
            } else {
                k.cpu_limit = value.into();
            }
        } else {
            bad.push(format!("{key}={value}"));
        }
    }
    for key in ["MEM_BUDGET", "PRODUCTION_RESERVE", "DB_MEM_LIMIT"] {
        let value = get(body, key);
        if value.is_empty() {
            continue;
        }
        match memory_bytes(value) {
            Ok(number) => match key {
                "MEM_BUDGET" => k.memory_budget = number,
                "PRODUCTION_RESERVE" => k.production_reserve = number,
                _ => k.database_reserve = number,
            },
            Err(_) => {
                k.invalid_budget = true;
                bad.push(format!("{key}={value}"));
            }
        }
    }
    let value = get(body, "ASK_PORT");
    if !value.is_empty() {
        if let Ok(number) = value.parse::<i64>()
            && (1..=65535).contains(&number)
        {
            k.ask_port = number;
        } else {
            bad.push(format!("ASK_PORT={value}"));
        }
    }
    let note = if bad.is_empty() {
        String::new()
    } else {
        format!(
            "invalid preview knob values (invalid MEM_BUDGET refuses up; other invalid limits use bounded defaults): {}",
            bad.join(", ")
        )
    };
    (k, note)
}
fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}
fn shared_label(value: &str) -> bool {
    let value = value.strip_suffix("-api").unwrap_or(value);
    let Some((app, pr)) = value.rsplit_once("-pr") else {
        return false;
    };
    valid_app(app) && digits(pr) && !pr.starts_with('0')
}
pub fn legacy_ask_allow(host: &str, domain: &str) -> bool {
    let host = host.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();
    let Some(label) = host.strip_suffix(&format!(".{domain}")) else {
        return false;
    };
    !domain.is_empty()
        && label
            .strip_prefix("pr-")
            .is_some_and(|pr| digits(pr.strip_suffix("-api").unwrap_or(pr)))
}
fn shared_ask_allow(host: &str, domain: &str) -> bool {
    let host = host.trim().to_lowercase();
    let domain = domain.trim().to_lowercase();
    !domain.is_empty()
        && host
            .strip_suffix(&format!(".{domain}"))
            .is_some_and(|label| label.len() <= 63 && shared_label(label))
}
impl Knob {
    pub fn path_domain_for(&self, app: &str) -> String {
        get(&self.body, &format!("PATH_DOMAIN.{app}")).into()
    }
    pub fn shared_domain_for(&self, app: &str) -> String {
        let domain = get(&self.body, &format!("SHARED_DOMAIN.{app}"));
        if domain.is_empty() {
            self.shared_domain.clone()
        } else {
            domain.into()
        }
    }
    pub fn legacy_domain_for(&self, app: &str) -> String {
        for key in [format!("DOMAIN.{app}"), "DOMAIN".into()] {
            let value = get(&self.body, &key);
            if !value.is_empty() {
                return value.into();
            }
        }
        self.domain.clone()
    }
    pub fn domain_for(&self, app: &str) -> String {
        for value in [
            self.path_domain_for(app),
            self.shared_domain_for(app),
            self.legacy_domain_for(app),
        ] {
            if !value.is_empty() {
                return value;
            }
        }
        String::new()
    }
    pub fn host_for(&self, app: &str, pr: i64) -> String {
        let domain = self.path_domain_for(app);
        if !domain.is_empty() {
            return format!("{app}.{domain}");
        }
        let shared = self.shared_domain_for(app);
        if !shared.is_empty() {
            return format!("{app}-pr{pr}.{shared}");
        }
        preview_host(pr, &self.domain_for(app))
    }
    pub fn api_host_for(&self, app: &str, pr: i64) -> String {
        let domain = self.path_domain_for(app);
        if !domain.is_empty() {
            return format!("{app}-api.{domain}");
        }
        let host = self.host_for(app, pr);
        let (label, domain) = host.split_once('.').unwrap_or((&host, ""));
        format!("{label}-api.{domain}")
    }
    pub fn domains(&self) -> Vec<String> {
        let mut output = vec![];
        let mut seen = BTreeSet::new();
        if !self.domain.is_empty() {
            output.push(self.domain.clone());
            seen.insert(self.domain.clone());
        }
        let mut rest = vec![];
        for line in self.body.split('\n') {
            let Some(tail) = line.strip_prefix("DOMAIN.") else {
                continue;
            };
            let Some((app, _)) = tail.split_once('=') else {
                continue;
            };
            if app.is_empty() {
                continue;
            }
            let domain = get(&self.body, &format!("DOMAIN.{app}"));
            if !domain.is_empty() && seen.insert(domain.into()) {
                rest.push(domain.into());
            }
        }
        rest.sort();
        output.extend(rest);
        output
    }
    pub fn validate_hosts(&self, app: &str, pr: i64) -> Result<()> {
        let domain = self.domain_for(app);
        ensure!(
            !domain.is_empty(),
            "preview requires an explicitly configured domain"
        );
        let host = self.api_host_for(app, pr);
        ensure!(
            host.len() <= 253 && domain.contains('.'),
            "preview domain does not produce a valid preview hostname"
        );
        let labels: Vec<_> = host.split('.').collect();
        let tld = labels.last().unwrap();
        ensure!(
            tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_lowercase()),
            "preview domain must have an alphabetic top-level domain"
        );
        for label in labels {
            ensure!(
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "preview domain or app name does not produce valid DNS labels"
            );
        }
        Ok(())
    }
    pub fn resolve(&self, app: &str, pr: i64, has_api: bool) -> Result<Target> {
        validate_args(app, pr)?;
        self.validate_hosts(app, pr)?;
        Ok(Target {
            app: app.into(),
            pr,
            domain: self.domain_for(app),
            host: self.host_for(app, pr),
            api_host: if has_api {
                self.api_host_for(app, pr)
            } else {
                String::new()
            },
            base_path: if self.path_domain_for(app).is_empty() {
                String::new()
            } else {
                format!("/{pr}")
            },
        })
    }
    pub fn shared_ask_allow(&self, host: &str) -> bool {
        if shared_ask_allow(host, &self.shared_domain) {
            return true;
        }
        for line in self.body.split('\n') {
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            let Some(app) = key.strip_prefix("SHARED_DOMAIN.") else {
                continue;
            };
            let domain = self.shared_domain_for(app);
            if !valid_app(app) || !shared_ask_allow(host, &domain) {
                continue;
            }
            let host = host.trim().to_lowercase();
            let suffix = format!(".{}", domain.to_lowercase());
            let label = host.strip_suffix(&suffix).unwrap_or(&host);
            if label
                .strip_prefix(&format!("{app}-pr"))
                .is_some_and(|pr| digits(pr.strip_suffix("-api").unwrap_or(pr)))
            {
                return true;
            }
        }
        false
    }
    pub fn path_ask_allow(&self, host: &str) -> bool {
        let host = host.trim().to_lowercase();
        for line in self.body.split('\n') {
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            let Some(app) = key.strip_prefix("PATH_DOMAIN.") else {
                continue;
            };
            if valid_app(app)
                && !self.path_domain_for(app).is_empty()
                && (host == self.host_for(app, 1) || host == self.api_host_for(app, 1))
            {
                return true;
            }
        }
        false
    }
    pub fn service_memory(&self, app: &str, service: &str) -> String {
        let mut keys = vec![];
        if !service.is_empty() {
            keys.push(format!("MEM_LIMIT.{app}.{service}"));
        }
        keys.push(format!("MEM_LIMIT.{app}"));
        for key in keys {
            let value = get(&self.body, &key);
            if !value.is_empty() {
                return value.into();
            }
        }
        self.mem_limit.clone()
    }
}
