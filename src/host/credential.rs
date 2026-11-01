use super::{AgentConf, authority::quote, store};
use anyhow::{Context, Result, anyhow, ensure};
use std::path::Path;
pub const AGENT_USER: &str = "komizo_monitor";
pub const AGENT_CONF_PATH: &str = "/etc/komizo/agent.json";
pub const DEFAULT_API: &str = "https://api.komizo.dev";
impl AgentConf {
    pub fn can_serve(&self) -> bool {
        !self.registry_key.is_empty() && !self.server_id.is_empty()
    }
    pub fn enrolled(&self) -> bool {
        !self.api.is_empty() && !self.token.expose().is_empty()
    }
    pub fn report_url(&self) -> String {
        self.api.clone() + "/v1/report"
    }
    pub fn enrol_url(&self) -> String {
        self.api.clone() + "/v1/enrol"
    }
}
pub fn read_agent_conf(path: &Path) -> Result<AgentConf> {
    let Some(bytes) = crate::statefile::read(path, 1 << 20)? else {
        return Ok(AgentConf::default());
    };
    let mut conf: AgentConf = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not readable as an agent config", path.display()))?;
    conf.api = conf.api.trim_end_matches('/').into();
    Ok(conf)
}
pub fn write_agent_conf(path: &Path, configuration: &AgentConf) -> Result<()> {
    let mut bytes = serde_json::to_string_pretty(configuration)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
        .into_bytes();
    bytes.push(b'\n');
    store::write_atomic(path, &mut bytes.as_slice(), 0o640, store::agent_group()?)
}
pub fn validate_api(raw: &str) -> Result<String> {
    ensure!(
        raw.contains("://"),
        "{} has no host -- it should look like https://api.komizo.dev",
        quote(raw)
    );
    let url = reqwest::Url::parse(raw).map_err(|e| {
        if !raw.contains("://") {
            anyhow!(
                "{} has no host -- it should look like https://api.komizo.dev",
                quote(raw)
            )
        } else {
            anyhow!("{} is not a URL: {e}", quote(raw))
        }
    })?;
    ensure!(
        url.host_str().is_some(),
        "{} has no host -- it should look like https://api.komizo.dev",
        quote(raw)
    );
    let scheme = raw.split(':').next().unwrap_or_default();
    let authority = raw
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = if host.starts_with('[') {
        host.strip_prefix('[')
            .and_then(|h| h.split_once(']'))
            .map(|(h, _)| h)
            .unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    match scheme {
        "https" => {}
        "http" => ensure!(
            loopback,
            "{} is not https -- the agent's token is a bearer credential and will not be sent in the clear",
            quote(raw)
        ),
        _ => anyhow::bail!("{} is not an http(s) URL", quote(raw)),
    }
    Ok(url.as_str().trim_end_matches('/').into())
}

pub fn is_ip_address(host: &str) -> bool {
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok()
}
pub fn validate_api_host(host: &str) -> Result<()> {
    ensure!(!host.is_empty(), "an endpoint cannot be empty");
    ensure!(
        !is_ip_address(host),
        "{} is an IP address; use a public DNS name or leave the endpoint unset",
        quote(host)
    );
    ensure!(
        host.trim_matches('.').contains('.'),
        "{} is not a fully qualified name, so no certificate authority will issue for it",
        quote(host)
    );
    ensure!(
        !host.starts_with('-')
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        "{} is not a hostname",
        quote(host)
    );
    Ok(())
}
pub fn api_host_for(ssh_host: &str, override_host: &str) -> Result<String> {
    if !override_host.is_empty() {
        validate_api_host(override_host)?;
        return Ok(override_host.into());
    }
    if validate_api_host(ssh_host).is_ok() {
        Ok(ssh_host.into())
    } else {
        Ok(String::new())
    }
}
