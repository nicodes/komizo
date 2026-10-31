use std::collections::BTreeMap;
pub struct Policy {
    values: BTreeMap<String, String>,
}
impl Policy {
    pub fn parse(body: &str) -> Self {
        let mut values = BTreeMap::new();
        for line in body.lines() {
            if let Some((key, value)) = line.split_once('=') {
                values
                    .entry(key.into())
                    .or_insert_with(|| value.trim_matches(['\r', ' ', '\t']).to_owned());
            }
        }
        Self { values }
    }
    fn value(&self, key: &str) -> &str {
        self.values.get(key).map_or("", String::as_str)
    }
    pub fn port(&self) -> u16 {
        self.value("ASK_PORT")
            .parse::<u16>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(8487)
    }
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim().to_lowercase();
        if legacy(&host, self.value("DOMAIN")) || shared(&host, self.value("SHARED_DOMAIN")) {
            return true;
        }
        for key in self.values.keys() {
            if let Some(app) = key.strip_prefix("DOMAIN.")
                && !app.is_empty()
                && legacy(&host, self.value(key))
            {
                return true;
            }
            if let Some(app) = key.strip_prefix("SHARED_DOMAIN.")
                && app_name(app)
                && shared(&host, self.value(key))
            {
                let suffix = format!(".{}", self.value(key).to_lowercase());
                if let Some(label) = host.strip_suffix(&suffix)
                    && let Some(number) = label.strip_prefix(&format!("{app}-pr"))
                    && digits(number.strip_suffix("-api").unwrap_or(number), false)
                {
                    return true;
                }
            }
            if let Some(app) = key.strip_prefix("PATH_DOMAIN.")
                && app_name(app)
                && !self.value(key).is_empty()
            {
                let domain = self.value(key);
                if host == format!("{app}.{domain}") || host == format!("{app}-api.{domain}") {
                    return true;
                }
            }
        }
        false
    }
}
fn app_name(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn digits(value: &str, positive: bool) -> bool {
    !value.is_empty()
        && (!positive || value.as_bytes()[0] != b'0')
        && value.bytes().all(|b| b.is_ascii_digit())
}
fn legacy(host: &str, domain: &str) -> bool {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return false;
    }
    host.strip_suffix(&format!(".{domain}"))
        .and_then(|s| s.strip_prefix("pr-"))
        .is_some_and(|n| digits(n.strip_suffix("-api").unwrap_or(n), false))
}
fn shared(host: &str, domain: &str) -> bool {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return false;
    }
    let Some(label) = host.strip_suffix(&format!(".{domain}")) else {
        return false;
    };
    if label.len() > 63 {
        return false;
    }
    let label = label.strip_suffix("-api").unwrap_or(label);
    let Some((app, number)) = label.rsplit_once("-pr") else {
        return false;
    };
    app_name(app) && digits(number, true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn certificate_authority_is_exactly_the_configured_preview_namespace() {
        let p = Policy::parse(
            "DOMAIN=preview.example\nSHARED_DOMAIN.canary=shared.example\nPATH_DOMAIN.docs=path.example\nDOMAIN.other=other.example\n",
        );
        for host in [
            "pr-1.preview.example",
            "pr-01-api.preview.example",
            "pr-2.other.example",
            "canary-pr1.shared.example",
            "canary-pr1-api.shared.example",
            "docs.path.example",
            "docs-api.path.example",
        ] {
            assert!(p.allows(host), "{host}");
        }
        for host in [
            "preview.example",
            "evil.pr-1.preview.example",
            "other-pr1.shared.example",
            "canary-pr0.shared.example",
            "other.path.example",
            "docs.evil.example",
            "pr-1.preview.example.evil",
        ] {
            assert!(!p.allows(host), "{host}");
        }
    }
}
