//! Existing first-party provisioning programs are embedded verbatim in native executables.
use anyhow::{Result, ensure};
use std::sync::OnceLock;
pub const PLATFORM: &str = include_str!("../scripts/platform.py");
pub const MAINTENANCE: &str = include_str!("../scripts/maintenance.py");
pub const MAINTENANCE_PREPARE: &str = include_str!("../scripts/maintenance_prepare.py");
pub const PLATFORM_PREPARE: &str = include_str!("../scripts/platform_prepare.py");
pub const PROXY_PREPARE: &str = include_str!("../scripts/proxy_prepare.py");
pub const CONTROLS_PREPARE: &str = include_str!("../scripts/controls_prepare.py");
pub const WORKLOAD_ACCEPTANCE: &str = include_str!("../scripts/workload_acceptance.py");
pub const ALPINE_REMOVE: &str = include_str!("../scripts/alpine-remove.sh");
pub const ALPINE_UNSET_SECRET: &str = include_str!("../scripts/alpine-unset-secret.sh");
pub const ALPINE_RELOAD_SSHD: &str = include_str!("../scripts/alpine-reload-sshd.sh");
pub const ALPINE_INIT: &str = include_str!("../scripts/alpine-init.sh");
pub const PREVIEW_DATABASE: &str = include_str!("../scripts/preview_database.py");
pub const COMPRESSED_SWAP: &str = include_str!("../scripts/compressed_swap.py");
pub const ALPINE_PROXY: &str = include_str!("../scripts/alpine-proxy.sh");
pub const AGENT_INSTALL: &str = include_str!("../scripts/agent-install.sh");
pub const STAGED_AGENT: &str = "/tmp/.komizo-box.staged";
pub const AGENT_INTERVAL: &str = "60s";
pub fn agent_install(stamp: &str, version: &str) -> Result<String> {
    use crate::host::paths::*;
    render(
        AGENT_INSTALL,
        &[
            ("__STAGED__", STAGED_AGENT),
            ("__INTERVAL__", AGENT_INTERVAL),
            ("__STATE_DIR__", STATE_DIR),
            ("__PENDING_DIR__", PENDING_DIR),
            ("__RUN_DIR__", RUN_DIR),
            ("__API_SOCKET_DIR__", API_SOCKET_DIR),
            ("__ETC_DIR__", "/etc/komizo"),
            ("__SERVED_DIR__", SERVED_DIR),
            ("__INBOX_DIR__", crate::host::inbox::INBOX_DIR),
            ("__RESULTS_DIR__", RESULTS_DIR),
            ("__REPORT_PATH__", REPORT_PATH),
            ("__HISTORY_PATH__", HISTORY_PATH),
            ("__STAMP__", &sh_quote(stamp)),
            ("__VERSION__", &sh_quote(version)),
        ],
    )
}
pub fn alpine() -> &'static str {
    static SCRIPT: OnceLock<String> = OnceLock::new();
    SCRIPT.get_or_init(|| {
        let raw = include_str!("../scripts/alpine.sh");
        let run = include_str!("../scripts/preview-run.sh");
        let stack = include_str!("../scripts/preview-stackenv.sh");
        for (marker, body) in [
            ("# __PREVIEW_RUN_BODY__\n", run),
            ("# __PREVIEW_STACKENV_BODY__\n", stack),
        ] {
            assert_eq!(
                raw.matches(marker).count(),
                1,
                "reviewed provisioning marker"
            );
            assert!(
                body.starts_with("#!/bin/sh\n"),
                "reviewed provisioning helper"
            );
        }
        raw.replacen("# __PREVIEW_RUN_BODY__\n", run, 1).replacen(
            "# __PREVIEW_STACKENV_BODY__\n",
            stack,
            1,
        )
    })
}
pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn render(script: &str, substitutions: &[(&str, &str)]) -> Result<String> {
    static PLACEHOLDER: OnceLock<regex::Regex> = OnceLock::new();
    let regex = PLACEHOLDER.get_or_init(|| regex::Regex::new(r"__[A-Z][A-Z0-9_]*__").unwrap());
    for marker in regex.find_iter(script) {
        ensure!(
            substitutions.iter().any(|(key, _)| *key == marker.as_str()),
            "scripts.render: {} was never substituted -- this is a komizo bug",
            marker.as_str()
        );
    }
    // One pass is required: replacement bytes may themselves resemble a placeholder.
    let mut output = String::new();
    let mut position = 0;
    while position < script.len() {
        if let Some((key, value)) = substitutions
            .iter()
            .find(|(key, _)| !key.is_empty() && script[position..].starts_with(key))
        {
            output.push_str(value);
            position += key.len();
        } else {
            let ch = script[position..].chars().next().unwrap();
            output.push(ch);
            position += ch.len_utf8();
        }
    }
    Ok(output)
}
