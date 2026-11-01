use komizo::scripts::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[test]
fn native_embeddings_match_go_provisioning_bytes_quotes_and_single_pass_substitutions() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/go-embedded-scripts.json")).unwrap();
    let installed = agent_install("fixture__ABC__'stamp", "v1.2.3").unwrap();
    for (name, body) in [
        ("platform", PLATFORM),
        ("maintenance", MAINTENANCE),
        ("maintenance_prepare", MAINTENANCE_PREPARE),
        ("platform_prepare", PLATFORM_PREPARE),
        ("proxy_prepare", PROXY_PREPARE),
        ("controls_prepare", CONTROLS_PREPARE),
        ("workload_acceptance", WORKLOAD_ACCEPTANCE),
        ("alpine", alpine()),
        ("alpine_remove", ALPINE_REMOVE),
        ("alpine_unset_secret", ALPINE_UNSET_SECRET),
        ("alpine_reload_sshd", ALPINE_RELOAD_SSHD),
        ("alpine_init", ALPINE_INIT),
        ("preview_database", PREVIEW_DATABASE),
        ("compressed_swap", COMPRESSED_SWAP),
        ("alpine_proxy", ALPINE_PROXY),
        ("agent_install", AGENT_INSTALL),
        ("agent_install_rendered", installed.as_str()),
    ] {
        assert_eq!(
            format!("{:x}", Sha256::digest(body.as_bytes())),
            fixture["hashes"][name],
            "{name}"
        );
    }
    for case in fixture["quotes"].as_array().unwrap() {
        assert_eq!(sh_quote(case["input"].as_str().unwrap()), case["output"]);
    }
    for case in fixture["renders"].as_array().unwrap() {
        let values = case["substitutions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let values: Vec<_> = values
            .chunks_exact(2)
            .map(|pair| (pair[0].as_str().unwrap(), pair[1].as_str().unwrap()))
            .collect();
        assert_eq!(
            render(case["input"].as_str().unwrap(), &values).unwrap(),
            case["output"]
        );
    }
    assert!(render("missing __PLACEHOLDER__", &[("__OTHER__", "value")]).is_err());
}
