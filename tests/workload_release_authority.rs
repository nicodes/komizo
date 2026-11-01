use komizo::workload::{
    backup,
    delivery::DeliveryAuthorization,
    policy::Policy,
    release::{self, RsaKey},
    stateful::StatefulContract,
};
use serde_json::Value;
fn error(result: anyhow::Result<()>) -> String {
    result.err().map(|e| e.to_string()).unwrap_or_default()
}
#[test]
fn signed_go_proofs_retain_authority_scope_and_exact_evidence() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/go-release-authority.json")).unwrap();
    let decode = komizo::host::authority::keys::decode;
    let public = RsaKey {
        n: decode(fixture["n"].as_str().unwrap()).unwrap(),
        e: decode(fixture["e"].as_str().unwrap()).unwrap(),
    };
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 150);
    for (index, case) in cases.iter().enumerate() {
        let kind = case["kind"].as_str().unwrap();
        let revision = case["revision"].as_str().unwrap();
        if kind == "stateful" {
            let contract: StatefulContract =
                serde_json::from_value(case["contract"].clone()).unwrap();
            let current: StatefulContract =
                serde_json::from_value(case["current"].clone()).unwrap();
            assert_eq!(
                error(contract.check(revision)),
                case["error"],
                "case {index}"
            );
            let (hash, hash_error) = match contract.sha256() {
                Ok(hash) => (hash, String::new()),
                Err(e) => (String::new(), e.to_string()),
            };
            assert_eq!(hash, case["hash"], "case {index}");
            assert_eq!(hash_error, case["hash_error"], "case {index}");
            assert_eq!(
                error(
                    contract
                        .supports_post_write_state(&current, case["observed"].as_i64().unwrap())
                ),
                case["compat_error"],
                "case {index}"
            );
            continue;
        }
        let policy: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
        let now = case["now"].as_str().unwrap().parse().unwrap();
        if kind == "delivery" {
            let authorization: DeliveryAuthorization =
                serde_json::from_value(case["authorization"].clone()).unwrap();
            assert_eq!(
                error(authorization.check(&policy, revision, now)),
                case["error"],
                "case {index}"
            );
            continue;
        }
        let mut calls = 0;
        let mut key = |_: &str| {
            calls += 1;
            Ok(public.clone())
        };
        let body = case["body"].as_str().unwrap().as_bytes();
        let result = match kind {
            "release" => release::verify_release(body, &policy, revision, now, &mut key)
                .map(|v| serde_json::to_value(v).unwrap()),
            "backup" => backup::verify_backup(body, &policy, revision, now, &mut key)
                .map(|v| serde_json::to_value(v).unwrap()),
            "owner" => release::approve_owner_release(body, &policy, revision, now)
                .map(|v| serde_json::to_value(v).unwrap()),
            _ => panic!("unknown case"),
        };
        let (output, err) = match result {
            Ok(v) => (v, String::new()),
            Err(e) => (Value::Null, e.to_string()),
        };
        assert_eq!(
            err, case["error"],
            "case {index} {} {}",
            case["name"], case["body"]
        );
        assert_eq!(output, case["output"], "case {index} {}", case["name"]);
        assert_eq!(
            calls,
            case["key_calls"].as_u64().unwrap(),
            "case {index} {}",
            case["name"]
        );
    }
}
