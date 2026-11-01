use komizo::workload::{compose, policy::Policy};
use serde_json::Value;
#[test]
fn frozen_go_compose_admission_keeps_refusals_and_exact_protected_configuration_bytes() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-workload-compose.json")).unwrap();
    assert!(cases.len() > 100);
    for case in cases {
        let policy: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
        let (output, error) = match compose::validate(
            case["input"].as_str().unwrap().as_bytes(),
            &policy,
            case["revision"].as_str().unwrap(),
        ) {
            Ok(bytes) => (String::from_utf8(bytes).unwrap(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        };
        assert_eq!(
            error,
            case["error"].as_str().unwrap(),
            "{} input {}",
            case["name"],
            case["input"]
        );
        assert_eq!(
            output,
            case["output"].as_str().unwrap(),
            "{} input {}",
            case["name"],
            case["input"]
        );
    }
}
