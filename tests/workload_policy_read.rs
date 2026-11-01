use komizo::workload::policy_read::read_policy;
use serde_json::Value;

#[test]
fn protected_policy_reader_matches_go_documents_and_refusals() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-workload-policy-read.json")).unwrap();
    assert_eq!(cases.len(), 32);
    for (index, case) in cases.into_iter().enumerate() {
        let (output, error) = match read_policy(case["input"].as_str().unwrap().as_bytes()) {
            Ok(policy) => (serde_json::to_value(policy).unwrap(), String::new()),
            Err(error) => (Value::Null, error.to_string()),
        };
        assert_eq!(error, case["error"].as_str().unwrap(), "case {index}");
        assert_eq!(output, case["output"], "case {index}");
    }
}
