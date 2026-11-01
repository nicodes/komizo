use komizo::workload::{policy::Policy, release::ReleaseAcceptance, release_bind};
use serde_json::Value;
#[test]
fn go_image_binding_preserves_exact_docker_operations_and_refusals() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-release-bind.json")).unwrap();
    assert_eq!(cases.len(), 52);
    for (index, case) in cases.into_iter().enumerate() {
        let policy: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
        let accepted: ReleaseAcceptance = serde_json::from_value(case["accepted"].clone()).unwrap();
        let mut calls: Vec<Vec<String>> = vec![];
        let mut run = |args: &[&str]| {
            let position = calls.len();
            calls.push(args.iter().map(|s| s.to_string()).collect());
            assert_eq!(
                serde_json::to_value(args).unwrap(),
                case["calls"][position],
                "case {index} call {position}"
            );
            let response = &case["responses"][position];
            let error = response["error"].as_str().unwrap();
            if error.is_empty() {
                Ok(response["output"].as_str().unwrap().to_string())
            } else {
                Err(anyhow::anyhow!("{error}"))
            }
        };
        let input = case["compose"].as_str().unwrap().as_bytes();
        let result = if case["kind"] == "refs" {
            release_bind::json_image_references(input)
                .map(|refs| serde_json::to_vec(&refs).unwrap())
        } else {
            release_bind::bind_release(
                &mut run,
                &policy,
                &accepted,
                case["revision"].as_str().unwrap(),
                case["config"].as_str().unwrap(),
                input,
                case["pull"].as_bool().unwrap(),
            )
        };
        let (output, error) = match result {
            Ok(bytes) => (String::from_utf8(bytes).unwrap(), String::new()),
            Err(e) => (String::new(), e.to_string()),
        };
        assert_eq!(error, case["error"], "case {index} {}", case["name"]);
        assert_eq!(output, case["output"], "case {index} {}", case["name"]);
        let expected = case["calls"].as_array().map_or(0, Vec::len);
        assert_eq!(calls.len(), expected, "case {index} {}", case["name"]);
    }
}
