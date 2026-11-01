use komizo::workload::policy::*;
use serde::de::DeserializeOwned;
use serde_json::Value;
fn checked<T: DeserializeOwned>(
    value: &Value,
    check: impl FnOnce(T) -> anyhow::Result<()>,
) -> String {
    check(serde_json::from_value(value.clone()).unwrap())
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default()
}
#[test]
fn one_hundred_ninety_eight_go_host_policy_and_static_profile_checks_remain_identical() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-workload-policy.json")).unwrap();
    assert_eq!(cases.len(), 198);
    for case in cases {
        let input = &case["input"];
        let result = match case["kind"].as_str().unwrap() {
            "policy" => checked::<Policy>(input, |p| p.check()),
            "readiness" => checked::<ReadinessPolicy>(input, |p| p.check()),
            "static_limits" => checked::<StaticLimits>(input, |p| p.bounds().map(|_| ())),
            "backup" => checked::<BackupPolicy>(input, |p| p.check()),
            "deployment" => checked::<DeploymentPolicy>(input, |p| p.check("fixture")),
            "stage" => checked::<DeploymentStage>(input, |p| p.check()),
            "static_options" => checked::<StaticServingOptions>(input, |p| p.check()),
            "static_policy" => checked::<StaticPolicy>(input, |p| p.check()),
            kind => panic!("unknown {kind}"),
        };
        assert_eq!(
            result,
            case["error"].as_str().unwrap(),
            "{} {input}",
            case["kind"]
        );
    }
}
