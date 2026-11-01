use komizo::host::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
fn equivalent(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) if left.is_f64() || right.is_f64() => {
            left.as_f64() == right.as_f64()
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right.get(key).is_some_and(|other| equivalent(value, other))
                })
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| equivalent(left, right))
        }
        _ => left == right,
    }
}
fn check<T: DeserializeOwned + Serialize + Default>(name: &str, fixture: &Value) {
    let zero = serde_json::to_value(T::default()).unwrap();
    assert!(
        equivalent(&zero, &fixture[name]["zero"]),
        "zero {name}: {zero}"
    );
    for variant in ["zero", "filled"] {
        let expected = &fixture[name][variant];
        let value: T = serde_json::from_value(expected.clone()).unwrap();
        let actual = serde_json::to_value(value).unwrap();
        assert!(equivalent(&actual, expected), "{name}/{variant}: {actual}");
    }
}
#[test]
fn all_forty_five_frozen_host_models_keep_their_v1_names_defaults_nulls_and_units() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/go-host-wire-models.json")).unwrap();
    check::<Report>("Report", &fixture);
    check::<Observation>("Observation", &fixture);
    check::<Server>("Server", &fixture);
    check::<KomizoInstall>("KomizoInstall", &fixture);
    check::<HostKey>("HostKey", &fixture);
    check::<App>("App", &fixture);
    check::<Container>("Container", &fixture);
    check::<Host>("Host", &fixture);
    check::<Proxy>("Proxy", &fixture);
    check::<Network>("Network", &fixture);
    check::<NetworkMember>("NetworkMember", &fixture);
    check::<Problem>("Problem", &fixture);
    check::<Deployment>("Deployment", &fixture);
    check::<System>("System", &fixture);
    check::<Cpu>("CPU", &fixture);
    check::<Mem>("Mem", &fixture);
    check::<Swap>("Swap", &fixture);
    check::<Disk>("Disk", &fixture);
    check::<Inodes>("Inodes", &fixture);
    check::<ContainerStat>("ContainerStat", &fixture);
    check::<GroupStat>("GroupStat", &fixture);
    check::<Pressure>("Pressure", &fixture);
    check::<PressureResource>("PressureResource", &fixture);
    check::<PressureLine>("PressureLine", &fixture);
    check::<Volume>("Volume", &fixture);
    check::<Sample>("Sample", &fixture);
    check::<Metrics>("Metrics", &fixture);
    check::<Span>("Span", &fixture);
    check::<Metric>("Metric", &fixture);
    check::<MetricsResponse>("MetricsResponse", &fixture);
    check::<ReportResponse>("ReportResponse", &fixture);
    check::<HistoryResponse>("HistoryResponse", &fixture);
    check::<Poll>("Poll", &fixture);
    check::<Monitor>("Monitor", &fixture);
    check::<LogLine>("LogLine", &fixture);
    check::<Result>("Result", &fixture);
    check::<LogsResponse>("LogsResponse", &fixture);
    check::<StaticServing>("StaticServing", &fixture);
    check::<PreviewProfile>("PreviewProfile", &fixture);
    check::<PreviewEnvironmentRule>("PreviewEnvironmentRule", &fixture);
    check::<PreviewHostResources>("PreviewHostResources", &fixture);
    check::<ScopedDefinition>("ScopedDefinition", &fixture);
    check::<AgentConf>("AgentConf", &fixture);
    check::<PreviewReap>("PreviewReap", &fixture);
    check::<SweepRecord>("SweepRecord", &fixture);
}
#[test]
fn observations_distinguish_unknown_counters_from_measured_zero_and_accept_additive_fields() {
    let unknown: ContainerStat =
        serde_json::from_value(json!({"app":"fixture","service":"api","future_field":true}))
            .unwrap();
    assert!(unknown.cpu_usec.is_none());
    let measured:ContainerStat=serde_json::from_value(json!({"app":"fixture","service":"api","cpu_usec":0,"memory_current":18446744073709551615_u64})).unwrap();
    assert_eq!(measured.cpu_usec, Some(0));
    assert_eq!(measured.memory_current, Some(u64::MAX));
    let value = serde_json::to_value(measured).unwrap();
    assert_eq!(value["cpu_usec"], 0);
    assert_eq!(value["memory_current"].as_u64(), Some(u64::MAX));
}
#[test]
fn enrolled_report_credentials_are_redacted_from_debug_output() {
    let configuration:AgentConf=serde_json::from_value(json!({"token":"fixture-never-log-this","api":"https://fixture.invalid","server_id":"fixture"})).unwrap();
    assert!(!format!("{configuration:?}").contains("fixture-never-log-this"));
    assert_eq!(configuration.token.expose(), "fixture-never-log-this");
}
