use komizo::workload::resources::{self, ResourcePolicy, ServiceBudget};
use serde_json::{Value, json};
fn same_numbers(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|other| same_numbers(value, other))
                })
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| same_numbers(left, right))
        }
        _ => left == right,
    }
}
#[test]
fn memory_and_cpu_admission_match_the_frozen_go_requests() {
    let fixture: Value =
        serde_json::from_str(include_str!("data/go-resource-budgets.json")).unwrap();
    for case in fixture["memory"].as_array().unwrap() {
        let result = resources::memory_bytes(&case["input"]);
        let error = result
            .as_ref()
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert_eq!(
            error,
            case["error"].as_str().unwrap(),
            "memory {}",
            case["input"]
        );
        if let Ok(value) = result {
            assert_eq!(value, case["value"].as_i64().unwrap());
        }
    }
    for case in fixture["services"].as_array().unwrap() {
        let mut service = case["input"].as_object().unwrap().clone();
        let budget: ServiceBudget = serde_json::from_value(case["budget"].clone()).unwrap();
        let result = resources::bound_service(&mut service, &budget);
        let error = result
            .as_ref()
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert_eq!(
            error,
            case["error"].as_str().unwrap(),
            "service {}",
            case["input"]
        );
        if let Ok((memory, swap, cpu)) = result {
            assert_eq!(
                (memory, swap, cpu),
                (
                    case["memory"].as_i64().unwrap(),
                    case["swap"].as_i64().unwrap(),
                    case["cpu"].as_i64().unwrap()
                )
            );
        }
        assert!(
            same_numbers(&Value::Object(service), &case["after"]),
            "service {}",
            case["input"]
        );
    }
}
fn fixture_policy() -> ResourcePolicy {
    ResourcePolicy {
        default: ServiceBudget {
            memory_bytes: 256 << 20,
            memory_reserve_bytes: 32 << 20,
            memory_swap_bytes: 512 << 20,
            milli_cpus: 1000,
        },
        max_memory_bytes: 640 << 20,
        max_memory_reserve_bytes: 64 << 20,
        max_memory_swap_bytes: 1152 << 20,
        max_milli_cpus: 2000,
        startup_allowance_bytes: 128 << 20,
        ..Default::default()
    }
}
#[test]
fn operator_envelopes_bound_each_service_and_keep_startup_and_parent_reserves() {
    let mut policy = fixture_policy();
    policy.check().unwrap();
    let mut services = json!({"api":{"cpus":0.5},"database":{}})
        .as_object()
        .unwrap()
        .clone();
    resources::bound_services(&mut services, Some(&policy)).unwrap();
    assert_eq!(services["api"]["mem_limit"], 256 << 20);
    assert_eq!(services["api"]["mem_reservation"], 32 << 20);
    assert!(resources::bound_services(&mut services, None).is_err());
    policy.startup_allowance_bytes += 1;
    assert!(resources::bound_services(&mut services, Some(&policy)).is_err());
    policy = fixture_policy();
    policy.cgroup_parent = "/unrelated".into();
    assert!(policy.check().is_err());
    policy.cgroup_parent = "/komizo-production/fixture".into();
    policy.aggregate_mode = "cgroup".into();
    policy.check().unwrap();
    policy.max_memory_reserve_bytes = 0;
    assert!(policy.check().is_err());
    policy = fixture_policy();
    policy
        .services
        .insert("../escape".into(), policy.default.clone());
    assert!(policy.check().is_err());
}
