use komizo::workload::yaml;
use serde_json::Value;
fn equivalent(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) if a.is_f64() || b.is_f64() => {
            a.as_f64() == b.as_f64()
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| equivalent(a, b)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equivalent(a, b))
        }
        _ => a == b,
    }
}
#[test]
fn ninety_one_go_yaml_documents_preserve_scalars_precision_and_structural_refusals() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-workload-yaml.json")).unwrap();
    assert_eq!(cases.len(), 91);
    for case in cases {
        let (value, error) = match yaml::parse(case["input"].as_str().unwrap().as_bytes()) {
            Ok(value) => (value, String::new()),
            Err(e) => (Value::Null, e.to_string()),
        };
        assert_eq!(
            error,
            case["error"].as_str().unwrap(),
            "input {}",
            case["input"]
        );
        assert!(
            equivalent(&value, &case["expected"]),
            "input {} value {value} expected {}",
            case["input"],
            case["expected"]
        );
    }
}
