use komizo::host::{
    PreviewHostResources,
    preview::{
        capacity,
        knob::{Knob, KnobValues},
    },
};
use serde_json::Value;
#[test]
fn frozen_go_preview_capacity_preserves_production_reserves_floor_decisions_and_freshness() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-preview-capacity.json")).unwrap();
    assert_eq!(cases.len(), 79);
    for (index, case) in cases.into_iter().enumerate() {
        let err = |r: anyhow::Result<()>| r.err().map(|e| e.to_string()).unwrap_or_default();
        match case["kind"].as_str().unwrap() {
            "parse-floors" => {
                let (floors, present, error) =
                    match capacity::parse_floors(case["body"].as_str().unwrap()) {
                        Ok((floors, present)) => (floors, present, String::new()),
                        Err(e) => (Default::default(), false, e.to_string()),
                    };
                assert_eq!(error, case["error"], "case {index}");
                assert_eq!(
                    serde_json::to_value(floors).unwrap(),
                    case["output"],
                    "case {index}"
                );
                assert_eq!(present, case["present"].as_bool().unwrap(), "case {index}");
            }
            "floors" => {
                let floors = serde_json::from_value(case["floors"].clone()).unwrap();
                let (refuse, warns, error) = match capacity::check_floors(
                    &floors,
                    case["present"].as_bool().unwrap(),
                    case["body"].as_str().unwrap().as_bytes(),
                ) {
                    Ok(v) => (
                        v.refuse,
                        serde_json::to_value(v.warns).unwrap(),
                        String::new(),
                    ),
                    Err(e) => (String::new(), Value::Null, e.to_string()),
                };
                assert_eq!(error, case["error"], "case {index}");
                assert_eq!(refuse, case["refuse"], "case {index}");
                assert_eq!(warns, case["warns"], "case {index}");
            }
            "envelope" => {
                let values: KnobValues = serde_json::from_value(case["knob"].clone()).unwrap();
                let mut k = Knob {
                    values,
                    ..Default::default()
                };
                let resources: PreviewHostResources =
                    serde_json::from_value(case["resources"].clone()).unwrap();
                assert_eq!(
                    err(k.protect_envelope(Some(&resources))),
                    case["error"],
                    "case {index}"
                );
                assert_eq!(
                    serde_json::to_value(&k).unwrap(),
                    case["output"],
                    "case {index}"
                );
                assert_eq!(k.cgroup_parent, case["cgroup_parent"], "case {index}");
            }
            "reserve" => {
                let k = Knob {
                    values: serde_json::from_value(case["knob"].clone()).unwrap(),
                    ..Default::default()
                };
                assert_eq!(
                    err(k.production_reserve(case["body"].as_str().unwrap().as_bytes())),
                    case["error"],
                    "case {index}"
                );
            }
            "fresh" => assert_eq!(
                err(capacity::report_fresh(
                    case["body"].as_str().unwrap().as_bytes(),
                    case["now"].as_str().unwrap().parse().unwrap()
                )),
                case["error"],
                "case {index}"
            ),
            _ => panic!("unknown case"),
        }
    }
}
