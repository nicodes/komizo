use komizo::flags::{self, Flag, Flags, Value};
use serde_json::{Value as Json, json};
#[test]
fn existing_go_flag_scalar_and_positional_semantics_are_preserved() {
    let cases: Vec<Json> = serde_json::from_str(include_str!("data/go-flags.json")).unwrap();
    assert!(cases.len() > 700);
    for (index, case) in cases.iter().enumerate() {
        let kind = case["kind"].as_str().unwrap();
        let accepted = case["ok"].as_bool().unwrap();
        match kind {
            "integer" | "duration" => {
                let text = case["input"].as_str().unwrap();
                let result = if kind == "integer" {
                    flags::integer(text)
                } else {
                    flags::duration(text)
                };
                assert_eq!(
                    result.is_ok(),
                    accepted,
                    "case {index} {kind} {text:?}: {result:?}"
                );
                if let Ok(value) = result {
                    assert_eq!(value, case["value"], "case {index} {kind} {text:?}")
                }
            }
            "flags" => {
                let args: Vec<String> = serde_json::from_value(case["args"].clone()).unwrap();
                let result = Flags::parse(
                    &[
                        Flag::text("name", "fallback"),
                        Flag::boolean("enabled", false),
                        Flag::integer("count", 7),
                        Flag::duration("duration", 3_000_000_000),
                    ],
                    &args,
                );
                assert_eq!(
                    result.is_ok(),
                    accepted,
                    "case {index} {args:?}: {result:?}"
                );
                match result {
                    Ok(flags) => {
                        let nanos = match flags.values["duration"] {
                            Value::Duration(value) => value,
                            _ => panic!("type"),
                        };
                        assert_eq!(
                            json!({"name":flags.text("name"),"enabled":flags.boolean("enabled"),"count":flags.integer("count"),"duration":nanos,"args":flags.args}),
                            case["value"],
                            "case {index}"
                        )
                    }
                    Err(error) => {
                        assert_eq!(error.is::<flags::Help>(), case["help"], "case {index}")
                    }
                }
            }
            _ => panic!("unknown fixture"),
        }
    }
}
