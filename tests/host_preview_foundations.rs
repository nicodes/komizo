use komizo::host::{preview::knob, scoped};
use serde_json::Value;
#[test]
fn frozen_go_preview_names_knobs_scoped_metadata_and_templates_match() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-preview-foundations.json")).unwrap();
    assert_eq!(cases.len(), 98);
    for (index, case) in cases.into_iter().enumerate() {
        let error = |e: anyhow::Error| e.to_string();
        match case["kind"].as_str().unwrap() {
            "scoped" => {
                let input = case["input"].as_array().unwrap();
                let result = scoped::parse_definition(
                    input[0].as_str().unwrap(),
                    input[1].as_str().unwrap(),
                    input[2].as_str().unwrap(),
                );
                let (output, marker, err) = match result {
                    Ok(value) => {
                        let marker = value
                            .as_ref()
                            .map(|v| {
                                String::from_utf8(v.marker("00112233445566778899aabbccddeeff"))
                                    .unwrap()
                            })
                            .unwrap_or_default();
                        (serde_json::to_value(value).unwrap(), marker, String::new())
                    }
                    Err(e) => (Value::Null, String::new(), error(e)),
                };
                assert_eq!(output, case["output"], "case {index}");
                assert_eq!(marker, case["marker"], "case {index}");
                assert_eq!(err, case["error"], "case {index}");
            }
            "limits" => {
                let value = case["value"].as_str().unwrap();
                let (number, err) = match knob::memory_bytes(value) {
                    Ok(n) => (n, String::new()),
                    Err(e) => (0, error(e)),
                };
                assert_eq!(number, case["memory"].as_i64().unwrap(), "case {index}");
                assert_eq!(err, case["error"], "case {index}");
                assert_eq!(
                    knob::valid_cpu(value),
                    case["cpu"].as_bool().unwrap(),
                    "case {index}"
                );
            }
            "knob" => {
                let (k, note) = knob::parse(case["body"].as_str().unwrap());
                assert_eq!(
                    serde_json::to_value(&k).unwrap(),
                    case["knob"],
                    "case {index}"
                );
                assert_eq!(note, case["note"], "case {index}");
                let domains: Vec<String> =
                    serde_json::from_value(case["domains"].clone()).unwrap_or_default();
                assert_eq!(k.domains(), domains, "case {index}");
                assert_eq!(
                    k.service_memory("example", ""),
                    case["memory_default"],
                    "case {index}"
                );
                assert_eq!(
                    k.service_memory("example", "runtime"),
                    case["memory_runtime"],
                    "case {index}"
                );
                for target in case["targets"].as_array().unwrap() {
                    let app = target["app"].as_str().unwrap();
                    let pr = target["pr"].as_i64().unwrap();
                    let (result, err) = match k.resolve(app, pr, target["api"].as_bool().unwrap()) {
                        Ok(v) => (v, String::new()),
                        Err(e) => (Default::default(), error(e)),
                    };
                    assert_eq!(
                        serde_json::to_value(result).unwrap(),
                        target["output"],
                        "case {index} {target}"
                    );
                    assert_eq!(err, target["error"], "case {index} {target}");
                    assert_eq!(k.domain_for(app), target["domain"]);
                    assert_eq!(k.host_for(app, pr), target["host"]);
                    assert_eq!(k.api_host_for(app, pr), target["api_host"]);
                }
                for request in case["asks"].as_array().unwrap() {
                    let host = request["host"].as_str().unwrap();
                    assert_eq!(
                        knob::legacy_ask_allow(host, &k.domain),
                        request["legacy"].as_bool().unwrap(),
                        "case {index} {host}"
                    );
                    assert_eq!(
                        k.shared_ask_allow(host),
                        request["shared"].as_bool().unwrap(),
                        "case {index} {host}"
                    );
                    assert_eq!(
                        k.path_ask_allow(host),
                        request["path"].as_bool().unwrap(),
                        "case {index} {host}"
                    );
                }
            }
            "template" => {
                let result = komizo::template::render(
                    "preview",
                    case["body"].as_str().unwrap(),
                    &case["values"],
                    1 << 20,
                );
                assert_eq!(
                    result.is_err(),
                    case["refused"].as_bool().unwrap(),
                    "case {index} {}: {result:?}",
                    case["body"]
                );
                if let Ok(output) = result {
                    assert_eq!(output, case["output"], "case {index} {}", case["body"]);
                }
            }
            _ => panic!("unknown fixture"),
        }
    }
}
#[test]
fn template_errors_and_output_bounds_never_include_credential_context() {
    let values = serde_json::json!({"Credentials":{"seed":"NEVER_ECHO_SYNTHETIC_CONTEXT"}});
    for body in [
        "{{.Missing}}",
        "{{.Credentials.Absent}}",
        "{{range .Credentials}}{{.}}{{end}}",
    ] {
        let error = komizo::template::render("preview", body, &values, 8)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("NEVER_ECHO_SYNTHETIC_CONTEXT"));
    }
}
