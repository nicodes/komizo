use base64::{Engine as _, engine::general_purpose::STANDARD};
use komizo::workload::{
    archive,
    policy::{StaticLimits, StaticServingOptions},
    routes, static_tree,
};
use serde_json::Value;
use std::{os::unix::fs::PermissionsExt, time::SystemTime};
#[test]
fn go_archives_and_routes_preserve_bounds_private_extraction_and_exact_serving_bytes() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-archive-routes.json")).unwrap();
    assert_eq!(cases.len(), 97);
    for (index, case) in cases.into_iter().enumerate() {
        let kind = case["kind"].as_str().unwrap();
        let error = |e: anyhow::Error| e.to_string();
        let result: anyhow::Result<Value> = match kind {
            "route" => {
                let result = routes::deployment_route(
                    case["app"].as_str().unwrap(),
                    case["revision"].as_str().unwrap(),
                    case["hosts"].as_str().unwrap().as_bytes(),
                    case["allow_wildcard"].as_bool().unwrap(),
                );
                let (body, metadata, names, err) = match result {
                    Ok((body, metadata, names)) => (
                        String::from_utf8(body).unwrap(),
                        String::from_utf8(metadata).unwrap(),
                        serde_json::to_value(names).unwrap(),
                        String::new(),
                    ),
                    Err(e) => (String::new(), String::new(), Value::Null, error(e)),
                };
                assert_eq!(err, case["error"], "case {index}");
                assert_eq!(body, case["body"], "case {index}");
                assert_eq!(metadata, case["metadata"], "case {index}");
                assert_eq!(names, case["names"], "case {index}");
                continue;
            }
            "static-route" => {
                let serving: StaticServingOptions =
                    serde_json::from_value(case["serving"].clone()).unwrap();
                let hosts: Vec<String> = serde_json::from_value(case["hosts"].clone()).unwrap();
                routes::static_route(
                    case["route"].as_str().unwrap().as_bytes(),
                    case["app"].as_str().unwrap(),
                    case["revision"].as_str().unwrap(),
                    &hosts,
                    &serving,
                )
                .map(|bytes| Value::String(String::from_utf8(bytes).unwrap()))
            }
            "gate" => archive::static_gate(
                case["body"].as_str().unwrap().as_bytes(),
                case["app"].as_str().unwrap(),
            )
            .map(Value::String),
            _ => {
                let body = STANDARD.decode(case["body"].as_str().unwrap()).unwrap();
                let limits: StaticLimits = serde_json::from_value(case["limits"].clone()).unwrap();
                match kind {
                    "config" => archive::read_configuration(&body[..]).map(|(a, b)| {
                        serde_json::json!([
                            String::from_utf8(a).unwrap(),
                            String::from_utf8(b).unwrap()
                        ])
                    }),
                    "image" => archive::docker_archive_config_digest(&body[..]).map(Value::String),
                    "static" => {
                        let parent = tempfile::tempdir().unwrap();
                        let destination = parent.path().join("public");
                        let result = static_tree::static_tree(&body[..], &destination, &limits);
                        assert_eq!(
                            destination.exists(),
                            case["exists"].as_bool().unwrap(),
                            "case {index}"
                        );
                        result.map(|hash|{let checksum=static_tree::static_tree_checksum(&destination,&limits).unwrap();let info=std::fs::metadata(destination.join("index.html")).unwrap();serde_json::json!({"hash":hash,"checksum":checksum,"file_mode":info.permissions().mode()&0o777,"mtime":info.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()})})
                    }
                    _ => panic!("unknown case"),
                }
            }
        };
        let (output, err) = match result {
            Ok(v) => (v, String::new()),
            Err(e) => (
                if matches!(kind, "gate" | "static-route") {
                    Value::String(String::new())
                } else {
                    Value::Null
                },
                error(e),
            ),
        };
        assert_eq!(err, case["error"], "case {index} {kind} {}", case["name"]);
        assert_eq!(output, case["output"], "case {index}");
    }
}
