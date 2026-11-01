use komizo::{
    host::preview::{Record, knob, profile},
    wire::Secret,
};
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt};
#[test]
fn go_operator_profile_render_and_admission_keep_exact_credentials_and_capability_refusals() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-preview-profile.json")).unwrap();
    assert_eq!(cases.len(), 45);
    for (index, case) in cases.into_iter().enumerate() {
        let kind = case["kind"].as_str().unwrap();
        if kind == "parse" {
            assert_eq!(
                profile::parse(case["body"].as_str().unwrap().as_bytes()).is_err(),
                case["refused"].as_bool().unwrap(),
                "case {index}"
            );
            continue;
        }
        let p = profile::parse(case["profile"].as_str().unwrap().as_bytes()).unwrap();
        let result = match kind {
            "images" => {
                let images: Vec<String> = serde_json::from_value(case["images"].clone()).unwrap();
                p.validate_images(&images)
            }
            "environment" => {
                let directory = tempfile::tempdir().unwrap();
                let file = directory.path().join("stack.env");
                fs::write(&file, case["body"].as_str().unwrap()).unwrap();
                fs::set_permissions(
                    &file,
                    fs::Permissions::from_mode(case["mode"].as_u64().unwrap() as u32),
                )
                .unwrap();
                p.validate_environment(&file)
            }
            "compose" | "render" => {
                let mut record: Record = serde_json::from_value(case["record"].clone()).unwrap();
                record.db_password = Secret::new(case["seed"].as_str().unwrap_or("").into());
                let (mut k, _) = knob::parse(case["knob_body"].as_str().unwrap());
                k.cgroup_parent = case["cgroup_parent"].as_str().unwrap().into();
                let network = case["network"].as_str().unwrap();
                if kind == "render" {
                    let output = p.compose(&record, &k, network).unwrap();
                    assert_eq!(output, case["output"], "case {index}");
                    p.validate_compose(&output, &record, &k, network).unwrap();
                    continue;
                }
                p.validate_compose(case["body"].as_str().unwrap(), &record, &k, network)
            }
            _ => panic!("unknown case"),
        };
        assert_eq!(
            result.err().map(|e| e.to_string()).unwrap_or_default(),
            case["error"],
            "case {index}"
        );
    }
}
