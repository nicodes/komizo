use komizo::workload::host_resources::HostResources;
use serde_json::Value;
use std::{collections::BTreeMap, fs, os::unix::fs::symlink, path::Path};
#[test]
fn frozen_go_reclaim_preflights_all_groups_and_retains_exact_finite_receipts() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-control-cache.json")).unwrap();
    assert_eq!(cases.len(), 16);
    fn snapshot(root: &Path) -> Value {
        fn walk(root: &Path, path: &Path, output: &mut BTreeMap<String, Value>) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                if entry.file_type().unwrap().is_symlink() {
                    output.insert(relative,serde_json::json!({"body":"","link":fs::read_link(path).unwrap().to_str().unwrap()}));
                } else if entry.file_type().unwrap().is_dir() {
                    walk(root, &path, output);
                } else {
                    output.insert(
                        relative,
                        serde_json::json!({"body":fs::read_to_string(path).unwrap()}),
                    );
                }
            }
        }
        let mut output = BTreeMap::new();
        walk(root, root, &mut output);
        serde_json::to_value(output).unwrap()
    }
    for (index, case) in cases.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        let before = case["before"].as_object().unwrap();
        for (name, value) in before {
            let path = root.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if value.get("link").is_none() {
                fs::write(path, value["body"].as_str().unwrap()).unwrap();
            }
        }
        for (name, value) in before {
            if let Some(link) = value.get("link") {
                symlink(link.as_str().unwrap(), root.path().join(name)).unwrap();
            }
        }
        assert_eq!(snapshot(root.path()), case["before"]);
        let policy: HostResources = serde_json::from_value(case["policy"].clone()).unwrap();
        let (rows, result) = policy.reclaim_control_cache(root.path());
        assert_eq!(
            result.err().map(|e| e.to_string()).unwrap_or_default(),
            case["error"],
            "case {index} {}",
            case["scenario"]
        );
        assert_eq!(
            serde_json::to_value(rows).unwrap(),
            case["rows"],
            "case {index}"
        );
        assert_eq!(snapshot(root.path()), case["after"], "case {index}");
    }
}
