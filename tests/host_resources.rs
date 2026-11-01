use komizo::workload::{host_resources::HostResources, resources::ResourcePolicy};
use serde_json::Value;
use std::{collections::BTreeMap, fs, os::unix::fs::symlink, path::Path};
fn fixture() -> Value {
    serde_json::from_str(include_str!("data/go-host-resources.json")).unwrap()
}
fn files(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, output: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), output);
            } else if entry.file_type().unwrap().is_file() {
                output.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .into(),
                    fs::read_to_string(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    output
}
#[test]
fn every_go_host_capacity_serving_and_startup_decision_matches() {
    let fixture = fixture();
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let policy: HostResources = serde_json::from_value(case["policy"].clone()).unwrap();
        let resources: Option<ResourcePolicy> =
            serde_json::from_value(case["resources"].clone()).unwrap();
        let result = match case["kind"].as_str().unwrap() {
            "check" => policy.check(
                case["memory"].as_i64().unwrap(),
                case["cpu"].as_i64().unwrap(),
            ),
            "serving" => policy.check_serving_budget("one", resources.as_ref()),
            "startup" => {
                let usage: BTreeMap<String, i64> =
                    serde_json::from_value(case["usage"].clone()).unwrap();
                policy.check_startup(
                    "one",
                    resources.as_ref(),
                    case["parent"].as_i64().unwrap(),
                    &usage,
                )
            }
            _ => panic!(),
        };
        let error = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert_eq!(
            error,
            case["error"].as_str().unwrap(),
            "case {index} {}",
            case["kind"]
        );
    }
}
#[test]
fn cgroup_application_and_recovery_preserve_exact_go_controller_values() {
    let fixture = fixture();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    let mut prior = HostResources::default();
    for step in fixture["snapshots"].as_array().unwrap() {
        for (name, _) in prior.groups() {
            let group = root.join(name);
            if group.exists() {
                for file in ["memory.current", "memory.swap.current", "pids.current"] {
                    fs::write(group.join(file), "0").unwrap();
                }
            }
        }
        if step["name"] == "application" {
            fs::write(root.join("komizo-production/io.weight"), "default 100").unwrap();
        }
        let policy: HostResources = serde_json::from_value(step["policy"].clone()).unwrap();
        policy.apply(root, 512 << 20, 1000).unwrap();
        let expected: BTreeMap<String, String> =
            serde_json::from_value(step["files"].clone()).unwrap();
        assert_eq!(files(root), expected, "snapshot {}", step["name"]);
        prior = policy;
    }
}
#[test]
fn preflight_writes_nothing_and_refuses_overuse_unsupported_io_and_symlinked_groups() {
    let fixture = fixture();
    let policy: HostResources =
        serde_json::from_value(fixture["snapshots"][1]["policy"].clone()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::write(root.join("cgroup.controllers"), "cpu memory pids io").unwrap();
    fs::write(root.join("cgroup.subtree_control"), "unchanged").unwrap();
    let before = files(root);
    assert!(policy.preflight(root, 512 << 20, 1000).is_err());
    assert_eq!(files(root), before);
    let parent = root.join("komizo-production");
    fs::create_dir(&parent).unwrap();
    fs::write(parent.join("io.weight"), "default 100").unwrap();
    for name in ["memory.current", "memory.swap.current", "pids.current"] {
        fs::write(parent.join(name), "0").unwrap();
    }
    let app = parent.join("one");
    fs::create_dir(&app).unwrap();
    for name in ["memory.current", "memory.swap.current", "pids.current"] {
        fs::write(app.join(name), "0").unwrap();
    }
    fs::write(app.join("memory.current"), (49_i64 << 20).to_string()).unwrap();
    let before = files(root);
    assert!(policy.apply(root, 512 << 20, 1000).is_err());
    assert_eq!(files(root), before);
    fs::remove_dir_all(&app).unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("memory.max"), "preserved").unwrap();
    symlink(outside.path(), &app).unwrap();
    assert!(policy.apply(root, 512 << 20, 1000).is_err());
    assert_eq!(
        fs::read_to_string(root.join("cgroup.subtree_control")).unwrap(),
        "unchanged"
    );
    assert_eq!(
        fs::read_to_string(outside.path().join("memory.max")).unwrap(),
        "preserved"
    );
}
