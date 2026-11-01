use komizo::host::resource_authority;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::Path,
};
fn tree(root: &Path) -> Value {
    fn walk(root: &Path, path: &Path, rows: &mut Vec<Value>) {
        let mut paths = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let info = fs::symlink_metadata(&path).unwrap();
            let mut row = json!({"path":path.strip_prefix(root).unwrap(),"mode":info.permissions().mode()&0o777});
            if info.is_dir() {
                row["directory"] = json!(true)
            } else if info.file_type().is_symlink() {
                row["link"] = json!(
                    fs::read_link(&path)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace(root.to_str().unwrap(), "$ROOT")
                )
            } else {
                row["body"] = json!(
                    fs::read_to_string(&path)
                        .unwrap()
                        .replace(root.to_str().unwrap(), "$ROOT")
                )
            }
            rows.push(row);
            if info.is_dir() {
                walk(root, &path, rows)
            }
        }
    }
    let mut rows = vec![];
    walk(root, root, &mut rows);
    json!(rows)
}
#[test]
fn go_proxy_read_and_kernel_adapters_preserve_controller_preflights_and_effects() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-resource-adapters.json")).unwrap();
    assert_eq!(cases.len(), 129);
    for (index, case) in cases.iter().enumerate() {
        let kind = case["kind"].as_str().unwrap();
        if kind == "kernel" && !cfg!(target_os = "linux") {
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        for file in case["input"].as_array().unwrap() {
            let path = root.join(file["path"].as_str().unwrap());
            let mode = file["mode"].as_u64().unwrap() as u32;
            if file["directory"] == true {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(mode)
                    .create(&path)
                    .unwrap()
            } else if let Some(target) = file["link"].as_str() {
                symlink(target.replace("$ROOT", root.to_str().unwrap()), &path).unwrap()
            } else {
                fs::write(
                    &path,
                    file["body"]
                        .as_str()
                        .unwrap()
                        .replace("$ROOT", root.to_str().unwrap()),
                )
                .unwrap()
            }
            if file["link"].is_null() {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap()
            }
        }
        let owner = unsafe { libc::geteuid() }
            + u32::from(matches!(
                case["scenario"].as_str(),
                Some("owner" | "foreign")
            ));
        let result = match kind {
            "proxy" => {
                let result = resource_authority::proxy_budget(
                    root,
                    &|_| case["scenario"] != "owner",
                    case["measured_memory"].as_i64().unwrap(),
                    case["measured_cpu"].as_i64().unwrap(),
                );
                if let Ok(budget) = &result {
                    assert_eq!(
                        serde_json::to_value(budget).unwrap(),
                        case["budget"],
                        "case {index}"
                    );
                    assert_eq!(budget.compose(), case["compose"], "case {index}")
                }
                result.map(|_| ())
            }
            "read" => resource_authority::enter_read_budget(
                &root.join("resources.json"),
                &root.join("cgroup"),
                case["pid"].as_i64().unwrap() as i32,
                owner,
            ),
            "kernel" => {
                resource_authority::kernel_memory(root, case["total"].as_i64().unwrap(), owner)
            }
            _ => panic!("unknown case"),
        };
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "case {index} {kind} {}: {result:?}",
            case["scenario"]
        );
        if kind != "proxy"
            && let Err(error) = result
        {
            assert_eq!(error.to_string(), case["error"], "case {index} {kind}")
        }
        assert_eq!(
            tree(root),
            case["output"],
            "case {index} {kind} {}",
            case["scenario"]
        );
    }
}
#[test]
#[cfg(target_os = "linux")]
fn host_cpu_admission_counts_affinity_instead_of_a_service_quota() {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let list = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .unwrap()
        .trim();
    let count: i64 = list
        .split(',')
        .map(|range| {
            if let Some((first, last)) = range.split_once('-') {
                last.parse::<i64>().unwrap() - first.parse::<i64>().unwrap() + 1
            } else {
                1
            }
        })
        .sum();
    assert!(count > 0);
    assert_eq!(resource_authority::measured_cpu(), count * 1000);
}
#[test]
fn strict_resource_documents_refuse_unknown_nested_fields_and_duplicate_keys() {
    for body in [
        br#"{"production":{"foreign":1}}"#.as_slice(),
        br#"{"controls":{"openrc.komizo-rootd":{"foreign":1}}}"#.as_slice(),
        br#"{"apps":{"example":{"io_max":[{"device":"8:0","foreign":1}]}}}"#.as_slice(),
        br#"{"version":1,"version":1}"#.as_slice(),
    ] {
        assert!(resource_authority::read_resources(body).is_err())
    }
    assert!(resource_authority::read_resources(br#"{"version":1,"controls":{}}"#).is_ok());
    assert!(
        komizo::workload::policy_read::read_resources(br#"{"default":{"foreign":1}}"#).is_err()
    );
    assert!(
        komizo::workload::policy_read::read_readiness(
            br#"{"probes":[{"url":"https://example.test/","foreign":true}]}"#
        )
        .is_err()
    );
}
