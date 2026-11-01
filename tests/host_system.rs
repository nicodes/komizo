use komizo::host::{Probe, system::*};
use serde_json::{Value, json};
use std::{fs, path::Path};
fn equivalent(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => a == b || a.as_f64() == b.as_f64(),
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|b| equivalent(v, b)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equivalent(a, b))
        }
        _ => a == b,
    }
}
fn write(root: &Path, path: &str, body: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}
#[test]
fn fifty_five_frozen_go_kernel_observations_preserve_counters_and_unknowns() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-system-observations.json")).unwrap();
    assert_eq!(cases.len(), 55);
    for case in cases {
        let temp = tempfile::tempdir().unwrap();
        let p = Probe {
            root: temp.path().into(),
        };
        let input = &case["input"];
        let actual = match case["kind"].as_str().unwrap() {
            "cpu" => {
                write(temp.path(), "/proc/stat", input.as_str().unwrap());
                json!(p.cpu())
            }
            "mem" => {
                write(temp.path(), "/proc/meminfo", input.as_str().unwrap());
                json!(p.mem())
            }
            "uptime" => {
                write(temp.path(), "/proc/uptime", input.as_str().unwrap());
                json!(p.uptime())
            }
            "pressure" => json!(parse_pressure(input.as_str().unwrap())),
            "disk" => {
                let n = input
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap())
                    .collect::<Vec<_>>();
                let (u, s, a) = disk_accounting(n[0], n[1], n[2], n[3]);
                json!([u, s, a])
            }
            "inode" => json!(inode_accounting(
                input[0].as_u64().unwrap(),
                input[1].as_u64().unwrap()
            )),
            kind @ ("ports" | "cgroup") => {
                for (path, body) in input.as_object().unwrap() {
                    write(temp.path(), path, body.as_str().unwrap());
                }
                if kind == "cgroup" {
                    json!(p.cgroup_stat(42))
                } else {
                    let ports = p.listening_ports(42);
                    if ports.is_empty() {
                        Value::Null
                    } else {
                        json!(ports)
                    }
                }
            }
            kind => panic!("unexpected {kind}"),
        };
        assert!(
            equivalent(&actual, &case["expected"]),
            "{} input {input}: {actual} expected {}",
            case["kind"],
            case["expected"]
        );
    }
}
#[test]
fn group_accounting_reports_measured_zero_without_inventing_memory_usage() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    for (name, body) in [
        (
            "cpu.stat",
            "usage_usec 99\nnr_periods 10\nnr_throttled 3\nthrottled_usec 17\n",
        ),
        ("memory.current", "123"),
        ("memory.swap.current", "5"),
        ("memory.events", "max 7\noom_kill 0\n"),
        ("memory.stat", "anon 80\nkernel 20\ninactive_file 0\n"),
    ] {
        write(
            root,
            &format!("/sys/fs/cgroup/komizo-production/{name}"),
            body,
        );
    }
    let groups = Probe { root: root.into() }.group_stats();
    assert_eq!(groups.len(), 1);
    let s = &groups[0].stat;
    assert_eq!(s.cpu_usec, Some(99));
    assert_eq!(s.cpu_throttled_usec, Some(17));
    assert_eq!(s.memory_anon, Some(80));
    assert_eq!(s.memory_kernel, Some(20));
    assert_eq!(s.memory_inactive_file, Some(0));
    assert_eq!(s.oom_kills, Some(0));
    assert_eq!(s.swap, Some(5));
    assert!(s.mem.is_none());
}
#[test]
fn cgroup_paths_cannot_escape_the_kernel_hierarchy() {
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "/proc/42/cgroup", "0::/../../private\n");
    write(t.path(), "/sys/private/cpu.stat", "usage_usec 123\n");
    let s = Probe {
        root: t.path().into(),
    }
    .cgroup_stat(42);
    assert!(s.cpu_usec.is_none());
}
