use komizo::host::{diagnose::diagnose, logs::*, paths::*, *};
use serde::Serialize;
use serde_json::{Value, json};
use std::{fs, path::Path};
fn nil_empty<T: Serialize>(values: &[T]) -> Value {
    if values.is_empty() {
        Value::Null
    } else {
        json!(values)
    }
}
fn write(root: &Path, path: &str, body: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}
#[test]
fn ninety_go_app_log_traffic_and_diagnosis_cases_remain_identical() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-host-records.json")).unwrap();
    assert_eq!(cases.len(), 90);
    for case in cases {
        let t = tempfile::tempdir().unwrap();
        let p = Probe {
            root: t.path().into(),
        };
        let input = &case["input"];
        let actual = match case["kind"].as_str().unwrap() {
            "parse_log" => {
                let lines = parse_log(input.as_str().unwrap());
                json!({"lines":nil_empty(&lines),"formatted":format_log(&lines),"services":nil_empty(&log_services(&lines)),"web":filter_log(&lines,"web")})
            }
            "states" => {
                for (path, body) in input.as_object().unwrap() {
                    write(t.path(), path, body.as_str().unwrap());
                }
                for dir in ["srv/leftover", "srv/a", "srv/_proxy"] {
                    fs::create_dir_all(t.path().join(dir)).unwrap();
                }
                let states: Vec<_> = p
                    .app_states()
                    .into_iter()
                    .map(|s| json!({"name":s.name,"values":s.values}))
                    .collect();
                json!({"states":states,"hosts":p.hosts("/srv/custom"),"orphans":p.orphans()})
            }
            "metrics" => {
                for (path, body) in input["files"].as_object().unwrap() {
                    write(t.path(), path, body.as_str().unwrap());
                }
                write(t.path(), ACCESS_LOG, input["log"].as_str().unwrap());
                json!(p.metrics(
                    input["from"].as_i64().unwrap(),
                    input["to"].as_i64().unwrap()
                ))
            }
            "diagnose" => nil_empty(&diagnose(
                &serde_json::from_value::<Report>(input.clone()).unwrap(),
            )),
            kind => panic!("unknown {kind}"),
        };
        assert_eq!(actual, case["expected"], "{} {input}", case["kind"]);
    }
}
#[test]
fn logs_retain_only_app_tails_preserve_tabs_and_do_not_rewrite_unchanged_files() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path();
    let body = format!("old\n{}\nweb\tnew\n", "x".repeat(LOGS_MAX));
    write_log(dir, "fixture", body.as_bytes()).unwrap();
    let path = log_path(dir, "fixture").unwrap();
    assert!(fs::metadata(&path).unwrap().len() <= LOGS_MAX as u64);
    assert_eq!(read_log(dir, "fixture", 1).unwrap(), "web\tnew");
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let stored = fs::read(&path).unwrap();
    write_log(dir, "fixture", &stored).unwrap();
    assert_eq!(modified, fs::metadata(&path).unwrap().modified().unwrap());
    for name in ["", "../private", "_proxy", "app/other", "app.ext"] {
        assert!(log_path(dir, name).is_err());
    }
    fs::write(dir.join("history.jsonl"), "keep").unwrap();
    fs::write(dir.join("removed.log"), "old").unwrap();
    prune_logs(dir, &["fixture".into()]).unwrap();
    assert!(path.exists());
    assert!(dir.join("history.jsonl").exists());
    assert!(!dir.join("removed.log").exists());
    assert!(!valid_service("web\tbad"));
    assert!(valid_service(""));
}
#[test]
fn runtime_health_uses_required_services_and_preserves_optional_profiles() {
    let t = tempfile::tempdir().unwrap();
    let p = Probe {
        root: t.path().into(),
    };
    let mut app = App {
        dir: "/srv/fixture".into(),
        ..Default::default()
    };
    let conf = r#"{"services":{"web":{"healthcheck":{"test":["CMD","check"]}},"optional":{"profiles":["manual"]}}}"#;
    write(t.path(), "/srv/fixture/compose.yml", conf);
    assert_eq!(p.runtime_state(&app), "down");
    app.containers = vec![Container {
        service: "web".into(),
        state: "running".into(),
        ..Default::default()
    }]
    .into();
    assert_eq!(p.runtime_state(&app), "degraded");
    app.containers[0].health = "healthy".into();
    assert_eq!(p.runtime_state(&app), "running");
    app.stopped = true;
    assert_eq!(p.runtime_state(&app), "stopped");
    app.stopped = false;
    app.containers[0].inspection = "unavailable".into();
    assert_eq!(p.runtime_state(&app), "unknown");
    app.containers[0].inspection.clear();
    let duplicate = app.containers[0].clone();
    let mut containers = app.containers.into_vec();
    containers.push(duplicate);
    app.containers = containers.into();
    assert_eq!(p.runtime_state(&app), "degraded");
    app.r#static = Some(StaticServing {
        active: true,
        ..Default::default()
    });
    assert_eq!(p.runtime_state(&app), "running");
    app.r#static.as_mut().unwrap().active = false;
    assert_eq!(p.runtime_state(&app), "down");
}
#[test]
fn metrics_output_has_no_private_request_fields() {
    let owners = std::collections::BTreeMap::from([(
        "example.com".into(),
        ("fixture".into(), "web".into()),
    )]);
    let input=br#"{"ts":180,"status":503,"client_ip":"never-export-address","request":{"host":"example.com","uri":"never-export-path","headers":{"Authorization":"never-export-credential"}}}
"#;
    let m = access::metrics_from_reader(input.as_slice(), &owners, 0, 999, false);
    assert_eq!(m.rows[0].c5, 1);
    let result = serde_json::to_string(&m).unwrap();
    assert!(!result.contains("never-export"));
}
