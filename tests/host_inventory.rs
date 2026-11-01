use komizo::{
    host::{inventory::*, *},
    wire::{Slice, Time},
};
use serde_json::{Value, json};
use std::{fs, path::Path};
fn write(root: &Path, path: &str, body: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}
#[test]
fn sixty_three_go_cli_inventory_readings_preserve_partial_failures_and_shared_indexes() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-docker-inventory.json")).unwrap();
    assert_eq!(cases.len(), 63);
    for case in cases {
        let t = tempfile::tempdir().unwrap();
        let p = Probe {
            root: t.path().into(),
        };
        write(
            t.path(),
            "/srv/_proxy/compose.yml",
            "name: ignored\nservices:\n  proxy:\n    image: ghcr.io/example/proxy\nnetworks:\n  edge:\n    name: edge\n",
        );
        write(
            t.path(),
            paths::CADDYFILE,
            "{\n  on_demand_tls {\n    ask http://127.0.0.1:8481\n  }\n}\n",
        );
        let failure = case["fail"].as_str().unwrap();
        let list = if failure == "list" {
            Err(anyhow::anyhow!("fixture"))
        } else {
            Ok(case["list"].as_str().unwrap().into())
        };
        let inv = Inventory::from_cli(list, |_| {
            if failure == "inspect" {
                Err(anyhow::anyhow!("fixture"))
            } else {
                Ok(case["inspect"].as_str().unwrap().into())
            }
        });
        let rows:Vec<_>=inv.sorted().iter().map(|c|json!({"id":c.id,"name":c.name,"pid":c.pid,"tty":c.tty,"inspection_unavailable":c.inspection_unavailable})).collect();
        let actual = json!({"status":inv.status,"failure":inv.failure,"rows":rows,"containers":p.containers("/srv/app",&inv),"proxy":p.proxy(&inv),"network":p.network_from_metadata("edge","bridge\t172.22.0.0/16",&inv)});
        assert_eq!(
            actual, case["expected"],
            "list {} failure {failure}",
            case["list"]
        );
    }
}
#[test]
fn fourteen_go_reports_keep_the_same_observations_health_and_diagnosis() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-host-reports.json")).unwrap();
    assert_eq!(cases.len(), 14);
    for case in cases {
        let t = tempfile::tempdir().unwrap();
        let p = Probe {
            root: t.path().into(),
        };
        for (path, body) in case["files"].as_object().unwrap() {
            write(t.path(), path, body.as_str().unwrap());
        }
        if case["kind"] == "orphan" {
            for dir in ["/srv/leftover", "/srv/_owned"] {
                fs::create_dir_all(p.path(dir)).unwrap();
            }
        }
        let kind = case["kind"].as_str().unwrap();
        let replies = case["docker"].as_object().unwrap();
        let reply = |prefix: &str| {
            replies
                .iter()
                .find(|(k, _)| k.starts_with(prefix))
                .map(|(_, v)| v.as_str().unwrap().to_owned())
                .unwrap_or_default()
        };
        let list = if matches!(kind, "bare" | "list_failed") {
            Err(anyhow::anyhow!("fixture"))
        } else {
            Ok(reply("ps -a"))
        };
        let inv = Inventory::from_cli(list, |_| {
            if matches!(kind, "bare" | "inspect_failed") {
                Err(anyhow::anyhow!("fixture"))
            } else {
                Ok(reply("inspect --format"))
            }
        });
        let server = p.server_facts(
            if kind == "bare" { "bare" } else { "ready" },
            if kind == "bare" {
                ""
            } else {
                "Docker version 29.1.3, build f52814d"
            },
            "test",
        );
        let at: Time = serde_json::from_value(json!("2026-08-02T12:00:00Z")).unwrap();
        let network = reply("network inspect");
        let mut report = p.assemble_report(server, &inv, Some(&network), at);
        report.system.disks = Slice::default();
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            case["expected"],
            "case {kind}"
        );
        struct FixtureRunner<'a> {
            kind: &'a str,
            replies: &'a serde_json::Map<String, Value>,
            calls: &'a std::cell::RefCell<Vec<String>>,
        }
        impl observer::Docker for FixtureRunner<'_> {
            fn run(
                &mut self,
                args: &[String],
                _deadline: std::time::Instant,
                _cancelled: &dyn Fn() -> bool,
            ) -> anyhow::Result<String> {
                let joined = args.join(" ");
                self.calls.borrow_mut().push(joined.clone());
                if self.kind == "bare"
                    || self.kind == "list_failed" && args[0] == "ps"
                    || self.kind == "inspect_failed" && args[0] == "inspect"
                {
                    anyhow::bail!("fixture failure");
                }
                self.replies
                    .iter()
                    .find(|(key, _)| joined.contains(key.as_str()))
                    .map(|(_, value)| value.as_str().unwrap().to_string())
                    .ok_or_else(|| anyhow::anyhow!("unexpected Docker request {joined}"))
            }
        }
        let calls = std::cell::RefCell::new(vec![]);
        let runner = FixtureRunner {
            kind,
            replies,
            calls: &calls,
        };
        let mut observer = observer::Observer::with_cli(
            &p,
            runner,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
            || false,
        );
        let mut report = observer.report("test", Some(at));
        report.system.disks = Slice::default();
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            case["expected"],
            "composed observation {kind}"
        );
        let calls = calls.borrow();
        assert_eq!(
            calls.iter().filter(|c| c.starts_with("ps ")).count(),
            usize::from(kind != "bare")
        );
        assert_eq!(
            calls.iter().filter(|c| c.starts_with("inspect ")).count(),
            usize::from(!matches!(kind, "bare" | "list_failed"))
        );
    }
}
