use anyhow::Result;
use komizo::{
    host::{
        application::{self, Lifecycle, Runtime, Subject},
        authority::Command,
    },
    workload::activation::Context,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
fn state(path: &Path, root: &Path) -> String {
    let body = fs::read_to_string(path).unwrap();
    body.split('\n')
        .map(|line| {
            if line.starts_with("STOPPED_AT=") {
                "STOPPED_AT=2026-11-01T18:00:00Z"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .replace(root.to_str().unwrap(), "$ROOT")
}
struct Tape<'a> {
    case: &'a Value,
    root: &'a Path,
    record: PathBuf,
    position: usize,
    provisions: usize,
}
impl Runtime for Tape<'_> {
    fn owner_verb(
        &mut self,
        _: &Context,
        _: &str,
        _: &Subject,
        _: &str,
        _: &str,
    ) -> Option<Result<()>> {
        None
    }
    fn compose(
        &mut self,
        _: &Context,
        subject: &Subject,
        args: &[String],
        _: bool,
        _: usize,
    ) -> Result<String> {
        let call = &self.case["calls"][self.position];
        self.position += 1;
        let mut argv = vec!["docker".into()];
        argv.extend(application::compose_base(&subject.dir, &subject.project));
        argv.extend_from_slice(args);
        let argv: Vec<_> = argv
            .iter()
            .map(|arg| arg.replace(self.root.to_str().unwrap(), "$ROOT"))
            .collect();
        assert_eq!(
            serde_json::to_value(argv).unwrap(),
            call["args"],
            "{} call {}",
            self.case["scenario"],
            self.position - 1
        );
        assert_eq!(
            state(&self.record, self.root),
            call["before"],
            "{} call {} marker ordering",
            self.case["scenario"],
            self.position - 1
        );
        let error = call["error"].as_str().unwrap();
        if error.is_empty() {
            Ok(call["output"].as_str().unwrap().into())
        } else {
            Err(anyhow::anyhow!("{error}"))
        }
    }
    fn provision(
        &mut self,
        _: &Context,
        script: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<()> {
        self.provisions += 1;
        assert_eq!(
            self.case["invocation"],
            serde_json::json!(["/bin/sh", "-s"])
        );
        assert_eq!(
            serde_json::to_value(environment).unwrap(),
            self.case["environment"]
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(script.as_bytes())),
            self.case["script_sha256"]
        );
        Ok(())
    }
}
#[test]
fn frozen_go_app_lifecycle_and_provisioning_keep_argv_marker_order_and_operator_authority() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-host-application.json")).unwrap();
    assert_eq!(cases.len(), 36);
    for (index, case) in cases.into_iter().enumerate() {
        let kind = case["kind"].as_str().unwrap();
        if kind == "service" {
            assert_eq!(
                application::valid_service(case["value"].as_str().unwrap())
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default(),
                case["error"],
                "case {index}"
            );
            continue;
        }
        if kind == "args" {
            let args = application::compose_args(
                case["verb"].as_str().unwrap(),
                case["tail"].as_i64().unwrap(),
                case["service"].as_str().unwrap(),
            );
            let expected: Vec<String> =
                serde_json::from_value(case["output"].clone()).unwrap_or_default();
            assert_eq!(args, expected, "case {index}");
            continue;
        }
        let root = tempfile::tempdir().unwrap();
        let records = root.path().join("var/lib/komizo/apps");
        fs::create_dir_all(&records).unwrap();
        let record = records.join("example.env");
        let body = if kind == "lifecycle" {
            case["before"]
                .as_str()
                .unwrap()
                .replace("$ROOT", root.path().to_str().unwrap())
        } else {
            case["state"].as_str().unwrap().into()
        };
        fs::write(&record, body).unwrap();
        let mut tape = Tape {
            case: &case,
            root: root.path(),
            record: record.clone(),
            position: 0,
            provisions: 0,
        };
        let ctx = Context::new(Instant::now() + Duration::from_secs(2));
        let result = if kind == "lifecycle" {
            let subject = application::resolve_subject(
                root.path(),
                "example",
                case["proxy"].as_bool().unwrap(),
            )
            .unwrap();
            if case["scenario"] == "restart-cancelled" {
                ctx.cancelled.store(true, Ordering::Release);
            }
            application::run_verb_at(
                &ctx,
                &mut tape,
                Lifecycle {
                    verb: case["verb"].as_str().unwrap(),
                    subject: &subject,
                    tail: 40,
                    service: case["service"].as_str().unwrap(),
                    actor: "account fixture",
                },
                case["now"].as_str().unwrap().parse().unwrap(),
            )
        } else {
            let command: Command = serde_json::from_value(case["command"].clone()).unwrap();
            application::perform(&ctx, &mut tape, root.path(), &command, "account fixture")
        };
        assert_eq!(
            result.err().map(|e| e.to_string()).unwrap_or_default(),
            case["error"],
            "case {index} {}",
            case["scenario"]
        );
        if kind == "lifecycle" {
            assert_eq!(
                tape.position,
                case["calls"].as_array().unwrap().len(),
                "case {index}"
            );
            assert_eq!(state(&record, root.path()), case["after"], "case {index}");
        } else {
            assert_eq!(
                tape.provisions,
                usize::from(!case["script_sha256"].as_str().unwrap().is_empty()),
                "case {index}"
            );
        }
    }
}
