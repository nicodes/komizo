use anyhow::{Result, ensure};
use komizo::{
    host::{
        application::Subject,
        workload::{
            activation::Host,
            effects::{ArchiveConsumer, Effects},
            files,
            transaction::hash,
        },
    },
    wire::{Bytes, Time},
    workload::{
        activation::{self, ActivationRequest, Context},
        policy::{Policy, ReadinessProbe},
        readiness,
    },
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn normalize(text: &str, root: &Path) -> String {
    let text = text.replace(root.to_str().unwrap(), "$ROOT");
    let text = regex::Regex::new(r#"validated-[^ /"\\]+"#)
        .unwrap()
        .replace_all(&text, "validated-$$WORK")
        .into_owned();
    regex::Regex::new(r"(?m)STOPPED_AT=[^\n]*")
        .unwrap()
        .replace_all(&text, "STOPPED_AT=$$TIME")
        .into_owned()
}
fn normalize_json(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if matches!(
                    key.as_str(),
                    "at" | "started_at" | "deadline" | "verified_at"
                ) {
                    *value = json!("$TIME")
                } else if matches!(
                    key.as_str(),
                    "policy_sha256" | "route_sha256" | "compose_sha256"
                ) {
                    *value = json!("$HASH")
                } else {
                    normalize_json(value)
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                normalize_json(value)
            }
        }
        _ => {}
    }
}
fn normalized_body(body: &str) -> Value {
    let mut value = serde_json::from_str(body).unwrap_or_else(|_| json!(body));
    normalize_json(&mut value);
    value
}
struct Tape<'a> {
    case: &'a Value,
    root: &'a Path,
    cursor: usize,
    boundaries: Vec<String>,
    crash: Option<String>,
}
impl Tape<'_> {
    fn next(&mut self, kind: &str) -> &Value {
        let call = &self.case["calls"][self.cursor];
        self.cursor += 1;
        assert_eq!(
            call["kind"],
            kind,
            "{} {} call {}",
            self.case["kind"],
            self.case["scenario"],
            self.cursor - 1
        );
        call
    }
    fn inject_stop(&self, args: &[&str]) {
        let scenario = self.case["scenario"].as_str().unwrap();
        let call = args.join(" ");
        if scenario == "new-stop" && args.first() == Some(&"exec") {
            komizo::host::stopped::mark_stopped(self.root, "example", "fixture-owner", Time::now())
                .unwrap();
        } else if scenario == "stop-during-up" && call.contains(" up -d ")
            || scenario == "stop-during-reload"
                && args.first() == Some(&"exec")
                && args.get(3) == Some(&"reload")
        {
            komizo::host::stopped::mark_stopped(self.root, "example", "fixture", Time::now())
                .unwrap();
        }
    }
}
impl Effects for Tape<'_> {
    fn reconciliation_readiness(
        &mut self,
        _: &Context,
        revision: &str,
        compose: &[u8],
    ) -> Option<Result<()>> {
        let body = normalize(std::str::from_utf8(compose).unwrap(), self.root);
        let call = self.next("reconciliation_ready");
        assert_eq!(revision, call["revision"]);
        assert_eq!(body, call["body"]);
        Some(if call["ok"] == true {
            Ok(())
        } else {
            Err(anyhow::anyhow!("{}", call["error"].as_str().unwrap()))
        })
    }
    fn owned(&self, _: &fs::Metadata) -> bool {
        true
    }
    fn read(&self, path: &Path, maximum: usize) -> Result<Vec<u8>> {
        let body = fs::read(path)?;
        ensure!(body.len() <= maximum, "fixture input exceeds bound");
        Ok(body)
    }
    fn write(&mut self, path: &Path, body: &[u8], mode: u32) -> Result<()> {
        files::write_atomic(path, body, mode)
    }
    fn directory(&mut self, path: &Path, mode: u32) -> Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }
    fn docker(&mut self, _: &Context, args: &[&str]) -> Result<String> {
        self.inject_stop(args);
        let actual = args
            .iter()
            .map(|arg| normalize(arg, self.root))
            .collect::<Vec<_>>();
        let root = self.root.to_str().unwrap().to_owned();
        let call = self.next("docker");
        assert_eq!(serde_json::to_value(actual).unwrap(), call["args"]);
        if !call["ok"].as_bool().unwrap() {
            anyhow::bail!("{}", call["error"].as_str().unwrap())
        }
        Ok(call["output"].as_str().unwrap().replace("$ROOT", &root))
    }
    fn login(
        &mut self,
        _: &Context,
        _: &komizo::host::workload::transaction::Credentials,
        _: &Path,
    ) -> Result<()> {
        self.next("login");
        Ok(())
    }
    fn archive(
        &mut self,
        _: &Context,
        args: &[&str],
        maximum: u64,
        consumer: &mut ArchiveConsumer<'_>,
    ) -> Result<()> {
        let args = args
            .iter()
            .map(|s| normalize(s, self.root))
            .collect::<Vec<_>>();
        let call = self.next("archive");
        assert_eq!(serde_json::to_value(args).unwrap(), call["args"]);
        let body: Bytes = serde_json::from_value(call["body"].clone()).unwrap();
        ensure!(
            body.len() as u64 <= maximum,
            "fixture archive exceeds bound"
        );
        consumer(&mut &body[..])
    }
    fn probe(
        &mut self,
        _: &Context,
        _: &reqwest::blocking::Client,
        candidate: &str,
        probe: &ReadinessProbe,
    ) -> Result<()> {
        let call = self.next("probe");
        assert_eq!(probe.url, call["url"]);
        readiness::check_route_response(200, candidate, b"ready", candidate, probe)
    }
    fn checkpoint(&mut self, name: &str) {
        self.boundaries.push(name.into());
        if self.crash.as_deref() == Some(name) {
            std::process::exit(77)
        }
    }
}
fn tree(root: &Path) -> Value {
    fn walk(root: &Path, path: &Path, rows: &mut Vec<Value>) {
        let mut entries = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
            if relative == "run" || relative.starts_with("run/") {
                continue;
            }
            let info = fs::symlink_metadata(&path).unwrap();
            let mut row = json!({"path":relative,"mode":info.permissions().mode()&0o777});
            if info.is_dir() {
                row["directory"] = json!(true)
            } else if info.file_type().is_symlink() {
                row["link"] = json!(normalize(
                    fs::read_link(&path).unwrap().to_str().unwrap(),
                    root
                ))
            } else {
                row["body"] = normalized_body(&normalize(&fs::read_to_string(&path).unwrap(), root))
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
fn install_files(case: &Value, root: &Path) {
    let expand = |text: &str| text.replace("$ROOT", root.to_str().unwrap());
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
            symlink(expand(target), &path).unwrap()
        } else {
            fs::write(&path, expand(file["body"].as_str().unwrap())).unwrap()
        }
        if file["link"].is_null() {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap()
        }
    }
}
fn install_fixture(case: &Value, root: &Path) -> (ActivationRequest, PathBuf, PathBuf, PathBuf) {
    install_files(case, root);
    let expand = |text: &str| text.replace("$ROOT", root.to_str().unwrap());
    let mut request: ActivationRequest =
        serde_json::from_str(&expand(&case["request"].to_string())).unwrap();
    request.deadline = Time((chrono::Utc::now() + chrono::Duration::minutes(10)).fixed_offset());
    request.policy_sha256 =
        hash(expand(case["hash_inputs"]["policy"].as_str().unwrap()).as_bytes());
    request.compose_sha256 = if request.version == 1 {
        hash(expand(case["hash_inputs"]["compose"].as_str().unwrap()).as_bytes())
    } else {
        String::new()
    };
    request.route_sha256 = if request.version == 1 {
        hash(expand(case["hash_inputs"]["route"].as_str().unwrap()).as_bytes())
    } else {
        String::new()
    };
    let policies = PathBuf::from(expand(case["policies"].as_str().unwrap()));
    let releases = PathBuf::from(expand(case["releases"].as_str().unwrap()));
    let queue = PathBuf::from(expand(case["queue"].as_str().unwrap()));
    let op_path = releases.join("example/operation.json");
    let mut op: Value = serde_json::from_slice(&fs::read(&op_path).unwrap()).unwrap();
    op["deadline"] = serde_json::to_value(request.deadline).unwrap();
    files::write_json(&op_path, &op).unwrap();
    let kind = case["kind"].as_str().unwrap();
    if matches!(kind, "activation" | "deployment") {
        files::write_json(&queue.join("pending.json"), &request).unwrap()
    }
    (request, policies, releases, queue)
}
#[test]
fn full_go_worker_traces_preserve_transactions_owner_intent_and_static_recovery() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("data/go-host-worker.json")).unwrap();
    assert_eq!(cases.len(), 45);
    for case in &cases {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let (request, policies, releases, queue) = install_fixture(case, root);
        let kind = case["kind"].as_str().unwrap();
        let tape = Tape {
            case,
            root,
            cursor: 0,
            boundaries: vec![],
            crash: None,
        };
        let mut host = Host::new(root.into(), tape).unwrap();
        host.policies = policies;
        host.releases = releases;
        if matches!(kind, "static" | "typed-owner" | "static-owner") {
            host.policy = serde_json::from_slice::<Policy>(
                &fs::read(host.policies.join("example.json")).unwrap(),
            )
            .unwrap()
        }
        let ctx = Context::new(Instant::now() + Duration::from_secs(8));
        let subject = Subject {
            app: "example".into(),
            dir: root.join("srv/example").to_str().unwrap().into(),
            root: root.into(),
            ..Default::default()
        };
        let (result, status) = match kind {
            "activation" | "deployment" => {
                let status = host.activation_pass(&ctx, &queue);
                let receipt: Value = serde_json::from_slice(
                    &fs::read(queue.join(format!("{}.json", request.id))).unwrap(),
                )
                .unwrap();
                (receipt, status)
            }
            "static" => {
                let (result, status) = activation::activate(&ctx, &request, &mut host);
                (serde_json::to_value(result).unwrap(), status)
            }
            "typed-owner" => (
                Value::Null,
                host.perform_typed_owner(
                    &ctx,
                    case["verb"].as_str().unwrap(),
                    &subject,
                    case["service"].as_str().unwrap(),
                    "fixture",
                    &queue,
                ),
            ),
            "static-owner" => {
                let status = host.owner_verb(
                    &ctx,
                    case["verb"].as_str().unwrap(),
                    &subject,
                    case["service"].as_str().unwrap(),
                    "fixture",
                );
                (json!(status.is_some()), status.unwrap_or(Ok(())))
            }
            _ => panic!("unknown case"),
        };
        assert_eq!(
            status.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{kind} {}: {status:?}",
            case["scenario"]
        );
        let mut result = result;
        normalize_json(&mut result);
        let mut expected = case["result"].clone();
        normalize_json(&mut expected);
        assert_eq!(result, expected, "{kind} {} result", case["scenario"]);
        assert_eq!(
            host.effects.cursor,
            case["calls"].as_array().unwrap().len(),
            "{kind} {} calls",
            case["scenario"]
        );
        assert_eq!(
            json!(host.effects.boundaries),
            case["boundaries"],
            "{kind} {} boundaries",
            case["scenario"]
        );
        let mut expected = case["output"].clone();
        for file in expected.as_array_mut().unwrap() {
            if let Some(body) = file["body"].as_str() {
                file["body"] = normalized_body(body)
            }
        }
        assert_eq!(tree(root), expected, "{kind} {} files", case["scenario"]);
    }
}
#[test]
fn crash_child() {
    let Ok(root) = std::env::var("KOMIZO_RUST_CRASH_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let kind = std::env::var("KOMIZO_RUST_CRASH_KIND").unwrap();
    let cases: Vec<Value> = serde_json::from_str(include_str!("data/go-host-worker.json")).unwrap();
    let case = cases
        .iter()
        .find(|case| case["kind"] == kind && case["scenario"] == "ordinary")
        .unwrap();
    let expand = |key: &str| {
        PathBuf::from(
            case[key]
                .as_str()
                .unwrap()
                .replace("$ROOT", root.to_str().unwrap()),
        )
    };
    let tape = Tape {
        case,
        root: &root,
        cursor: 0,
        boundaries: vec![],
        crash: Some(std::env::var("KOMIZO_RUST_CRASH_BOUNDARY").unwrap()),
    };
    let mut host = Host::new(root.clone(), tape).unwrap();
    host.policies = expand("policies");
    host.releases = expand("releases");
    host.activation_pass(
        &Context::new(Instant::now() + Duration::from_secs(8)),
        &expand("queue"),
    )
    .unwrap();
    panic!("requested crash boundary was not reached")
}
#[test]
fn real_process_crashes_keep_uncertain_effects_fenced_and_reconstruct_accepted_receipts() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("data/go-host-worker.json")).unwrap();
    for (kind, boundaries) in [
        (
            "deployment",
            &[
                "journal_staging",
                "snapshot",
                "compose-swap",
                "route-swap",
                "hostname-swap",
                "revision-swap",
                "journal_configured",
                "journal_activating",
                "proxy_reload",
                "retention",
                "journal_activated",
            ][..],
        ),
        (
            "static",
            &[
                "public_copy",
                "public_rename",
                "route_write",
                "serving_record",
                "journal_ready",
            ][..],
        ),
    ] {
        for boundary in boundaries {
            let case = cases
                .iter()
                .find(|case| case["kind"] == kind && case["scenario"] == "ordinary")
                .unwrap();
            let root = tempfile::tempdir().unwrap();
            let root = root.path();
            let (request, policies, releases, queue) = install_fixture(case, root);
            files::write_json(&queue.join("pending.json"), &request).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "crash_child", "--nocapture"])
                .env("KOMIZO_RUST_CRASH_ROOT", root)
                .env("KOMIZO_RUST_CRASH_KIND", kind)
                .env("KOMIZO_RUST_CRASH_BOUNDARY", boundary)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(77),
                "{kind} {boundary}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let before = tree(&root.join("srv/example"));
            let route = fs::read(&request.route_path).unwrap();
            let mut resume = case.clone();
            resume["calls"] = json!([]);
            let tape = Tape {
                case: &resume,
                root,
                cursor: 0,
                boundaries: vec![],
                crash: None,
            };
            let mut host = Host::new(root.into(), tape).unwrap();
            host.policies = policies;
            host.releases = releases;
            host.activation_pass(
                &Context::new(Instant::now() + Duration::from_secs(8)),
                &queue,
            )
            .unwrap();
            assert_eq!(
                host.effects.cursor, 0,
                "{kind} {boundary} replayed external effects"
            );
            assert_eq!(
                tree(&root.join("srv/example")),
                before,
                "{kind} {boundary} rewrote application configuration"
            );
            assert_eq!(fs::read(&request.route_path).unwrap(), route);
            let result: Value = serde_json::from_slice(
                &fs::read(queue.join(format!("{}.json", request.id))).unwrap(),
            )
            .unwrap();
            if *boundary == "journal_ready" {
                assert_eq!(result["phase"], "ready");
                assert_eq!(result["ok"], true);
                assert_eq!(result["started"], true)
            } else {
                assert_eq!(
                    result["phase"], "reconciliation_required",
                    "{kind} {boundary}"
                );
                assert_eq!(result["ok"], false);
                assert!(result["started"].is_null())
            }
            assert!(!queue.join("pending.json").exists());
            assert!(!queue.join(format!("credentials-{}", request.id)).exists());
        }
    }
}
#[test]
fn malformed_queue_identities_refuse_before_constructing_lock_or_result_paths() {
    let cases: Vec<Value> = serde_json::from_str(include_str!("data/go-host-worker.json")).unwrap();
    let case = cases
        .iter()
        .find(|case| case["kind"] == "deployment" && case["scenario"] == "ordinary")
        .unwrap();
    for mutation in [
        "app",
        "operation",
        "route",
        "version",
        "unknown",
        "duplicate",
    ] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let (request, policies, releases, queue) = install_fixture(case, root);
        let mut request = serde_json::to_value(request).unwrap();
        match mutation {
            "app" => request["app"] = json!("../foreign"),
            "operation" => request["operation_id"] = json!("../../outside"),
            "route" => request["route_path"] = json!("/etc/foreign.caddy"),
            "version" => request["version"] = json!(999),
            "unknown" => request["new_authority"] = json!(true),
            _ => {}
        }
        let body = if mutation == "duplicate" {
            format!(
                "{},\"version\":2}}",
                request.to_string().trim_end_matches('}')
            )
            .into_bytes()
        } else {
            serde_json::to_vec(&request).unwrap()
        };
        fs::write(queue.join("pending.json"), body).unwrap();
        let before = tree(root);
        let tape = Tape {
            case,
            root,
            cursor: 0,
            boundaries: vec![],
            crash: None,
        };
        let mut host = Host::new(root.into(), tape).unwrap();
        host.policies = policies;
        host.releases = releases;
        assert!(
            host.activation_pass(
                &Context::new(Instant::now() + Duration::from_secs(2)),
                &queue
            )
            .is_err(),
            "{mutation}"
        );
        assert_eq!(host.effects.cursor, 0);
        assert_eq!(tree(root), before, "{mutation}");
        assert!(!root.join("run").exists(), "{mutation}");
    }
}
#[test]
fn go_reconciliation_restores_only_reviewed_configuration_and_retains_uncertain_fences() {
    use komizo::host::workload::reconciliation::Request;
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-host-reconciliation.json")).unwrap();
    assert_eq!(cases.len(), 17);
    for case in &cases {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let expand = |text: &str| text.replace("$ROOT", root.to_str().unwrap());
        install_files(case, root);
        let input = &case["request"];
        let mut request = Request {
            id: input["ID"].as_str().unwrap().into(),
            candidate: input["Candidate"].as_str().unwrap().into(),
            policy_sha256: input["PolicySHA256"].as_str().unwrap().into(),
            phase: input["Phase"].as_str().unwrap().into(),
            serving: input["Serving"].as_str().unwrap().into(),
            outcome: input["Outcome"].as_str().unwrap().into(),
        };
        if case["policy_matches"] == true {
            request.policy_sha256 = hash(expand(case["policy"].as_str().unwrap()).as_bytes())
        }
        let tape = Tape {
            case,
            root,
            cursor: 0,
            boundaries: vec![],
            crash: None,
        };
        let mut host = Host::new(root.into(), tape).unwrap();
        host.policies = PathBuf::from(expand(case["policies"].as_str().unwrap()));
        host.releases = PathBuf::from(expand(case["releases"].as_str().unwrap()));
        host.policy = serde_json::from_str(&expand(case["policy"].as_str().unwrap())).unwrap();
        let result = host.reconcile(
            &Context::new(Instant::now() + Duration::from_secs(8)),
            &request,
            Path::new(&expand(case["queue"].as_str().unwrap())),
        );
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{}: {result:?}",
            case["scenario"]
        );
        let mut actual = result.unwrap_or(Value::Null);
        normalize_json(&mut actual);
        let mut expected = case["result"].clone();
        normalize_json(&mut expected);
        assert_eq!(actual, expected, "{} result", case["scenario"]);
        assert_eq!(
            host.effects.cursor,
            case["calls"].as_array().unwrap().len(),
            "{} calls",
            case["scenario"]
        );
        assert_eq!(
            json!(host.effects.boundaries),
            case["boundaries"],
            "{} boundaries",
            case["scenario"]
        );
        let mut expected = case["output"].clone();
        for file in expected.as_array_mut().unwrap() {
            if let Some(body) = file["body"].as_str() {
                file["body"] = normalized_body(body)
            }
        }
        assert_eq!(tree(root), expected, "{} files", case["scenario"]);
    }
}
#[test]
fn snapshots_require_private_regular_files_and_reject_links_unknown_fields_and_oversize() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let case = json!({});
    let tape = Tape {
        case: &case,
        root,
        cursor: 0,
        boundaries: vec![],
        crash: None,
    };
    let path = root.join("snapshot");
    files::write_json(
        &path,
        &json!({"version":1,"operation_id":"a".repeat(32),"files":[]}),
    )
    .unwrap();
    assert_eq!(tape.snapshot(&path).unwrap().version, 1);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(tape.snapshot(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.join("alias");
    symlink(&path, &alias).unwrap();
    assert!(tape.snapshot(&alias).is_err());
    assert!(tape.snapshot(root).is_err());
    for body in [
        br#"{"unknown":true}"#.as_slice(),
        br#"{"version":1,"version":1}"#.as_slice(),
        br#"{"files":[{"path":"/tmp/file","foreign":true}]}"#.as_slice(),
        &vec![b' '; (4 << 20) + 1],
    ] {
        fs::write(&path, body).unwrap();
        assert!(tape.snapshot(&path).is_err())
    }
}
