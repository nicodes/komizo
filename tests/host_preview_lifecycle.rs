use komizo::{
    host::preview::{
        self, Record,
        knob::{self, KnobValues},
        profile,
        runtime::{self, Config, Request},
        store,
    },
    wire::Secret,
    workload::activation::Context,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, Instant},
};
const SEED: &str = "00112233445566778899aabb";
fn snapshot(root: &Path) -> Value {
    fn walk(root: &Path, path: &Path, output: &mut BTreeMap<String, Value>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), output);
            } else {
                let bytes = fs::read_to_string(entry.path())
                    .unwrap()
                    .replace(root.to_str().unwrap(), "$ROOT");
                output.insert(entry.path().strip_prefix(root).unwrap().to_str().unwrap().into(),serde_json::json!({"body":bytes,"mode":entry.metadata().unwrap().permissions().mode()&0o777}));
            }
        }
    }
    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    serde_json::to_value(output).unwrap()
}
#[test]
fn frozen_go_preview_lifecycles_keep_ownership_reservations_private_seeds_and_cleanup_receipts() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-preview-lifecycle.json")).unwrap();
    assert_eq!(cases.len(), 24);
    for (index, case) in cases.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("routes")).unwrap();
        for (name, file) in case["before"].as_object().unwrap() {
            let path = root.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(
                &path,
                file["body"]
                    .as_str()
                    .unwrap()
                    .replace("$ROOT", root.path().to_str().unwrap()),
            )
            .unwrap();
            fs::set_permissions(
                path,
                fs::Permissions::from_mode(file["mode"].as_u64().unwrap() as u32),
            )
            .unwrap();
        }
        let (mut k, _) = knob::parse(case["knob_body"].as_str().unwrap());
        k.values = serde_json::from_value::<KnobValues>(case["knob"].clone()).unwrap();
        k.cgroup_parent = case["cgroup_parent"].as_str().unwrap().into();
        k.profiles = Some(BTreeMap::new());
        let app = case["app"].as_str().unwrap();
        if let Some(body) = case["profile"].as_str().filter(|s| !s.is_empty()) {
            k.profiles
                .as_mut()
                .unwrap()
                .insert(app.into(), Some(profile::parse(body.as_bytes()).unwrap()));
        }
        let cfg = Config {
            knob: k,
            root: root.path().into(),
            routes_dir: root.path().join("routes"),
            proxy: "komizo-proxy".into(),
            network: "edge".into(),
            floors_body: case["floors"].as_str().unwrap().into(),
            report_json: case["report"].as_str().unwrap().as_bytes().to_vec(),
            report_path: None,
            host_resources: None,
            manage_idle_database: case["manage_idle"].as_bool().unwrap(),
        };
        assert_eq!(
            snapshot(root.path()),
            case["before"],
            "case {index} initial state"
        );
        let calls = case["calls"].as_array().cloned().unwrap_or_default();
        let mut position = 0;
        let mut run = |ctx: &Context, input: &str, args: &[&str]| {
            ctx.check().unwrap();
            let call = calls.get(position).unwrap_or_else(|| {
                panic!("case {index} {} unexpected call {args:?}", case["scenario"])
            });
            position += 1;
            let args: Vec<_> = args
                .iter()
                .map(|arg| arg.replace(root.path().to_str().unwrap(), "$ROOT"))
                .collect();
            assert_eq!(
                serde_json::to_value(args).unwrap(),
                call["args"],
                "case {index} {} call {}",
                case["scenario"],
                position - 1
            );
            assert_eq!(
                input,
                call["stdin"],
                "case {index} stdin call {}",
                position - 1
            );
            let error = call["error"].as_str().unwrap();
            if error.is_empty() {
                Ok(call["output"].as_str().unwrap().into())
            } else {
                Err(anyhow::anyhow!("{error}"))
            }
        };
        let ctx = Context::new(Instant::now() + Duration::from_secs(5));
        let now = case["now"].as_str().unwrap().parse().unwrap();
        let mut output = Value::Null;
        let result = match case["mode"].as_str().unwrap() {
            "up" => {
                let images: Vec<String> = serde_json::from_value(case["images"].clone()).unwrap();
                runtime::up_with_seed(
                    &ctx,
                    &mut run,
                    &cfg,
                    Request {
                        app,
                        pr: case["pr"].as_i64().unwrap(),
                        images: &images,
                        now,
                    },
                    || Ok(Secret::new(SEED.into())),
                )
                .map(|record| output = serde_json::to_value(record).unwrap())
            }
            "down" => {
                let record: Record = serde_json::from_value(case["down_record"].clone()).unwrap();
                runtime::down(&ctx, &mut run, &cfg, &record)
            }
            "gc" => {
                let (reap, result) = runtime::gc(&ctx, &mut run, &cfg, now);
                output = serde_json::to_value(reap).unwrap();
                result
            }
            _ => panic!("unknown fixture"),
        };
        let error = result
            .err()
            .map(|e| {
                e.to_string()
                    .replace(root.path().to_str().unwrap(), "$ROOT")
            })
            .unwrap_or_default();
        assert_eq!(error, case["error"], "case {index} {}", case["scenario"]);
        assert_eq!(output, case["output"], "case {index}");
        assert_eq!(position, calls.len(), "case {index}");
        assert_eq!(
            snapshot(root.path()),
            case["after"],
            "case {index} {} final state",
            case["scenario"]
        );
        // Inventory exposes no credential field even when a failed cleanup retained its private seed.
        for record in store::list(root.path()).unwrap() {
            assert!(!serde_json::to_string(&record).unwrap().contains(SEED));
            assert_eq!(record.project, preview::project(&record.app, record.pr));
        }
    }
}
