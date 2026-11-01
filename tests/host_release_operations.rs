use anyhow::Result;
use komizo::{
    host::workload::{
        activation::Host,
        admission::Admission,
        effects::{ArchiveConsumer, Effects},
        files,
        operations::{self, BackupOperation},
        secrets::SecretSet,
        transaction::hash,
    },
    wire::Bytes,
    workload::{activation::Context, operation::Operation, policy::Policy, release::RsaKey},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    time::{Duration, Instant},
};
fn bytes(value: &Value) -> Vec<u8> {
    if let Some(byte) = value["repeat"].as_u64() {
        vec![byte as u8; value["length"].as_u64().unwrap() as usize]
    } else {
        serde_json::from_value::<Bytes>(value["body"].clone())
            .unwrap()
            .into_vec()
    }
}
#[test]
fn go_secret_batches_and_backup_serving_do_not_confuse_desired_and_accepted_state() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-host-operation-inputs.json")).unwrap();
    assert_eq!(cases.len(), 611);
    for (index, case) in cases.iter().enumerate() {
        match case["kind"].as_str().unwrap() {
            "secret-set" => {
                let set = SecretSet(
                    case["values"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| (key.clone(), bytes(value).into()))
                        .collect(),
                );
                let previous = bytes(&case["previous"]);
                let result = set.merge(&previous);
                assert_eq!(
                    result.is_ok(),
                    case["ok"].as_bool().unwrap(),
                    "case {index}: {result:?}"
                );
                let body = match result {
                    Ok(body) => body,
                    Err(error) => {
                        assert_eq!(error.to_string(), case["error"], "case {index}");
                        previous
                    }
                };
                assert_eq!(
                    body.len(),
                    case["length"].as_u64().unwrap() as usize,
                    "case {index}"
                );
                assert_eq!(hash(&body), case["sha256"], "case {index}");
                if !case["body"].is_null() {
                    assert_eq!(
                        serde_json::to_value(Bytes::from(body)).unwrap(),
                        case["body"],
                        "case {index}"
                    )
                }
            }
            "secret-file" => assert_eq!(
                komizo::host::workload::secrets::valid_file_name(case["name"].as_str().unwrap()),
                case["ok"].as_bool().unwrap(),
                "case {index}"
            ),
            "backup-serving" => {
                let op: Operation = serde_json::from_value(case["operation"].clone()).unwrap();
                let result = operations::serving_revision(
                    "example",
                    case["environment"].as_str().unwrap().as_bytes(),
                    &op,
                );
                assert_eq!(
                    result.is_ok(),
                    case["ok"].as_bool().unwrap(),
                    "case {index}"
                );
                match result {
                    Ok(value) => assert_eq!(value, case["value"], "case {index}"),
                    Err(error) => assert_eq!(error.to_string(), case["error"], "case {index}"),
                }
            }
            _ => panic!("unknown case"),
        }
    }
}
#[test]
fn backup_claim_is_exclusive_durable_and_never_replayed_even_if_corrupt() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("claim.json");
    let winners = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for _ in 0..32 {
            let path = &path;
            let winners = winners.clone();
            scope.spawn(move || {
                if operations::claim_backup(
                    path,
                    &BackupOperation {
                        version: 1,
                        phase: "claimed".into(),
                        ..Default::default()
                    },
                )
                .is_ok()
                {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(winners.load(Ordering::SeqCst), 1);
    let body = fs::read(&path).unwrap();
    let op: BackupOperation = files::decode(&body, 64 << 10).unwrap();
    assert_eq!(op.phase, "claimed");
    fs::write(&path, b"partial").unwrap();
    assert!(operations::claim_backup(&path, &op).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"partial");
}
#[test]
fn secret_refusals_preserve_whole_store_and_root_publication_keeps_private_metadata() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("secrets.env");
    fs::write(&path, b"KEEP=synthetic\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    for (name, value) in [
        ("NEW", b"".as_slice()),
        ("GITHUB_TOKEN", b"synthetic"),
        ("NEW", b"line\nbreak"),
    ] {
        let set = SecretSet(BTreeMap::from([(name.into(), value.to_vec().into())]));
        assert!(set.write(root.path()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"KEEP=synthetic\n")
    }
    let set = SecretSet(BTreeMap::from([
        ("SECOND".into(), b"synthetic-b".to_vec().into()),
        ("FIRST".into(), b"synthetic-a".to_vec().into()),
    ]));
    if unsafe { libc::geteuid() } == 0 {
        set.write(root.path()).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            b"KEEP=synthetic\nFIRST=synthetic-a\nSECOND=synthetic-b\n"
        );
        let info = fs::metadata(&path).unwrap();
        assert_eq!(info.uid(), 0);
        assert_eq!(info.permissions().mode() & 0o777, 0o600)
    }
    let outside = root.path().join("outside");
    fs::rename(&path, &outside).unwrap();
    symlink(&outside, &path).unwrap();
    let before = fs::read(&outside).unwrap();
    assert!(set.write(root.path()).is_err());
    assert_eq!(fs::read(outside).unwrap(), before);
    assert!(!format!("{set:?}").contains("synthetic-a"));
}
struct Keys {
    key: RsaKey,
    calls: usize,
}
impl Effects for Keys {
    fn read(&self, path: &Path, maximum: usize) -> Result<Vec<u8>> {
        let bytes = fs::read(path)?;
        anyhow::ensure!(bytes.len() <= maximum, "fixture input bound");
        Ok(bytes)
    }
    fn release_key(&mut self, ctx: &Context, _: &str) -> Result<RsaKey> {
        ctx.check()?;
        self.calls += 1;
        Ok(self.key.clone())
    }
    fn docker(&mut self, _: &Context, _: &[&str]) -> Result<String> {
        panic!("admission reached Docker")
    }
    fn archive(
        &mut self,
        _: &Context,
        _: &[&str],
        _: u64,
        _: &mut ArchiveConsumer<'_>,
    ) -> Result<()> {
        panic!("admission requested an archive")
    }
}
fn now() -> chrono::DateTime<chrono::Utc> {
    "2026-11-01T18:00:00Z".parse().unwrap()
}
fn fixture() -> (Value, RsaKey) {
    let fixture: Value =
        serde_json::from_str(include_str!("data/go-release-authority.json")).unwrap();
    let decode = komizo::host::authority::keys::decode;
    let key = RsaKey {
        n: decode(fixture["n"].as_str().unwrap()).unwrap(),
        e: decode(fixture["e"].as_str().unwrap()).unwrap(),
    };
    (fixture, key)
}
fn frame(body: &str) -> Vec<u8> {
    use base64::Engine as _;
    format!(
        "komizo-release/v1:{}",
        base64::engine::general_purpose::STANDARD.encode(body)
    )
    .into_bytes()
}
#[test]
fn signed_release_admission_publishes_only_verified_receipts_and_task_proof_cannot_borrow_backup_scope()
 {
    let (fixture, key) = fixture();
    let mut cases = 0;
    for case in fixture["cases"].as_array().unwrap().iter().filter(|case| {
        matches!(case["kind"].as_str(), Some("release" | "backup"))
            && case["now"] == "2026-11-01T18:00:00Z"
    }) {
        let root = tempfile::tempdir().unwrap();
        let policy: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
        let revision = case["revision"].as_str().unwrap();
        let mut host = Host::new(
            root.path().into(),
            Keys {
                key: key.clone(),
                calls: 0,
            },
        )
        .unwrap();
        host.now = now;
        let wire = frame(case["body"].as_str().unwrap());
        let ctx = Context::new(Instant::now() + Duration::from_secs(2));
        if case["kind"] == "backup" {
            let result = host.verify_task_release(&ctx, &policy, &wire);
            assert_eq!(
                result.is_ok(),
                case["name"] == "release-not-backup",
                "{} scope",
                case["name"]
            );
            continue;
        }
        cases += 1;
        let dir = root.path().join("receipts");
        let output = root.path().join("output");
        let result = host.admit(
            &ctx,
            &policy,
            Admission {
                revision,
                directory: &dir,
                output: &output,
            },
            &wire,
        );
        assert_eq!(
            result.is_ok(),
            case["error"] == "",
            "{}: {result:?}",
            case["name"]
        );
        if let Ok(accepted) = result {
            assert_eq!(serde_json::to_value(&accepted).unwrap(), case["output"]);
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(&output).unwrap()).unwrap(),
                case["output"]
            );
            assert!(dir.join(format!("{revision}.json")).exists())
        } else {
            assert!(!output.exists());
            assert!(!dir.exists())
        }
    }
    assert_eq!(cases, 99);
}
#[test]
fn missing_or_expired_delivery_grants_precede_network_and_cached_acceptance() {
    use komizo::{wire::Time, workload::delivery::DeliveryAuthorization};
    let (fixture, key) = fixture();
    let case = &fixture["cases"][0];
    let mut policy: Policy = serde_json::from_value(case["policy"].clone()).unwrap();
    policy.require_delivery_authorization = true;
    let root = tempfile::tempdir().unwrap();
    let mut host = Host::new(root.path().into(), Keys { key, calls: 0 }).unwrap();
    host.now = now;
    let revision = case["revision"].as_str().unwrap();
    let wire = frame(case["body"].as_str().unwrap());
    let ctx = Context::new(Instant::now() + Duration::from_secs(2));
    let dir = root.path().join("receipts");
    let output = root.path().join("output");
    files::write_json(&dir.join(format!("{revision}.json")), &case["output"]).unwrap();
    for input in [&wire[..], b"".as_slice()] {
        assert!(
            host.admit(
                &ctx,
                &policy,
                Admission {
                    revision,
                    directory: &dir,
                    output: &output
                },
                input
            )
            .is_err()
        );
        assert_eq!(host.effects.calls, 0);
        assert!(!output.exists())
    }
    assert!(host.verify_task_release(&ctx, &policy, &wire).is_err());
    assert_eq!(host.effects.calls, 0);
    let mut grant = DeliveryAuthorization {
        version: 1,
        repository: policy.source_repository.clone(),
        repository_id: policy.repository_id.clone(),
        app: policy.app.clone(),
        revision: revision.into(),
        tree: "b".repeat(40),
        head: "c".repeat(40),
        base: "d".repeat(40),
        ci_run_id: 1,
        ci_attempt: 1,
        integration_artifact_id: 1,
        inputs_sha256: "e".repeat(64),
        kind: "owner".into(),
        scope: "production-delivery".into(),
        issued_at: Time((now() - chrono::Duration::minutes(1)).fixed_offset()),
        expires_at: Time((now() - chrono::Duration::seconds(1)).fixed_offset()),
    };
    let path = host
        .path(komizo::host::workload::DELIVERY)
        .join(&policy.app)
        .join(format!("{revision}.json"));
    files::write_json(&path, &grant).unwrap();
    assert!(host.verify_task_release(&ctx, &policy, &wire).is_err());
    assert_eq!(host.effects.calls, 0);
    grant.expires_at = Time((now() + chrono::Duration::minutes(1)).fixed_offset());
    files::write_json(&path, &grant).unwrap();
    assert_eq!(
        host.verify_task_release(&ctx, &policy, &wire).unwrap(),
        revision
    );
    assert_eq!(host.effects.calls, 1);
    host.effects.calls = 0;
    assert!(
        host.admit(
            &ctx,
            &policy,
            Admission {
                revision,
                directory: &dir,
                output: &output
            },
            b""
        )
        .is_err()
    );
    assert_eq!(host.effects.calls, 0);
    assert!(!output.exists());
}
