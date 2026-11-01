use anyhow::Result;
use komizo::{
    host::workload::{
        files,
        transaction::{self, Credentials, Snapshot},
    },
    wire::Bytes,
    workload::{operation::Operation, policy::Policy},
};
use serde_json::{Value, json};
fn value(result: Result<impl serde::Serialize>) -> (bool, Value, String) {
    match result {
        Ok(value) => (true, serde_json::to_value(value).unwrap(), String::new()),
        Err(e) => (false, Value::Null, e.to_string()),
    }
}
#[test]
fn preserved_go_deployment_state_and_credentials() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-host-transaction.json")).unwrap();
    for (index, case) in cases.iter().enumerate() {
        let text = |key: &str| case[key].as_str().unwrap_or_default();
        let (kind, expected_ok) = (text("kind"), case["ok"].as_bool().unwrap());
        let (ok, actual, error) = match kind {
            "version" => value(transaction::deployment_version(text("input").as_bytes())),
            "env" => value(
                transaction::deployment_env(text("input").as_bytes(), text("revision"))
                    .map(|v| String::from_utf8(v).unwrap()),
            ),
            "serving" => value(transaction::bootstrap_serving(
                text("compose").as_bytes(),
                text("input").as_bytes(),
                case["retained"].as_bool().unwrap(),
            )),
            "retained" => value(transaction::parse_retained(text("input").as_bytes())),
            "credential" => {
                let credential: Credentials =
                    serde_json::from_value(case["credential"].clone()).unwrap();
                value(credential.check(&Policy {
                    image_prefix: text("prefix").into(),
                    ..Default::default()
                }))
            }
            "local" => value(Ok(transaction::local_current_allowed(
                &Operation {
                    candidate: text("candidate").into(),
                    phase: text("phase").into(),
                    ..Default::default()
                },
                text("serving"),
            ))),
            "bytes" => {
                value(serde_json::from_value::<Bytes>(case["input"].clone()).map_err(Into::into))
            }
            "snapshot" => value(files::decode::<Snapshot>(
                &serde_json::to_vec(&case["input"]).unwrap(),
                64 << 10,
            )),
            _ => panic!("unknown fixture"),
        };
        assert_eq!(ok, expected_ok, "case {index} {kind}: {error}");
        if ok {
            assert_eq!(actual, case["value"], "case {index} {kind}")
        } else if !matches!(kind, "bytes" | "snapshot") {
            assert_eq!(error, case["error"], "case {index} {kind}")
        }
    }
    assert!(cases.len() > 750);
}
#[test]
fn root_files_are_bounded_atomic_and_never_follow_leaf_links() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input");
    files::create_private(&input, b"secret\0bytes").unwrap();
    assert!(files::create_private(&input, b"replace").is_err());
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(files::protected(&input, 12).unwrap(), b"secret\0bytes")
    } else {
        assert!(files::protected(&input, 12).is_err())
    }
    assert!(files::protected(&input, 11).is_err());
    let alias = root.path().join("alias");
    symlink(&input, &alias).unwrap();
    assert!(files::protected(&alias, 64).is_err());
    fs::set_permissions(&input, fs::Permissions::from_mode(0o622)).unwrap();
    assert!(files::protected(&input, 64).is_err());
    let output = root.path().join("state");
    files::write_json(
        &output,
        &json!({"body":"<>&\u{2028}","nil":Bytes::default(),"empty":Bytes::from(vec![])}),
    )
    .unwrap();
    let body = fs::read_to_string(&output).unwrap();
    assert!(body.contains("\\u003c\\u003e\\u0026\\u2028"));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["nil"],
        Value::Null
    );
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(transaction::write_deployment(&alias, b"corrupt", 0o600).is_err());
    assert_eq!(fs::read(&input).unwrap(), b"secret\0bytes");
    let queue = root.path().join("activations");
    fs::create_dir(&queue).unwrap();
    files::activation_idle(&queue).unwrap();
    files::create_private(&queue.join("pending.json"), b"{}").unwrap();
    assert!(files::activation_idle(&queue).is_err());
    files::remove(&queue.join("pending.json")).unwrap();
    fs::create_dir(root.path().join("upgrades")).unwrap();
    symlink("missing", root.path().join("upgrades/pending.json")).unwrap();
    assert!(files::activation_idle(&queue).is_err());
}
#[test]
fn snapshot_restores_original_bytes_modes_and_absence() {
    use std::{fs, path::Path};
    let root = tempfile::tempdir().unwrap();
    let old = root.path().join("original");
    let absent = root.path().join("absent");
    fs::write(&old, b"changed").unwrap();
    fs::write(&absent, b"created").unwrap();
    let snapshot:Snapshot=serde_json::from_value(json!({"version":1,"operation_id":"a".repeat(32),"files":[{"path":old,"exists":true,"body":"AAEC/w==","mode":384},{"path":absent,"exists":false,"mode":0}]})).unwrap();
    transaction::restore_snapshot(&snapshot, &mut |path: &Path, body: &[u8], mode: u32| {
        assert_eq!(mode, 0o600);
        fs::write(path, body)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::read(old).unwrap(), [0, 1, 2, 255]);
    assert!(!absent.exists());
    assert!(
        !format!(
            "{:?}",
            serde_json::from_value::<Credentials>(json!({"password":"super-private"})).unwrap()
        )
        .contains("super-private")
    );
}
