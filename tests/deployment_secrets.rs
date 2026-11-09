use komizo::deployment::{secrets, *};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn secret_generations_are_immutable_and_rotation_does_not_rewrite_installed_snapshots() {
    let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let source = dir.path().join("runtime.env");
    fs::write(&source, b"PASSWORD=first\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let doc = read_release(include_bytes!("fixtures/deployment/release.json")).unwrap();
    let mut policy:Policy=serde_json::from_value(serde_json::json!({"kind":"komizo.policy","version":1,"application":"mailroom","authority":{"kind":"owner"},"artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],"limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},"readiness":[{"url":"https://mail.example/","status":200}],"secrets":{"runtime":{"path":source.to_str().unwrap(),"services":["api"],"environment_file":true,"generation":"11111111111111111111111111111111"}}})).unwrap();
    let root = dir.path().join("state");
    let first = secrets::stage(&root, &doc, &policy, "production").unwrap();
    let retained = first["runtime"].clone();
    fs::write(&source, b"PASSWORD=changed-without-generation\n").unwrap();
    assert!(secrets::stage(&root, &doc, &policy, "production").is_err());
    let update = SecretUpdate {
        reference: "runtime".into(),
        expected_generation: "11111111111111111111111111111111".into(),
        format: "environment-file".into(),
        value: "PASSWORD=second\n".into(),
    };
    let generation = secrets::rotate(
        &dir.path().join("policy.json"),
        &mut policy,
        std::slice::from_ref(&update),
        &root,
    )
    .unwrap();
    assert_eq!(generation["runtime"].len(), 32);
    let next = secrets::stage(&root, &doc, &policy, "production").unwrap();
    assert_ne!(next["runtime"].path, retained.path);
    assert_eq!(fs::read(&retained.path).unwrap(), b"PASSWORD=first\n");
    assert_eq!(
        fs::read(&next["runtime"].path).unwrap(),
        b"PASSWORD=second\n"
    );
    assert!(
        secrets::rotate(
            &dir.path().join("policy.json"),
            &mut policy,
            std::slice::from_ref(&update),
            &root
        )
        .is_err()
    );
}

#[test]
fn environment_secret_format_preserves_literal_values_and_refuses_ambiguous_assignments() {
    secrets::environment_file(
        b"URL=postgres://name:password@postgres/db\nLITERAL=$(not-host-shell) %n\n",
    )
    .unwrap();
    for body in [
        b"A=one\nA=two\n".as_slice(),
        b"export A=one\n",
        b"A=one\r\n",
        b"NO_VALUE\n",
        b"A=one\0two\n",
    ] {
        assert!(secrets::environment_file(body).is_err());
    }
}

#[test]
fn coupled_secret_versions_commit_together_and_invalid_batches_preserve_all_authority() {
    let dir = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let mut policy: Policy = serde_json::from_value(serde_json::json!({
        "kind":"komizo.policy","version":1,"application":"mailroom","authority":{"kind":"owner"},
        "artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],
        "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},
        "readiness":[{"url":"https://mail.example/","status":200}],
        "secrets":{
            "runtime":{"path":"/etc/komizo/runtime","services":["api"],"environment_file":true,"generation":"11111111111111111111111111111111"},
            "migration":{"path":"/etc/komizo/migration","jobs":["migrate"],"environment_file":true,"generation":"22222222222222222222222222222222"}
        }
    })).unwrap();
    let path = dir.path().join("policy.json");
    let original = serde_json::to_vec(&policy).unwrap();
    fs::write(&path, &original).unwrap();
    let root = dir.path().join("state");
    let updates = vec![
        SecretUpdate {
            reference: "runtime".into(),
            expected_generation: "1".repeat(32),
            format: "environment-file".into(),
            value: "PASSWORD=new-runtime\n".into(),
        },
        SecretUpdate {
            reference: "migration".into(),
            expected_generation: "2".repeat(32),
            format: "environment-file".into(),
            value: "PASSWORD=new-migrator\n".into(),
        },
    ];
    let mut stale = updates.clone();
    stale[1].expected_generation = "3".repeat(32);
    assert!(secrets::rotate(&path, &mut policy, &stale, &root).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(serde_json::to_vec(&policy).unwrap(), original);
    assert!(!root.exists());
    assert!(
        secrets::rotate(
            &path,
            &mut policy,
            &[updates[0].clone(), updates[0].clone()],
            &root
        )
        .is_err()
    );
    assert!(!root.exists());
    // Even failure at the final policy rename cannot expose a mixed set.
    let blocked = dir.path().join("blocked");
    fs::create_dir(&blocked).unwrap();
    assert!(secrets::rotate(&blocked, &mut policy, &updates, &root).is_err());
    assert_eq!(serde_json::to_vec(&policy).unwrap(), original);
    assert_eq!(fs::read(&path).unwrap(), original);
    let versions = secrets::rotate(&path, &mut policy, &updates, &root).unwrap();
    let committed: Policy = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    for update in updates {
        assert_eq!(
            committed.secrets[&update.reference].generation,
            versions[&update.reference]
        );
        assert_eq!(
            fs::read(&committed.secrets[&update.reference].path).unwrap(),
            update.value.as_bytes()
        );
    }
    assert_eq!(
        serde_json::to_vec(&committed).unwrap(),
        serde_json::to_vec(&policy).unwrap()
    );
}
