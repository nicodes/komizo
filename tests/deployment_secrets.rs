use komizo::deployment::{secrets, *};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn secret_generations_are_immutable_and_rotation_does_not_rewrite_installed_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("runtime.env");
    fs::write(&source, b"PASSWORD=first\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let doc = read_release(include_bytes!("fixtures/deployment/release.json")).unwrap();
    let mut policy:Policy=serde_json::from_value(serde_json::json!({"kind":"komizo.policy","version":1,"application":"mailroom","authority":{"kind":"owner"},"artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],"limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},"readiness":[{"url":"https://mail.example/","status":200}],"secrets":{"runtime":{"path":source.to_str().unwrap(),"services":["api"],"environment_file":true,"generation":"1"}}})).unwrap();
    let root = dir.path().join("state");
    let first = secrets::stage(&root, &doc, &policy, "production").unwrap();
    let retained = first["runtime"].clone();
    fs::write(&source, b"PASSWORD=changed-without-generation\n").unwrap();
    assert!(secrets::stage(&root, &doc, &policy, "production").is_err());
    let update = SecretUpdate {
        reference: "runtime".into(),
        expected_generation: "1".into(),
        format: "environment-file".into(),
        value: "PASSWORD=second\n".into(),
    };
    let generation =
        secrets::rotate(&dir.path().join("policy.json"), &mut policy, &update, &root).unwrap();
    assert_eq!(generation.len(), 32);
    let next = secrets::stage(&root, &doc, &policy, "production").unwrap();
    assert_ne!(next["runtime"].path, retained.path);
    assert_eq!(fs::read(&retained.path).unwrap(), b"PASSWORD=first\n");
    assert_eq!(
        fs::read(&next["runtime"].path).unwrap(),
        b"PASSWORD=second\n"
    );
    assert!(secrets::rotate(&dir.path().join("policy.json"), &mut policy, &update, &root).is_err());
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
