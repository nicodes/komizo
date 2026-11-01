use komizo::caller::source;
use std::{
    fs,
    io::Write,
    os::unix::fs::symlink,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[test]
fn private_source_copy_refuses_links_and_oversized_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("ok"), b"reviewed").unwrap();
    fs::create_dir(source.join("target")).unwrap();
    fs::write(source.join("target/ignored"), b"build").unwrap();
    let dest = dir.path().join("copy");
    source::copy_tree(&source, &dest, &mut 64).unwrap();
    assert_eq!(fs::read(dest.join("ok")).unwrap(), b"reviewed");
    assert!(!dest.join("target").exists());
    assert!(source::copy_tree(&source, &dir.path().join("small"), &mut 1).is_err());
    symlink("ok", source.join("link")).unwrap();
    assert!(source::copy_tree(&source, &dir.path().join("linked"), &mut 64).is_err());
}
#[test]
fn bundled_platform_programs_are_valid_python_without_executing_effects() {
    for kind in ["platform", "proxy", "controls", "maintenance", "workload"] {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import ast,sys; ast.parse(sys.stdin.read())"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(komizo::caller::platform::program(kind).as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "{kind}");
    }
}
#[test]
#[ignore = "full locked source build runs only on the native Linux CI builder"]
fn exact_source_build_contains_and_supervises_its_axum_api() {
    let ctx =
        komizo::workload::activation::Context::new(Instant::now() + Duration::from_secs(14 * 60));
    let body = source::build(&ctx, "amd64", &mut std::io::stderr()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("komizo-box");
    komizo::caller::artifacts::write_new(&binary, &body).unwrap();
    let output = Command::new(binary)
        .args([
            "serve",
            "--config",
            dir.path().join("missing.json").to_str().unwrap(),
            "--socket",
            dir.path().join("api.sock").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!error.contains("KOMIZO_API_BINARY"), "{error}");
    assert!(error.contains("this box has no registry key"), "{error}");
    assert!(!dir.path().join("api.sock").exists());
}
