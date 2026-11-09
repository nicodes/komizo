use std::{
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

// This is an installation proof fixture. Production installs authenticated
// executable artifacts and never invoke a privileged source compiler.
fn copy_tree(source: &Path, destination: &Path, budget: &mut u64) -> anyhow::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if ["target", ".git", "node_modules", ".native-target"]
            .iter()
            .any(|name| entry.file_name() == *name)
        {
            continue;
        }
        let path = entry.path();
        let target = destination.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&path, &target, budget)?;
        } else {
            anyhow::ensure!(kind.is_file(), "source proof refuses nonregular files");
            let size = entry.metadata()?.len();
            anyhow::ensure!(
                size <= 16 << 20 && size <= *budget,
                "source proof exceeds its bound"
            );
            let bytes = fs::read(&path)?;
            anyhow::ensure!(bytes.len() as u64 == size, "source proof file changed");
            *budget -= size;
            fs::write(target, bytes)?;
        }
    }
    Ok(())
}
#[test]
fn private_source_copy_refuses_links_and_oversized_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("ok"), b"reviewed").unwrap();
    fs::create_dir(source.join("target")).unwrap();
    fs::write(source.join("target/ignored"), b"build").unwrap();
    let dest = dir.path().join("copy");
    copy_tree(&source, &dest, &mut 64).unwrap();
    assert_eq!(fs::read(dest.join("ok")).unwrap(), b"reviewed");
    assert!(!dest.join("target").exists());
    assert!(copy_tree(&source, &dir.path().join("small"), &mut 1).is_err());
    symlink("ok", source.join("link")).unwrap();
    assert!(copy_tree(&source, &dir.path().join("linked"), &mut 64).is_err());
}
#[test]
#[ignore = "full locked source build runs only on the native Linux CI builder"]
fn exact_source_build_contains_and_supervises_its_axum_api() {
    let deadline = Instant::now() + Duration::from_secs(14 * 60);
    let original = Path::new(env!("CARGO_MANIFEST_DIR"));
    let private = tempfile::tempdir().unwrap();
    let root = private.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut budget = 128 << 20;
    for name in ["src", "vendor", "crates"] {
        copy_tree(&original.join(name), &root.join(name), &mut budget).unwrap();
    }
    copy_tree(
        &original.join(".artifacts/ui"),
        &root.join(".artifacts/ui"),
        &mut budget,
    )
    .unwrap();
    for name in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        fs::copy(original.join(name), root.join(name)).unwrap();
    }
    let target = "x86_64-unknown-linux-musl";
    let build_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| root.join("target"));
    let compiler =
        std::env::var_os("CC_x86_64_unknown_linux_musl").unwrap_or_else(|| "musl-gcc".into());
    let run = |command: &mut Command| {
        command.current_dir(root);
        let output = komizo::process::stream(
            command,
            None,
            8192,
            deadline,
            || false,
            &mut std::io::stderr(),
            &mut std::io::stderr(),
        )
        .unwrap();
        assert!(
            output.status.success(),
            "locked private source build failed: {}",
            output.status
        );
    };
    let configure = |command: &mut Command| {
        command
            .env("CARGO_TARGET_DIR", &build_root)
            .env("CC_x86_64_unknown_linux_musl", &compiler)
            .env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", &compiler)
            .env_remove("KOMIZO_API_PAYLOAD")
            .env_remove("KOMIZO_HOST_AMD64")
            .env_remove("KOMIZO_HOST_ARM64");
    };
    let mut api = Command::new("cargo");
    api.args([
        "+1.94.0",
        "build",
        "--locked",
        "--release",
        "--manifest-path",
        "crates/api/Cargo.toml",
        "--target",
        target,
    ]);
    configure(&mut api);
    run(&mut api);
    let api_bytes = fs::read(build_root.join(target).join("release/komizo-api")).unwrap();
    assert!(!api_bytes.is_empty() && api_bytes.len() <= 64 << 20);
    let mut compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    compressor.write_all(&api_bytes).unwrap();
    let payload = root.join("api.gz");
    fs::write(&payload, compressor.finish().unwrap()).unwrap();
    let mut cli = Command::new("cargo");
    cli.args([
        "+1.94.0",
        "build",
        "--locked",
        "--release",
        "--bin",
        "komizo",
        "--target",
        target,
    ]);
    configure(&mut cli);
    cli.env("KOMIZO_API_PAYLOAD", &payload);
    run(&mut cli);
    let artifact = root.join("komizo");
    fs::copy(build_root.join(target).join("release/komizo"), &artifact).unwrap();
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o700)).unwrap();
    let mut smoke = Command::new("/usr/bin/python3");
    smoke
        .args(["-I", "-B"])
        .arg(original.join("tests/acceptance/api-smoke.py"))
        .arg(artifact)
        .arg(root.join(".artifacts/ui"));
    run(&mut smoke);
}
