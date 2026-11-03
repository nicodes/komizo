//! Developer source installations compile this exact locked Rust tree privately.
use crate::workload::activation::Context;
use anyhow::{Result, ensure};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
pub fn copy_tree(source: &Path, destination: &Path, budget: &mut usize) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if ["target", ".git", "node_modules", ".native-target"]
            .iter()
            .any(|v| name == *v)
        {
            continue;
        }
        let path = entry.path();
        let target = destination.join(name);
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&path, &target, budget)?;
        } else {
            ensure!(
                kind.is_file(),
                "source build refuses nonregular source files"
            );
            let body = super::state::read_file(&path, 16 << 20, false)?;
            ensure!(body.len() <= *budget, "source tree exceeds its bound");
            *budget -= body.len();
            fs::write(target, body)?;
        }
    }
    Ok(())
}
pub fn build(ctx: &Context, arch: &str, progress: &mut dyn Write) -> Result<Vec<u8>> {
    let target = match arch {
        "amd64" => "x86_64-unknown-linux-musl",
        "arm64" => "aarch64-unknown-linux-musl",
        _ => anyhow::bail!("unsupported host architecture"),
    };
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    ensure!(
        source.join("Cargo.lock").is_file(),
        "source tree is unavailable; install an authenticated release archive"
    );
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let mut budget = 128 << 20;
    for name in ["src", "scripts", "third_party", "api"] {
        copy_tree(&source.join(name), &root.join(name), &mut budget)?;
    }
    copy_tree(
        &source.join(".artifacts/ui"),
        &root.join(".artifacts/ui"),
        &mut budget,
    )?;
    for name in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        fs::copy(source.join(name), root.join(name))?;
    }
    let native_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => "",
    };
    let cc_key = format!("CC_{}", target.replace('-', "_"));
    let compiler = std::env::var_os(&cc_key).unwrap_or_else(|| {
        if cfg!(target_os = "linux") && arch == native_arch {
            "musl-gcc".into()
        } else {
            format!(
                "{}-linux-musl-gcc",
                if arch == "amd64" { "x86_64" } else { "aarch64" }
            )
            .into()
        }
    });
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| root.join(".native-target"));
    let configure = |command: &mut Command| {
        command
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env(&cc_key, &compiler)
            .env(
                format!(
                    "CARGO_TARGET_{}_LINKER",
                    target.replace('-', "_").to_uppercase()
                ),
                &compiler,
            )
            .env_remove("KOMIZO_API_PAYLOAD")
            .env_remove("KOMIZO_HOST_AMD64")
            .env_remove("KOMIZO_HOST_ARM64")
            .env("KOMIZO_VERSION", crate::runtime::VERSION);
    };
    let run = |command: &mut Command, progress: &mut dyn Write| -> Result<()> {
        let result = crate::process::stream(
            command,
            None,
            8192,
            ctx.deadline,
            || ctx.check().is_err(),
            &mut std::io::sink(),
            progress,
        )?;
        ensure!(
            result.status.success(),
            "locked native source build failed: {}; install Rust 1.94.0 and the musl C compiler, or use an authenticated release archive",
            result.status
        );
        Ok(())
    };
    let mut setup = Command::new("rustup");
    setup.args(["target", "add", "--toolchain", "1.94.0", target]);
    run(&mut setup, progress)?;
    let mut api = Command::new("cargo");
    api.args([
        "+1.94.0",
        "build",
        "--locked",
        "--release",
        "--manifest-path",
        "api/Cargo.toml",
        "--target",
        target,
    ]);
    configure(&mut api);
    run(&mut api, progress)?;
    let binary = super::state::read_file(
        &target_dir.join(target).join("release/komizo-api"),
        64 << 20,
        false,
    )?;
    let payload = root.join("api.gz");
    let mut zip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&binary)?;
    fs::write(&payload, zip.finish()?)?;
    let mut host = Command::new("cargo");
    host.args([
        "+1.94.0",
        "build",
        "--locked",
        "--release",
        "--bin",
        "komizo-box",
        "--target",
        target,
    ]);
    configure(&mut host);
    host.env("KOMIZO_API_PAYLOAD", &payload);
    run(&mut host, progress)?;
    super::state::read_file(
        &target_dir.join(target).join("release/komizo-box"),
        64 << 20,
        false,
    )
}
