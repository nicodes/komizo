//! Host artifacts are authenticated build inputs carried by a release CLI.
use crate::scripts;
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
pub fn arch(uname: &str) -> Option<&'static str> {
    match uname {
        "x86_64" | "amd64" => Some("amd64"),
        "aarch64" | "arm64" => Some("arm64"),
        _ => None,
    }
}
pub fn embedded(arch: &str) -> Result<&'static [u8]> {
    match arch {
        #[cfg(packed_host_amd64)]
        "amd64" => Ok(include_bytes!(env!("KOMIZO_HOST_AMD64"))),
        #[cfg(packed_host_arm64)]
        "arm64" => Ok(include_bytes!(env!("KOMIZO_HOST_ARM64"))),
        "amd64" | "arm64" => anyhow::bail!(
            "this komizo carries no linux/{arch} agent; run mise run agents before building, or use an authenticated release archive"
        ),
        _ => anyhow::bail!("unsupported host architecture"),
    }
}
pub fn stamp() -> String {
    let mut hash = Sha256::new();
    let mut any = false;
    for name in ["amd64", "arm64"] {
        if let Ok(body) = embedded(name) {
            any = true;
            hash.update(name.as_bytes());
            hash.update(body);
        }
    }
    if any {
        format!("{:x}", hash.finalize())[..12].into()
    } else {
        String::new()
    }
}
pub fn write_new(path: &Path, body: &[u8]) -> Result<()> {
    ensure!(
        !body.is_empty() && body.len() <= 64 << 20,
        "invalid bounded host artifact"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let identity = file.metadata()?;
    let result = (|| -> Result<()> {
        file.write_all(body)?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err()
        && fs::symlink_metadata(path)
            .is_ok_and(|m| m.dev() == identity.dev() && m.ino() == identity.ino())
    {
        let _ = fs::remove_file(path);
    }
    result
}
pub struct Prepared {
    body: std::borrow::Cow<'static, [u8]>,
    stamp: String,
}
pub fn prepare(
    cli: &mut super::client::Cli<'_>,
    remote: &super::transport::Remote,
) -> Result<Prepared> {
    let uname = remote.quiet(&cli.context, "uname -m")?;
    let arch =
        arch(uname.trim()).ok_or_else(|| anyhow::anyhow!("unsupported host architecture"))?;
    let body = match embedded(arch) {
        Ok(body) => std::borrow::Cow::Borrowed(body),
        Err(_) => std::borrow::Cow::Owned(super::source::build(&cli.context, arch, cli.progress)?),
    };
    let stamp = if stamp().is_empty() {
        format!("v:{}", crate::runtime::VERSION)
    } else {
        stamp()
    };
    Ok(Prepared { body, stamp })
}
pub fn install(
    cli: &mut super::client::Cli<'_>,
    remote: &super::transport::Remote,
    prepared: &Prepared,
) -> Result<()> {
    let command = format!("cat > {}", scripts::sh_quote(scripts::STAGED_AGENT));
    remote.capture(&cli.context, &command, Some(&prepared.body), 4096)?;
    let installer = scripts::agent_install(&prepared.stamp, crate::runtime::VERSION)?;
    cli.script(remote, &installer, &Default::default())
}
pub fn run(cli: &mut super::client::Cli<'_>, args: &[String]) -> Result<()> {
    use crate::flags::Flag;
    let flags = cli.parse(
        &[Flag::text("arch", ""), Flag::text("output", "")],
        args,
        "artifact accepts only flags",
    )?;
    ensure!(
        !flags.text("output").is_empty() && matches!(flags.text("arch"), "amd64" | "arm64"),
        "artifact requires an exact architecture and new output file"
    );
    let body = embedded(flags.text("arch"))?;
    write_new(Path::new(flags.text("output")), body)?;
    cli.emit(serde_json::json!({"version":crate::runtime::VERSION,"architecture":flags.text("arch"),"sha256":format!("{:x}",Sha256::digest(body)),"stamp":stamp()}))
}
pub fn installed_stamp_differs(installed: &str, mine: &str) -> bool {
    !installed.starts_with("v:") && !mine.starts_with("v:") && installed != mine
}
