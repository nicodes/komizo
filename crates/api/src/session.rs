//! A launch capability reaches the browser only through an owner-private file.
use crate::{
    config::Config,
    error::{Result, invalid},
};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    kind: String,
    version: u32,
    capability: String,
    bootstrap_directory: PathBuf,
}
pub struct Session {
    capability: String,
    directory: PathBuf,
    directory_identity: (u64, u64),
    file_identity: (u64, u64),
}
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn private_directory(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || fs::canonicalize(path)? != path
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid("owner bootstrap directory is not private"));
    }
    Ok(metadata)
}
impl Session {
    pub fn receive(reader: impl Read, config: &Config) -> Result<Self> {
        let mut bytes = Vec::new();
        reader.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(invalid("owner bootstrap frame exceeds its bound"));
        }
        let frame: Frame =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid owner bootstrap frame"))?;
        if frame.kind != "komizo.ui-session"
            || frame.version != 1
            || !crate::config::hex(&frame.capability, 64)
        {
            return Err(invalid("invalid owner bootstrap identity"));
        }
        let directory = private_directory(&frame.bootstrap_directory)?;
        if fs::read_dir(&frame.bootstrap_directory)?.next().is_some() {
            return Err(invalid("owner bootstrap directory is not fresh"));
        }
        let url = format!(
            "http://{}/#komizo-session={}",
            config.authority(),
            frame.capability
        );
        let html = format!(
            "<!doctype html><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>Open Komizo</title><meta http-equiv=\"refresh\" content=\"0;url={url}\"><p><a rel=\"noreferrer\" href=\"{url}\">Open the owner UI</a></p>"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(frame.bootstrap_directory.join("index.html"))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let session = Self {
            capability: frame.capability,
            directory: frame.bootstrap_directory,
            directory_identity: identity(&directory),
            file_identity: identity(&file.metadata()?),
        };
        file.write_all(html.as_bytes())?;
        file.sync_all()?;
        if identity(&private_directory(&session.directory)?) != identity(&directory) {
            return Err(invalid("owner bootstrap directory changed"));
        }
        Ok(session)
    }
    pub fn authorizes(&self, headers: &axum::http::HeaderMap) -> bool {
        let mut values = headers.get_all("authorization").iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Some(value) = value.as_bytes().strip_prefix(b"Bearer ") else {
            return false;
        };
        bool::from(self.capability.as_bytes().ct_eq(value))
    }
    pub fn launcher_url(&self) -> String {
        let mut result = String::from("file://");
        use std::os::unix::ffi::OsStrExt;
        for byte in self.directory.join("index.html").as_os_str().as_bytes() {
            if byte.is_ascii_alphanumeric() || b"/-._~".contains(byte) {
                result.push(*byte as char);
            } else {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
        result
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let path = self.directory.join("index.html");
        if private_directory(&self.directory).is_ok_and(|m| identity(&m) == self.directory_identity)
            && fs::symlink_metadata(&path).is_ok_and(|m| {
                m.is_file()
                    && m.uid() == unsafe { libc::geteuid() }
                    && m.mode() & 0o7777 == 0o600
                    && m.nlink() == 1
                    && identity(&m) == self.file_identity
            })
        {
            let _ = fs::remove_file(path);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}
