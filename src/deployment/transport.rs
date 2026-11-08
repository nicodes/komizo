use super::{
    model::MAX_DOCUMENT_BYTES,
    store::{protected_directory, read_protected},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::Shutdown,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

pub const SOCKET: &str = "/run/komizo/control.sock";

#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    ensure!(
        status == 0 && size as usize == std::mem::size_of::<libc::ucred>(),
        "kernel peer identity is unavailable"
    );
    Ok(credentials.uid)
}
#[cfg(not(target_os = "linux"))]
pub fn peer_uid(_: &UnixStream) -> Result<u32> {
    Err(anyhow!(
        "host submission requires Linux kernel peer credentials"
    ))
}

pub fn submit(input: &mut dyn Read, output: &mut dyn Write) -> Result<()> {
    let mut body = Vec::new();
    input
        .take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut body)?;
    ensure!(
        body.len() <= MAX_DOCUMENT_BYTES && !body.is_empty(),
        "submission exceeds its document bound"
    );
    let metadata = fs::symlink_metadata(SOCKET)?;
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == 0 && metadata.mode() & 0o007 == 0,
        "submission socket is not protected"
    );
    let mut stream = UnixStream::connect(SOCKET)?;
    stream.set_read_timeout(Some(Duration::from_secs(1560)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    stream.write_all(&body)?;
    stream.shutdown(Shutdown::Write)?;
    // Exports can exceed the JSON response bound. A small typed first line
    // controls exactly how many following bytes the bridge may copy.
    let mut header = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte)?;
        ensure!(
            n == 1 && header.len() < MAX_DOCUMENT_BYTES,
            "invalid daemon response framing"
        );
        if byte[0] == b'\n' {
            break;
        }
        header.push(byte[0]);
    }
    let value = crate::strict::value(&header, MAX_DOCUMENT_BYTES)?;
    output.write_all(&header)?;
    output.write_all(b"\n")?;
    if value["kind"] == "komizo.export" {
        let size = value["size_bytes"]
            .as_u64()
            .filter(|n| *n <= 64u64 << 30)
            .ok_or_else(|| anyhow!("export size is invalid"))?;
        let count = std::io::copy(&mut (&mut stream).take(size), output)?;
        ensure!(count == size, "export ended before its declared size");
    }
    let mut tail = [0u8; 1];
    ensure!(
        stream.read(&mut tail)? == 0,
        "daemon response has unexpected trailing bytes"
    );
    ensure!(value["kind"] != "komizo.error", "host refused submission");
    Ok(())
}

pub type Completion = Box<dyn FnOnce(&mut UnixStream) -> Result<()> + Send>;

pub fn serve(
    socket: &Path,
    gid: u32,
    handler: impl Fn(Vec<u8>, u32) -> Result<Completion> + Send + Sync + 'static,
) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && socket == Path::new(SOCKET),
        "daemon requires the fixed protected root socket"
    );
    let parent = socket.parent().unwrap();
    protected_directory(parent)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent.join("daemon.lock"))?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another root daemon holds the socket lease"
    );
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750))?;
    let parent_c = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(parent_c.as_ptr(), 0, gid) } == 0,
        "cannot assign submission directory group"
    );
    if let Ok(metadata) = fs::symlink_metadata(socket) {
        ensure!(
            metadata.file_type().is_socket() && metadata.uid() == 0,
            "refusing unsafe socket replacement"
        );
        fs::remove_file(socket)?;
    }
    let listener = UnixListener::bind(socket)?;
    let socket_c = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(socket_c.as_ptr(), 0, gid) } == 0,
        "cannot assign submission socket group"
    );
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    let handler = Arc::new(handler);
    let active = Arc::new(AtomicUsize::new(0));
    let readers = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        if active.fetch_add(1, Ordering::AcqRel) >= 32 {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let handler = handler.clone();
        let active = active.clone();
        let readers = readers.clone();
        std::thread::spawn(move || {
            struct Permit(Arc<AtomicUsize>);
            impl Drop for Permit {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _permit = Permit(active);
            let result = (|| -> Result<()> {
                ensure!(
                    readers.fetch_add(1, Ordering::AcqRel) < 4 || {
                        readers.fetch_sub(1, Ordering::AcqRel);
                        false
                    },
                    "host admission readers are busy"
                );
                let reader_permit = Permit(readers);
                let uid = peer_uid(&stream)?;
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                stream.set_write_timeout(Some(Duration::from_secs(30)))?;
                let mut body = Vec::new();
                (&mut stream)
                    .take(MAX_DOCUMENT_BYTES as u64 + 1)
                    .read_to_end(&mut body)?;
                ensure!(
                    !body.is_empty() && body.len() <= MAX_DOCUMENT_BYTES,
                    "invalid submission document bound"
                );
                let completion = handler(body, uid)?;
                drop(reader_permit);
                completion(&mut stream)
            })();
            if result.is_err() {
                let _ = stream.write_all(
                    b"{\"kind\":\"komizo.error\",\"version\":1,\"code\":\"request_refused\"}\n",
                );
            }
        });
    }
    drop(lock);
    Ok(())
}

pub fn submission_gid(path: &Path) -> Result<u32> {
    let body = read_protected(path, 4096)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        kind: String,
        version: u32,
        submission_gid: u32,
    }
    let config: Config = serde_json::from_value(crate::strict::value(&body, 4096)?)?;
    ensure!(
        config.kind == "komizo.controller" && config.version == 1 && config.submission_gid > 0,
        "invalid protected controller configuration"
    );
    Ok(config.submission_gid)
}
