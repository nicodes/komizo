//! Held directory descriptors keep policy-controlled cgroup writes inside their verified root.
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};
pub struct Directory(File);
fn leaf(name: &str) -> io::Result<CString> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cgroup filename",
        ));
    }
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cgroup filename"))
}
impl Directory {
    pub fn open(path: &Path) -> io::Result<Self> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map(Self)
    }
    pub fn directory(&self, name: &str, create: bool) -> io::Result<Option<Self>> {
        let name = leaf(name)?;
        if create && unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o755) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        let descriptor = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some(Self(unsafe { File::from_raw_fd(descriptor) })))
    }
    pub fn read(&self, name: &str, limit: usize) -> io::Result<Option<Vec<u8>>> {
        let name = leaf(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let file = unsafe { File::from_raw_fd(descriptor) };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("cgroup value must be a regular file"));
        }
        let mut body = vec![];
        file.take(limit as u64 + 1).read_to_end(&mut body)?;
        if body.len() > limit {
            return Err(io::Error::other("cgroup value exceeds its bound"));
        }
        Ok(Some(body))
    }
    pub fn write(&self, name: &str, value: &str) -> io::Result<()> {
        self.write_inner(name, value, true)
    }
    pub fn write_existing(&self, name: &str, value: &str) -> io::Result<()> {
        self.write_inner(name, value, false)
    }
    pub fn regular(&self, name: &str) -> io::Result<bool> {
        let name = leaf(name)?;
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { status.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFREG)
    }
    fn write_inner(&self, name: &str, value: &str, create: bool) -> io::Result<()> {
        let name = leaf(name)?;
        let descriptor = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | if create { libc::O_CREAT } else { 0 }
                    | libc::O_TRUNC
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("cgroup value must be a regular file"));
        }
        file.write_all(value.as_bytes())
    }
}
