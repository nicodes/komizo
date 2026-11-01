use anyhow::{Result, ensure};
use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
};
pub fn account() -> Result<Option<(u32, u32)>> {
    let mut capacity = 1024;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut user = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let code = unsafe {
            libc::getpwnam_r(
                c"komizo_monitor".as_ptr(),
                user.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE && capacity < 1 << 20 {
            capacity *= 2;
            continue;
        }
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code).into());
        }
        return Ok(if result.is_null() {
            None
        } else {
            Some(unsafe { ((*result).pw_uid, (*result).pw_gid) })
        });
    }
}
fn directory(path: &Path) -> Result<std::fs::File> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(path)?;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?)
}
pub fn prepare_state(path: &Path) -> Result<()> {
    let file = directory(path)?;
    if let Some((_, gid)) = account()? {
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), 0, gid) } == 0,
            "could not group state directory: {}",
            io::Error::last_os_error()
        );
        file.set_permissions(fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}
pub fn prepare_inbox_or_socket(path: &Path) -> Result<()> {
    let file = directory(path)?;
    if let Some((uid, _)) = account()? {
        ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), uid, 0) } == 0,
            "could not give directory to monitor: {}",
            io::Error::last_os_error()
        );
        file.set_permissions(fs::Permissions::from_mode(0o2750))?;
    }
    Ok(())
}
