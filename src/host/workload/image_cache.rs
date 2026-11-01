//! Immutable image configuration memoization cannot replace local verification.
use super::files;
use crate::{
    host::{locking::HostLock, preview::capacity::parse_floors},
    statefile, wire_struct,
    workload::{activation::Context, release::digest},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt},
    },
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};
pub const LIMIT: usize = 256;
wire_struct!(Record{version:"version":i64=>required,image:"image":String=>required,config:"config":String=>required});
pub struct Cache<'a> {
    pub root: &'a Path,
    pub directory: &'a Path,
    pub owner: &'a dyn Fn(&fs::Metadata) -> bool,
    pub space: &'a mut dyn FnMut(&Path) -> bool,
}
impl Cache<'_> {
    fn inspect_directory(&self) -> Result<()> {
        let info = fs::symlink_metadata(self.directory)?;
        ensure!(
            info.is_dir() && (self.owner)(&info) && info.mode() & 0o777 == 0o700,
            "image configuration cache requires a protected directory"
        );
        Ok(())
    }
    fn record(&self, path: &Path, image: &str) -> Result<Record> {
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_file()
                && (self.owner)(&info)
                && info.mode() & 0o777 == 0o600
                && info.len() <= 512,
            "invalid protected image configuration record"
        );
        let body = statefile::read(path, 512)?
            .ok_or_else(|| anyhow!("image configuration record unavailable"))?;
        let record: Record = serde_json::from_slice(&body)
            .map_err(|_| anyhow!("image configuration record differs from its immutable key"))?;
        ensure!(
            record.version == 1 && record.image == image && digest(&record.config),
            "image configuration record differs from its immutable key"
        );
        ensure!(
            files::json_bytes(&record)? == body,
            "noncanonical image configuration record"
        );
        Ok(record)
    }
    fn entries(&self) -> Result<Vec<PathBuf>> {
        Ok(fs::read_dir(self.directory)?
            .take(LIMIT + 1)
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?)
    }
    pub fn config_digest(
        &mut self,
        ctx: &Context,
        image: &str,
        export: &mut dyn FnMut(&Context, &str) -> Result<String>,
    ) -> Result<String> {
        ensure!(digest(image), "invalid immutable image identity");
        ctx.check()?;
        let exists = match self.inspect_directory() {
            Ok(()) => true,
            Err(e) if missing(&e) => false,
            Err(e) => return Err(e),
        };
        let path = self
            .directory
            .join(format!("{}.json", image.strip_prefix("sha256:").unwrap()));
        if exists {
            match fs::symlink_metadata(&path) {
                Ok(_) => return Ok(self.record(&path, image)?.config),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let config = export(ctx, image)?;
        ensure!(
            digest(&config),
            "invalid verified image configuration digest"
        );
        let parent = if exists {
            self.directory
        } else {
            self.directory.parent().unwrap_or(Path::new("."))
        };
        if !(self.space)(parent) {
            return Ok(config);
        }
        let _lock = HostLock::acquire(self.root, "image-metadata.lock", ctx.remaining()?, || {
            ctx.cancelled.load(Ordering::Acquire)
        })?;
        ctx.check()?;
        if !exists {
            match fs::DirBuilder::new().mode(0o700).create(self.directory) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.inspect_directory()?;
        let entries = self.entries()?;
        if entries.len() > LIMIT {
            return Ok(config);
        }
        if entries.len() >= LIMIT {
            let mut known = vec![];
            for path in entries {
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    return Ok(config);
                };
                let Some(id) = name.strip_suffix(".json") else {
                    return Ok(config);
                };
                if !digest(&format!("sha256:{id}")) {
                    return Ok(config);
                }
                let Ok(info) = fs::symlink_metadata(&path) else {
                    return Ok(config);
                };
                if !info.is_file()
                    || !(self.owner)(&info)
                    || info.mode() & 0o777 != 0o600
                    || info.len() > 512
                {
                    return Ok(config);
                }
                known.push((info.modified()?, path));
            }
            known.sort();
            fs::remove_file(&known[0].1)?;
        }
        files::write_json(
            &path,
            &Record {
                version: 1,
                image: image.into(),
                config: config.clone(),
            },
        )?;
        Ok(config)
    }
    pub fn cached_image(
        &self,
        ctx: &Context,
        expected: &str,
        present: &mut dyn FnMut(&str) -> bool,
    ) -> Result<String> {
        ensure!(digest(expected), "invalid accepted configuration identity");
        self.inspect_directory()
            .map_err(|_| anyhow!("configuration cache is not protected"))?;
        let mut entries = self.entries()?;
        ensure!(
            entries.len() <= LIMIT,
            "configuration cache exceeds lookup bound"
        );
        entries.sort();
        for path in entries {
            ctx.check()?;
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let image = format!("sha256:{}", name.strip_suffix(".json").unwrap_or_default());
            ensure!(digest(&image), "unknown configuration cache entry");
            let record = self.record(&path, &image)?;
            if record.config == expected && present(&image) {
                return Ok(image);
            }
        }
        anyhow::bail!("accepted configuration image is unavailable locally")
    }
}
pub fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
pub fn space(directory: &Path, floors: &Path) -> bool {
    let mut floor = 2_u64 << 30;
    match files::protected(floors, 1 << 20) {
        Ok(body) => match parse_floors(&String::from_utf8_lossy(&body)) {
            Ok((floors, _)) => floor = floor.max(floors.disk_bytes.max(0) as u64),
            Err(_) => return false,
        },
        Err(e) if missing(&e) => {}
        Err(_) => return false,
    }
    let Ok(path) = std::ffi::CString::new(directory.as_os_str().as_bytes()) else {
        return false;
    };
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    let stat = unsafe { stat.assume_init() };
    u128::from(stat.f_bavail)
        * u128::from(if stat.f_frsize == 0 {
            stat.f_bsize
        } else {
            stat.f_frsize
        })
        > u128::from(floor) + 512
        && stat.f_ffree > 1025
}
