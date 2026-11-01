use super::{Probe, Volume, inventory::Inventory};
use std::{collections::BTreeMap, path::Path};

/// Allocated disk blocks on the starting filesystem, without following links.
/// Live trees can change during measurement; vanished children are skipped.
#[cfg(target_os = "linux")]
pub fn dir_bytes(root: &Path) -> Option<u64> {
    use std::{collections::HashSet, os::unix::fs::MetadataExt};
    let initial = std::fs::symlink_metadata(root).ok()?;
    let device = initial.dev();
    let mut seen = HashSet::new();
    let mut pending = vec![root.to_owned()];
    let mut total = 0u64;
    while let Some(path) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.dev() != device || (metadata.nlink() > 1 && !seen.insert(metadata.ino())) {
            continue;
        }
        total = total.saturating_add(metadata.blocks().saturating_mul(512));
        if metadata.is_dir()
            && let Ok(entries) = std::fs::read_dir(path)
        {
            pending.extend(entries.filter_map(Result::ok).map(|entry| entry.path()));
        }
    }
    Some(total)
}
#[cfg(not(target_os = "linux"))]
pub fn dir_bytes(_: &Path) -> Option<u64> {
    None
}

impl Probe {
    pub fn volumes_from_inventory(&self, inventory: &Inventory, only: &str) -> Vec<Volume> {
        let mut sizes = BTreeMap::new();
        let mut volumes = vec![];
        for app in self.app_states() {
            if !only.is_empty() && app.name != only {
                continue;
            }
            for container in inventory.for_dir(app.dir()) {
                for mount in container.mounts.iter() {
                    let size = if let Some(size) = sizes.get(&mount.source) {
                        *size
                    } else {
                        let Some(size) = dir_bytes(&self.path(&mount.source)) else {
                            continue;
                        };
                        sizes.insert(mount.source.clone(), size);
                        size
                    };
                    volumes.push(Volume {
                        app: app.name.clone(),
                        service: container.service.clone(),
                        name: mount.name.clone(),
                        bytes: size,
                    });
                }
            }
        }
        volumes.sort_by(|a, b| (&a.app, &a.service, &a.name).cmp(&(&b.app, &b.service, &b.name)));
        volumes
    }
}
