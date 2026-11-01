use komizo::{
    host::workload::{
        files,
        image_cache::{Cache, Record},
    },
    workload::activation::Context,
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    time::{Duration, Instant},
};
fn context() -> Context {
    Context::new(Instant::now() + Duration::from_secs(10))
}
fn id(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
#[test]
fn cache_avoids_reexport_and_binds_the_immutable_local_key() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("cache");
    let mut exports = 0;
    let mut space = |_: &std::path::Path| true;
    let mut cache = Cache {
        root: root.path(),
        directory: &directory,
        owner: &|_| true,
        space: &mut space,
    };
    let mut export = |_: &Context, _: &str| {
        exports += 1;
        Ok(id('b'))
    };
    for _ in 0..2 {
        assert_eq!(
            cache
                .config_digest(&context(), &id('a'), &mut export)
                .unwrap(),
            id('b')
        )
    }
    cache
        .config_digest(&context(), &id('c'), &mut export)
        .unwrap();
    assert_eq!(exports, 2);
    let mut seen = vec![];
    let found = cache
        .cached_image(&context(), &id('b'), &mut |image| {
            seen.push(image.to_owned());
            image == id('c')
        })
        .unwrap();
    assert_eq!(found, id('c'));
    assert_eq!(seen, [id('a'), id('c')]);
    assert!(
        cache
            .cached_image(&context(), &id('b'), &mut |_| false)
            .is_err()
    );
}
#[test]
fn corrupt_unprotected_noncanonical_and_foreign_cache_records_never_trigger_an_export() {
    for kind in [
        "key",
        "mode",
        "symlink",
        "unknown",
        "duplicate",
        "owner",
        "oversized",
        "directory-mode",
    ] {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("cache");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join(format!("{}.json", "a".repeat(64)));
        files::write_json(
            &path,
            &Record {
                version: 1,
                image: if kind == "key" { id('c') } else { id('a') },
                config: id('b'),
            },
        )
        .unwrap();
        match kind {
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "directory-mode" => {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap()
            }
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink("missing", &path).unwrap()
            }
            "unknown" | "duplicate" => {
                let body = fs::read_to_string(&path).unwrap();
                let body = format!(
                    "{},\"{}\":1}}",
                    body.trim_end().trim_end_matches('}'),
                    if kind == "unknown" {
                        "extra"
                    } else {
                        "version"
                    }
                );
                fs::write(&path, body).unwrap()
            }
            "oversized" => fs::write(&path, vec![b' '; 513]).unwrap(),
            _ => {}
        }
        let mut space = |_: &std::path::Path| true;
        let owner = |_: &fs::Metadata| kind != "owner";
        let mut cache = Cache {
            root: root.path(),
            directory: &directory,
            owner: &owner,
            space: &mut space,
        };
        let mut exports = 0;
        let result = cache.config_digest(&context(), &id('a'), &mut |_, _| {
            exports += 1;
            Ok(id('b'))
        });
        assert!(result.is_err(), "{kind}");
        assert_eq!(exports, 0, "{kind}");
        assert!(
            cache
                .cached_image(&context(), &id('b'), &mut |_| true)
                .is_err(),
            "{kind}"
        );
    }
}
#[test]
fn metadata_space_refusal_and_failed_or_cancelled_exports_do_not_create_cache() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("cache");
    let mut space = |_: &std::path::Path| false;
    let mut cache = Cache {
        root: root.path(),
        directory: &directory,
        owner: &|_| true,
        space: &mut space,
    };
    assert_eq!(
        cache
            .config_digest(&context(), &id('a'), &mut |_, _| Ok(id('b')))
            .unwrap(),
        id('b')
    );
    assert!(!directory.exists());
    assert!(
        cache
            .config_digest(&context(), &id('a'), &mut |_, _| anyhow::bail!(
                "export failed"
            ))
            .is_err()
    );
    assert!(!directory.exists());
    let ctx = context();
    ctx.cancelled
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(
        cache
            .config_digest(&ctx, &id('a'), &mut |_, _| panic!("cancelled export"))
            .is_err()
    );
    assert!(!directory.exists());
}
#[test]
fn concurrent_writers_bound_only_metadata_and_lookup_never_exports_or_mutates() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("cache");
    std::thread::scope(|scope| {
        for worker in 0..4 {
            let root = root.path();
            let directory = &directory;
            scope.spawn(move || {
                let mut space = |_: &std::path::Path| true;
                let mut cache = Cache {
                    root,
                    directory,
                    owner: &|_| true,
                    space: &mut space,
                };
                for n in (worker..270).step_by(4) {
                    cache
                        .config_digest(
                            &Context::new(Instant::now() + Duration::from_secs(60)),
                            &format!("sha256:{n:064x}"),
                            &mut |_, _| Ok(id('b')),
                        )
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 256);
    let mut before = fs::read_dir(&directory)
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let info = fs::metadata(&path).unwrap();
            assert_eq!(info.permissions().mode() & 0o777, 0o600);
            assert!(info.len() <= 512);
            (path.clone(), fs::read(path).unwrap())
        })
        .collect::<Vec<_>>();
    before.sort();
    let mut space = |_: &std::path::Path| panic!("lookup reserved space");
    let cache = Cache {
        root: root.path(),
        directory: &directory,
        owner: &|_| true,
        space: &mut space,
    };
    let image = cache
        .cached_image(&context(), &id('b'), &mut |_| true)
        .unwrap();
    assert!(image.starts_with("sha256:"));
    for (path, body) in before {
        assert_eq!(fs::read(path).unwrap(), body)
    }
}
