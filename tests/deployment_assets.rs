use komizo::deployment::{assets, *};
use std::os::unix::fs::MetadataExt;
use std::{fs, io::Write};

fn policy() -> Policy {
    serde_json::from_value(serde_json::json!({"kind":"komizo.policy","version":1,"application":"mailroom","authority":{"kind":"owner"},"artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example"],"limits":{"memory_bytes":1048576,"memory_swap_bytes":1048576,"milli_cpus":100,"pids":64},"readiness":[{"url":"https://mail.example/","status":200}],"max_asset_bytes":1024,"max_asset_file_bytes":512})).unwrap()
}
fn archive(entries: &[(&str, &[u8], tar::EntryType)], trailer: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes, kind) in entries {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(*kind);
        h.set_size(bytes.len() as u64);
        h.set_mode(0o777);
        h.set_uid(1234);
        h.set_gid(1234);
        h.set_cksum();
        tar.append_data(&mut h, *name, *bytes).unwrap();
    }
    let mut bytes = tar.into_inner().unwrap();
    if trailer {
        bytes.extend(b"hidden after archive");
    }
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&bytes).unwrap();
    gzip.finish().unwrap()
}

#[test]
fn static_bytes_are_exact_and_archive_metadata_cannot_choose_host_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("web.gz");
    let target = dir.path().join("web");
    let bytes = archive(
        &[
            ("index.html", b"<main>hello</main>", tar::EntryType::Regular),
            ("app/release.json", b"{}", tar::EntryType::Regular),
        ],
        false,
    );
    fs::write(&source, &bytes).unwrap();
    assets::verify_file(&source, &document_digest(&bytes), bytes.len() as u64).unwrap();
    assets::extract(&source, &target, &policy()).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        fs::read(target.join("index.html")).unwrap(),
        b"<main>hello</main>"
    );
    assert_eq!(
        fs::metadata(target.join("index.html")).unwrap().mode() & 0o777,
        0o444
    );
    assert!(assets::extract(&source, &target, &policy()).is_err());
    fs::write(&source, b"changed").unwrap();
    assert!(assets::verify_file(&source, &document_digest(&bytes), bytes.len() as u64).is_err());
}

#[test]
fn public_asset_permissions_survive_the_private_controller_umask() {
    if std::env::var_os("KOMIZO_ASSET_UMASK_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "public_asset_permissions_survive_the_private_controller_umask",
            ])
            .env("KOMIZO_ASSET_UMASK_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    unsafe {
        libc::umask(0o077);
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("web.gz");
    let target = dir.path().join("web");
    fs::write(
        &source,
        archive(&[("index.html", b"public", tar::EntryType::Regular)], false),
    )
    .unwrap();
    assets::extract(&source, &target, &policy()).unwrap();
    assert_eq!(
        fs::metadata(target.join("index.html")).unwrap().mode() & 0o777,
        0o444
    );
    assert_eq!(fs::metadata(target).unwrap().mode() & 0o777, 0o755);
}

#[test]
fn archive_links_duplicates_expansion_and_trailing_payload_refuse_before_installation() {
    for bytes in [
        archive(&[("link", b"", tar::EntryType::Symlink)], false),
        archive(
            &[
                ("same", b"a", tar::EntryType::Regular),
                ("same", b"b", tar::EntryType::Regular),
            ],
            false,
        ),
        archive(&[("large", &[b'a'; 513], tar::EntryType::Regular)], false),
        archive(
            &[
                ("a", &[b'a'; 512], tar::EntryType::Regular),
                ("b", &[b'b'; 512], tar::EntryType::Regular),
                ("c", b"c", tar::EntryType::Regular),
            ],
            false,
        ),
        archive(&[("index.html", b"ok", tar::EntryType::Regular)], true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("web.gz");
        let target = dir.path().join("web");
        fs::write(&source, bytes).unwrap();
        assert!(assets::extract(&source, &target, &policy()).is_err());
        assert!(!target.exists());
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("web.gz");
    let target = dir.path().join("web");
    let mut bytes = archive(&[("index.html", b"ok", tar::EntryType::Regular)], false);
    bytes.extend(archive(
        &[("other", b"hidden", tar::EntryType::Regular)],
        false,
    ));
    fs::write(&source, bytes).unwrap();
    assert!(assets::extract(&source, &target, &policy()).is_err());
    assert!(!target.exists());
}
