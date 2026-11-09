use komizo_api::{config::Config, session::Session};
use serde_json::json;
use std::{
    fs,
    io::Cursor,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
};
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn root() -> PathBuf {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("komizo-session-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn config() -> Config {
    Config {
        bind: "127.0.0.1".into(),
        port: 8480,
        host: "host.example.test".into(),
        owner_client: std::env::current_exe().unwrap(),
        identity: None,
        parent_pid: None,
    }
}
fn frame(root: &std::path::Path) -> serde_json::Value {
    json!({"kind":"komizo.ui-session","version":1,"capability":TOKEN,"bootstrap_directory":root})
}
#[test]
fn owner_private_file_is_the_only_bootstrap_and_is_removed_with_its_session() {
    let root = root();
    let session = Session::receive(
        Cursor::new(serde_json::to_vec(&frame(&root)).unwrap()),
        &config(),
    )
    .unwrap();
    let path = root.join("index.html");
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, 0o700);
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains(&format!("http://127.0.0.1:8480/#komizo-session={TOKEN}"))
    );
    assert!(!session.launcher_url().contains(TOKEN));
    assert!(session.launcher_url().starts_with("file:///"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    assert!(session.authorizes(&headers));
    headers.append("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    assert!(!session.authorizes(&headers));
    drop(session);
    assert!(!root.exists());
}
#[test]
fn unsafe_directories_substitution_and_invalid_frames_never_publish_a_capability() {
    let root = root();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        Session::receive(
            Cursor::new(serde_json::to_vec(&frame(&root)).unwrap()),
            &config()
        )
        .is_err()
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.with_extension("link");
    symlink(&root, &link).unwrap();
    assert!(
        Session::receive(
            Cursor::new(serde_json::to_vec(&frame(&link)).unwrap()),
            &config()
        )
        .is_err()
    );
    fs::remove_file(link).unwrap();
    for selected in [
        json!({"kind":"wrong"}),
        {
            let mut v = frame(&root);
            v["capability"] = json!("guess");
            v
        },
        {
            let mut v = frame(&root);
            v["private"] = json!("unexpected");
            v
        },
        {
            let mut v = frame(&root);
            v["version"] = json!(1.5);
            v
        },
    ] {
        assert!(
            Session::receive(
                Cursor::new(serde_json::to_vec(&selected).unwrap()),
                &config()
            )
            .is_err()
        );
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }
    assert!(Session::receive(Cursor::new(vec![b'x'; 4097]), &config()).is_err());
    fs::write(root.join("index.html"), "previous evidence").unwrap();
    assert!(
        Session::receive(
            Cursor::new(serde_json::to_vec(&frame(&root)).unwrap()),
            &config()
        )
        .is_err()
    );
    assert_eq!(
        fs::read_to_string(root.join("index.html")).unwrap(),
        "previous evidence"
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cleanup_never_follows_a_replaced_bootstrap_file() {
    let root = root();
    let outside = root.with_extension("outside");
    fs::write(&outside, "retained").unwrap();
    let session = Session::receive(
        Cursor::new(serde_json::to_vec(&frame(&root)).unwrap()),
        &config(),
    )
    .unwrap();
    fs::remove_file(root.join("index.html")).unwrap();
    symlink(&outside, root.join("index.html")).unwrap();
    drop(session);
    assert_eq!(fs::read_to_string(&outside).unwrap(), "retained");
    assert!(
        fs::symlink_metadata(root.join("index.html"))
            .unwrap()
            .is_symlink()
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_file(outside).unwrap();
}
