use komizo::host::{locking::HostLock, scoped};
use std::{
    fs::{self, FileTimes, Permissions},
    os::unix::fs::{PermissionsExt, symlink},
    time::{Duration, SystemTime},
};
#[test]
fn scoped_start_requires_bound_root_provenance_without_reading_credentials() {
    let root = tempfile::tempdir().unwrap();
    let app = root.path().join("srv/worker");
    let id = "0123456789abcdef0123456789abcdef";
    let generation = app.join("secrets/generations").join(id);
    fs::create_dir_all(&generation).unwrap();
    let states = root.path().join("var/lib/komizo/apps");
    fs::create_dir_all(&states).unwrap();
    let record = format!(
        "APP_DIR={}\nSCOPED_ENV=example-credentials-v2\nSCOPED_SCHEMA=27\nSCOPED_FILES=worker.env\nSCOPED_GENERATION={id}\n",
        app.display()
    );
    fs::write(states.join("worker.env"), record).unwrap();
    symlink(format!("generations/{id}"), app.join("secrets/current")).unwrap();
    let secret = generation.join("worker.env");
    fs::write(
        &secret,
        "KEY=SYNTHETIC_CREDENTIAL_MUST_NOT_BE_READ_OR_ECHOED\n",
    )
    .unwrap();
    fs::set_permissions(&secret, Permissions::from_mode(0o600)).unwrap();
    let ancient = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    fs::File::open(&secret)
        .unwrap()
        .set_times(FileTimes::new().set_accessed(ancient).set_modified(ancient))
        .unwrap();
    let error = scoped::check_start(root.path(), "worker")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SYNTHETIC_CREDENTIAL"));
    let definition = scoped::parse_definition("example-credentials-v2", "27", "worker.env")
        .unwrap()
        .unwrap();
    let marker = generation.join("provenance");
    fs::write(&marker, definition.marker(id)).unwrap();
    fs::set_permissions(&marker, Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        scoped::check_start(root.path(), "worker").is_ok(),
        unsafe { libc::geteuid() } == 0
    );
    assert_eq!(fs::metadata(&secret).unwrap().accessed().unwrap(), ancient);
    fs::set_permissions(&marker, Permissions::from_mode(0o600)).unwrap();
    assert!(scoped::check_start(root.path(), "worker").is_err());
    fs::remove_file(&marker).unwrap();
    symlink(&secret, &marker).unwrap();
    assert!(scoped::check_start(root.path(), "worker").is_err());
}
#[test]
fn unscoped_start_and_shared_app_lock_preserve_existing_lifecycle_fences() {
    let root = tempfile::tempdir().unwrap();
    let states = root.path().join("var/lib/komizo/apps");
    fs::create_dir_all(&states).unwrap();
    fs::write(states.join("blog.env"), "APP_DIR=/srv/blog\n").unwrap();
    scoped::refuse_start(root.path(), "blog").unwrap();
    let lock = scoped::lock_for_start(root.path(), "blog", Duration::ZERO, || false).unwrap();
    assert!(HostLock::acquire(root.path(), "deploy-blog.lock", Duration::ZERO, || false).is_err());
    drop(lock);
    HostLock::acquire(root.path(), "deploy-blog.lock", Duration::ZERO, || false).unwrap();
}
