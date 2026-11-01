use super::{PREVIEWS_DIR, Record, RecordValues};
use crate::{
    statefile,
    wire::{Secret, Slice, Time},
};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};
pub fn directory_root(root: &Path) -> PathBuf {
    if root.as_os_str().is_empty() {
        PREVIEWS_DIR.into()
    } else {
        root.join("previews")
    }
}
pub fn directory(root: &Path, project: &str) -> PathBuf {
    directory_root(root).join(project)
}
fn stamp(time: &Time) -> String {
    time.0
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
pub fn write_record(root: &Path, r: &Record) -> Result<()> {
    let directory = directory(root, &r.project);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(&directory)?;
    let body = format!(
        "V=1\nAPP={}\nPR={}\nPROJECT={}\nDB_NAME={}\nDB_PASSWORD={}\nGATE_PORT={}\nIMAGES={}\nCREATED_AT={}\nLAST_USED={}\nROUTE_FILE={}\nHOST={}\nAPI_HOST={}\nBASE_PATH={}\nMEMORY_RESERVED_BYTES={}\nPRIVATE_PROFILE={}\nPROFILE_SHA256={}\n",
        r.app,
        r.pr,
        r.project,
        r.db_name,
        r.db_password.expose(),
        r.gate_port,
        r.images.join(","),
        stamp(&r.created_at),
        stamp(&r.last_used),
        r.route_file,
        r.host,
        r.api_host,
        r.base_path,
        r.memory_reserved_bytes,
        r.private_profile,
        r.profile_sha256
    );
    let mut file = tempfile::Builder::new()
        .prefix(".preview-")
        .tempfile_in(&directory)?;
    file.write_all(body.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(directory.join("preview.env"))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}
pub fn read_record(directory: &Path) -> Result<Record> {
    let body = statefile::read(&directory.join("preview.env"), 128 << 10)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let mut values = BTreeMap::new();
    for line in String::from_utf8_lossy(&body).split('\n') {
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("");
    let number = |key: &str| get(key).parse::<i64>().unwrap_or(0);
    let date = |key: &str| {
        serde_json::from_value::<Time>(Value::String(get(key).into())).unwrap_or_default()
    };
    use serde_json::Value;
    let memory = if get("MEMORY_RESERVED_BYTES").is_empty() {
        0
    } else {
        get("MEMORY_RESERVED_BYTES")
            .parse::<i64>()
            .ok()
            .filter(|n| *n >= 0)
            .ok_or_else(|| anyhow!("invalid preview memory reservation"))?
    };
    let record = Record {
        values: RecordValues {
            v: number("V"),
            app: get("APP").into(),
            pr: number("PR"),
            project: get("PROJECT").into(),
            db_name: get("DB_NAME").into(),
            gate_port: number("GATE_PORT"),
            images: if get("IMAGES").is_empty() {
                Slice::default()
            } else {
                get("IMAGES").split(',').map(str::to_owned).collect()
            },
            created_at: date("CREATED_AT"),
            last_used: date("LAST_USED"),
            route_file: get("ROUTE_FILE").into(),
            host: get("HOST").into(),
            api_host: get("API_HOST").into(),
            base_path: get("BASE_PATH").into(),
            memory_reserved_bytes: memory,
            private_profile: get("PRIVATE_PROFILE") == "true",
            profile_sha256: get("PROFILE_SHA256").into(),
        },
        db_password: Secret::new(get("DB_PASSWORD").into()),
    };
    ensure!(
        !record.app.is_empty() && !record.project.is_empty() && record.pr != 0,
        "{} is not a readable preview record",
        directory.display()
    );
    Ok(record)
}
pub fn list(root: &Path) -> Result<Vec<Record>> {
    let entries = match fs::read_dir(directory_root(root)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut entries = entries.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut output = vec![];
    for entry in entries {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        match read_record(&directory) {
            Ok(record) => output.push(record),
            Err(error) => {
                let missing = error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
                if missing
                    && fs::metadata(directory.join("compose.yml"))
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    continue;
                }
                return Err(anyhow!(
                    "preview inventory contains unreadable state: {error}"
                ));
            }
        }
    }
    output.sort_by(|a, b| a.last_used.0.cmp(&b.last_used.0));
    Ok(output)
}
