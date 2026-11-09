use super::{model::*, render, validation::*};
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

fn read_document(path: &str, maximum: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= maximum as u64,
        "selected document is not a bounded ordinary file"
    );
    let mut body = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut body)?;
    let after = file.metadata()?;
    ensure!(
        body.len() <= maximum
            && body.len() as u64 == before.len()
            && (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ) == (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            ),
        "selected document changed or exceeds bounds"
    );
    Ok(body)
}

fn policy(args: &[String], out: &mut dyn Write) -> Result<()> {
    ensure!(
        args.len() == 4 || (args.len() == 6 && args[4] == "--instance"),
        "policy validation requires POLICY RELEASE and optional --instance INST"
    );
    let instance = if args.len() == 6 {
        &args[5]
    } else {
        "production"
    };
    ensure!(
        instance == "production"
            || instance.strip_prefix("pr-").is_some_and(|number| number
                .parse::<u64>()
                .is_ok_and(|value| value > 0 && value.to_string() == number)),
        "invalid policy validation instance"
    );
    let raw = crate::strict::value(
        &read_document(&args[2], MAX_DOCUMENT_BYTES)?,
        MAX_DOCUMENT_BYTES,
    )?;
    let policy: Policy = serde_json::from_value(raw.clone())
        .map_err(|_| anyhow!("selected policy has invalid schema or field types"))?;
    let release = read_release(&read_document(&args[3], MAX_DOCUMENT_BYTES)?).map_err(|error| {
        if error.downcast_ref::<serde_json::Error>().is_some() {
            anyhow!("selected release has invalid schema or field types")
        } else {
            error
        }
    })?;
    policy.admit(&release.release, instance)?;
    serde_json::to_writer(
        &mut *out,
        &serde_json::json!({"kind":"komizo.policy-validation","version":1,"ok":true,"application":policy.application,"instance":instance,"policy_digest":document_digest(&canonical(&raw)?),"release_digest":release.digest}),
    )?;
    out.write_all(b"\n")?;
    Ok(())
}

pub fn offline(args: &[String], out: &mut dyn Write) -> Result<()> {
    ensure!(
        args.len() >= 3,
        "expected release validate|render FILE or application validate FILE"
    );
    if args[0] == "policy" {
        ensure!(args[1] == "validate", "unsupported offline policy command");
        return policy(args, out);
    }
    ensure!(
        ["release", "application"].contains(&args[0].as_str()),
        "unsupported offline command"
    );
    let body = read_document(&args[2], MAX_DOCUMENT_BYTES)?;
    match (args[0].as_str(), args[1].as_str()) {
        ("application", "validate") => {
            ensure!(args.len() == 3, "unexpected validation arguments");
            let application: Application = if args[2].ends_with(".toml") {
                toml::from_str(std::str::from_utf8(&body)?)?
            } else {
                serde_json::from_value(crate::strict::value(&body, MAX_DOCUMENT_BYTES)?)?
            };
            ensure!(
                application.kind == "komizo.application"
                    && application.version == 1
                    && name(&application.application),
                "invalid application identity"
            );
            application.workload.validate()?;
            writeln!(out, "{{\"ok\":true}}")?;
        }
        ("release", "validate") => {
            ensure!(args.len() == 3, "unexpected validation arguments");
            let document = read_release(&body)?;
            writeln!(
                out,
                "{{\"ok\":true,\"release_digest\":\"{}\"}}",
                document.digest
            )?;
        }
        ("release", "render") => {
            let document = read_release(&body)?;
            let mut root = None;
            let mut upstreams = BTreeMap::new();
            let mut http = false;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--assets-root" | "--upstreams" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| anyhow!("missing render argument"))?;
                        if args[i] == "--assets-root" {
                            ensure!(root.is_none(), "duplicate assets root");
                            root = Some(value.clone());
                        } else {
                            upstreams = serde_json::from_value(crate::strict::value(
                                &read_document(value, 64 << 10)?,
                                64 << 10,
                            )?)?;
                        }
                        i += 2;
                    }
                    "--http" => {
                        ensure!(!http, "duplicate HTTP fixture flag");
                        http = true;
                        i += 1;
                    }
                    _ => return Err(anyhow!("unknown render argument")),
                }
            }
            out.write_all(
                render::caddy(
                    &document,
                    root.as_deref()
                        .ok_or_else(|| anyhow!("render requires --assets-root"))?,
                    &upstreams,
                    http,
                )?
                .as_bytes(),
            )?;
        }
        _ => return Err(anyhow!("unsupported offline command")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::{fs, io::Cursor, os::unix::fs::symlink};

    fn selected() -> (tempfile::TempDir, Vec<String>, Value) {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let value = json!({
            "kind":"komizo.policy","version":1,"application":"mailroom","authority":{"kind":"owner"},
            "artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],
            "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},
            "secrets":{"runtime":{"path":"/not-present/offline-only.env","services":["api"],"environment_file":true,"generation":"1".repeat(32)}},
            "readiness":[{"url":"https://api.mail.example/readyz","status":200,"revision_field":"revision"}]
        });
        let policy = directory.path().join("policy.json");
        let release = directory.path().join("release.json");
        fs::write(&policy, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::write(
            &release,
            include_bytes!("../../tests/fixtures/deployment/release.json"),
        )
        .unwrap();
        (
            directory,
            vec![
                "policy".into(),
                "validate".into(),
                policy.display().to_string(),
                release.display().to_string(),
            ],
            value,
        )
    }

    #[test]
    fn offline_policy_review_binds_both_identities_without_reading_secret_references() {
        let (_directory, args, value) = selected();
        let mut output = Vec::new();
        super::super::daemon::run(&args, &mut Cursor::new([]), &mut output).unwrap();
        let observed: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(observed["kind"], "komizo.policy-validation");
        assert_eq!(observed["application"], "mailroom");
        assert_eq!(observed["instance"], "production");
        assert_eq!(
            observed["policy_digest"],
            document_digest(&canonical(&value).unwrap())
        );
        assert_eq!(
            observed["release_digest"],
            read_release(&fs::read(&args[3]).unwrap()).unwrap().digest
        );
        assert_eq!(observed["ok"], true);
        assert!(
            !String::from_utf8(output)
                .unwrap()
                .contains("offline-only.env")
        );
        assert!(super::super::daemon::USAGE.contains("policy validate POLICY RELEASE"));
    }

    #[test]
    fn offline_policy_review_refuses_unsafe_inputs_and_invalid_workload_constraints() {
        let (directory, args, mut value) = selected();
        let mut output = Vec::new();
        value["limits"]["memory_bytes"] = json!(16 << 20);
        fs::write(&args[2], serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            offline(&args, &mut output)
                .unwrap_err()
                .to_string()
                .contains("service exceeds")
        );
        assert!(output.is_empty());
        let link = directory.path().join("linked.json");
        symlink(&args[2], &link).unwrap();
        let mut linked = args.clone();
        linked[2] = link.display().to_string();
        assert!(offline(&linked, &mut output).is_err());
        fs::write(&args[2], vec![b' '; MAX_DOCUMENT_BYTES + 1]).unwrap();
        assert!(
            offline(&args, &mut output)
                .unwrap_err()
                .to_string()
                .contains("bounded ordinary")
        );
        let marker = "private-value-not-a-version";
        value["version"] = json!(marker);
        fs::write(&args[2], serde_json::to_vec(&value).unwrap()).unwrap();
        let error = offline(&args, &mut output).unwrap_err().to_string();
        assert!(error.contains("schema or field types") && !error.contains(marker));
        fs::write(&args[2], b"{\"version\":1,\"version\":1}").unwrap();
        assert!(offline(&args, &mut output).is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn policy_dispatch_cannot_select_a_host_effect_or_noncanonical_instance() {
        let (_directory, args, _) = selected();
        for extra in [
            vec!["--host", "example.test"],
            vec!["--instance", "pr-01"],
            vec!["--instance", "production", "--instance", "production"],
        ] {
            let mut invalid = args.clone();
            invalid.extend(extra.into_iter().map(str::to_owned));
            let mut output = Vec::new();
            assert!(
                super::super::daemon::run(&invalid, &mut Cursor::new([]), &mut output).is_err()
            );
            assert!(output.is_empty());
        }
        let mut unknown = args;
        unknown[1] = "install".into();
        assert!(
            offline(&unknown, &mut Vec::new())
                .unwrap_err()
                .to_string()
                .contains("unsupported offline policy")
        );
    }
}
