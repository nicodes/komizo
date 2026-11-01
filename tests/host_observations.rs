use komizo::{
    host::{Probe, collect, sweep},
    wire::Time,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
#[test]
fn frozen_go_sweep_knobs_effects_and_log_frames() {
    let data: Value = serde_json::from_str(include_str!("data/go-host-observations.json")).unwrap();
    assert_eq!(data["knobs"].as_array().unwrap().len(), 10);
    for case in data["knobs"].as_array().unwrap() {
        let (knob, note) = sweep::parse_knob(case["body"].as_str().unwrap());
        assert_eq!(
            json!({"age":knob.min_age_ns,"interval":knob.interval_ns,"disabled":knob.disabled,"note":note}),
            json!({"age":case["age"],"interval":case["interval"],"disabled":case["disabled"],"note":case["note"]})
        );
    }
    assert_eq!(data["sweeps"].as_array().unwrap().len(), 14);
    for case in data["sweeps"].as_array().unwrap() {
        let temp = tempfile::tempdir().unwrap();
        let probe = Probe {
            root: temp.path().into(),
        };
        let apps = probe.path("/var/lib/komizo/apps");
        std::fs::create_dir_all(&apps).unwrap();
        if !case["state"].as_str().unwrap().is_empty() {
            std::fs::write(apps.join("unrelated.env"), case["state"].as_str().unwrap()).unwrap();
        }
        let knob = sweep::Knob {
            min_age_ns: case["age"].as_i64().unwrap(),
            disabled: case["disabled"].as_bool().unwrap(),
            ..Default::default()
        };
        let now: Time = serde_json::from_value(case["expected"]["at"].clone()).unwrap();
        let kind = case["kind"].as_str().unwrap();
        let mut calls = vec![];
        let record = sweep::docker_sweep(&knob, now, &probe, |args| {
            calls.push(args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
            match args {
                ["images", ..] => {
                    if kind == "list-fail" {
                        anyhow::bail!("offline")
                    };
                    Ok(case["images"].as_str().unwrap().into())
                }
                ["ps", ..] => {
                    if kind == "refs-fail" {
                        anyhow::bail!("offline")
                    };
                    Ok(case["refs"].as_str().unwrap().into())
                }
                ["image", "inspect", ..] => {
                    if kind == "inspect-fail" && args.last() == Some(&"sha256:edge") {
                        anyhow::bail!("offline")
                    };
                    Ok(match kind {
                        "bad-size" => "lots",
                        "negative-size" => "-1",
                        "huge-size" => "9223372036854775808",
                        _ => "+1024\n",
                    }
                    .into())
                }
                ["image", "rm", _] => {
                    if kind == "remove-fail" {
                        anyhow::bail!("still referenced")
                    };
                    Ok(String::new())
                }
                _ => panic!("foreign effect {args:?}"),
            }
        });
        assert_eq!(json!(calls), case["calls"], "{kind}");
        assert_eq!(json!(record), case["expected"], "{kind}");
        let path = temp.path().join("served/sweep.json");
        sweep::write_record(&path, &record).unwrap();
        assert_eq!(json!(sweep::read_record(&path).unwrap()), case["expected"]);
    }
    assert_eq!(data["frames"].as_array().unwrap().len(), 24);
    for case in data["frames"].as_array().unwrap() {
        let body: Vec<u8> = if case["body"].is_object() {
            let head: komizo::wire::Bytes =
                serde_json::from_value(case["body"]["head"].clone()).unwrap();
            let mut body = head.to_vec();
            body.extend(std::iter::repeat_n(
                case["body"]["byte"].as_u64().unwrap() as u8,
                case["body"]["repeat"].as_u64().unwrap() as usize,
            ));
            body
        } else {
            let body: komizo::wire::Bytes = serde_json::from_value(case["body"].clone()).unwrap();
            body.to_vec()
        };
        let output = collect::decode_frames(body.as_ref(), case["tty"].as_bool().unwrap());
        assert_eq!(
            output.is_ok(),
            case["ok"].as_bool().unwrap(),
            "frame {} tty {}",
            case["i"],
            case["tty"]
        );
        if let Ok(output) = output {
            use sha2::{Digest, Sha256};
            assert_eq!(output.len(), case["output_len"].as_u64().unwrap() as usize);
            assert_eq!(
                format!("{:x}", Sha256::digest(&output)),
                case["output_sha256"].as_str().unwrap()
            );
        }
    }
}
#[test]
fn frozen_go_compose_prefixes_and_streaming_service_metadata() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-compose-collection.json")).unwrap();
    let services = BTreeMap::from([("web-1".into(), "web-1".into())]);
    for case in cases {
        assert_eq!(
            collect::with_services(case["body"].as_str().unwrap(), &services),
            case["expected"].as_str().unwrap()
        );
    }
    let metadata = r#"{"Name":"a-1","Service":"web-1"}
    [{"Name":"b-1","Service":"db"},{"Name":"empty","Service":""}]
    false
    {"Name":"a-1","Service":"updated"} malformed {"Name":"late","Service":"no"}"#;
    assert_eq!(
        collect::service_map(metadata),
        BTreeMap::from([
            ("a-1".into(), "updated".into()),
            ("b-1".into(), "db".into())
        ])
    );
}
#[cfg(target_os = "linux")]
#[test]
fn volume_disk_blocks_match_du_with_sparse_files_hardlinks_and_external_symlinks() {
    use komizo::host::{
        inventory::{ContainerInfo, Inventory, Mount},
        volume::dir_bytes,
    };
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let probe = Probe {
        root: temp.path().into(),
    };
    let volume = probe.path("/volumes/shared");
    std::fs::create_dir_all(volume.join("nested")).unwrap();
    std::fs::write(volume.join("nested/file"), vec![42; 12000]).unwrap();
    std::fs::hard_link(volume.join("nested/file"), volume.join("hardlink")).unwrap();
    std::fs::File::create(volume.join("sparse"))
        .unwrap()
        .set_len(64 << 20)
        .unwrap();
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("data"), vec![42; 1 << 20]).unwrap();
    symlink(&outside, volume.join("link")).unwrap();
    let output = std::process::Command::new("du")
        .args(["-sx", "-B1"])
        .arg(&volume)
        .output()
        .unwrap();
    assert!(output.status.success());
    let expected = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert_eq!(dir_bytes(&volume), Some(expected));
    assert!(expected < 1 << 20);
    assert_eq!(dir_bytes(&temp.path().join("missing")), None);
    let apps = probe.path("/var/lib/komizo/apps");
    std::fs::create_dir_all(&apps).unwrap();
    std::fs::write(apps.join("blog.env"), "APP_DIR=/srv/blog\n").unwrap();
    let mut inventory = Inventory::default();
    for (id, service) in [("1", "db"), ("2", "web")] {
        inventory.insert(ContainerInfo {
            id: id.into(),
            working_dir: "/srv/blog".into(),
            service: service.into(),
            mounts: vec![
                Mount {
                    name: "shared".into(),
                    source: "/volumes/shared".into(),
                },
                Mount {
                    name: "missing".into(),
                    source: "/absent".into(),
                },
            ]
            .into(),
            ..Default::default()
        });
    }
    let volumes = probe.volumes_from_inventory(&inventory, "");
    assert_eq!(volumes.len(), 2);
    assert_eq!(volumes[0].service, "db");
    assert!(volumes.iter().all(|v| v.bytes == expected));
    assert!(probe.volumes_from_inventory(&inventory, "other").is_empty());
}
#[test]
fn collection_prefix_is_bounded_and_survives_process_failure() {
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "printf 'diagnostic'; exit 7"]);
    assert_eq!(
        collect::capture_prefix(
            &mut cmd,
            100,
            Instant::now() + Duration::from_secs(2),
            &|| false
        ),
        b"diagnostic"
    );
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "while :; do printf 'abcdefgh'; done"]);
    let now = Instant::now();
    assert_eq!(
        collect::capture_prefix(&mut cmd, 100, now + Duration::from_secs(2), &|| false),
        b"abcdefgh".repeat(13)[..100]
    );
    assert!(now.elapsed() < Duration::from_secs(1));
}
#[test]
fn invalid_oversized_duration_knobs_keep_conservative_defaults() {
    let (knob, note) =
        sweep::parse_knob("MIN_AGE_DAYS=9223372036854775807\nINTERVAL_HOURS=9223372036854775807");
    assert_eq!(knob.min_age_ns, sweep::Knob::default().min_age_ns);
    assert_eq!(knob.interval_ns, sweep::Knob::default().interval_ns);
    assert!(note.contains("MIN_AGE_DAYS="));
}
#[test]
fn ten_frozen_go_native_collection_traces_preserve_prior_tails_and_never_read_proxy_logs() {
    use komizo::host::{engine::Engine, observer::Observer};
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixListener,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("data/go-native-collection.json")).unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let temp = tempfile::tempdir().unwrap();
        let probe = Probe {
            root: temp.path().into(),
        };
        let kind = case["kind"].as_str().unwrap();
        if kind != "registry-failure" {
            let apps = probe.path("/var/lib/komizo/apps");
            std::fs::create_dir_all(&apps).unwrap();
            std::fs::write(
                apps.join("blog.env"),
                if kind == "stopped" {
                    "APP_DIR=/srv/blog\nSTOPPED=1\n"
                } else {
                    "APP_DIR=/srv/blog\n"
                },
            )
            .unwrap();
        }
        let logs = temp.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(logs.join("blog.log"), "web\tprevious\n").unwrap();
        std::fs::write(logs.join("removed.log"), "removed\n").unwrap();
        let socket = temp.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let responses = case["responses"].as_object().unwrap().clone();
        let seen = Arc::new(Mutex::new(vec![]));
        let requests = seen.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopping = stopped.clone();
        let server = std::thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut first = String::new();
                    if reader.read_line(&mut first).unwrap_or(0) == 0 {
                        break;
                    }
                    let parts: Vec<_> = first.split_whitespace().collect();
                    assert_eq!(parts[0], "GET");
                    let path = parts[1];
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        if header == "\r\n" {
                            break;
                        }
                        assert!(!header.to_ascii_lowercase().starts_with("authorization:"));
                    }
                    requests.lock().unwrap().push(path.to_owned());
                    let response = responses
                        .get(path)
                        .unwrap_or_else(|| panic!("foreign endpoint {path}"));
                    let body = response["body"].as_str().unwrap();
                    let status = response["status"].as_u64().unwrap();
                    write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",body.len()).unwrap();
                    stream.flush().unwrap();
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(4);
        let engine = Engine::connect(&socket, deadline).unwrap().unwrap();
        let mut observer = Observer::with_engine(&probe, engine, deadline, || false);
        observer.collect_logs(&logs);
        drop(observer);
        stopped.store(true, Ordering::Release);
        server.join().unwrap();
        let files: BTreeMap<_, _> = std::fs::read_dir(&logs)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read_to_string(e.path()).unwrap(),
                )
            })
            .collect();
        assert_eq!(json!(files), case["files"], "{kind}");
        assert_eq!(json!(*seen.lock().unwrap()), case["calls"], "{kind}");
    }
}
