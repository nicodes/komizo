use komizo::host::{store::*, *};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
fn sample(index: i64) -> Sample {
    Sample {
        at: serde_json::from_value(serde_json::json!(
            chrono::DateTime::from_timestamp(1785672000 + index * 60, 0).unwrap()
        ))
        .unwrap(),
        system: System {
            cores: index,
            ..Default::default()
        },
    }
}
#[test]
fn report_versions_and_public_read_permissions_remain_explicit() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("report.json");
    let r = Report {
        v: 1,
        ..Default::default()
    };
    write_report(&path, &r).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(read_report(&path).unwrap().v, 1);
    for (body, part) in [
        (r#"{}"#, "states no schema"),
        (r#"{"v":2}"#, "speaks report schema v2"),
    ] {
        assert!(
            decode::<Report>(body.as_bytes())
                .unwrap_err()
                .to_string()
                .contains(part)
        );
    }
    assert!(decode::<Poll>(br#"{"v":1,"report":{},"metrics":{}}"#).is_ok());
    assert!(decode::<Monitor>(br#"{"v":1}"#).is_ok());
}
#[test]
fn history_keeps_ranges_newest_whole_records_and_recovers_large_legacy_files() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("history.jsonl");
    assert!(read_samples(&path, 0, i64::MAX).unwrap().is_none());
    for i in 0..10 {
        append_sample(&path, &sample(i), HISTORY_MAX, HISTORY_KEEP, None).unwrap();
    }
    let found = read_samples(&path, 1785672120, 1785672300)
        .unwrap()
        .unwrap();
    assert_eq!(
        found.iter().map(|s| s.system.cores).collect::<Vec<_>>(),
        vec![2, 3, 4, 5]
    );
    trim_lines(&path, 3, HISTORY_MAX).unwrap();
    let found = read_samples(&path, 0, i64::MAX).unwrap().unwrap();
    assert_eq!(
        found.iter().map(|s| s.system.cores).collect::<Vec<_>>(),
        vec![7, 8, 9]
    );
    for limit in [6, 7, 8, 10] {
        fs::write(&path, b"old\nmid\nnew\n").unwrap();
        trim_lines(&path, 20, limit).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            if limit >= 8 {
                b"mid\nnew\n".as_slice()
            } else {
                b"new\n"
            }
        );
    }
    fs::write(&path, b"old\r\nmid\r\nnew\r\n").unwrap();
    trim_lines(&path, 2, HISTORY_MAX).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"mid\r\nnew\r\n");
    let mut file = std::fs::File::create(&path).unwrap();
    use std::io::Write;
    for _ in 0..20000 {
        writeln!(
            file,
            "{{\"at\":\"2026-08-02T12:00:00Z\",\"system\":{{\"cores\":7}},\"padding\":\"{}\"}}",
            "x".repeat(2500)
        )
        .unwrap();
    }
    drop(file);
    append_sample(&path, &sample(999), HISTORY_MAX, HISTORY_KEEP, None).unwrap();
    assert!(fs::metadata(&path).unwrap().len() <= HISTORY_MAX / 2);
    let found = read_samples(&path, 0, i64::MAX).unwrap().unwrap();
    assert_eq!(found.last().unwrap().system.cores, 999);
}
#[test]
fn refusal_handoffs_and_symlinks_preserve_existing_data() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("history");
    fs::write(&path, b"original\n").unwrap();
    assert!(append_sample(&path, &sample(1), 1, 3, None).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"original\n");
    assert!(
        write_atomic_with(&path, &mut b"new".as_slice(), 0o640, |_| anyhow::bail!(
            "injected group refusal"
        ))
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"original\n");
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    let link = t.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(append_sample(&link, &sample(1), HISTORY_MAX, HISTORY_KEEP, None).is_err());
    assert!(read_samples(&link, 0, i64::MAX).is_err());
}
#[test]
fn metrics_span_intersection_never_claims_unmeasured_coverage() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("metrics");
    let missing = read_metrics(&path, 0, 999).unwrap();
    assert!(missing.rows.is_empty());
    assert!(missing.span.is_none());
    let metrics = Metrics {
        span: Some(Span { from: 100, to: 300 }),
        rows: vec![
            Metric {
                minute: 120,
                app: "fixture".into(),
                c2: 7,
                ..Default::default()
            },
            Metric {
                minute: 240,
                app: "fixture".into(),
                c5: 2,
                ..Default::default()
            },
        ]
        .into(),
    };
    write_metrics(&path, &metrics).unwrap();
    let found = read_metrics(&path, 150, 250).unwrap();
    assert_eq!(found.rows.len(), 1);
    assert_eq!(found.rows[0].total(), 2);
    let span = found.span.unwrap();
    assert_eq!((span.from, span.to), (150, 250));
    assert!(read_metrics(&path, 301, 400).unwrap().span.is_none());
}
