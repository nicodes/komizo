use komizo::{
    host::preview::{Record, effects, knob, profile},
    workload::activation::Context,
};
use std::time::{Duration, Instant};
#[test]
fn foreign_preview_networks_refuse_before_attachment_or_removal() {
    let ctx = Context::new(Instant::now() + Duration::from_secs(1));
    for operation in 0..4 {
        let mut calls = vec![];
        let mut run = |_: &Context, input: &str, args: &[&str]| {
            assert!(input.is_empty());
            calls.push(args.iter().map(|v| v.to_string()).collect::<Vec<_>>());
            Ok("another-preview".into())
        };
        let result = match operation {
            0 => effects::ensure_ingress(&ctx, &mut run, "example-pr-7", "proxy").map(|_| ()),
            1 => effects::ensure_backend(&ctx, &mut run, "example-pr-7", true),
            2 => effects::remove_network(&ctx, &mut run, "example-pr-7", "proxy", true, false),
            _ => effects::remove_network(&ctx, &mut run, "example-pr-7", "proxy", false, true),
        };
        assert!(result.is_err());
        assert_eq!(calls.len(), 1);
        assert_eq!(&calls[0][..2], &["network", "inspect"]);
    }
}
#[test]
fn operator_yaml_alias_expansion_and_recursive_aliases_are_bounded() {
    let profile=profile::parse(br#"{"version":1,"services":["gate"],"image_prefixes":["example/gate:"],"compose_template":"services: {}"}"#).unwrap();
    let (record, k) = (Record::default(), knob::Knob::default());
    let mut bomb = "x-a: &a [a,a,a,a,a,a,a,a]\n".to_owned();
    for index in 1..12 {
        let prev = if index == 1 {
            "a".to_owned()
        } else {
            format!("a{}", index - 1)
        };
        bomb.push_str(&format!(
            "x-a{index}: &a{index} [{}]\n",
            vec![format!("*{prev}"); 8].join(",")
        ));
    }
    for body in [
        bomb,
        "x-a: &a [*a]\nservices: {}\n".into(),
        "services: {}\nservices: {}\n".into(),
    ] {
        let result = profile.validate_compose(&body, &record, &k, "ingress");
        assert!(result.is_err());
    }
}
#[test]
fn profile_configuration_requires_root_private_parents_and_drained_previews() {
    use komizo::host::preview::{RecordValues, store};
    let root = tempfile::tempdir().unwrap();
    let ctx = Context::new(Instant::now() + Duration::from_secs(2));
    let body=br#"{"version":1,"services":["gate"],"image_prefixes":["example/gate:"],"compose_template":"services: {}"}"#;
    let result = profile::configure(&ctx, root.path(), "example", body);
    if unsafe { libc::geteuid() } != 0 {
        assert!(result.is_err());
        assert!(!root.path().join("etc").exists());
        return;
    }
    result.unwrap();
    let path = root.path().join("etc/komizo/preview-profiles/example.json");
    assert_eq!(std::fs::read(&path).unwrap(), body);
    profile::read(root.path(), "example").unwrap().unwrap();
    assert!(profile::configure(&ctx, root.path(), "example", br#"{"version":2}"#).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), body);
    store::write_record(
        root.path(),
        &Record {
            values: RecordValues {
                v: 1,
                app: "example".into(),
                pr: 1,
                project: "example-pr-1".into(),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        profile::configure(&ctx, root.path(), "example", body)
            .unwrap_err()
            .to_string()
            .contains("drain application previews")
    );
    assert_eq!(std::fs::read(path).unwrap(), body);
}
