use komizo::deployment::Condition;
use komizo::deployment::{Policy, canonical, read_release};
use serde_json::{Value, json};

fn example() -> Value {
    serde_json::from_str(include_str!("fixtures/deployment/release.json")).unwrap()
}
fn read(value: &Value) -> anyhow::Result<komizo::deployment::ReleaseDocument> {
    read_release(&serde_json::to_vec(value)?)
}
fn policy() -> Policy {
    serde_json::from_value(json!({
        "kind":"komizo.policy","version":1,"application":"mailroom",
        "authority":{"kind":"owner"},
        "artifact_prefixes":["ghcr.io/example/mailroom"],
        "hostnames":["mail.example","api.mail.example"],
        "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},
        "secrets":{"runtime":{"path":"/etc/komizo/secrets/mailroom/runtime.env","services":["api"],"environment_file":true,"generation":"11111111111111111111111111111111"}},
        "readiness":[{"url":"https://api.mail.example/readyz","status":200,"revision_field":"revision"}]
    })).unwrap()
}

#[test]
fn static_release_has_no_container_or_configuration_image() {
    let mut value = example();
    value["artifacts"].as_object_mut().unwrap().remove("api");
    value["workload"]["services"] = json!({});
    value["workload"]["networks"] = json!({});
    value["workload"]["routes"].as_array_mut().unwrap().pop();
    value["workload"]["readiness"] = json!([{"url":"https://mail.example/","status":200}]);
    let document = read(&value).unwrap();
    assert!(document.release.workload.services.is_empty());
    assert_eq!(document.release.artifacts.len(), 1);
    policy().admit(&document.release, "production").unwrap();
}

#[test]
fn release_identity_binds_workload_bytes_but_not_json_key_order() {
    let first = read(&example()).unwrap();
    let mut value = example();
    value["workload"]["assets"]["web"]["serving"]["headers"]["Cache-Control"] = json!("no-store");
    assert_ne!(first.digest, read(&value).unwrap().digest);
    let unordered = json!({"z":{"b":2,"a":1},"a":"é"});
    assert_eq!(
        canonical(&unordered).unwrap(),
        "{\"a\":\"é\",\"z\":{\"a\":1,\"b\":2}}".as_bytes()
    );
}

#[test]
fn https_sites_default_hsts_without_catchall_content_policy_or_http_override() {
    let document = read(&example()).unwrap();
    let upstreams = std::collections::BTreeMap::from([("api".into(), "127.0.0.1:8080".into())]);
    let https =
        komizo::deployment::render::sites(&document, "/var/lib/komizo-assets", &upstreams, false)
            .unwrap();
    assert_eq!(
        https
            .matches("header ?Strict-Transport-Security \"max-age=31536000\"")
            .count(),
        2
    );
    assert!(!https.contains("default-src 'none'"));
    let http =
        komizo::deployment::render::sites(&document, "/var/lib/komizo-assets", &upstreams, true)
            .unwrap();
    assert!(!http.contains("Strict-Transport-Security"));
    let mut value = example();
    value["workload"]["assets"]["web"]["serving"]["headers"]["Strict-Transport-Security"] =
        json!("max-age=600; includeSubDomains");
    let explicit = komizo::deployment::render::sites(
        &read(&value).unwrap(),
        "/var/lib/komizo-assets",
        &upstreams,
        false,
    )
    .unwrap();
    assert!(explicit.contains("\"Strict-Transport-Security\" \"max-age=600; includeSubDomains\""));
    assert!(explicit.contains("header ?Strict-Transport-Security \"max-age=31536000\""));
}

#[test]
fn duplicate_unknown_and_retired_fields_refuse() {
    let mut value = example();
    value["workload"]["services"]["api"]["privileged"] = json!(true);
    assert!(read(&value).is_err());
    let raw = serde_json::to_string(&example()).unwrap();
    let duplicate = raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(read_release(duplicate.as_bytes()).is_err());
    let mut old = example();
    old["config_image"] = json!("registry.example/config:latest");
    assert!(read(&old).is_err());
}

#[test]
fn cross_application_artifact_route_and_secret_grants_refuse() {
    let document = read(&example()).unwrap();
    let grant = policy();
    grant.admit(&document.release, "production").unwrap();
    let mut other = document.release.clone();
    other.application = "elsewhere".into();
    assert!(grant.admit(&other, "production").is_err());
    let mut value = example();
    value["artifacts"]["api"]["reference"] = json!(
        "ghcr.io/example/elsewhere-api@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert!(
        grant
            .admit(&read(&value).unwrap().release, "production")
            .is_err()
    );
    let mut value = example();
    value["workload"]["routes"][0]["host"] = json!("foreign.example");
    assert!(
        grant
            .admit(&read(&value).unwrap().release, "production")
            .is_err()
    );
    let mut value = example();
    value["workload"]["services"]["api"]["environment_files"] = json!(["database-owner"]);
    assert!(
        grant
            .admit(&read(&value).unwrap().release, "production")
            .is_err()
    );
    let mut grant = policy();
    grant.secrets.get_mut("runtime").unwrap().services = vec!["database".into()];
    assert!(grant.admit(&document.release, "production").is_err());
}

#[test]
fn invalid_image_and_host_escape_inputs_refuse() {
    for reference in [
        "ghcr.io/example/mailroom-api:latest",
        "../../host@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ] {
        let mut value = example();
        value["artifacts"]["api"]["reference"] = json!(reference);
        assert!(read(&value).is_err());
    }
    let mut value = example();
    value["workload"]["services"]["api"]["volumes"] = json!([{"name":"/","target":"/host"}]);
    assert!(read(&value).is_err());
    let mut value = example();
    value["workload"]["assets"]["web"]["serving"]["deny_paths"] = json!(["/{$HOST_SECRET}"]);
    assert!(read(&value).is_err());
    let mut value = example();
    value["workload"]["assets"]["web"]["serving"]["header_rules"] =
        json!([{"path_regexp":"[{$HOST_SECRET}]","headers":{"X-Test":"match"}}]);
    assert!(read(&value).is_err());
    let mut value = example();
    value["workload"]["services"]["api"]["capabilities"] = json!(["SYS_ADMIN"]);
    assert!(read(&value).is_err());
    let mut value = example();
    value["workload"]["assets"]["web"]["serving"]["headers"]["X-Leak"] = json!("{env.HOST_SECRET}");
    assert!(read(&value).is_err());
}

#[test]
fn job_dependencies_are_typed_acyclic_and_bounded() {
    let mut value = example();
    let mut migrate = value["workload"]["services"]["api"].clone();
    migrate.as_object_mut().unwrap().remove("health");
    migrate["timeout_seconds"] = json!(120);
    value["workload"]["jobs"]["migrate"] = migrate;
    value["workload"]["services"]["api"]["needs"] = json!({"migrate":"completed"});
    read(&value).unwrap();
    value["workload"]["jobs"]["migrate"]["needs"] = json!({"api":"healthy"});
    assert!(read(&value).is_err());
    value["workload"]["jobs"]["migrate"]["needs"] = json!({});
    value["workload"]["services"]["api"]["needs"] = json!({"migrate":"healthy"});
    assert!(read(&value).is_err());
    value["workload"]["services"]["api"]["needs"] = json!({"migrate":"completed"});
    value["workload"]["jobs"]["migrate"]["timeout_seconds"] = json!(0);
    assert!(read(&value).is_err());
}

#[test]
fn retained_data_contract_is_required_and_does_not_grant_rollback() {
    let mut grant = policy();
    grant.require_stateful_contract = true;
    assert!(
        grant
            .admit(&read(&example()).unwrap().release, "production")
            .is_err()
    );
    let mut value = example();
    value["stateful_contract"] = json!({
        "version":1,"source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "schema":{"minimum":1,"maximum":1,"write":1},"data_revision":"1","credential_revision":"1",
        "migrations":[{"identity":"001.sql","sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}],
        "recovery_action":"forward_only"
    });
    let document = read(&value).unwrap();
    grant.admit(&document.release, "production").unwrap();
    let contract = document.release.stateful_contract.as_ref().unwrap();
    assert!(contract.permits_rollback(contract, 1).is_err());
}

#[test]
fn previews_cannot_inherit_production_secret_grants() {
    let mut grant = policy();
    grant.previews=Some(serde_json::from_value(json!({
        "hostname_suffix":"preview.example","max_instances":2,"max_ttl_seconds":3600,
        "readiness":[{"url":"https://{instance}.preview.example/","status":200}],
        "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256}
    })).unwrap());
    let mut value = example();
    value["workload"]["routes"][0]["host"] = json!("pr-1.preview.example");
    value["workload"]["routes"][1]["host"] = json!("pr-1-api.preview.example");
    value["workload"]["readiness"][0]["url"] = json!("https://pr-1-api.preview.example/readyz");
    assert!(grant.admit(&read(&value).unwrap().release, "pr-1").is_err());
    value["workload"]["services"]["api"]["environment_files"] = json!([]);
    grant.admit(&read(&value).unwrap().release, "pr-1").unwrap();
}

#[test]
fn static_assets_do_not_bypass_workload_bounds() {
    let mut value = example();
    for i in 0..33 {
        let mut service = value["workload"]["services"]["api"].clone();
        service["environment_files"] = json!([]);
        value["workload"]["services"][format!("worker-{i}")] = service;
    }
    assert!(read(&value).is_err());
}

#[test]
fn oversized_security_structure_refuses_before_materialization() {
    let body = format!("[{}]", vec!["0"; 40000].join(","));
    assert!(komizo::deployment::validation::bounded_value(body.as_bytes(), 4 << 20).is_err());
    let punctuation = json!({"literal":"{[,:]}".repeat(10000)});
    assert!(
        komizo::deployment::validation::bounded_value(
            &serde_json::to_vec(&punctuation).unwrap(),
            4 << 20
        )
        .is_ok()
    );
}

#[test]
fn backup_service_scope_is_explicit_and_cannot_start_jobs_or_unlisted_renderers() {
    let mut p = policy();
    p.limits.memory_bytes = 1 << 30;
    p.limits.memory_swap_bytes = 1 << 30;
    p.limits.milli_cpus = 4000;
    p.limits.pids = 4096;
    p.backup=Some(serde_json::from_value(json!({"program":"/etc/komizo/backup.bundle","sha256":format!("sha256:{}","a".repeat(64)),"timeout_seconds":300,"max_export_bytes":1 << 20,"services":["api"]})).unwrap());
    let mut document = read(&example()).unwrap();
    p.admit(&document.release, "production").unwrap();
    let mut renderer = document.release.workload.services["api"].clone();
    renderer.environment_files.clear();
    renderer.secrets.clear();
    document
        .release
        .workload
        .services
        .insert("renderer".into(), renderer);
    document
        .release
        .workload
        .services
        .get_mut("api")
        .unwrap()
        .needs
        .insert("renderer".into(), Condition::Started);
    assert!(p.admit(&document.release, "production").is_err());
    p.backup.as_mut().unwrap().services.push("renderer".into());
    p.admit(&document.release, "production").unwrap();
    let mut migrate = document.release.workload.services["renderer"].clone();
    migrate.health = None;
    migrate.timeout_seconds = Some(120);
    document
        .release
        .workload
        .jobs
        .insert("migrate".into(), migrate);
    document
        .release
        .workload
        .services
        .get_mut("api")
        .unwrap()
        .needs
        .insert("migrate".into(), Condition::Completed);
    assert!(p.admit(&document.release, "production").is_err());
    p.backup.as_mut().unwrap().services.clear();
    assert!(p.validate().is_err());
}
