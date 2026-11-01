use komizo::{
    host::{credential::*, results::*, *},
    wire::Time,
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};
fn fixture() -> Value {
    serde_json::from_str(include_str!("data/go-host-credential-results.json")).unwrap()
}
#[test]
fn agent_credentials_match_go_storage_permissions_and_url_boundaries() {
    let value = fixture();
    for case in value["urls"].as_array().unwrap() {
        let (out, error) = match validate_api(case["input"].as_str().unwrap()) {
            Ok(url) => (url, String::new()),
            Err(e) => (String::new(), e.to_string()),
        };
        assert_eq!(out, case["output"].as_str().unwrap());
        assert_eq!(error, case["error"].as_str().unwrap());
    }
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("agent.json");
    assert!(!read_agent_conf(&path).unwrap().enrolled());
    for case in value["configs"].as_array().unwrap() {
        fs::write(&path, case["input"].as_str().unwrap()).unwrap();
        let configuration = read_agent_conf(&path).unwrap();
        assert_eq!(json!(configuration), case["configuration"]);
        assert_eq!(
            configuration.can_serve(),
            case["can_serve"].as_bool().unwrap()
        );
        assert_eq!(
            configuration.enrolled(),
            case["enrolled"].as_bool().unwrap()
        );
        assert_eq!(
            configuration.can_command(),
            case["can_command"].as_bool().unwrap()
        );
        assert_eq!(
            configuration.can_read_logs(),
            case["can_read_logs"].as_bool().unwrap()
        );
        assert_eq!(
            configuration.report_url(),
            case["report_url"].as_str().unwrap()
        );
        assert_eq!(
            configuration.enrol_url(),
            case["enrol_url"].as_str().unwrap()
        );
        write_agent_conf(&path, &configuration).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            case["written"].as_str().unwrap()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(!format!("{configuration:?}").contains("kmz_agt_test_only_fixture"));
    }
}
#[test]
fn results_keep_go_tail_truncation_bytes_and_replay_records_survive_corruption() {
    let value = fixture();
    let t = tempfile::tempdir().unwrap();
    let dir = t.path();
    for case in value["results"].as_array().unwrap() {
        let at: Time = serde_json::from_value(json!("2026-11-01T12:00:00Z")).unwrap();
        let result = Result {
            v: 99,
            id: "fixture_123".into(),
            op: "app.stop".into(),
            at,
            detail: case["detail"].as_str().unwrap().into(),
            ..Default::default()
        };
        write_result(dir, result).unwrap();
        let found = read_result(dir, "fixture_123").unwrap().unwrap();
        assert_eq!(json!(found), case["expected"]);
        let path = result_path(dir, "fixture_123").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            case["written"].as_str().unwrap()
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(applied(dir, "fixture_123"));
    }
    assert!(read_result(dir, "not_applied").unwrap().is_none());
    let path = result_path(dir, "fixture_123").unwrap();
    fs::write(&path, "broken").unwrap();
    assert!(applied(dir, "fixture_123"));
    assert!(read_result(dir, "fixture_123").is_err());
    assert!(result_path(dir, "../escape").is_err());
}
