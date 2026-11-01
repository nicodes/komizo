use komizo::{
    caller::{doctor, keys},
    wire::Bytes,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[test]
fn frozen_go_openssh_keys_and_prerequisite_decisions() {
    let data: Value =
        serde_json::from_str(include_str!("data/go-caller-keys-doctor.json")).unwrap();
    assert_eq!(data["originals"].as_array().unwrap().len(), 12);
    assert_eq!(data["keys"].as_array().unwrap().len(), 132);
    for case in data["originals"].as_array().unwrap() {
        let seed: Bytes = serde_json::from_value(case["seed"].clone()).unwrap();
        let check: Bytes = serde_json::from_value(case["check"].clone()).unwrap();
        let expected: Bytes = serde_json::from_value(case["body"].clone()).unwrap();
        let key = keys::encode(
            seed.as_ref().try_into().unwrap(),
            case["comment"].as_str().unwrap(),
            check.as_ref().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(key.private.as_ref(), expected.as_ref());
        assert_eq!(
            keys::decode(&key.private, case["comment"].as_str().unwrap())
                .unwrap()
                .public,
            key.public
        );
    }
    for case in data["keys"].as_array().unwrap() {
        let body: Bytes = serde_json::from_value(case["body"].clone()).unwrap();
        let result = keys::decode(&body, case["comment"].as_str().unwrap());
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{} comment {}",
            case["kind"],
            case["comment"]
        );
        if let Ok(key) = result {
            assert_eq!(key.private.as_ref(), body.as_ref());
            assert_eq!(key.public, case["public"].as_str().unwrap());
        }
    }
    for case in data["doctors"].as_array().unwrap() {
        let result = doctor::decode("root@fixture", case["body"].as_str().unwrap());
        assert_eq!(result.is_ok(), case["ok"].as_bool().unwrap());
        match result {
            Ok(value) => assert_eq!(json!(value), case["expected"]),
            Err(e) => assert_eq!(e.to_string(), case["error"].as_str().unwrap()),
        }
    }
    let digest: Bytes = serde_json::from_value(data["script_sha256"].clone()).unwrap();
    assert_eq!(
        Sha256::digest(doctor::SCRIPT.as_bytes()).as_slice(),
        digest.as_ref()
    );
}
#[test]
fn generated_keys_are_distinct_private_in_debug_and_bound_to_the_exact_comment() {
    let comment = keys::comment("komizo-fixture", " host.example ");
    assert_eq!(comment, "komizo:komizo-fixture@host.example");
    let a = keys::generate(&comment).unwrap();
    let b = keys::generate(&comment).unwrap();
    assert_ne!(a.private.as_ref(), b.private.as_ref());
    assert_ne!(a.public, b.public);
    assert!(keys::decode(&a.private, &comment).is_ok());
    assert!(keys::decode(&a.private, "komizo:other@host.example").is_err());
    let debug = format!("{a:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("BEGIN OPENSSH"));
}
