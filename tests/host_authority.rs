use komizo::{
    host::{AgentConf, authority::*},
    wire::Time,
};
use serde_json::{Value, json};
fn fixture() -> Value {
    serde_json::from_str(include_str!("data/go-host-authority.json")).unwrap()
}
fn keys(value: &Value) -> (Vec<u8>, [u8; 32]) {
    let seed = value["seed_hex"].as_str().unwrap();
    let seed: Vec<_> = (0..seed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&seed[i..i + 2], 16).unwrap())
        .collect();
    let public = public_from_seed(&seed).unwrap();
    assert_eq!(encode(&public), value["public"].as_str().unwrap());
    let mut private = seed;
    private.extend(public);
    (private, public)
}
#[test]
fn signatures_and_read_tokens_match_go_bytes_and_nanosecond_expiry_boundaries() {
    let value = fixture();
    let (private, public) = keys(&value);
    let signatures = value["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 4);
    for case in signatures {
        let command: Command = serde_json::from_value(case["command"].clone()).unwrap();
        let signed = sign_command(&private, command).unwrap();
        assert_eq!(serde_json::to_value(signed).unwrap(), case["expected"]);
    }
    let cases = value["tokens"].as_array().unwrap();
    assert_eq!(cases.len(), 36);
    for case in cases {
        let expires: Time = serde_json::from_value(case["expires"].clone()).unwrap();
        let token = sign_read_token(&private, "srv_mine", expires).unwrap();
        assert_eq!(token, case["token"].as_str().unwrap());
        let now: Time = serde_json::from_value(case["now"].clone()).unwrap();
        assert_eq!(
            verify_read_token(&public, &token, case["server"].as_str().unwrap(), now),
            case["valid"].as_bool().unwrap()
        );
    }
}
#[test]
fn eighty_go_signature_authority_and_envelope_refusals_remain_identical() {
    let value = fixture();
    let cases = value["verifications"].as_array().unwrap();
    assert_eq!(cases.len(), 80);
    for case in cases {
        let trusted: Vec<[u8; 32]> = case["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| decode(k.as_str().unwrap()).unwrap().try_into().unwrap())
            .collect();
        let now: Time = serde_json::from_value(case["now"].clone()).unwrap();
        let checked = verify_command(
            &trusted,
            case["raw"].as_str().unwrap().as_bytes(),
            case["server"].as_str().unwrap(),
            now,
        );
        let actual = match checked {
            Ok(verified) => {
                json!({"command":verified.command,"signer":encode(&verified.signer),"error":verified.unsupported.unwrap_or_default(),"refused":false})
            }
            Err(e) => {
                json!({"command":Command::default(),"signer":"","error":e.to_string(),"refused":true})
            }
        };
        assert_eq!(
            actual, case["expected"],
            "{} raw {}",
            case["name"], case["raw"]
        );
    }
}
#[test]
fn seventy_four_go_provisioning_and_key_rotation_argument_checks_remain_identical() {
    let value = fixture();
    let cases = value["arguments"].as_array().unwrap();
    assert_eq!(cases.len(), 74);
    for case in cases {
        let command: Command = serde_json::from_value(case["command"].clone()).unwrap();
        let (actual, error) = if case["kind"] == "add" {
            match command.add_of() {
                Ok(spec) => (json!(spec), String::new()),
                Err(e) => (json!(arguments::AddSpec::default()), e.to_string()),
            }
        } else {
            match command.rotate_of() {
                Ok((app, key)) => (json!([app, key]), String::new()),
                Err(e) => (json!(["", ""]), e.to_string()),
            }
        };
        assert_eq!(
            error,
            case["error"].as_str().unwrap(),
            "arguments {}",
            case["command"]
        );
        assert_eq!(actual, case["expected"], "arguments {}", case["command"]);
    }
}
#[test]
fn planted_authorities_are_distinct_from_registry_read_keys_and_validate_as_a_whole() {
    let value = fixture();
    let (_, public) = keys(&value);
    let device = format_device_key(&public);
    let log = format_log_key(&public);
    assert_eq!(parse_device_key(&device).unwrap(), public);
    assert_eq!(parse_log_key(&log).unwrap(), public);
    assert_eq!(parse_public_key(&encode(&public)).unwrap(), public);
    assert!(parse_device_key(&log).is_err());
    assert!(parse_log_key(&device).is_err());
    assert!(parse_device_key(&encode(&public)).is_err());
    let mut config = AgentConf {
        server_id: "srv_mine".into(),
        registry_key: encode(&public),
        ..Default::default()
    };
    assert!(!config.can_command());
    assert!(!config.can_read_logs());
    assert!(config.trusted_keys().unwrap().is_empty());
    config.log_keys = vec![log].into();
    assert!(config.can_read_logs());
    assert!(!config.can_command());
    config.operator_keys = vec![device.clone()].into();
    assert_eq!(config.trusted_keys().unwrap(), vec![public]);
    assert_eq!(config.log_trusted_keys().unwrap(), vec![public, public]);
    config.operator_keys = vec![device, "kmz_dev_bad".into()].into();
    assert!(config.trusted_keys().is_err());
    assert!(config.log_trusted_keys().is_err());
    let id = new_command_id().unwrap();
    assert_eq!(id.len(), 22);
    valid_command_id(&id).unwrap();
    assert!(decode("AB").is_err());
    assert_eq!(decode("AA\r\n").unwrap(), vec![0]);
}
