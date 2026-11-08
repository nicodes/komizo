use aws_lc_rs::{
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{KeyPair, RSA_PKCS1_SHA256, RsaPublicKeyComponents},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use komizo::deployment::{
    authority::{self, PublicKey},
    *,
};
use serde_json::{Value, json};
use std::sync::OnceLock;

fn key() -> &'static RsaKeyPair {
    static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
    KEY.get_or_init(|| RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
}
fn public(_: &str) -> anyhow::Result<PublicKey> {
    let parts: RsaPublicKeyComponents<Vec<u8>> = key().public_key().into();
    Ok(PublicKey {
        modulus: parts.n,
        exponent: parts.e,
    })
}
fn sign(claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"fixture"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let mut signature = vec![0; key().public_modulus_len()];
    key()
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}
fn policy() -> Policy {
    serde_json::from_value(json!({
    "kind":"komizo.policy","version":1,"application":"mailroom",
    "authority":{"kind":"github","repository":"example/mailroom","repository_id":"123","workflows":{"deploy":"example/mailroom/.github/workflows/cd.yml@refs/heads/main","preview-deploy":"example/mailroom/.github/workflows/preview.yml@refs/heads/main","backup":"example/mailroom/.github/workflows/backup.yml@refs/heads/main"},"reference":"refs/heads/main","environment":"production","publisher_workflows":{"deploy":format!("example/publisher/.github/workflows/deliver.yml@{}","d".repeat(40)),"preview-deploy":format!("example/publisher/.github/workflows/preview.yml@{}","d".repeat(40))}},
    "artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],
    "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},
    "secrets":{"runtime":{"path":"/etc/komizo/secrets/runtime.env","services":["api"],"environment_file":true,"generation":"1"}},
    "readiness":[{"url":"https://mail.example/","status":200}]
})).unwrap()
}
fn request() -> Value {
    let release: Value =
        serde_json::from_str(include_str!("fixtures/deployment/release.json")).unwrap();
    let digest = read_release(&serde_json::to_vec(&release).unwrap())
        .unwrap()
        .digest;
    let mut request = json!({"kind":"komizo.request","version":1,"authority":"github","application":"mailroom","instance":"production","action":"deploy","release_digest":digest,"nonce":"1".repeat(32),"issued_at":1000,"expires_at":1120,"release":release});
    let mut proof = json!({"kind":"komizo.release-proof","version":1,"release_digest":request["release_digest"],"source_revision":"a".repeat(40),"run_id":"12345","run_attempt":"1","workflow_ref":"example/mailroom/.github/workflows/cd.yml@refs/heads/main","workflow_sha":"a".repeat(40)});
    let mut publisher = claims(&request);
    publisher["aud"] = json!(format!(
        "komizo-release:{}",
        document_digest(&authority::body_without_proof(&proof).unwrap())
    ));
    publisher["job_workflow_ref"] = json!(format!(
        "example/publisher/.github/workflows/deliver.yml@{}",
        "d".repeat(40)
    ));
    publisher["run_id"] = json!("12345");
    publisher["run_attempt"] = json!("1");
    proof["proof"] = json!(sign(&publisher));
    request["release_proof"] = proof;
    request
}
fn claims(request: &Value) -> Value {
    json!({"iss":authority::ISSUER,"aud":format!("komizo-request:{}",document_digest(&authority::body_without_proof(request).unwrap())),"iat":1000,"nbf":995,"exp":1300,"jti":"unique-token","repository":"example/mailroom","repository_id":"123","workflow_ref":"example/mailroom/.github/workflows/cd.yml@refs/heads/main","workflow_sha":"a".repeat(40),"sha":"a".repeat(40),"ref":"refs/heads/main","sub":"repo:example/mailroom:environment:production","runner_environment":"github-hosted","event_name":"push"})
}
fn admit(request: &Value, policy: &Policy, uid: u32) -> anyhow::Result<authority::AdmittedRequest> {
    authority::admit(
        &serde_json::to_vec(request)?,
        policy,
        uid,
        1050,
        &mut public,
    )
}

#[test]
fn signed_request_binds_app_action_workload_and_actual_workflow_authority() {
    let mut r = request();
    let c = claims(&r);
    r["proof"] = json!(sign(&c));
    let p = policy();
    assert!(admit(&r, &p, 1000).is_ok());
    for (field, value) in [
        ("repository", json!("example/elsewhere")),
        ("repository_id", json!("456")),
        (
            "workflow_ref",
            json!("example/mailroom/.github/workflows/test.yml@refs/heads/main"),
        ),
        ("ref", json!("refs/heads/feature")),
        ("sha", json!("b".repeat(40))),
        ("workflow_sha", json!("b".repeat(40))),
        ("sub", json!("repo:example/mailroom:pull_request")),
        ("aud", json!("other")),
        ("exp", json!(1049)),
        ("iat", json!(1100)),
        ("iss", json!("https://untrusted.example")),
    ] {
        let mut forged = c.clone();
        forged[field] = value;
        let mut changed = r.clone();
        changed["proof"] = json!(sign(&forged));
        assert!(
            admit(&changed, &p, 1000).is_err(),
            "accepted changed {field}"
        );
    }
    let mut changed = r.clone();
    changed["action"] = json!("stop");
    changed.as_object_mut().unwrap().remove("release");
    assert!(admit(&changed, &p, 1000).is_err());
    let mut changed = r.clone();
    changed["release"]["workload"]["services"]["api"]["command"] = json!(["/unreviewed"]);
    assert!(admit(&changed, &p, 1000).is_err());
}

#[test]
fn owner_is_kernel_peer_and_cannot_bypass_github_release_approval() {
    let mut r = request();
    r["authority"] = json!("owner");
    r.as_object_mut().unwrap().remove("release_proof");
    assert!(admit(&r, &policy(), 0).is_err());
    let mut p = policy();
    p.authority = Authority::Owner;
    assert!(admit(&r, &p, 1000).is_err());
    assert!(admit(&r, &p, 0).is_ok());
    r["proof"] = json!("not-owner-evidence");
    assert!(admit(&r, &p, 0).is_err());
}

#[test]
fn current_is_only_a_read_selector_and_secret_updates_are_owner_only() {
    let mut r = request();
    r.as_object_mut().unwrap().remove("release");
    r.as_object_mut().unwrap().remove("release_proof");
    r["action"] = json!("inspect");
    r["release_digest"] = json!("current");
    r["proof"] = json!(sign(&claims(&r)));
    assert!(admit(&r, &policy(), 1000).is_ok());
    r["action"] = json!("remove");
    r["proof"] = json!(sign(&claims(&r)));
    assert!(admit(&r, &policy(), 1000).is_err());
    r["action"] = json!("secret-set");
    r["release_digest"] = request()["release_digest"].clone();
    r["secret_update"] = json!({"reference":"runtime","expected_generation":"1","format":"environment-file","value":"PASSWORD=secret"});
    r["proof"] = json!(sign(&claims(&r)));
    assert!(admit(&r, &policy(), 1000).is_err());
}
