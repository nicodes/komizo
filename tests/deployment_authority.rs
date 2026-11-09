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
    "authority":{
        "kind":"github","repository":"example/mailroom","repository_id":"123",
        "workflows":{
            "deploy":["example/mailroom/.github/workflows/cd.yml@refs/heads/main"],
            "preview-deploy":["example/mailroom/.github/workflows/preview.yml@refs/heads/main"],
            "backup":["example/mailroom/.github/workflows/backup.yml@refs/heads/main","example/mailroom/.github/workflows/cd.yml@refs/heads/main"]
        },
        "reference":"refs/heads/main","environment":"production",
        "publisher_workflows":{
            "deploy":format!("example/publisher/.github/workflows/deliver.yml@{}","d".repeat(40)),
            "preview-deploy":format!("example/publisher/.github/workflows/preview.yml@{}","d".repeat(40))
        }
    },
    "artifact_prefixes":["ghcr.io/example/mailroom"],"hostnames":["mail.example","api.mail.example"],
    "limits":{"memory_bytes":268435456,"memory_swap_bytes":268435456,"milli_cpus":500,"pids":256},
    "secrets":{"runtime":{"path":"/etc/komizo/secrets/runtime.env","services":["api"],"environment_file":true,"generation":"11111111111111111111111111111111"}},
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
        ("event_name", json!("issue_comment")),
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

fn preview_policy() -> Policy {
    let mut value = serde_json::to_value(policy()).unwrap();
    let mut runtime = value["secrets"]["runtime"].clone();
    runtime["path"] = json!("/var/lib/komizo/preview-secrets/mailroom/{instance}/runtime.env");
    value["previews"] = json!({
        "environment":"Preview","hostname_suffix":"preview.example",
        "max_instances":2,"max_ttl_seconds":3600,
        "limits":value["limits"],"secrets":{"runtime":runtime},
        "readiness":[{"url":"https://{instance}-api.preview.example/readyz","status":200,"revision_field":"revision"}]
    });
    serde_json::from_value(value).unwrap()
}

fn preview_claims(request: &Value) -> Value {
    let mut value = claims(request);
    value["workflow_ref"] = json!("example/mailroom/.github/workflows/preview.yml@refs/heads/main");
    value["sub"] = json!("repo:example/mailroom:environment:Preview");
    value["event_name"] = json!("issue_comment");
    value
}

fn preview_request() -> Value {
    let mut value = request();
    value["instance"] = json!("pr-7");
    value["ttl_seconds"] = json!(3600);
    value["release"]["source"]["revision"] = json!("b".repeat(40));
    value["release"]["workload"]["routes"][0]["host"] = json!("pr-7.preview.example");
    value["release"]["workload"]["routes"][1]["host"] = json!("pr-7-api.preview.example");
    value["release"]["workload"]["readiness"][0]["url"] =
        json!("https://pr-7-api.preview.example/readyz");
    value["release_digest"] = json!(
        read_release(&serde_json::to_vec(&value["release"]).unwrap())
            .unwrap()
            .digest
    );
    let mut proof = value["release_proof"].clone();
    proof.as_object_mut().unwrap().remove("proof");
    proof["release_digest"] = value["release_digest"].clone();
    proof["source_revision"] = json!("b".repeat(40));
    proof["workflow_ref"] = json!("example/mailroom/.github/workflows/preview.yml@refs/heads/main");
    let mut publisher = preview_claims(&value);
    publisher["aud"] = json!(format!(
        "komizo-release:{}",
        document_digest(&authority::body_without_proof(&proof).unwrap())
    ));
    publisher["job_workflow_ref"] = json!(format!(
        "example/publisher/.github/workflows/preview.yml@{}",
        "d".repeat(40)
    ));
    publisher["run_id"] = proof["run_id"].clone();
    publisher["run_attempt"] = proof["run_attempt"].clone();
    proof["proof"] = json!(sign(&publisher));
    value["release_proof"] = proof;
    value["proof"] = json!(sign(&preview_claims(&value)));
    value
}

#[test]
fn preview_comments_require_the_protected_main_workflow_and_selected_source_publisher() {
    let policy = preview_policy();
    let request = preview_request();
    assert!(admit(&request, &policy, 1000).is_ok());
    for (field, value) in [
        ("event_name", json!("pull_request")),
        ("event_name", json!("discussion_comment")),
        ("sub", json!("repo:example/mailroom:environment:production")),
        (
            "workflow_ref",
            json!("example/mailroom/.github/workflows/cd.yml@refs/heads/main"),
        ),
        ("ref", json!("refs/heads/feature")),
    ] {
        let mut changed = request.clone();
        let mut caller = preview_claims(&changed);
        caller[field] = value;
        changed["proof"] = json!(sign(&caller));
        assert!(admit(&changed, &policy, 1000).is_err());
    }
    let publisher = authority::verify_token(
        request["release_proof"]["proof"].as_str().unwrap(),
        &format!(
            "komizo-release:{}",
            document_digest(&authority::body_without_proof(&request["release_proof"]).unwrap())
        ),
        1050,
        &mut public,
    )
    .unwrap();
    for (field, value) in [
        ("event_name", json!("pull_request")),
        ("sub", json!("repo:example/mailroom:environment:production")),
        (
            "job_workflow_ref",
            json!(format!(
                "example/publisher/.github/workflows/preview.yml@{}",
                "e".repeat(40)
            )),
        ),
        ("workflow_sha", json!("b".repeat(40))),
        ("run_attempt", json!("2")),
    ] {
        let mut changed = request.clone();
        let mut forged = publisher.clone();
        forged[field] = value;
        changed["release_proof"]["proof"] = json!(sign(&forged));
        changed["proof"] = json!(sign(&preview_claims(&changed)));
        assert!(admit(&changed, &policy, 1000).is_err());
    }
}

#[test]
fn preview_comment_can_plan_its_origin_with_read_only_inspection() {
    let mut request = preview_request();
    request["action"] = json!("inspect");
    request["release_digest"] = json!("current");
    for field in ["release", "release_proof", "ttl_seconds", "proof"] {
        request.as_object_mut().unwrap().remove(field);
    }
    request["proof"] = json!(sign(&preview_claims(&request)));
    assert!(admit(&request, &preview_policy(), 1000).is_ok());
    request["instance"] = json!("production");
    let mut caller = claims(&request);
    caller["workflow_ref"] =
        json!("example/mailroom/.github/workflows/preview.yml@refs/heads/main");
    caller["event_name"] = json!("issue_comment");
    request["proof"] = json!(sign(&caller));
    assert!(admit(&request, &preview_policy(), 1000).is_err());
}

#[test]
fn manual_and_predeployment_backups_share_only_their_explicit_action_authority() {
    let p = policy();
    let mut r = request();
    for field in ["release", "release_proof"] {
        r.as_object_mut().unwrap().remove(field);
    }
    for action in ["backup", "export"] {
        r["action"] = json!(action);
        if action == "export" {
            r["operation"] = json!("c".repeat(32));
            r["export_name"] = json!("snapshot.cms");
        }
        for (workflow, event) in [("cd.yml", "push"), ("backup.yml", "workflow_dispatch")] {
            let mut c = claims(&r);
            c["workflow_ref"] = json!(format!(
                "example/mailroom/.github/workflows/{workflow}@refs/heads/main"
            ));
            c["event_name"] = json!(event);
            r["proof"] = json!(sign(&c));
            assert!(admit(&r, &p, 1000).is_ok());
        }
        let mut c = claims(&r);
        c["workflow_ref"] = json!("example/mailroom/.github/workflows/test.yml@refs/heads/main");
        r["proof"] = json!(sign(&c));
        assert!(admit(&r, &p, 1000).is_err());
    }
    let mut deployment = request();
    let mut c = claims(&deployment);
    c["workflow_ref"] = json!("example/mailroom/.github/workflows/backup.yml@refs/heads/main");
    deployment["proof"] = json!(sign(&c));
    assert!(admit(&deployment, &p, 1000).is_err());
}

#[test]
fn caller_lists_are_finite_unique_and_require_explicit_main_workflows() {
    let original = serde_json::to_value(policy()).unwrap();
    let approved = "example/mailroom/.github/workflows/backup.yml@refs/heads/main";
    for callers in [
        json!([]),
        json!([approved, approved]),
        json!(["example/foreign/.github/workflows/backup.yml@refs/heads/main"]),
        json!(["example/mailroom/.github/workflows/backup.yml@refs/heads/feature"]),
        json!(
            (0..9)
                .map(|i| format!(
                    "example/mailroom/.github/workflows/backup-{i}.yml@refs/heads/main"
                ))
                .collect::<Vec<_>>()
        ),
    ] {
        let mut changed = original.clone();
        changed["authority"]["workflows"]["backup"] = callers;
        let parsed: Policy = serde_json::from_value(changed).unwrap();
        assert!(parsed.validate().is_err());
    }
    let mut legacy = original.clone();
    legacy["authority"]["workflows"]["backup"] = json!(approved);
    assert!(serde_json::from_value::<Policy>(legacy).is_err());
    let mut oversized = original;
    for i in 0..33 {
        oversized["authority"]["workflows"][format!("extra-{i}")] = json!([approved]);
    }
    let parsed: Policy = serde_json::from_value(oversized).unwrap();
    assert!(parsed.validate().is_err());
}

#[test]
fn independent_release_proof_binds_the_selected_caller_within_an_approved_set() {
    let alternate = "example/mailroom/.github/workflows/alternate-cd.yml@refs/heads/main";
    let mut p = serde_json::to_value(policy()).unwrap();
    p["authority"]["workflows"]["deploy"]
        .as_array_mut()
        .unwrap()
        .push(json!(alternate));
    let p: Policy = serde_json::from_value(p).unwrap();
    let mut r = request();
    let mut caller = claims(&r);
    caller["workflow_ref"] = json!(alternate);
    r["proof"] = json!(sign(&caller));
    assert!(admit(&r, &p, 1000).is_err());

    let mut proof = r["release_proof"].clone();
    proof.as_object_mut().unwrap().remove("proof");
    proof["workflow_ref"] = json!(alternate);
    let mut publisher = claims(&r);
    publisher["workflow_ref"] = json!(alternate);
    publisher["aud"] = json!(format!(
        "komizo-release:{}",
        document_digest(&authority::body_without_proof(&proof).unwrap())
    ));
    publisher["job_workflow_ref"] = json!(format!(
        "example/publisher/.github/workflows/deliver.yml@{}",
        "d".repeat(40)
    ));
    publisher["run_id"] = proof["run_id"].clone();
    publisher["run_attempt"] = proof["run_attempt"].clone();
    proof["proof"] = json!(sign(&publisher));
    r["release_proof"] = proof;
    let mut caller = claims(&r);
    caller["workflow_ref"] = json!(alternate);
    r["proof"] = json!(sign(&caller));
    assert!(admit(&r, &p, 1000).is_ok());

    r["proof"] = json!(sign(&claims(&r)));
    assert!(admit(&r, &p, 1000).is_err());
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
    r["secret_updates"] = json!([{"reference":"runtime","expected_generation":"11111111111111111111111111111111","format":"environment-file","value":"PASSWORD=secret"}]);
    r["proof"] = json!(sign(&claims(&r)));
    assert!(admit(&r, &policy(), 1000).is_err());
}

#[test]
fn retained_data_preparation_and_acceptance_require_the_kernel_owner_and_exact_evidence() {
    let p = policy();
    let mut r = request();
    r.as_object_mut().unwrap().remove("release_proof");
    r["action"] = json!("data-prepare");
    r["authority"] = json!("owner");
    assert!(admit(&r, &p, 0).is_ok());
    assert!(admit(&r, &p, 1000).is_err());
    r["authority"] = json!("github");
    r["proof"] = json!(sign(&claims(&r)));
    assert!(admit(&r, &p, 1000).is_err());
    r["authority"] = json!("owner");
    r.as_object_mut().unwrap().remove("proof");
    r["action"] = json!("data-accept");
    r.as_object_mut().unwrap().remove("release");
    assert!(admit(&r, &p, 0).is_err());
    r["data_evidence"] = json!(format!("sha256:{}", "a".repeat(64)));
    assert!(admit(&r, &p, 0).is_ok());
    r["action"] = json!("stop");
    assert!(admit(&r, &p, 0).is_err());
}
