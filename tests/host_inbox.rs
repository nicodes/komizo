use anyhow::Result;
use chrono::{DateTime, Utc};
use komizo::{
    host::{
        AgentConf, Result as Receipt,
        authority::{self, Command, keys},
        inbox::{self, Executor},
        results,
    },
    wire::Time,
    workload::activation::Context,
};
use std::{
    fs,
    os::unix::fs::symlink,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
fn fixture() -> (AgentConf, Vec<u8>, DateTime<Utc>) {
    let seed = [17u8; 32];
    let public = keys::public_from_seed(&seed).unwrap();
    let mut private = seed.to_vec();
    private.extend_from_slice(&public);
    (
        AgentConf {
            server_id: "fixture-server".into(),
            operator_keys: vec![keys::format_device_key(&public)].into(),
            ..Default::default()
        },
        private,
        "2026-11-01T18:00:00Z".parse().unwrap(),
    )
}
fn command(now: DateTime<Utc>, id: &str) -> Command {
    Command {
        v: 1,
        id: id.into(),
        srv: "fixture-server".into(),
        exp: now.timestamp() + 60,
        op: "app.stop".into(),
        args: std::collections::BTreeMap::from([("app".into(), "example".into())]),
        ..Default::default()
    }
}
fn drop_signed(path: &Path, private: &[u8], command: Command) {
    let signed = authority::sign_command(private, command).unwrap();
    fs::write(path, serde_json::to_vec(&signed).unwrap()).unwrap();
}
struct Handler<'a> {
    directory: &'a Path,
    calls: Vec<(String, String)>,
}
impl Executor for Handler<'_> {
    fn perform(&mut self, ctx: &Context, command: &Command, actor: &str) -> Result<()> {
        ctx.check()?;
        let receipt = results::read_result(self.directory, &command.id)?.unwrap();
        assert_eq!(receipt.detail, "applying");
        assert!(!receipt.ok);
        self.calls.push((command.id.clone(), actor.into()));
        Ok(())
    }
}
#[test]
fn authenticated_inbox_claims_before_effects_rejects_bad_authority_and_applies_each_id_once() {
    let (conf, private, now) = fixture();
    let root = tempfile::tempdir().unwrap();
    let inbox = root.path().join("inbox");
    let receipts = root.path().join("results");
    fs::create_dir(&inbox).unwrap();
    fs::create_dir(&receipts).unwrap();
    let mut good = command(now, "one-command");
    good.sub = "account_fixture".into();
    drop_signed(&inbox.join("a"), &private, good.clone());
    drop_signed(&inbox.join("b"), &private, good);
    let mut wrong = command(now, "wrong-audience");
    wrong.srv = "other-server".into();
    drop_signed(&inbox.join("c"), &private, wrong);
    let mut expired = command(now, "expired");
    expired.exp = now.timestamp() - 60;
    drop_signed(&inbox.join("d"), &private, expired);
    let mut stranger = vec![23u8; 32];
    stranger.extend_from_slice(&keys::public_from_seed(&stranger).unwrap());
    drop_signed(&inbox.join("e"), &stranger, command(now, "stranger"));
    fs::write(inbox.join("raw"), "not a command").unwrap();
    let sentinel = root.path().join("private-file");
    fs::write(&sentinel, "SYNTHETIC_SECRET_NEVER_READ").unwrap();
    symlink(&sentinel, inbox.join("linked")).unwrap();
    let mut handler = Handler {
        directory: &receipts,
        calls: vec![],
    };
    let ctx = Context::new(Instant::now() + Duration::from_secs(2));
    let errors =
        inbox::apply_pending_with_clock(&ctx, &conf, &inbox, &receipts, &mut handler, || now);
    assert_eq!(
        handler.calls,
        vec![("one-command".into(), "account account_fixture".into())]
    );
    assert!(
        results::read_result(&receipts, "one-command")
            .unwrap()
            .unwrap()
            .ok
    );
    assert_eq!(fs::read_dir(&inbox).unwrap().count(), 0);
    assert!(!errors.join("\n").contains("SYNTHETIC_SECRET"));
    assert_eq!(
        fs::read_to_string(sentinel).unwrap(),
        "SYNTHETIC_SECRET_NEVER_READ"
    );
    for id in ["wrong-audience", "expired", "stranger"] {
        assert!(!results::applied(&receipts, id));
    }
}
#[test]
fn an_unwritable_claim_prevents_effects_and_stale_sweep_runs_without_operator_keys() {
    let (conf, private, now) = fixture();
    let root = tempfile::tempdir().unwrap();
    let inbox = root.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let blocked = root.path().join("blocked");
    fs::write(&blocked, "not a directory").unwrap();
    drop_signed(
        &inbox.join("claim"),
        &private,
        command(now, "claim-failure"),
    );
    let mut handler = Handler {
        directory: &blocked,
        calls: vec![],
    };
    let ctx = Context::new(Instant::now() + Duration::from_secs(2));
    let errors =
        inbox::apply_pending_with_clock(&ctx, &conf, &inbox, &blocked, &mut handler, || now);
    assert!(handler.calls.is_empty());
    assert!(errors.iter().any(|e| e.contains("could not claim")));
    let receipts = root.path().join("results");
    fs::create_dir(&receipts).unwrap();
    let stale = inbox.join("stale-id");
    fs::write(&stale, "old").unwrap();
    let modified: SystemTime = (now - chrono::Duration::minutes(7)).into();
    fs::File::open(&stale)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let mut handler = Handler {
        directory: &receipts,
        calls: vec![],
    };
    let conf = AgentConf::default();
    inbox::apply_pending_with_clock(&ctx, &conf, &inbox, &receipts, &mut handler, || now);
    assert!(!stale.exists());
    let receipt = results::read_result(&receipts, "stale-id")
        .unwrap()
        .unwrap();
    assert!(!receipt.ok);
    assert!(receipt.detail.contains("before it expired"));
    assert!(handler.calls.is_empty());
}
#[test]
fn concurrent_replay_claims_publish_one_winner() {
    let root = tempfile::tempdir().unwrap();
    let directory = Arc::new(root.path().to_owned());
    let winners = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..32)
        .map(|_| {
            let directory = directory.clone();
            let winners = winners.clone();
            std::thread::spawn(move || {
                if results::claim_result(
                    &directory,
                    Receipt {
                        id: "same-command".into(),
                        at: Time::default(),
                        detail: "applying".into(),
                        ..Default::default()
                    },
                )
                .unwrap()
                {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(winners.load(Ordering::SeqCst), 1);
    assert_eq!(
        results::read_result(&directory, "same-command")
            .unwrap()
            .unwrap()
            .detail,
        "applying"
    );
}
