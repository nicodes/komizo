use super::{
    go_json,
    keys::{self, nanos},
    quote,
};
use crate::{wire::Time, wire_struct};
use anyhow::{Result, anyhow, ensure};
use std::collections::{BTreeMap, BTreeSet};
pub const COMMAND_VERSION: i64 = 1;
pub const COMMAND_PREFIX: &str = "kmz_cmd_";
pub const MAX_COMMAND_BYTES: usize = 8 << 10;
pub const MAX_ARG_NAME_BYTES: usize = 64;
pub const MAX_ARG_VALUE_BYTES: usize = 256;
pub const MAX_SUBJECT_BYTES: usize = 64;
pub const APPLY_OPS: &[&str] = &[
    "app.start",
    "app.stop",
    "app.restart",
    "app.add",
    "app.rotate",
];
pub const READ_OPS: &[&str] = &["logs.read", "report.read", "history.read", "metrics.read"];
pub const REFUSAL: &str = "this box will not act on that";
wire_struct!(Command{v:"v":i64=>required,id:"id":String=>required,srv:"srv":String=>required,exp:"exp":i64=>required,op:"op":String=>required,sub:"sub":String=>optional,args:"args":BTreeMap<String,String> =>optional});
wire_struct!(Signed{payload:"payload":String=>required,sig:"sig":String=>required});
pub struct Verified {
    pub command: Command,
    pub signer: [u8; 32],
    pub unsupported: Option<String>,
}
pub fn applies(op: &str) -> bool {
    APPLY_OPS.contains(&op)
}
pub fn known_op(op: &str) -> bool {
    applies(op) || READ_OPS.contains(&op)
}
pub fn alphabet(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
pub fn valid_command_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty() && id.len() <= 64,
        "a command id is 1 to 64 characters; this one is {}",
        id.len()
    );
    ensure!(alphabet(id), "{} is not a command id", quote(id));
    Ok(())
}
pub fn new_command_id() -> Result<String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    Ok(keys::encode(&random))
}
pub fn sign_command(private: &[u8], mut command: Command) -> Result<Signed> {
    ensure!(private.len() == 64, "that is not an ed25519 private key");
    ensure!(
        !command.srv.is_empty(),
        "a command must name the server it is for"
    );
    if !command.id.is_empty() {
        valid_command_id(&command.id)?;
    }
    ensure!(!command.op.is_empty(), "a command must say what to do");
    command.v = COMMAND_VERSION;
    if command.id.is_empty() {
        command.id = new_command_id()?;
    }
    let payload = go_json(&command)?;
    ensure!(
        payload.len() <= MAX_COMMAND_BYTES,
        "that command is larger than {MAX_COMMAND_BYTES} bytes"
    );
    Ok(Signed {
        payload: keys::encode(&payload),
        sig: keys::encode(&keys::sign(private, &payload)?),
    })
}
fn normalize(mut value: serde_json::Value) -> Result<serde_json::Value> {
    if let Some(object) = value.as_object_mut() {
        let mut seen = BTreeSet::new();
        let mut output = serde_json::Map::new();
        for (key, value) in std::mem::take(object) {
            if let Some(name) = ["v", "id", "srv", "exp", "op", "sub", "args"]
                .iter()
                .find(|name| name.eq_ignore_ascii_case(&key))
            {
                ensure!(seen.insert(*name), "ambiguous command field");
                let mut value = value;
                if *name == "args"
                    && let Some(args) = value.as_object_mut()
                {
                    for value in args.values_mut() {
                        if value.is_null() {
                            *value = serde_json::Value::String(String::new());
                        }
                    }
                }
                output.insert((*name).into(), value);
            }
        }
        *object = output;
    }
    Ok(value)
}
pub fn verify_command(keys: &[[u8; 32]], raw: &[u8], server: &str, now: Time) -> Result<Verified> {
    let refuse = || anyhow!(REFUSAL);
    ensure!(raw.len() <= MAX_COMMAND_BYTES, "{REFUSAL}");
    let envelope: Signed = serde_json::from_slice(raw).map_err(|_| refuse())?;
    let payload = keys::decode(&envelope.payload).map_err(|_| refuse())?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_COMMAND_BYTES,
        "{REFUSAL}"
    );
    let signature = keys::decode(&envelope.sig).map_err(|_| refuse())?;
    ensure!(signature.len() == 64, "{REFUSAL}");
    let signer = keys
        .iter()
        .find(|key| keys::verifies(key.as_slice(), &payload, &signature))
        .copied()
        .ok_or_else(refuse)?;
    let value = crate::strict::value(&payload, MAX_COMMAND_BYTES)
        .and_then(normalize)
        .map_err(|_| refuse())?;
    let command: Command = serde_json::from_value(value).map_err(|_| refuse())?;
    if command.v != COMMAND_VERSION {
        let message = format!(
            "this command is v{} and this box speaks v{COMMAND_VERSION}",
            command.v
        );
        return Ok(Verified {
            command,
            signer,
            unsupported: Some(message),
        });
    }
    let instant = nanos(now);
    let expiry = i128::from(command.exp) * 1_000_000_000;
    ensure!(
        valid_command_id(&command.id).is_ok()
            && !server.is_empty()
            && command.srv == server
            && instant <= expiry + 30_000_000_000
            && expiry <= instant + 330_000_000_000
            && command.sub.len() <= MAX_SUBJECT_BYTES
            && alphabet(&command.sub),
        "{REFUSAL}"
    );
    if !known_op(&command.op) {
        let message = format!("this box does not know how to {}", quote(&command.op));
        return Ok(Verified {
            command,
            signer,
            unsupported: Some(message),
        });
    }
    ensure!(
        command
            .args
            .iter()
            .all(|(k, v)| k.len() <= MAX_ARG_NAME_BYTES && v.len() <= MAX_ARG_VALUE_BYTES),
        "{REFUSAL}"
    );
    Ok(Verified {
        command,
        signer,
        unsupported: None,
    })
}
