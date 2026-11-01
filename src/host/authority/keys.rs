use super::go_json;
use crate::{host::AgentConf, wire::Time};
use anyhow::{Result, anyhow, ensure};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub const DEVICE_KEY_PREFIX: &str = "kmz_dev_";
pub const LOG_KEY_PREFIX: &str = "kmz_log_";
pub const READ_TOKEN_PREFIX: &str = "kmz_rd_";
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode(value: &str) -> Result<Vec<u8>> {
    let value: Vec<_> = value
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    URL_SAFE_NO_PAD.decode(value).map_err(Into::into)
}
pub fn format_device_key(public: &[u8]) -> String {
    DEVICE_KEY_PREFIX.to_owned() + &encode(public)
}
pub fn format_log_key(public: &[u8]) -> String {
    LOG_KEY_PREFIX.to_owned() + &encode(public)
}
fn parse_prefixed(value: &str, prefix: &str, kind: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    let body=value.strip_prefix(prefix).ok_or_else(||anyhow!("a {kind} key starts with {prefix} -- this one does not, so it is some other kind of credential"))?;
    let bytes = decode(body).map_err(|e| anyhow!("that {kind} key is not valid base64: {e}"))?;
    ensure!(
        bytes.len() == 32,
        "that {kind} key is {} bytes, want 32",
        bytes.len()
    );
    Ok(bytes.try_into().unwrap())
}
pub fn parse_device_key(value: &str) -> Result<[u8; 32]> {
    parse_prefixed(value, DEVICE_KEY_PREFIX, "device")
}
pub fn parse_log_key(value: &str) -> Result<[u8; 32]> {
    parse_prefixed(value, LOG_KEY_PREFIX, "log")
}
pub fn parse_public_key(value: &str) -> Result<[u8; 32]> {
    let bytes =
        decode(value.trim()).map_err(|e| anyhow!("the registry key is not valid base64: {e}"))?;
    ensure!(
        bytes.len() == 32,
        "the registry key is {} bytes, want 32",
        bytes.len()
    );
    Ok(bytes.try_into().unwrap())
}
pub fn fingerprint(value: &str) -> String {
    let value = value.strip_prefix(DEVICE_KEY_PREFIX).unwrap_or(value);
    let bytes = value.as_bytes();
    if bytes.len() <= 16 {
        return value.into();
    }
    format!(
        "{}…{}",
        String::from_utf8_lossy(&bytes[..8]),
        String::from_utf8_lossy(&bytes[bytes.len() - 8..])
    )
}
pub fn public_from_seed(seed: &[u8]) -> Result<[u8; 32]> {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| anyhow!("that is not an ed25519 seed"))?;
    Ok(pair.public_key().as_ref().try_into().unwrap())
}
pub(crate) fn sign(private: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(private.len() == 64, "that is not an ed25519 private key");
    let pair = Ed25519KeyPair::from_seed_and_public_key(&private[..32], &private[32..])
        .map_err(|_| anyhow!("that is not an ed25519 private key"))?;
    Ok(pair.sign(payload).as_ref().to_vec())
}
pub fn verifies(public: &[u8], payload: &[u8], signature: &[u8]) -> bool {
    public.len() == 32
        && UnparsedPublicKey::new(&ED25519, public)
            .verify(payload, signature)
            .is_ok()
}
pub fn sign_read_token(private: &[u8], server: &str, expires: Time) -> Result<String> {
    ensure!(private.len() == 64, "that is not an ed25519 private key");
    ensure!(!server.is_empty(), "a read token must name a server");
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        srv: &'a str,
        exp: i64,
    }
    let payload = go_json(&Claims {
        srv: server,
        exp: expires.utc().timestamp(),
    })?;
    Ok(format!(
        "{READ_TOKEN_PREFIX}{}.{}",
        encode(&payload),
        encode(&sign(private, &payload)?)
    ))
}
pub(crate) fn nanos(time: Time) -> i128 {
    let time = time.utc();
    i128::from(time.timestamp()) * 1_000_000_000 + i128::from(time.timestamp_subsec_nanos())
}
pub fn verify_read_token(public: &[u8], token: &str, server: &str, now: Time) -> bool {
    if public.len() != 32 || server.is_empty() || token.len() > 16384 {
        return false;
    }
    let Some((payload, signature)) = token
        .strip_prefix(READ_TOKEN_PREFIX)
        .and_then(|t| t.split_once('.'))
    else {
        return false;
    };
    let (Ok(payload), Ok(signature)) = (decode(payload), decode(signature)) else {
        return false;
    };
    if !verifies(public, &payload, &signature) {
        return false;
    }
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct Claims {
        #[serde(deserialize_with = "crate::wire::null_default")]
        srv: String,
        #[serde(deserialize_with = "crate::wire::null_default")]
        exp: i64,
    }
    serde_json::from_slice::<Claims>(&payload).is_ok_and(|c| {
        c.srv == server && nanos(now) <= i128::from(c.exp) * 1_000_000_000 + 30_000_000_000
    })
}
impl AgentConf {
    pub fn trusted_keys(&self) -> Result<Vec<[u8; 32]>> {
        self.operator_keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                parse_device_key(k).map_err(|e| {
                    anyhow!(
                        "operator key {} of {}: {e}",
                        i + 1,
                        self.operator_keys.len()
                    )
                })
            })
            .collect()
    }
    pub fn log_trusted_keys(&self) -> Result<Vec<[u8; 32]>> {
        let mut keys = self.trusted_keys()?;
        for (i, key) in self.log_keys.iter().enumerate() {
            keys.push(
                parse_log_key(key)
                    .map_err(|e| anyhow!("log key {} of {}: {e}", i + 1, self.log_keys.len()))?,
            );
        }
        Ok(keys)
    }
    pub fn can_command(&self) -> bool {
        !self.server_id.is_empty() && !self.operator_keys.is_empty()
    }
    pub fn can_read_logs(&self) -> bool {
        !self.server_id.is_empty() && (!self.operator_keys.is_empty() || !self.log_keys.is_empty())
    }
}
