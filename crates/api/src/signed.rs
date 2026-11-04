use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
pub const MAX_COMMAND: usize = 8 << 10;
pub const APPLY: &[&str] = &[
    "app.start",
    "app.stop",
    "app.restart",
    "app.add",
    "app.rotate",
];
pub const READ: &[&str] = &["logs.read", "report.read", "history.read", "metrics.read"];
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Forbidden,
    Unsupported(String),
}
#[derive(Default, Deserialize, Debug)]
#[serde(default)]
pub struct Command {
    pub v: i64,
    pub id: String,
    pub srv: String,
    pub exp: i64,
    pub op: String,
    pub sub: String,
    #[serde(default, deserialize_with = "nullable_args")]
    pub args: BTreeMap<String, String>,
}
fn nullable_args<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    Ok(Option::<BTreeMap<String, String>>::deserialize(deserializer)?.unwrap_or_default())
}
#[derive(Deserialize)]
struct Envelope {
    payload: String,
    sig: String,
}
pub fn key(text: &str) -> Result<[u8; 32], Refusal> {
    URL_SAFE_NO_PAD
        .decode(text.trim())
        .map_err(|_| Refusal::Forbidden)?
        .try_into()
        .map_err(|_| Refusal::Forbidden)
}
pub fn id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && alphabet(value)
}
fn alphabet(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
pub fn read_token(public: &[u8; 32], token: &str, server: &str, now: i64) -> bool {
    if server.is_empty() || token.len() > 16384 {
        return false;
    }
    let Some((payload, signature)) = token
        .strip_prefix("kmz_rd_")
        .and_then(|s| s.split_once('.'))
    else {
        return false;
    };
    let (Ok(payload), Ok(signature)) = (
        URL_SAFE_NO_PAD.decode(payload),
        URL_SAFE_NO_PAD.decode(signature),
    ) else {
        return false;
    };
    if UnparsedPublicKey::new(&ED25519, public)
        .verify(&payload, &signature)
        .is_err()
    {
        return false;
    }
    #[derive(Deserialize)]
    struct Claims {
        srv: String,
        exp: i64,
    }
    serde_json::from_slice::<Claims>(&payload)
        .is_ok_and(|c| c.srv == server && now <= c.exp.saturating_add(30))
}
pub fn command(keys: &[[u8; 32]], raw: &[u8], server: &str, now: i64) -> Result<Command, Refusal> {
    let deny = || Refusal::Forbidden;
    if raw.len() > MAX_COMMAND {
        return Err(deny());
    }
    let envelope: Envelope = serde_json::from_slice(raw).map_err(|_| deny())?;
    let payload = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|_| deny())?;
    let signature = URL_SAFE_NO_PAD.decode(&envelope.sig).map_err(|_| deny())?;
    if payload.is_empty()
        || payload.len() > MAX_COMMAND
        || signature.len() != 64
        || !keys.iter().any(|key| {
            UnparsedPublicKey::new(&ED25519, key)
                .verify(&payload, &signature)
                .is_ok()
        })
    {
        return Err(deny());
    }
    // Verify the original opaque bytes before parsing. Every object rejects
    // duplicate keys, including unknown extension fields and flat arguments.
    let unique: Unique = serde_json::from_slice(&payload).map_err(|_| deny())?;
    let command: Command = serde_json::from_value(unique.0).map_err(|_| deny())?;
    if command.v != 1 {
        return Err(Refusal::Unsupported(format!(
            "this command is v{} and this box speaks v1",
            command.v
        )));
    }
    if !id(&command.id)
        || server.is_empty()
        || command.srv != server
        || now > command.exp.saturating_add(30)
        || command.exp > now.saturating_add(330)
        || command.sub.len() > 64
        || !alphabet(&command.sub)
    {
        return Err(deny());
    }
    if !APPLY.contains(&command.op.as_str()) && !READ.contains(&command.op.as_str()) {
        return Err(Refusal::Unsupported(format!(
            "this box does not know how to {:?}",
            command.op
        )));
    }
    if command
        .args
        .iter()
        .any(|(key, value)| key.len() > 64 || value.len() > 256)
    {
        return Err(deny());
    }
    Ok(command)
}
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Unique, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = sequence.next_element::<Unique>()? {
                    items.push(item.0);
                }
                Ok(Unique(Value::Array(items)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Unique, A::Error> {
                let mut items = Map::new();
                let mut keys = BTreeSet::new();
                while let Some(key) = object.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    items.insert(key, object.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(items)))
            }
        }
        deserializer.deserialize_any(Strict)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    fn sign(key: &Ed25519KeyPair, payload: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"payload":URL_SAFE_NO_PAD.encode(payload),"sig":URL_SAFE_NO_PAD.encode(key.sign(payload).as_ref())})).unwrap()
    }
    #[test]
    fn signed_transport_has_separate_audience_expiry_algorithm_and_duplicate_guards() {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let key: [u8; 32] = signer.public_key().as_ref().try_into().unwrap();
        let payload=br#"{"v":1,"id":"request_1","srv":"box_one","exp":1000,"op":"app.stop","args":{"app":"web"}}"#;
        let raw = sign(&signer, payload);
        assert_eq!(
            command(&[key], &raw, "box_one", 1000).unwrap().op,
            "app.stop"
        );
        assert_eq!(
            command(&[key], &raw, "box_other", 1000).unwrap_err(),
            Refusal::Forbidden
        );
        assert_eq!(
            command(&[key], &raw, "box_one", 1031).unwrap_err(),
            Refusal::Forbidden
        );
        assert_eq!(
            command(&[key], &raw, "box_one", 669).unwrap_err(),
            Refusal::Forbidden
        );
        assert_eq!(
            command(&[], &raw, "box_one", 1000).unwrap_err(),
            Refusal::Forbidden
        );
        let duplicate=br#"{"v":1,"id":"request_1","srv":"box_other","srv":"box_one","exp":1000,"op":"app.stop"}"#;
        assert_eq!(
            command(&[key], &sign(&signer, duplicate), "box_one", 1000).unwrap_err(),
            Refusal::Forbidden
        );
        let future = br#"{"v":2,"id":"request_1","srv":"box_one","exp":1000,"op":"app.stop"}"#;
        assert!(matches!(
            command(&[key], &sign(&signer, future), "box_one", 1000),
            Err(Refusal::Unsupported(_))
        ));
        let claims = br#"{"srv":"box_one","exp":1000}"#;
        let token = format!(
            "kmz_rd_{}.{}",
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode(signer.sign(claims).as_ref())
        );
        assert!(read_token(&key, &token, "box_one", 1030));
        assert!(!read_token(&key, &token, "box_other", 1000));
        assert!(!read_token(&key, &token, "box_one", 1031));
    }
}
