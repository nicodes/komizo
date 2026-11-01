//! Bounded security documents reject duplicate keys and excessive nesting before typed decoding.
use anyhow::{Result, bail, ensure};
use serde::{
    Deserialize,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, fmt};
pub const RELEASE_MAX_BYTES: usize = 64 << 10;
struct Node(usize);
impl<'de> DeserializeSeed<'de> for Node {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        if self.0 > 32 {
            return Err(serde::de::Error::custom(
                "release JSON exceeds nesting limit",
            ));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Node {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON with unique keys")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut seen = BTreeSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate release JSON key"));
            }
            values.insert(key, map.next_value_seed(Node(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = vec![];
        while let Some(value) = seq.next_element_seed(Node(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
}
pub fn value(body: &[u8], limit: usize) -> Result<Value> {
    ensure!(body.len() <= limit, "invalid bounded release JSON");
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = Node(0).deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(value)
}
pub fn fields(value: Value, names: &[&str]) -> Result<Value> {
    let Value::Object(values) = value else {
        if value.is_null() {
            return Ok(value);
        }
        bail!("invalid release fields")
    };
    let mut out = Map::new();
    for (key, value) in values {
        let Some(name) = names.iter().find(|name| name.eq_ignore_ascii_case(&key)) else {
            bail!("invalid release fields")
        };
        out.insert((*name).into(), value);
    }
    Ok(Value::Object(out))
}
pub fn decode<T: for<'de> Deserialize<'de>>(body: &[u8], limit: usize) -> Result<T> {
    Ok(serde_json::from_value(value(body, limit)?)?)
}
