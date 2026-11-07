//! Existing persisted JSON conventions: nil slices, explicit raw nulls and Go timestamps.
use chrono::{DateTime, FixedOffset, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};
pub fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    d: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
pub fn raw_some<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(d).map(Some)
}
pub fn decode<T: serde::de::DeserializeOwned + Default>(input: &str) -> serde_json::Result<T> {
    if input.trim() == "null" {
        Ok(T::default())
    } else {
        serde_json::from_str(input)
    }
}
pub fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de> + Default> serde::de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<T, E> {
            Ok(T::default())
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<T, E> {
            Ok(T::default())
        }
    }
    deserializer.deserialize_any(Object(std::marker::PhantomData))
}
pub fn finite_f64<S: Serializer>(value: &f64, s: S) -> Result<S::Ok, S::Error> {
    if !value.is_finite() {
        return Err(serde::ser::Error::custom("non-finite JSON number"));
    }
    s.serialize_f64(*value)
}
pub fn finite_f64_slice<S: Serializer>(value: &Slice<f64>, s: S) -> Result<S::Ok, S::Error> {
    if value.iter().any(|number| !number.is_finite()) {
        return Err(serde::ser::Error::custom("non-finite JSON number"));
    }
    value.serialize(s)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Slice<T>(pub Option<Vec<T>>);
impl<T> Default for Slice<T> {
    fn default() -> Self {
        Self(None)
    }
}
impl<T> From<Vec<T>> for Slice<T> {
    fn from(value: Vec<T>) -> Self {
        Self(Some(value))
    }
}
impl<T> FromIterator<T> for Slice<T> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> Self {
        Self(Some(items.into_iter().collect()))
    }
}
impl<T> Deref for Slice<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.0.as_deref().unwrap_or(&[])
    }
}
impl<T> DerefMut for Slice<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.0.as_deref_mut().unwrap_or(&mut [])
    }
}
impl<T> Slice<T> {
    pub fn push(&mut self, value: T) {
        self.0.get_or_insert_with(Vec::new).push(value);
    }
    pub fn extend(&mut self, items: impl IntoIterator<Item = T>) {
        self.0.get_or_insert_with(Vec::new).extend(items);
    }
    pub fn take_vec(&mut self) -> Vec<T> {
        self.0.take().unwrap_or_default()
    }
    pub fn into_vec(self) -> Vec<T> {
        self.0.unwrap_or_default()
    }
}
impl<'de, T: Deserialize<'de> + Default> Deserialize<'de> for Slice<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Item<T>(
            #[serde(deserialize_with = "null_default")]
            #[serde(bound(deserialize = "T: Deserialize<'de> + Default"))]
            T,
        );
        Ok(Self(Option::<Vec<Item<T>>>::deserialize(d)?.map(|items| {
            items.into_iter().map(|item| item.0).collect()
        })))
    }
}
pub trait Empty {
    fn empty(&self) -> bool;
}
impl Empty for u64 {
    fn empty(&self) -> bool {
        *self == 0
    }
}
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Secret(String);
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Bytes(pub Option<Vec<u8>>);
impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{} bytes]", self.len())
    }
}
impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_deref().unwrap_or_default()
    }
}
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Some(value))
    }
}
impl Bytes {
    pub fn into_vec(self) -> Vec<u8> {
        self.0.unwrap_or_default()
    }
}
pub fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    let value: Vec<_> = value
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true),
    )
    .decode(value)
}
pub fn trim_space(body: &[u8]) -> &[u8] {
    std::str::from_utf8(body)
        .map(str::trim)
        .map(str::as_bytes)
        .unwrap_or_else(|_| body.trim_ascii())
}
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        self.0
            .as_ref()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
            .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Encoded {
            Text(String),
            Array(Vec<Option<u8>>),
        }
        let Some(value) = Option::<Encoded>::deserialize(deserializer)? else {
            return Ok(Self::default());
        };
        let bytes = match value {
            Encoded::Array(bytes) => bytes
                .into_iter()
                .map(|value| value.unwrap_or_default())
                .collect(),
            Encoded::Text(value) => decode_base64(&value).map_err(serde::de::Error::custom)?,
        };
        Ok(bytes.into())
    }
}
impl Empty for Bytes {
    fn empty(&self) -> bool {
        self.is_empty()
    }
}
impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}
impl Empty for Secret {
    fn empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl Empty for String {
    fn empty(&self) -> bool {
        self.is_empty()
    }
}
impl Empty for bool {
    fn empty(&self) -> bool {
        !*self
    }
}
impl Empty for std::sync::Arc<str> {
    fn empty(&self) -> bool {
        self.is_empty()
    }
}
impl Empty for i64 {
    fn empty(&self) -> bool {
        *self == 0
    }
}
impl Empty for f64 {
    fn empty(&self) -> bool {
        *self == 0.
    }
}
impl<T> Empty for Option<T> {
    fn empty(&self) -> bool {
        self.is_none()
    }
}
impl<T> Empty for Slice<T> {
    fn empty(&self) -> bool {
        self.is_empty()
    }
}
impl<K, V> Empty for BTreeMap<K, V> {
    fn empty(&self) -> bool {
        self.is_empty()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub DateTime<FixedOffset>);
impl Default for Time {
    fn default() -> Self {
        Self(
            DateTime::from_timestamp(-62135596800, 0)
                .unwrap()
                .fixed_offset(),
        )
    }
}
impl Time {
    pub fn now() -> Self {
        Self(chrono::Local::now().fixed_offset())
    }
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }
    pub fn utc(&self) -> DateTime<Utc> {
        self.0.with_timezone(&Utc)
    }
}
impl Serialize for Time {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut value = self.0.format("%Y-%m-%dT%H:%M:%S").to_string();
        if self.0.nanosecond() != 0 {
            value.push('.');
            value.push_str(format!("{:09}", self.0.nanosecond()).trim_end_matches('0'));
        }
        if self.0.offset().local_minus_utc() == 0 {
            value.push('Z');
        } else {
            value.push_str(&self.0.format("%:z").to_string());
        }
        s.serialize_str(&value)
    }
}
impl<'de> Deserialize<'de> for Time {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let Some(value) = Option::<String>::deserialize(d)? else {
            return Ok(Self::default());
        };
        let parsed = DateTime::parse_from_rfc3339(&value).map_err(serde::de::Error::custom)?;
        if parsed.nanosecond() >= 1_000_000_000 {
            return Err(serde::de::Error::custom("leap seconds are not supported"));
        }
        Ok(Self(parsed))
    }
}
#[macro_export]
macro_rules! wire_struct {
    ($name:ident { $($field:ident:$wire:literal:$ty:ty=>$mode:ident),*$(,)? }) => {
        $crate::wire_struct!(@fields $name [] $($field:$wire:$ty=>$mode,)*);
    };
    (@fields $name:ident [$($fields:tt)*]) => {
        $crate::wire_struct!(@finish $name {$($fields)*});
    };
    (@finish $name:ident {$($(#[$attribute:meta])*pub $field:ident:$ty:ty,)*}) => {
        #[derive(Clone,Debug,Default,serde::Serialize)]pub struct $name {$($(#[$attribute])*pub $field:$ty,)*}
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D:serde::Deserializer<'de>>(deserializer:D)->std::result::Result<Self,D::Error> {
                #[derive(Default,serde::Deserialize)]struct Fields {$($(#[$attribute])*$field:$ty,)*}
                let Fields{$($field,)*}=$crate::wire::deserialize_object(deserializer)?;
                Ok(Self{$($field,)*})
            }
        }
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>required,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::null_default")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>optional,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::null_default",skip_serializing_if="crate::wire::Empty::empty")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>raw,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::raw_some")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>raw_optional,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::raw_some",skip_serializing_if="Option::is_none")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>time_optional,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,skip_serializing_if="crate::wire::Time::is_zero")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>float,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::null_default",serialize_with="crate::wire::finite_f64")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>floats,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::null_default",serialize_with="crate::wire::finite_f64_slice")]pub $field:$ty,] $($rest)*);
    };
    (@fields $name:ident [$($fields:tt)*] $field:ident:$wire:literal:$ty:ty=>float_optional,$($rest:tt)*) => {
        $crate::wire_struct!(@fields $name [$($fields)* #[serde(rename=$wire,default,deserialize_with="crate::wire::null_default",serialize_with="crate::wire::finite_f64",skip_serializing_if="crate::wire::Empty::empty")]pub $field:$ty,] $($rest)*);
    };
}
