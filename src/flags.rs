//! Existing command flags retain last-value, boolean and positional semantics.
use anyhow::{Result, anyhow, ensure};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Bool(bool),
    Int(i64),
    Duration(i64),
    List(Vec<String>),
}
pub struct Flag {
    pub name: &'static str,
    pub default: Value,
}
impl Flag {
    pub fn list(name: &'static str) -> Self {
        Self {
            name,
            default: Value::List(vec![]),
        }
    }
    pub fn text(name: &'static str, value: impl Into<String>) -> Self {
        Self {
            name,
            default: Value::Text(value.into()),
        }
    }
    pub fn boolean(name: &'static str, value: bool) -> Self {
        Self {
            name,
            default: Value::Bool(value),
        }
    }
    pub fn integer(name: &'static str, value: i64) -> Self {
        Self {
            name,
            default: Value::Int(value),
        }
    }
    pub fn duration(name: &'static str, nanos: i64) -> Self {
        Self {
            name,
            default: Value::Duration(nanos),
        }
    }
}
#[derive(Default, Debug)]
pub struct Flags {
    pub values: BTreeMap<String, Value>,
    pub seen: BTreeSet<String>,
    pub args: Vec<String>,
}
#[derive(Debug)]
pub struct Help;
impl std::fmt::Display for Help {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("flag: help requested")
    }
}
impl std::error::Error for Help {}
impl Flags {
    pub fn list(&self, name: &str) -> &[String] {
        match &self.values[name] {
            Value::List(values) => values,
            _ => panic!("flag specification mismatch"),
        }
    }
    pub fn parse(spec: &[Flag], args: &[String]) -> Result<Self> {
        let mut parsed = Self::default();
        for flag in spec {
            ensure!(
                parsed
                    .values
                    .insert(flag.name.into(), flag.default.clone())
                    .is_none(),
                "duplicate flag specification"
            );
        }
        let mut position = 0;
        while position < args.len() {
            let argument = &args[position];
            if argument == "--" {
                position += 1;
                break;
            }
            if !argument.starts_with('-') || argument == "-" {
                break;
            }
            let name = argument
                .strip_prefix("--")
                .unwrap_or_else(|| &argument[1..]);
            ensure!(
                !name.is_empty() && !name.starts_with(['-', '=']),
                "bad flag syntax"
            );
            let (name, explicit) = name
                .split_once('=')
                .map(|(name, value)| (name, Some(value)))
                .unwrap_or((name, None));
            let Some(default) = parsed.values.get(name) else {
                if matches!(name, "help" | "h") {
                    return Err(Help.into());
                }
                anyhow::bail!("flag provided but not defined: -{name}")
            };
            let value = if matches!(default, Value::Bool(_)) {
                match explicit {
                    None => Value::Bool(true),
                    Some(value) => Value::Bool(
                        parse_bool(value)
                            .ok_or_else(|| anyhow!("invalid boolean value for -{name}"))?,
                    ),
                }
            } else {
                let value = match explicit {
                    Some(value) => value,
                    None => {
                        position += 1;
                        args.get(position)
                            .map(String::as_str)
                            .ok_or_else(|| anyhow!("flag needs an argument: -{name}"))?
                    }
                };
                match default {
                    Value::List(previous) => {
                        let mut values = previous.clone();
                        values.push(value.into());
                        Value::List(values)
                    }
                    Value::Text(_) => Value::Text(value.into()),
                    Value::Int(_) => Value::Int(
                        integer(value).map_err(|_| anyhow!("invalid integer value for -{name}"))?,
                    ),
                    Value::Duration(_) => Value::Duration(
                        duration(value)
                            .map_err(|_| anyhow!("invalid duration value for -{name}"))?,
                    ),
                    _ => unreachable!(),
                }
            };
            parsed.values.insert(name.into(), value);
            parsed.seen.insert(name.into());
            position += 1;
        }
        parsed.args = args[position..].to_vec();
        Ok(parsed)
    }
    pub fn text(&self, name: &str) -> &str {
        match &self.values[name] {
            Value::Text(value) => value,
            _ => panic!("flag specification mismatch"),
        }
    }
    pub fn boolean(&self, name: &str) -> bool {
        match self.values[name] {
            Value::Bool(value) => value,
            _ => panic!("flag specification mismatch"),
        }
    }
    pub fn integer(&self, name: &str) -> i64 {
        match self.values[name] {
            Value::Int(value) => value,
            _ => panic!("flag specification mismatch"),
        }
    }
    pub fn duration(&self, name: &str) -> Result<std::time::Duration> {
        match self.values[name] {
            Value::Duration(value) => {
                ensure!(value >= 0, "negative duration for -{name}");
                Ok(std::time::Duration::from_nanos(value as u64))
            }
            _ => panic!("flag specification mismatch"),
        }
    }
    pub fn no_args(&self, message: &str) -> Result<()> {
        ensure!(self.args.is_empty(), "{message}");
        Ok(())
    }
}
pub fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}
pub fn integer(value: &str) -> Result<i64> {
    let (negative, value) = if let Some(value) = value.strip_prefix('-') {
        (true, value)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    ensure!(!value.is_empty(), "invalid integer");
    let (base, digits, prefix) = if value.starts_with("0x") || value.starts_with("0X") {
        (16, &value[2..], true)
    } else if value.starts_with("0b") || value.starts_with("0B") {
        (2, &value[2..], true)
    } else if value.starts_with("0o") || value.starts_with("0O") {
        (8, &value[2..], true)
    } else if value.starts_with('0') && value.len() > 1 {
        (8, &value[1..], true)
    } else {
        (10, value, false)
    };
    ensure!(!digits.is_empty(), "invalid integer");
    let mut number = 0_u128;
    let mut previous_digit = prefix;
    for byte in digits.bytes() {
        if byte == b'_' {
            ensure!(previous_digit, "invalid integer");
            previous_digit = false;
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u128,
            b'a'..=b'f' => (byte - b'a' + 10) as u128,
            b'A'..=b'F' => (byte - b'A' + 10) as u128,
            _ => anyhow::bail!("invalid integer"),
        };
        ensure!(digit < base, "invalid integer");
        number = number
            .checked_mul(base)
            .and_then(|n| n.checked_add(digit))
            .ok_or_else(|| anyhow!("integer overflow"))?;
        ensure!(
            number <= (i64::MAX as u128) + u128::from(negative),
            "integer overflow"
        );
        previous_digit = true;
    }
    ensure!(previous_digit, "invalid integer");
    Ok(if negative {
        (-(number as i128)) as i64
    } else {
        number as i64
    })
}
pub fn duration(value: &str) -> Result<i64> {
    let (negative, mut rest) = if let Some(value) = value.strip_prefix('-') {
        (true, value)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if rest == "0" {
        return Ok(0);
    }
    ensure!(!rest.is_empty(), "invalid duration");
    let mut total = 0_u128;
    while !rest.is_empty() {
        let whole_end = rest.bytes().take_while(u8::is_ascii_digit).count();
        let whole = &rest[..whole_end];
        rest = &rest[whole_end..];
        let mut fraction = "";
        if let Some(tail) = rest.strip_prefix('.') {
            let end = tail.bytes().take_while(u8::is_ascii_digit).count();
            fraction = &tail[..end];
            rest = &tail[end..];
        }
        ensure!(
            !whole.is_empty() || !fraction.is_empty(),
            "invalid duration"
        );
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];
        let unit = match unit {
            "ns" => 1_u128,
            "us" | "µs" | "μs" => 1000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => anyhow::bail!("invalid duration unit"),
        };
        let whole = if whole.is_empty() {
            0
        } else {
            whole
                .parse::<u128>()
                .map_err(|_| anyhow!("duration overflow"))?
        };
        let whole = whole
            .checked_mul(unit)
            .ok_or_else(|| anyhow!("duration overflow"))?;
        let fractional = if fraction.is_empty() {
            0
        } else {
            let mut number = 0_u64;
            let mut scale = 1_f64;
            for byte in fraction.bytes() {
                let Some(next) = number
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                    .filter(|n| *n <= (1_u64 << 63))
                else {
                    break;
                };
                number = next;
                scale *= 10.0;
            }
            (number as f64 * (unit as f64 / scale)) as u128
        };
        total = total
            .checked_add(whole)
            .and_then(|n| n.checked_add(fractional))
            .ok_or_else(|| anyhow!("duration overflow"))?;
        ensure!(
            total <= (i64::MAX as u128) + u128::from(negative),
            "duration overflow"
        );
    }
    Ok(if negative {
        (-(total as i128)) as i64
    } else {
        total as i64
    })
}
