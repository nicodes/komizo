//! Parse repository YAML without aliases, custom constructors or file resolution.
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Map, Number, Value};
use std::sync::OnceLock;
use yaml_rust2::{
    parser::{Event, Parser, Tag},
    scanner::TScalarStyle,
};
pub const MAX_BYTES: usize = 1 << 20;
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    String,
    Null,
    Bool,
    Int,
    Float,
}
fn timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 5 || !bytes[..4].iter().all(u8::is_ascii_digit) || bytes[4] != b'-' {
        return false;
    }
    if let Some(index) = value.find(['T', 't']) {
        let fields: Vec<_> = value[..index].split('-').collect();
        if fields.len() == 3
            && let (Ok(month), Ok(day)) = (fields[1].parse::<u32>(), fields[2].parse::<u32>())
        {
            let normalized = format!("{}-{month:02}-{day:02}T{}", fields[0], &value[index + 1..]);
            if chrono::DateTime::parse_from_rfc3339(&normalized).is_ok() {
                return true;
            }
        }
    }
    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
        || chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f").is_ok()
        || chrono::DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f%:z").is_ok()
        || chrono::DateTime::parse_from_str(value, "%Y-%m-%dt%H:%M:%S%.f%:z").is_ok()
        || chrono::DateTime::parse_from_rfc3339(value).is_ok()
}
fn integer(value: &str) -> Option<Number> {
    let (negative, positive, body) = if let Some(body) = value.strip_prefix('-') {
        (true, false, body)
    } else if let Some(body) = value.strip_prefix('+') {
        (false, true, body)
    } else {
        (false, false, value)
    };
    let (base, digits) =
        if let Some(v) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            (16, v)
        } else if let Some(v) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
            (2, v)
        } else if let Some(v) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
            (8, v)
        } else if body.starts_with('0') && body.len() > 1 {
            (8, &body[1..])
        } else {
            (10, body)
        };
    if digits.is_empty()
        || digits
            .as_bytes()
            .first()
            .is_some_and(|b| matches!(b, b'+' | b'-'))
    {
        return None;
    }
    let unsigned = i128::from_str_radix(digits, base).ok()?;
    let signed = if negative { -unsigned } else { unsigned };
    if let Ok(value) = i64::try_from(signed) {
        Some(value.into())
    } else if !negative && !positive {
        u64::try_from(unsigned).ok().map(Into::into)
    } else {
        None
    }
}
fn infer(value: &str, dates: bool) -> Result<(Kind, Value)> {
    match value {
        "" | "~" | "null" | "Null" | "NULL" => return Ok((Kind::Null, Value::Null)),
        "true" | "True" | "TRUE" => return Ok((Kind::Bool, true.into())),
        "false" | "False" | "FALSE" => return Ok((Kind::Bool, false.into())),
        ".nan" | ".NaN" | ".NAN" => bail!("json: unsupported value: NaN"),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
            bail!("json: unsupported value: +Inf")
        }
        "-.inf" | "-.Inf" | "-.INF" => bail!("json: unsupported value: -Inf"),
        _ => {}
    }
    let first = value.as_bytes().first().copied().unwrap_or_default();
    if first == b'.' {
        if let Some(number) = super::resources::parse_cpu(value).filter(|v| v.is_finite()) {
            return Ok((Kind::Float, Number::from_f64(number).unwrap().into()));
        }
    } else if first.is_ascii_digit() || matches!(first, b'+' | b'-') {
        ensure!(!dates || !timestamp(value), "unsupported workload scalar");
        let plain = value.replace('_', "");
        if let Some(number) = integer(&plain) {
            return Ok((Kind::Int, number.into()));
        }
        static FLOAT: OnceLock<regex::Regex> = OnceLock::new();
        if FLOAT
            .get_or_init(|| {
                regex::Regex::new(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$").unwrap()
            })
            .is_match(&plain)
            && let Some(number) = super::resources::parse_cpu(&plain).filter(|v| v.is_finite())
        {
            return Ok((Kind::Float, Number::from_f64(number).unwrap().into()));
        }
    }
    Ok((Kind::String, value.into()))
}
fn scalar(value: &str, style: TScalarStyle, tag: Option<&Tag>) -> Result<Value> {
    if let Some(tag) = tag {
        ensure!(
            tag.handle == "tag:yaml.org,2002:"
                && matches!(
                    tag.suffix.as_str(),
                    "str" | "null" | "bool" | "int" | "float"
                ),
            "unsupported workload scalar"
        );
        if tag.suffix == "str" {
            return Ok(value.into());
        }
        let (kind, resolved) = infer(value, false)?;
        let valid = matches!(
            (tag.suffix.as_str(), kind),
            ("null", Kind::Null)
                | ("bool", Kind::Bool)
                | ("int", Kind::Int)
                | ("float", Kind::Int | Kind::Float)
        );
        ensure!(valid, "invalid workload scalar");
        return Ok(if tag.suffix == "float" && kind == Kind::Int {
            Number::from_f64(resolved.as_f64().unwrap()).unwrap().into()
        } else {
            resolved
        });
    }
    if style != TScalarStyle::Plain {
        return Ok(value.into());
    }
    infer(value, true).map(|(_, v)| v)
}
fn collection_tag(tag: Option<&Tag>, kind: &str) -> bool {
    tag.is_none_or(|t| t.handle == "tag:yaml.org,2002:" && t.suffix == kind)
}
fn node(
    events: &[Event],
    markers: &[usize],
    source: &[u8],
    position: &mut usize,
    depth: usize,
) -> Result<Value> {
    ensure!(
        depth <= 32,
        "workload nesting, anchors or aliases are not supported"
    );
    let event = events
        .get(*position)
        .ok_or_else(|| anyhow!("unsupported workload YAML node"))?;
    *position += 1;
    match event {
        Event::Alias(_) => bail!("workload nesting, anchors or aliases are not supported"),
        Event::Scalar(value, style, anchor, tag) => {
            ensure!(
                *anchor == 0,
                "workload nesting, anchors or aliases are not supported"
            );
            scalar(value, *style, tag.as_ref())
        }
        Event::SequenceStart(anchor, tag) => {
            ensure!(
                *anchor == 0 && collection_tag(tag.as_ref(), "seq"),
                "workload nesting, anchors or aliases are not supported"
            );
            let mut values = vec![];
            while events.get(*position) != Some(&Event::SequenceEnd) {
                values.push(node(events, markers, source, position, depth + 1)?);
            }
            *position += 1;
            Ok(values.into())
        }
        Event::MappingStart(anchor, tag) => {
            ensure!(
                *anchor == 0 && collection_tag(tag.as_ref(), "map"),
                "workload nesting, anchors or aliases are not supported"
            );
            let mut values = Map::new();
            while events.get(*position) != Some(&Event::MappingEnd) {
                let Some(Event::Scalar(raw, style, _, tag)) = events.get(*position) else {
                    bail!("workload keys must be plain strings");
                };
                *position += 1;
                let key = scalar(raw, *style, tag.as_ref())
                    .map_err(|_| anyhow!("workload keys must be plain strings"))?;
                let key = key
                    .as_str()
                    .filter(|k| *k != "<<")
                    .ok_or_else(|| anyhow!("workload keys must be plain strings"))?;
                ensure!(!values.contains_key(key), "duplicate workload key");
                if *style == TScalarStyle::Plain
                    && matches!(
                        events.get(*position),
                        Some(Event::MappingStart(..) | Event::SequenceStart(..))
                    )
                    && markers
                        .get(*position)
                        .and_then(|index| index.checked_sub(1))
                        .and_then(|index| source.get(index))
                        == Some(&b':')
                {
                    bail!("invalid workload YAML");
                }
                let value = node(events, markers, source, position, depth + 1)?;
                values.insert(key.into(), value);
            }
            *position += 1;
            Ok(values.into())
        }
        _ => bail!("unsupported workload YAML node"),
    }
}
pub fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= MAX_BYTES, "workload exceeds document limit");
    let text = std::str::from_utf8(bytes).map_err(|_| anyhow!("invalid workload YAML"))?;
    let mut parser = Parser::new_from_str(text);
    let mut events = vec![];
    let mut markers = vec![];
    let mut documents = 0;
    let mut first_ended = false;
    loop {
        let (event, marker) = parser.next_token().map_err(|_| {
            anyhow!(if first_ended {
                "workload must contain one document"
            } else {
                "invalid workload YAML"
            })
        })?;
        if event == Event::DocumentStart {
            documents += 1;
            ensure!(documents == 1, "workload must contain one document");
        }
        if event == Event::DocumentEnd {
            first_ended = true;
        }
        let ended = event == Event::StreamEnd;
        events.push(event);
        markers.push(marker.index());
        if ended {
            break;
        }
    }
    ensure!(
        documents == 1
            && events.first() == Some(&Event::StreamStart)
            && events.get(1) == Some(&Event::DocumentStart),
        "invalid workload YAML"
    );
    let mut position = 2;
    let value = node(&events, &markers, bytes, &mut position, 0)?;
    ensure!(
        events.get(position) == Some(&Event::DocumentEnd)
            && events.get(position + 1) == Some(&Event::StreamEnd),
        "invalid workload YAML"
    );
    Ok(value)
}
