//! Canonical authored configuration: TOML with JSON-compatible scalar values.
//! Wire JSON and explicit legacy-v1 decoders stay separate from file discovery.
use serde_json::Value;

pub fn parse(text: &str) -> Result<Value, String> {
    let value: toml::Value =
        toml::from_str(text).map_err(|_| "invalid configuration TOML".to_owned())?;
    fn check(value: &toml::Value) -> Result<(), String> {
        match value {
            toml::Value::Datetime(_) => {
                return Err("configuration dates must be quoted strings".into());
            }
            toml::Value::Float(v) if !v.is_finite() => {
                return Err("configuration numbers must be finite".into());
            }
            toml::Value::Array(values) => {
                for value in values {
                    check(value)?;
                }
            }
            toml::Value::Table(values) => {
                for value in values.values() {
                    check(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    check(&value)?;
    serde_json::to_value(value).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_values_preserve_types_and_refuse_lossy_or_ambiguous_input() {
        let value =
            parse("zero = 0\nno = false\nempty = []\n[map]\nquoted = \"line\\ntext\"\n").unwrap();
        assert_eq!(value["zero"], 0);
        assert_eq!(value["no"], false);
        assert_eq!(value["empty"], serde_json::json!([]));
        assert_eq!(value["map"]["quoted"], "line\ntext");
        for invalid in [
            "x = 1\nx = 2",
            "x = nan",
            "x = inf",
            "x = 2026-11-07",
            "{\"x\":1}",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
    }
}
