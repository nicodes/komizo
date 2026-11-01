//! Stable Go-compatible JSON bytes retain existing protected artifact identities.
use anyhow::Result;
use serde_json::Value;
fn string(value: &str) -> Result<String> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}
fn write(value: &Value, depth: usize, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::String(value) => output.push_str(&string(value)?),
        Value::Number(number) => {
            if number.is_f64() {
                let number = number.as_f64().unwrap();
                if number != 0.0 && (number.abs() < 1e-6 || number.abs() >= 1e21) {
                    let formatted = format!("{number:e}");
                    let (mantissa, exponent) = formatted.split_once('e').unwrap();
                    let exponent: i32 = exponent.parse().unwrap();
                    output.push_str(&format!("{mantissa}e{exponent:+}"));
                } else {
                    output.push_str(&number.to_string());
                }
            } else {
                output.push_str(&number.to_string());
            }
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push('\n');
                output.push_str(&"  ".repeat(depth + 1));
                write(value, depth + 1, output)?;
            }
            if !values.is_empty() {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
            }
            output.push(']');
        }
        Value::Object(values) => {
            let sorted: std::collections::BTreeMap<_, _> = values.iter().collect();
            output.push('{');
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push('\n');
                output.push_str(&"  ".repeat(depth + 1));
                output.push_str(&string(key)?);
                output.push_str(": ");
                write(value, depth + 1, output)?;
            }
            if !values.is_empty() {
                output.push('\n');
                output.push_str(&"  ".repeat(depth));
            }
            output.push('}');
        }
    }
    Ok(())
}
pub fn pretty(value: &Value) -> Result<Vec<u8>> {
    let mut output = String::new();
    write(value, 0, &mut output)?;
    Ok(output.into_bytes())
}
