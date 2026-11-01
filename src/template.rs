//! Native rendering of existing operator templates; context never enters diagnostics.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{self, Write},
};
fn context(value: &Value) -> gtmpl::Value {
    match value {
        Value::Null => gtmpl::Value::Nil,
        Value::Bool(value) => (*value).into(),
        Value::String(value) => value.clone().into(),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                value.into()
            } else if let Some(value) = value.as_u64() {
                value.into()
            } else {
                value.as_f64().unwrap().into()
            }
        }
        Value::Array(values) => gtmpl::Value::Array(values.iter().map(context).collect()),
        Value::Object(values) => gtmpl::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), context(value)))
                .collect::<HashMap<_, _>>(),
        ),
    }
}
pub fn validate(name: &str, body: &str) -> Result<()> {
    let mut template = gtmpl::Template::with_name(name);
    template
        .parse(body)
        .map_err(|_| anyhow!("invalid preview compose template"))?;
    Ok(())
}
pub fn render(name: &str, body: &str, values: &Value, limit: usize) -> Result<String> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit - self.bytes.len() {
                return Err(io::Error::other("template output exceeds bound"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut template = gtmpl::Template::with_name(name);
    template
        .parse(body)
        .map_err(|_| anyhow!("invalid preview compose template"))?;
    let mut output = Bounded {
        bytes: vec![],
        limit,
    };
    template
        .execute(&mut output, &gtmpl::Context::from(context(values)))
        .map_err(|_| anyhow!("preview template could not render declared inputs"))?;
    ensure!(
        output.bytes.len() <= limit,
        "rendered preview exceeds limit"
    );
    String::from_utf8(output.bytes).map_err(|_| anyhow!("invalid rendered preview encoding"))
}
