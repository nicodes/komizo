use super::{
    LogLine,
    inventory::ContainerInfo,
    logs::{LOGS_MAX, format_log},
};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

/// Preserve the bounded prefix even if Compose fails or writes past the limit.
/// Returning an error from the sink stops and reaps its complete process group.
pub fn capture_prefix(
    command: &mut std::process::Command,
    maximum: usize,
    deadline: std::time::Instant,
    cancelled: &dyn Fn() -> bool,
) -> Vec<u8> {
    use std::io::{self, Write};
    struct Prefix {
        body: Vec<u8>,
        maximum: usize,
    }
    impl Write for Prefix {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes
                .len()
                .min(self.maximum.saturating_sub(self.body.len()));
            self.body.extend_from_slice(&bytes[..count]);
            if count < bytes.len() {
                return Err(io::Error::other("log prefix complete"));
            }
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut prefix = Prefix {
        body: vec![],
        maximum,
    };
    let _ = crate::process::stream(
        command,
        None,
        8192,
        deadline,
        cancelled,
        &mut prefix,
        &mut io::sink(),
    );
    prefix.body
}

pub fn decode_frames(mut body: &[u8], tty: bool) -> Result<Vec<u8>> {
    if tty {
        return Ok(body.to_vec());
    }
    let mut output = vec![];
    while !body.is_empty() {
        ensure!(
            body.len() >= 8 && matches!(body[0], 1 | 2) && body[1..4] == [0, 0, 0],
            "invalid log frame"
        );
        let size = u32::from_be_bytes(body[4..8].try_into().unwrap()) as usize;
        body = &body[8..];
        ensure!(
            size <= body.len() && size <= LOGS_MAX.saturating_sub(output.len()),
            "invalid or oversized log frame"
        );
        output.extend_from_slice(&body[..size]);
        body = &body[size..];
    }
    Ok(output)
}
impl super::engine::Engine {
    pub fn logs(&mut self, container: &ContainerInfo) -> Result<Vec<u8>> {
        // Inventory has already checked IDs. Keep this method safe independently.
        ensure!(
            container.id.len() == 64
                && container
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid log request"
        );
        let body = self.read_bytes(
            &format!(
                "/v1.45/containers/{}/logs?stdout=1&stderr=1&tail=500",
                container.id
            ),
            LOGS_MAX + 8 * 500,
        )?;
        decode_frames(&body, container.tty)
    }
}
pub fn service_map(body: &str) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    for document in serde_json::Deserializer::from_str(body).into_iter::<serde_json::Value>() {
        let Ok(document) = document else { break };
        let rows = match document {
            serde_json::Value::Array(rows) => rows,
            value => vec![value],
        };
        for row in rows {
            if let (Some(name), Some(service)) = (
                row.get("Name").and_then(|v| v.as_str()),
                row.get("Service").and_then(|v| v.as_str()),
            ) && !name.is_empty()
                && !service.is_empty()
            {
                output.insert(name.into(), service.into());
            }
        }
    }
    output
}
pub fn cut_compose_prefix(line: &str) -> Option<(&str, &str)> {
    let (prefix, text) = line.split_once('|')?;
    let name = prefix.trim();
    if name.is_empty() || name.contains([' ', '\t']) {
        return None;
    }
    Some((name, text.strip_prefix(' ').unwrap_or(text)))
}
pub fn with_services(body: &str, services: &BTreeMap<String, String>) -> String {
    let lines: Vec<_> = body
        .strip_suffix('\n')
        .unwrap_or(body)
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (service, text) = cut_compose_prefix(line)
                .map(|(name, text)| (services.get(name).cloned().unwrap_or_default(), text))
                .unwrap_or((String::new(), line));
            LogLine {
                service,
                text: text.into(),
            }
        })
        .collect();
    format_log(&lines)
}
