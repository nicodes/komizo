//! Typed command results retain mutation uncertainty until locally proved otherwise.
use crate::{wire::Slice, wire_struct, workload::activation::Context};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    fmt,
    io::{self, Write},
};
pub const MAX_OUTPUT: usize = 4 << 20;
wire_struct!(MachineError{code:"code":String=>required,message:"message":String=>required,retryable:"retryable":bool=>required,reconciliation_required:"reconciliation_required":bool=>required});
wire_struct!(MachineResult{version:"version":i64=>required,command:"command":String=>required,ok:"ok":bool=>required,exit_code:"exit_code":i64=>required,data:"data":Value=>required,error:"error":Option<MachineError> =>required,next_action:"next_action":Slice<String> =>optional});
#[derive(Debug)]
pub struct Failure {
    pub code: i64,
    pub error: anyhow::Error,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}
pub fn local(error: anyhow::Error) -> anyhow::Error {
    Failure { code: 64, error }.into()
}
pub fn mismatch(error: anyhow::Error) -> anyhow::Error {
    Failure { code: 65, error }.into()
}
pub fn exit_code(error: &anyhow::Error) -> i64 {
    error.downcast_ref::<Failure>().map(|e| e.code).unwrap_or(1)
}
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| {
        arg == &format!("--{name}")
            || arg == &format!("-{name}")
            || arg.starts_with(&format!("--{name}="))
    })
}
pub fn help(args: &[String]) -> bool {
    for arg in args.iter().skip(1) {
        if matches!(arg.as_str(), "--help" | "-h") {
            return true;
        }
        if arg.starts_with('-') {
            return false;
        }
    }
    args.first()
        .is_some_and(|arg| matches!(arg.as_str(), "help" | "--help" | "-h"))
}
pub fn command_name(args: &[String]) -> &str {
    match args.first().map(String::as_str).unwrap_or("") {
        "--version" | "-v" => "version",
        "--help" | "-h" => "help",
        name => name,
    }
}
pub fn capabilities() -> Value {
    let mut value: Value = serde_json::from_str(include_str!("capabilities.json"))
        .expect("reviewed capability metadata");
    value["cli_version"] = crate::runtime::VERSION.into();
    value
}
pub fn known(name: &str) -> bool {
    capabilities()["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"].as_str() == Some(name))
}
pub fn mutating(name: &str, args: &[String]) -> bool {
    if capabilities()["commands"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"].as_str() == Some(name) && c["mutating"] == false)
    {
        return false;
    }
    if name == "unset-secret"
        && has_flag(args, "list")
        && !has_flag(args, "name")
        && !has_flag(args, "keep")
    {
        return args.iter().any(|arg| {
            (arg.starts_with("--list=") || arg.starts_with("-list=")) && !arg.ends_with("=true")
        });
    }
    if let Some(subcommand) = args.get(1)
        && ((matches!(name, "operation" | "platform") && subcommand == "inspect")
            || (name == "preview" && matches!(subcommand.as_str(), "ls" | "resolve" | "database")))
    {
        return false;
    }
    true
}
pub fn next_action(args: &[String], mutating: bool) -> Vec<String> {
    let mut values = std::collections::BTreeMap::new();
    for (index, arg) in args.iter().enumerate().skip(1) {
        for name in ["host", "app", "port"] {
            if arg == &format!("--{name}")
                && let Some(value) = args.get(index + 1)
            {
                values.insert(name, value.clone());
            } else if let Some(value) = arg.strip_prefix(&format!("--{name}=")) {
                values.insert(name, value.into());
            }
        }
    }
    let Some(host) = values.get("host").filter(|s| !s.is_empty()) else {
        return ["komizo", "--json", "capabilities"]
            .map(String::from)
            .to_vec();
    };
    let mut next = if mutating && values.get("app").is_some_and(|s| !s.is_empty()) {
        vec![
            "komizo".into(),
            "--json".into(),
            "operation".into(),
            "inspect".into(),
            "--host".into(),
            host.clone(),
            "--app".into(),
            values["app"].clone(),
        ]
    } else {
        vec![
            "komizo".into(),
            "--json".into(),
            "doctor".into(),
            "--host".into(),
            host.clone(),
        ]
    };
    if let Some(port) = values.get("port").filter(|s| !s.is_empty()) {
        next.extend(["--port".into(), port.clone()]);
    }
    next
}
pub struct Text {
    body: Vec<u8>,
    pub truncated: bool,
    maximum: usize,
}
impl Default for Text {
    fn default() -> Self {
        Self::with_limit(MAX_OUTPUT)
    }
}
impl Text {
    pub fn with_limit(maximum: usize) -> Self {
        Self {
            body: vec![],
            truncated: false,
            maximum,
        }
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}
impl Write for Text {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes
            .len()
            .min(self.maximum.saturating_sub(self.body.len()));
        self.body.extend_from_slice(&bytes[..n]);
        self.truncated |= n < bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default)]
pub struct Output {
    pub text: Text,
    pub data: Option<Value>,
}
impl Output {
    pub fn emit(&mut self, value: Value) -> Result<()> {
        ensure!(
            self.data.is_none(),
            "command emitted more than one structured result"
        );
        ensure!(
            serde_json::to_vec(&value)?.len() <= MAX_OUTPUT,
            "structured result exceeds 4 MiB"
        );
        self.data = Some(value);
        Ok(())
    }
    pub fn protocol(&mut self, body: &[u8]) -> Result<()> {
        ensure!(body.len() <= MAX_OUTPUT, "protocol response exceeds 4 MiB");
        self.emit(
            crate::strict::value(body, MAX_OUTPUT)
                .map_err(|_| anyhow::anyhow!("invalid structured protocol response"))?,
        )
    }
}
pub fn early_failure(name: &str, code: &str, message: &str, uncertain: bool) -> MachineResult {
    MachineResult {
        version: 1,
        command: name.into(),
        exit_code: 1,
        data: Value::Null,
        error: Some(MachineError {
            code: code.into(),
            message: message.into(),
            reconciliation_required: uncertain,
            ..Default::default()
        }),
        next_action: ["komizo", "--json", "capabilities"]
            .map(String::from)
            .to_vec()
            .into(),
        ..Default::default()
    }
}
pub fn finish(
    ctx: &Context,
    args: &[String],
    output: Output,
    result: Result<()>,
    parser_help: bool,
) -> MachineResult {
    let name = command_name(args);
    let is_help = parser_help
        || result
            .as_ref()
            .is_err_and(|e| e.is::<crate::flags::Help>() || exit_code(e) == 66)
        || (result.is_ok() && help(args));
    let mutating = mutating(name, args) && !is_help;
    let mut envelope = MachineResult {
        version: 1,
        command: name.into(),
        ok: result.is_ok() || is_help,
        data: output.data.clone().unwrap_or(Value::Null),
        ..Default::default()
    };
    if let Err(error) = result
        && !is_help
    {
        let exit = exit_code(&error);
        envelope.exit_code = exit;
        let (mut code, mut message, mut uncertain) =
            ("command_failed", error.to_string(), mutating);
        if exit == 64 {
            code = "invalid_input";
            uncertain = false;
        }
        if exit == 65 {
            code = "state_mismatch";
            uncertain = false;
        }
        if ctx.check().is_err() {
            code = "timeout";
            message = "deadline expired; inspect state before retrying a mutation".into();
        }
        envelope.error = Some(MachineError {
            code: code.into(),
            message,
            reconciliation_required: uncertain,
            ..Default::default()
        });
        envelope.next_action = if code == "invalid_input" {
            vec![
                "komizo".into(),
                "--json".into(),
                name.into(),
                "--help".into(),
            ]
        } else {
            next_action(args, mutating)
        }
        .into();
    } else if output.text.truncated {
        envelope.ok = false;
        envelope.exit_code = 1;
        envelope.error = Some(MachineError {
            code: "output_limit".into(),
            message: "output exceeded 4 MiB; request a smaller report or log tail".into(),
            reconciliation_required: mutating,
            ..Default::default()
        });
    } else if is_help
        || capabilities()["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"].as_str() == Some(name) && c["data"] == "text")
    {
        envelope.data = json!({"text":String::from_utf8_lossy(output.text.body())});
    } else if output.data.is_none() {
        envelope.ok = false;
        envelope.exit_code = 1;
        envelope.error = Some(MachineError {
            code: "invalid_response".into(),
            message: "command returned no structured result; inspect state before retrying".into(),
            reconciliation_required: mutating,
            ..Default::default()
        });
        envelope.next_action = next_action(args, mutating).into();
    }
    envelope
}
pub fn receipt(
    action: &str,
    target: &super::transport::Target,
    app: &str,
    details: Value,
) -> Value {
    let mut value = json!({"version":1,"action":action,"host":target.addr(),"details":if details.is_null(){json!({})}else{details},"acknowledged":true});
    if !app.is_empty() {
        value["app"] = app.into();
    }
    value
}
