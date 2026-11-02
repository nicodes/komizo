use super::{
    protocol, reach, state,
    transport::{Remote, Target},
};
use crate::{
    flags::{Flag, Flags},
    input::Input,
    workload::activation::Context,
};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::{io::Write, path::Path};
pub struct Cli<'a> {
    pub context: Context,
    pub machine: bool,
    pub output: &'a mut dyn Write,
    pub progress: &'a mut dyn Write,
    pub result: protocol::Output,
    pub input: Option<Input>,
}
impl Cli<'_> {
    pub fn emit(&mut self, value: impl serde::Serialize) -> Result<()> {
        let value = serde_json::to_value(value)?;
        if self.machine {
            self.result.emit(value)
        } else {
            crate::host::commands::emit(self.output, &value)
        }
    }
    pub fn text(&mut self, body: &[u8]) -> Result<()> {
        if self.machine {
            self.result.text.write_all(body)?;
        } else {
            self.output.write_all(body)?;
        }
        Ok(())
    }
    pub fn note(&mut self, text: &str) -> Result<()> {
        writeln!(self.progress, "    {text}")?;
        Ok(())
    }
    pub fn parse(&self, spec: &[Flag], args: &[String], message: &str) -> Result<Flags> {
        let flags = Flags::parse(spec, args).map_err(|e| {
            if e.is::<crate::flags::Help>() {
                e
            } else {
                protocol::local(e)
            }
        })?;
        flags.no_args(message).map_err(protocol::local)?;
        Ok(flags)
    }
    pub fn target(&self, flags: &Flags) -> Result<Remote> {
        Ok(Remote::new(
            Target::resolve(flags, &self.context).map_err(protocol::local)?,
        ))
    }
    pub fn bound_target(&self, flags: &mut Flags, directory: &str) -> Result<Remote> {
        if flags.text("host").is_empty() {
            state::default_target(
                Path::new(directory),
                &state::target_path().map_err(protocol::local)?,
                flags,
            )
            .map_err(protocol::local)?;
        }
        self.target(flags)
    }
    pub fn reachable(&mut self, remote: &Remote, accept: bool) -> Result<()> {
        reach::ensure_reachable(&self.context, remote, accept, self.progress)
    }
    pub fn script(
        &mut self,
        remote: &Remote,
        script: &str,
        env: &std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        use std::{cell::RefCell, rc::Rc};
        let shared = Rc::new(RefCell::new(&mut *self.progress));
        remote
            .script(
                &self.context,
                script,
                env,
                &mut Shared(shared.clone()),
                &mut Shared(shared),
            )
            .result
    }
    pub fn body(&mut self, maximum: usize) -> Result<Vec<u8>> {
        if self.input.is_none() {
            self.input = Some(Input::stdin()?);
        }
        self.input.as_mut().unwrap().bounded(&self.context, maximum)
    }
    pub fn stream(&mut self, remote: &Remote, command: &str, input: &[u8]) -> Result<()> {
        use std::{cell::RefCell, rc::Rc};
        let shared = Rc::new(RefCell::new(&mut *self.progress));
        let result = crate::process::stream(
            &mut remote.command(command),
            Some(input),
            8192,
            self.context.deadline,
            || self.context.check().is_err(),
            &mut Shared(shared.clone()),
            &mut Shared(shared),
        )?;
        ensure!(
            result.status.success(),
            "remote command failed: {}; see the output above",
            result.status
        );
        Ok(())
    }
    pub fn receipt(
        &mut self,
        action: &str,
        remote: &Remote,
        app: &str,
        details: Value,
    ) -> Result<()> {
        if self.machine {
            self.emit(protocol::receipt(action, &remote.target, app, details))
        } else {
            Ok(())
        }
    }
}
pub struct Shared<'a, W: Write + ?Sized>(pub std::rc::Rc<std::cell::RefCell<&'a mut W>>);
impl<W: Write + ?Sized> Write for Shared<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}
pub fn common() -> Vec<Flag> {
    vec![
        Flag::text("host", ""),
        Flag::integer("port", 22),
        Flag::boolean("accept-host-key", false),
    ]
}
pub fn validate_service(service: &str) -> Result<()> {
    crate::host::application::valid_service(service)
}
pub fn exact_revision(value: &str) -> Result<()> {
    ensure!(
        crate::workload::policy::commit_id(value),
        "exact source revision is required"
    );
    Ok(())
}
