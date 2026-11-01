use super::{
    assembly::now,
    engine::{Engine, local_engine_eligible},
    inventory::{INSPECT_FORMAT, Inventory, PS_FORMAT},
    *,
};
use anyhow::{Result, ensure};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
pub trait Docker {
    fn run(
        &mut self,
        args: &[String],
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<String>;
    fn logs(&mut self, args: &[String], deadline: Instant, cancelled: &dyn Fn() -> bool) -> String {
        let mut body = self.run(args, deadline, cancelled).unwrap_or_default();
        let mut end = body.len().min(super::logs::LOGS_MAX);
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        body
    }
}
pub struct NativeDocker;
impl Docker for NativeDocker {
    fn logs(&mut self, args: &[String], deadline: Instant, cancelled: &dyn Fn() -> bool) -> String {
        String::from_utf8_lossy(&super::collect::capture_prefix(
            Command::new("docker").args(args),
            super::logs::LOGS_MAX,
            deadline,
            cancelled,
        ))
        .into_owned()
    }
    fn run(
        &mut self,
        args: &[String],
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<String> {
        let captured = crate::process::capture(
            Command::new("docker").args(args),
            None,
            64 << 20,
            deadline,
            cancelled,
        )?;
        ensure!(captured.status.success(), "Docker metadata unavailable");
        Ok(String::from_utf8_lossy(&captured.stdout).into_owned())
    }
}
enum Backend<'a> {
    Engine(Box<Engine>),
    Unavailable,
    Cli(Box<dyn Docker + 'a>),
}
pub struct Observer<'a> {
    probe: &'a Probe,
    backend: Backend<'a>,
    deadline: Instant,
    cancelled: Box<dyn Fn() -> bool + 'a>,
}
impl<'a> Observer<'a> {
    pub fn new(probe: &'a Probe, cancelled: impl Fn() -> bool + 'a) -> Self {
        let deadline = Instant::now() + Duration::from_secs(8);
        let backend = if local_engine_eligible(probe) {
            match Engine::connect(Path::new("/var/run/docker.sock"), deadline) {
                Ok(Some(engine)) => Backend::Engine(Box::new(engine)),
                Ok(None) => Backend::Cli(Box::new(NativeDocker)),
                Err(_) => Backend::Unavailable,
            }
        } else {
            Backend::Cli(Box::new(NativeDocker))
        };
        Self {
            probe,
            backend,
            deadline,
            cancelled: Box::new(cancelled),
        }
    }
    pub fn with_cli(
        probe: &'a Probe,
        runner: impl Docker + 'a,
        deadline: Instant,
        cancelled: impl Fn() -> bool + 'a,
    ) -> Self {
        Self {
            probe,
            backend: Backend::Cli(Box::new(runner)),
            deadline,
            cancelled: Box::new(cancelled),
        }
    }
    pub fn with_engine(
        probe: &'a Probe,
        engine: Engine,
        deadline: Instant,
        cancelled: impl Fn() -> bool + 'a,
    ) -> Self {
        Self {
            probe,
            backend: Backend::Engine(Box::new(engine)),
            deadline,
            cancelled: Box::new(cancelled),
        }
    }
    fn cli(&mut self, args: &[&str]) -> Result<String> {
        let Backend::Cli(runner) = &mut self.backend else {
            anyhow::bail!("CLI metadata is not selected");
        };
        let args: Vec<_> = args.iter().map(|a| a.to_string()).collect();
        runner.run(&args, self.deadline, &self.cancelled)
    }
    pub fn inventory(&mut self) -> Inventory {
        match &mut self.backend {
            Backend::Engine(engine) => return engine.inventory(),
            Backend::Unavailable => return Inventory::unavailable("list_unavailable"),
            Backend::Cli(_) => {}
        }
        let list = self.cli(&["ps", "-a", "--no-trunc", "--format", PS_FORMAT]);
        Inventory::from_cli(list, |ids| {
            let mut args = vec!["inspect".into(), "--format".into(), INSPECT_FORMAT.into()];
            args.extend_from_slice(ids);
            let Backend::Cli(runner) = &mut self.backend else {
                unreachable!()
            };
            runner.run(&args, self.deadline, &self.cancelled)
        })
    }
    pub fn volumes(&mut self, only: &str) -> Vec<Volume> {
        let inventory = self.inventory();
        self.probe.volumes_from_inventory(&inventory, only)
    }
    pub fn collect_logs(&mut self, dir: &Path) {
        use super::logs::{LOGS_MAX, format_log, log_path, prune_logs, write_log};
        if matches!(self.backend, Backend::Unavailable) {
            return;
        }
        if matches!(self.backend, Backend::Engine(_)) {
            let inventory = self.inventory();
            if inventory.status != "current" {
                return;
            }
            let Ok(states) = self.probe.app_states_available() else {
                return;
            };
            let mut names = vec![];
            for app in states {
                if log_path(dir, &app.name).is_err() {
                    continue;
                }
                names.push(app.name.clone());
                if app.get("STOPPED") == "1" {
                    continue;
                }
                let mut containers = inventory.for_dir(app.dir());
                containers.sort_by(|a, b| a.name.cmp(&b.name));
                let mut collected = vec![];
                let mut failed = false;
                for container in containers {
                    if container.name == "komizo-proxy" || container.state != "running" {
                        continue;
                    }
                    let Backend::Engine(engine) = &mut self.backend else {
                        unreachable!()
                    };
                    let Ok(body) = engine.logs(container) else {
                        failed = true;
                        break;
                    };
                    let body = String::from_utf8_lossy(&body);
                    let lines: Vec<_> = body
                        .strip_suffix('\n')
                        .unwrap_or(&body)
                        .split('\n')
                        .filter(|line| !line.is_empty())
                        .map(|line| LogLine {
                            service: container.service.clone(),
                            text: line.into(),
                        })
                        .collect();
                    collected.extend_from_slice(format_log(&lines).as_bytes());
                    if collected.len() > LOGS_MAX {
                        collected.drain(..collected.len() - LOGS_MAX);
                        if let Some(index) = collected.iter().position(|b| *b == b'\n') {
                            collected.drain(..=index);
                        }
                    }
                }
                if !failed && !crate::wire::trim_space(&collected).is_empty() {
                    let _ = write_log(dir, &app.name, &collected);
                }
            }
            let _ = prune_logs(dir, &names);
            return;
        }
        // A failed registry scan must never delete retained diagnostic tails.
        let Ok(entries) = std::fs::read_dir(self.probe.path(super::paths::APPS_DIR)) else {
            return;
        };
        let mut names = vec![];
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(name) = name.strip_suffix(".env")
                && log_path(dir, name).is_ok()
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        for name in &names {
            let Ok(subject) = super::application::resolve_subject(&self.probe.root, name, false)
            else {
                continue;
            };
            let mut args = super::application::compose_base(&subject.dir, &subject.project);
            args.extend(["logs", "--tail", "500", "--no-color"].map(String::from));
            let Backend::Cli(runner) = &mut self.backend else {
                unreachable!()
            };
            let body = runner.logs(&args, self.deadline, &self.cancelled);
            if body.trim().is_empty() {
                continue;
            }
            let mut args = super::application::compose_base(&subject.dir, &subject.project);
            args.extend(["ps", "--all", "--format", "json"].map(String::from));
            let metadata = runner
                .run(&args, self.deadline, &self.cancelled)
                .unwrap_or_default();
            let _ = write_log(
                dir,
                name,
                super::collect::with_services(&body, &super::collect::service_map(&metadata))
                    .as_bytes(),
            );
        }
        let _ = prune_logs(dir, &names);
    }
    fn server(&mut self, agent: &str) -> Server {
        let (state, docker) = match &self.backend {
            Backend::Unavailable => ("docker-stopped", String::new()),
            Backend::Engine(engine) => {
                if engine.available {
                    (
                        "ready",
                        format!(
                            "Docker version {}, build {}",
                            engine.version.version, engine.version.git_commit
                        ),
                    )
                } else {
                    ("docker-stopped", String::new())
                }
            }
            Backend::Cli(_) => match self.cli(&["--version"]) {
                Ok(version) => {
                    if self
                        .cli(&["version", "--format", "{{.Server.Version}}"])
                        .is_ok()
                    {
                        (
                            "ready",
                            version.lines().next().unwrap_or_default().trim().into(),
                        )
                    } else {
                        ("docker-stopped", String::new())
                    }
                }
                Err(_) => ("bare", String::new()),
            },
        };
        self.probe.server_facts(state, &docker, agent)
    }
    fn network(&mut self, name: &str) -> Option<String> {
        match &mut self.backend {
            Backend::Engine(engine) => engine.network(name).ok(),
            Backend::Unavailable => None,
            Backend::Cli(_) => self
                .cli(&[
                    "network",
                    "inspect",
                    name,
                    "--format",
                    "{{.Driver}}\t{{range .IPAM.Config}}{{.Subnet}}{{end}}",
                ])
                .ok(),
        }
    }
    pub fn report(&mut self, agent: &str, at: Option<crate::wire::Time>) -> Report {
        let at = at.unwrap_or_else(now);
        let server = self.server(agent);
        if !server.ready() {
            return self
                .probe
                .assemble_report(server, &Inventory::default(), None, at);
        }
        let inventory = self.inventory();
        let proxy = self.probe.proxy(&inventory);
        let name = proxy
            .as_ref()
            .map(|p| p.network.as_str())
            .filter(|s| !s.is_empty() && *s != "?")
            .unwrap_or("edge");
        let metadata = self.network(name);
        self.probe
            .assemble_report(server, &inventory, metadata.as_deref(), at)
    }
}
