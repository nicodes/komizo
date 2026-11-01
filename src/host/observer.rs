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
}
pub struct NativeDocker;
impl Docker for NativeDocker {
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
