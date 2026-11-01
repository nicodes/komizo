use super::{App, Container, Probe, paths::*};
use crate::wire::{Slice, null_default};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Desired {
    #[serde(deserialize_with = "null_default")]
    pub restart: String,
    #[serde(deserialize_with = "null_default")]
    pub profiles: Slice<String>,
    pub healthcheck: Option<Healthcheck>,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Healthcheck {
    #[serde(deserialize_with = "null_default")]
    pub test: Slice<String>,
    #[serde(deserialize_with = "null_default")]
    pub disable: bool,
}
pub fn ready(service: &Desired, state: &str, exit_code: i64, health: &str) -> bool {
    if service.restart == "no" && state == "exited" && exit_code == 0 {
        return true;
    }
    if state != "running" {
        return false;
    }
    let required = service
        .healthcheck
        .as_ref()
        .is_some_and(|h| !h.disable && !h.test.is_empty() && h.test[0] != "NONE");
    health == "healthy" || health.is_empty() && !required
}
impl Probe {
    pub fn runtime_state(&self, app: &App) -> String {
        if app.stopped {
            return "stopped".into();
        }
        if let Some(serving) = &app.r#static {
            return if serving.active { "running" } else { "down" }.into();
        }
        let Ok(Some(bytes)) =
            crate::statefile::read(&self.path(Path::new(&app.dir).join("compose.yml")), 1 << 20)
        else {
            return "unknown".into();
        };
        #[derive(Deserialize)]
        struct Projection {
            services: BTreeMap<String, Desired>,
        }
        let Ok(projection) = serde_json::from_slice::<Projection>(&bytes) else {
            return "unknown".into();
        };
        if projection.services.is_empty() || projection.services.len() > 32 {
            return "unknown".into();
        }
        let mut containers: BTreeMap<&str, &Container> = BTreeMap::new();
        for container in app.containers.iter() {
            if container.inspection == "unavailable" {
                return "unknown".into();
            }
            if containers.insert(&container.service, container).is_some() {
                return "degraded".into();
            }
        }
        let (mut healthy, mut missing, mut running) = (0, 0, 0);
        for (name, service) in projection.services {
            let container = containers.get(name.as_str());
            if container.is_none() && !service.profiles.is_empty() {
                continue;
            }
            if container.is_some_and(|c| c.state == "running") {
                running += 1;
            }
            if container.is_some_and(|c| ready(&service, &c.state, c.exit_code, &c.health)) {
                healthy += 1;
            } else {
                missing += 1;
            }
        }
        if missing > 0 {
            return if healthy > 0 || running > 0 {
                "degraded"
            } else {
                "down"
            }
            .into();
        }
        if healthy == 0 {
            return "unknown".into();
        }
        if running == 0 { "completed" } else { "running" }.into()
    }
    pub fn komizo_install(&self, agent: &str) -> super::KomizoInstall {
        let mut install = super::KomizoInstall {
            agent: agent.into(),
            ..Default::default()
        };
        let lines = super::system::lines(self.path(VERSION_PATH));
        if lines.is_empty() {
            return install;
        }
        install.installed = true;
        if lines.len() >= 2 && !lines[0].trim().is_empty() && !lines[1].trim().is_empty() {
            install.version = lines[0].trim().into();
            install.stamp = lines[1].trim().into();
        }
        install
    }
}
