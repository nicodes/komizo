use super::{
    Record,
    knob::{Knob, memory_bytes},
};
use crate::host::authority::quote;
use anyhow::{Result, anyhow, ensure};
pub fn runtime_role(image: &str) -> &str {
    let name = image.rsplit('/').next().unwrap_or(image);
    let name = name.split('@').next().unwrap().split(':').next().unwrap();
    for role in ["renderer", "runtime"] {
        if name == role || name.ends_with(&format!("-{role}")) {
            return role;
        }
    }
    ""
}
pub fn has_runtime(images: &[String]) -> bool {
    images
        .iter()
        .skip(1)
        .any(|image| !runtime_role(image).is_empty())
}
impl Knob {
    pub fn profile(&self, app: &str) -> Option<&super::profile::Profile> {
        self.profiles
            .as_ref()
            .and_then(|profiles| profiles.get(app))
            .and_then(Option::as_ref)
    }
    pub fn memory_reservation(&self, app: &str, images: &[String]) -> Result<i64> {
        ensure!(!images.is_empty(), "no preview images");
        if let Some(profile) = self.profile(app) {
            let mut total = 0;
            for service in profile.services.iter() {
                total += memory_bytes(&self.service_memory(app, service)).map_err(|_| {
                    anyhow!("preview up refused: invalid memory limit for {app} {service}")
                })?;
            }
            return Ok(total);
        }
        let base = memory_bytes(&self.service_memory(app, ""))
            .map_err(|_| anyhow!("preview up refused: invalid memory limit for {app} "))?;
        let mut total = base * images.len() as i64;
        for image in images.iter().skip(1) {
            let role = runtime_role(image);
            if role.is_empty() {
                continue;
            }
            let memory = memory_bytes(&self.service_memory(app, role))
                .map_err(|e| anyhow!("invalid private runtime memory limit: {e}"))?;
            total += memory - base;
        }
        Ok(total)
    }
}
pub fn render(
    r: &Record,
    k: &Knob,
    network: &str,
    stack_env: bool,
    db_endpoint: &str,
) -> Result<String> {
    if let Some(profile) = k.profile(&r.app) {
        return profile.compose(r, k, network);
    }
    let mut output =
        "# Written by komizo preview. Re-run `komizo preview up` to change it.\n".to_owned();
    if r.db_name.is_empty() {
        output.push_str(&format!("# Preview of {} PR #{}. Own project, own route. Gate only -- no database.\nservices:\n",r.app,r.pr));
    } else {
        output.push_str(&format!(
            "# Preview of {} PR #{}. Own project, own database ({}), own route.\nservices:\n",
            r.app, r.pr, r.db_name
        ));
    }
    for (index, image) in r.images.iter().enumerate() {
        let basename = image
            .rsplit('/')
            .next()
            .unwrap_or(image)
            .split(':')
            .next()
            .unwrap();
        let name = if index == 0 {
            format!("{}-gate", r.project)
        } else {
            basename.into()
        };
        let role = if index == 0 { "" } else { runtime_role(image) };
        let limit = k.service_memory(&r.app, role);
        output.push_str(&format!("  {name}:\n    image: {image}\n    mem_limit: {limit}\n    memswap_limit: {limit}\n    cpu_shares: 128\n    cpus: {}\n    restart: unless-stopped\n",k.cpu_limit));
        if !k.cgroup_parent.is_empty() {
            output.push_str(&format!("    cgroup_parent: {}\n", k.cgroup_parent));
        }
        output.push_str("    tmpfs:\n      - /tmp:rw,noexec,nosuid,size=64m,mode=1777\n");
        if index == 0 {
            let host = r.web_host(k);
            output.push_str(&format!("    container_name: {}-gate\n    environment:\n      PREVIEW: \"1\"\n      PR: \"{}\"\n      BASE_URL: https://{host}{}\n      PREVIEW_HOST: {host}\n      PREVIEW_API_HOST: {}\n      PREVIEW_BASE_PATH: {}\n    ports:\n      - \"127.0.0.1:{}:80\"\n    networks:\n      - shared\n",r.project,r.pr,r.base_path,r.public_api_host(k),quote(&r.base_path),r.gate_port));
            if r.images.len() > 1 {
                output.push_str("      - backend\n");
            }
        } else if !role.is_empty() {
            output.push_str("    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    init: true\n    pids_limit: 128\n    networks:\n      - runtime\n");
        } else {
            output.push_str(&format!(
                "    environment:\n      PREVIEW: \"1\"\n      PR: \"{}\"\n",
                r.pr
            ));
            if !r.db_name.is_empty() {
                output.push_str(&format!("      DB_NAME: {}\n      PGDATABASE: {}\n      PGUSER: {}\n      PGPASSWORD: {}\n",r.db_name,r.db_name,r.db_name,r.db_password.expose()));
            }
            if !db_endpoint.is_empty() {
                output.push_str(&format!(
                    "      RUNTIME_DATABASE_URL: postgres://{}:{}@{db_endpoint}:5432/{}\n",
                    r.db_name,
                    r.db_password.expose(),
                    r.db_name
                ));
            }
            if stack_env {
                output.push_str("    env_file:\n      - stack.env\n");
            }
            output.push_str("    networks:\n      - backend\n");
            if has_runtime(&r.images) {
                output.push_str("      - runtime\n");
            }
        }
    }
    output.push_str(&format!(
        "networks:\n  shared:\n    external: true\n    name: {network}\n"
    ));
    if r.images.len() > 1 {
        output.push_str(&format!(
            "  backend:\n    external: true\n    name: {}-backend\n",
            r.project
        ));
    }
    if has_runtime(&r.images) {
        output.push_str(&format!(
            "  runtime:\n    name: {}-runtime\n    internal: true\n",
            r.project
        ));
    }
    Ok(output)
}
pub fn route(r: &Record, k: &Knob) -> String {
    let mut hosts = r.web_host(k);
    if r.images.len() > 1 {
        hosts.push_str(&format!(", {}", r.public_api_host(k)));
    }
    format!(
        "# Written by komizo preview. {} PR #{} -- removed by 'komizo preview down'.\n{hosts} {{\n\theader >Strict-Transport-Security \"max-age=31536000\"\n\treverse_proxy {}-gate:80\n}}\n",
        r.app, r.pr, r.project
    )
}
pub fn path_site(r: &Record, k: &Knob) -> String {
    let mut hosts = r.web_host(k);
    if r.images.len() > 1 {
        hosts.push_str(&format!(", {}", r.public_api_host(k)));
    }
    format!(
        "# Written by komizo preview. Stable hostname for {}.\n{hosts} {{\n header >Strict-Transport-Security \"max-age=31536000\"\n import /etc/caddy/routes/_preview-pr-*.{}.route\n respond \"no preview is configured for this path\" 404\n}}\n",
        r.app, r.app
    )
}
pub fn path_route(r: &Record) -> String {
    format!(
        "# Written by komizo preview. {} PR #{}.\nredir {} {}/?{{http.request.uri.query}} 308\nhandle_path {}/* {{\n reverse_proxy {}-gate:80 {{\n  header_up X-Forwarded-Prefix {}\n }}\n}}\n",
        r.app, r.pr, r.base_path, r.base_path, r.base_path, r.project, r.base_path
    )
}
