//! Workload command transport uses the same native policy and transaction implementation.
use super::{
    activation::{self, Host},
    admission::Admission,
    effects::{Effects, Native},
    files,
    image_cache::missing,
    operations::TaskAuthority,
    reconciliation, secrets,
    transaction::{self, Credentials, hash},
};
use crate::{
    flags::{Flag, Flags},
    host::{locking::DeploymentLock, paths, resource_authority, scoped},
    input::Input,
    wire::{Secret, Time, decode_base64},
    workload::{
        activation::{ActivationRequest, Context},
        compose,
        delivery::DeliveryAuthorization,
        operation::{self, Operation},
        policy::{DeploymentPolicy, DeploymentStage, Policy, commit_id, operation_identity},
        policy_read, readiness,
        release::{self, ReleaseAcceptance},
        release_bind,
    },
};
use anyhow::{Result, anyhow, ensure};
use serde::Serialize;
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
pub struct Commands<'a, E> {
    pub host: Host<E>,
    pub input: Option<Input>,
    pub output: &'a mut dyn Write,
}
pub fn run(args: &[String], ctx: &Context, output: &mut dyn Write) -> Result<()> {
    let root = PathBuf::new();
    Commands {
        host: Host::new(root.clone(), Native { root })?,
        input: None,
        output,
    }
    .run(args, ctx)
}
fn context(parent: &Context, seconds: u64) -> Context {
    let mut ctx = parent.clone();
    ctx.deadline = ctx
        .deadline
        .min(Instant::now() + Duration::from_secs(seconds));
    ctx
}
fn root(message: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "{message}");
    Ok(())
}
pub fn enabled_policy(mut p: Policy) -> Result<Policy> {
    ensure!(
        p.has_release_authority() && p.readiness.is_some() && p.resources.is_some(),
        "configure trusted source, resource budgets and readiness before enabling deployment"
    );
    let expected = DeploymentPolicy {
        route_path: format!("/srv/_proxy/routes/{}.caddy", p.app),
        proxy: "komizo-proxy".into(),
        proxy_dir: "/srv/_proxy".into(),
    };
    ensure!(
        p.deployment
            .as_ref()
            .is_none_or(|d| d.route_path == expected.route_path
                && d.proxy == expected.proxy
                && d.proxy_dir == expected.proxy_dir),
        "existing deployment authority differs; explicit operator review required"
    );
    p.deployment = Some(expected);
    p.check()?;
    Ok(p)
}
impl<E: Effects> Commands<'_, E> {
    fn emit(&mut self, value: &impl Serialize) -> Result<()> {
        serde_json::to_writer(&mut self.output, value)?;
        self.output.write_all(b"\n")?;
        Ok(())
    }
    fn input(&mut self) -> Result<&mut Input> {
        if self.input.is_none() {
            self.input = Some(Input::stdin()?)
        }
        Ok(self.input.as_mut().unwrap())
    }
    fn body(&mut self, ctx: &Context, maximum: usize) -> Result<Vec<u8>> {
        self.input()?.bounded(&context(ctx, 10), maximum)
    }
    fn policy(&self, path: &str) -> Result<Policy> {
        files::read_policy(Path::new(path))
    }
    fn installed(&self, path: &str, p: &Policy) -> Result<()> {
        ensure!(
            Path::new(path) == self.host.policies.join(format!("{}.json", p.app)),
            "operation requires the installed root policy"
        );
        Ok(())
    }
    fn lock(&self, ctx: &Context, app: &str) -> Result<DeploymentLock> {
        DeploymentLock::acquire(
            &self.host.root,
            app,
            ctx.remaining()?.min(Duration::from_secs(60)),
            || ctx.cancelled.load(Ordering::Acquire),
        )
    }
    pub fn run(&mut self, args: &[String], parent: &Context) -> Result<()> {
        let (verb, args) = args
            .split_first()
            .ok_or_else(|| anyhow!("workload requires init or validate"))?;
        match verb.as_str() {
            "capabilities" => {
                ensure!(
                    args.is_empty(),
                    "workload capabilities accepts no arguments"
                );
                self.emit(&json!({"version":1,"policy_bootstrap":true,"typed_deployment":true,"operation_contract_version":1}))
            }
            "operation-contract" => {
                ensure!(args.is_empty(), "operation-contract accepts no arguments");
                self.output.write_all(operation::contract())?;
                Ok(())
            }
            "image-refs" => {
                ensure!(args.is_empty(), "image-refs reads only standard input");
                let body = self.body(parent, 1 << 20)?;
                for image in release_bind::json_image_references(&body)? {
                    writeln!(self.output, "{image}")?
                }
                Ok(())
            }
            "scoped-definition-check" => {
                let flags = Flags::parse(
                    &[
                        Flag::text("profile", ""),
                        Flag::text("schema", ""),
                        Flag::text("files", ""),
                    ],
                    args,
                )?;
                flags.no_args("scoped definition accepts only declared fields")?;
                scoped::parse_definition(
                    flags.text("profile"),
                    flags.text("schema"),
                    flags.text("files"),
                )?;
                Ok(())
            }
            "capacity" => {
                let flags = Flags::parse(&[Flag::text("report", "")], args)?;
                ensure!(
                    flags.args.is_empty() && !flags.text("report").is_empty(),
                    "capacity needs a report path"
                );
                let body = crate::statefile::read(Path::new(flags.text("report")), 1 << 20)?
                    .ok_or_else(|| anyhow!("capacity report unreadable or oversized"))?;
                super::deployment::report_fresh(&body, (self.host.now)())
            }
            "init" | "validate" => self.init_validate(verb, args, parent),
            "policy-check" => {
                let flags = Flags::parse(&[Flag::text("policy", "")], args)?;
                root(
                    "policy-check needs the root executor, one policy and no positional arguments",
                )?;
                ensure!(
                    flags.args.is_empty() && !flags.text("policy").is_empty(),
                    "policy-check needs the root executor, one policy and no positional arguments"
                );
                self.policy(flags.text("policy"))?;
                Ok(())
            }
            "ingress-name" | "isolate-ingress" => {
                let flags = Flags::parse(&[Flag::text("policy", "")], args)?;
                ensure!(
                    flags.args.is_empty() && !flags.text("policy").is_empty(),
                    "ingress needs a policy path"
                );
                let mut p = self.policy(flags.text("policy"))?;
                if verb == "isolate-ingress" {
                    root("ingress isolation requires the operator")?;
                    p.ingress_network = crate::workload::policy::isolated_ingress(&p.app);
                    files::write_json(Path::new(flags.text("policy")), &p)
                } else {
                    writeln!(
                        self.output,
                        "{}",
                        if p.ingress_network.is_empty() {
                            &p.shared_network
                        } else {
                            &p.ingress_network
                        }
                    )?;
                    Ok(())
                }
            }
            "readiness" | "budgets" => {
                let flags = Flags::parse(&[Flag::text("policy", "")], args)?;
                root("authority update requires root and a policy path")?;
                ensure!(
                    flags.args.is_empty() && !flags.text("policy").is_empty(),
                    "authority update requires root and a policy path"
                );
                let mut p = self.policy(flags.text("policy"))?;
                let body = self.body(parent, 1 << 20)?;
                if verb == "readiness" {
                    p.readiness = Some(policy_read::read_readiness(&body)?)
                } else {
                    p.resources = Some(policy_read::read_resources(&body)?);
                    p.check()?;
                    resource_authority::installed_serving_budget(&self.host.root, &p)?
                }
                files::write_json(Path::new(flags.text("policy")), &p)
            }
            "policy-bootstrap" => self.bootstrap(args, parent),
            "proxy-budget" => {
                root("proxy budget requires the root operator and optional --compose")?;
                ensure!(
                    args.is_empty() || args == ["--compose"],
                    "proxy budget requires the root operator and optional --compose"
                );
                let probe = crate::host::Probe {
                    root: self.host.root.clone(),
                };
                let live_root = if self.host.root.as_os_str().is_empty() {
                    Path::new("/")
                } else {
                    &self.host.root
                };
                let budget = resource_authority::proxy_budget(
                    live_root,
                    &files::owned,
                    resource_authority::host_memory(&probe)?,
                    resource_authority::measured_cpu(),
                )?;
                if args.is_empty() {
                    self.emit(&budget)
                } else {
                    self.output.write_all(budget.compose().as_bytes())?;
                    Ok(())
                }
            }
            "host-resources" => self.resources(args, parent),
            "startup-check" => {
                let flags = Flags::parse(&[Flag::text("policy", "")], args)?;
                root("startup inspection requires the root operator and an installed policy")?;
                flags.no_args(
                    "startup inspection requires the root operator and an installed policy",
                )?;
                let p = self.policy(flags.text("policy"))?;
                self.installed(flags.text("policy"), &p)?;
                let ctx = context(parent, 10);
                let _lock = self.lock(&ctx, &p.app)?;
                let current = self.policy(flags.text("policy"))?;
                ensure!(
                    current.app == p.app,
                    "startup inspection policy identity changed"
                );
                self.host.startup_capacity(&current)
            }
            "delivery-enable" | "delivery-authorize" => self.delivery(verb, args),
            "trust"
            | "release-admit"
            | "owner-recovery-admit"
            | "release-bind"
            | "release-bootstrap"
            | "operation"
            | "ready" => self.release(verb, args, parent),
            "deployment-enable" | "deployment-enabled" | "deployment-submit" => {
                self.deployment(verb, args, parent)
            }
            "activation-idle" | "activation-submit" | "activation-wait" => {
                self.activation(verb, args, parent)
            }
            "inspect" | "reconcile" => self.reconcile(verb, args, parent),
            "release-secrets" | "owner-secret" | "legacy-secrets-allowed" => {
                self.secrets(verb, args, parent)
            }
            "owner-task" | "task" => {
                let flags = Flags::parse(&[Flag::text("policy", "")], args)?;
                root("named tasks require the root executor and protected policy")?;
                ensure!(
                    !flags.text("policy").is_empty(),
                    "named tasks require the root executor and protected policy"
                );
                let p = self.policy(flags.text("policy"))?;
                let ctx = context(parent, 900);
                let proof = if p.require_delivery_authorization && verb == "task" {
                    let line = self.input()?.line(&ctx, 128 << 10)?;
                    Some(line.strip_suffix(b"\n").unwrap_or(&line).to_vec())
                } else {
                    None
                };
                let authority = if verb == "owner-task" {
                    TaskAuthority::Owner
                } else {
                    TaskAuthority::Ci(proof.as_deref().unwrap_or_default())
                };
                let input = self
                    .input
                    .take()
                    .map(Input::into_stdio)
                    .unwrap_or_else(Stdio::inherit);
                self.host.run_named(&ctx, &p, &flags.args, authority, input)
            }
            "routine-backup" | "backup-inspect" => {
                let flags = Flags::parse(
                    &[
                        Flag::text("policy", ""),
                        Flag::text("run", ""),
                        Flag::text("attempt", ""),
                    ],
                    args,
                )?;
                root("routine backup requires root, a policy and no program arguments")?;
                ensure!(
                    !flags.text("policy").is_empty() && flags.args.is_empty(),
                    "routine backup requires root, a policy and no program arguments"
                );
                let p = self.policy(flags.text("policy"))?;
                if verb == "backup-inspect" {
                    let operation = self.host.inspect_backup(
                        &p.app,
                        flags.text("run"),
                        flags.text("attempt"),
                    )?;
                    return self.emit(&operation);
                }
                ensure!(
                    flags.text("run").is_empty()
                        && flags.text("attempt").is_empty()
                        && p.routine_backup.is_some(),
                    "routine backup requires a protected capability and audience-bound proof"
                );
                let ctx = context(parent, 900);
                let line = self.input()?.line(&ctx, 128 << 10)?;
                self.host
                    .routine_backup(&ctx, Path::new(flags.text("policy")), &p, &line)
            }
            _ => anyhow::bail!("workload requires init or validate"),
        }
    }
    fn init_validate(&mut self, verb: &str, args: &[String], _parent: &Context) -> Result<()> {
        let flags = Flags::parse(
            &[
                Flag::text("policy", ""),
                Flag::text("app", ""),
                Flag::text("app-dir", ""),
                Flag::text("config-image", ""),
                Flag::text("network", "edge"),
                Flag::text("compose", ""),
                Flag::text("output", ""),
                Flag::text("version", ""),
            ],
            args,
        )?;
        ensure!(
            flags.args.is_empty() && !flags.text("policy").is_empty(),
            "workload needs a policy path and no positional arguments"
        );
        let path = Path::new(flags.text("policy"));
        if verb == "init" {
            let p = Policy::new(
                flags.text("app"),
                flags.text("app-dir"),
                flags.text("config-image"),
                flags.text("network"),
            )?;
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    let mut old = self.policy(flags.text("policy"))?;
                    old.source_repository.clear();
                    old.repository_id.clear();
                    old.owner_approval = false;
                    old.resources = None;
                    old.readiness = None;
                    old.ingress_network.clear();
                    old.require_delivery_authorization = false;
                    old.require_stateful_contract = false;
                    old.r#static = None;
                    old.deployment = None;
                    old.routine_backup = None;
                    ensure!(
                        serde_json::to_vec(&old)? == serde_json::to_vec(&p)?,
                        "existing workload policy differs; review an operator policy update"
                    );
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(files::parent(path))?;
            return files::create_private(path, &files::json_bytes(&p)?);
        }
        ensure!(
            !flags.text("compose").is_empty() && !flags.text("output").is_empty(),
            "workload validation needs compose and output paths"
        );
        let p = self.policy(flags.text("policy"))?;
        ensure!(
            p.app == flags.text("app") && p.app_dir == flags.text("app-dir"),
            "workload policy does not match this deployment"
        );
        let body = crate::statefile::read(Path::new(flags.text("compose")), 1 << 20)?
            .ok_or_else(|| anyhow!("workload configuration must be a regular file"))?;
        let mut canonical = compose::validate(&body, &p, flags.text("version"))?;
        canonical = canonical.trim_ascii().to_vec();
        canonical.push(b'\n');
        files::create_private(Path::new(flags.text("output")), &canonical)?;
        writeln!(self.output, "workload: host policy accepted")?;
        Ok(())
    }
    fn bootstrap(&mut self, args: &[String], parent: &Context) -> Result<()> {
        let flags = Flags::parse(&[Flag::text("app", "")], args)?;
        root("policy bootstrap requires root and a registered application")?;
        ensure!(
            flags.args.is_empty() && !flags.text("app").is_empty(),
            "policy bootstrap requires root and a registered application"
        );
        let ctx = context(parent, 15);
        let body = self.body(&ctx, 1 << 20)?;
        let next = policy_read::read_policy(&body)?;
        let _lock = self.lock(&ctx, flags.text("app"))?;
        files::activation_idle(&self.host.path(super::ACTIVATIONS))?;
        let settings = paths::app_settings(&self.host.root, flags.text("app"))?;
        let get = |name: &str| settings.get(name).map(String::as_str).unwrap_or_default();
        let base = Policy::new(
            flags.text("app"),
            get("APP_DIR"),
            get("CONFIG_IMAGE"),
            &next.shared_network,
        )?;
        let path = self
            .host
            .policies
            .join(format!("{}.json", flags.text("app")));
        let existing = files::read_policy(&path)?;
        let next = enabled_policy(next)?;
        let compose = self
            .host
            .effects
            .read(&Path::new(&base.app_dir).join("compose.yml"), 1 << 20)?;
        let environment = self
            .host
            .effects
            .read(&Path::new(&base.app_dir).join(".env"), 1 << 20)?;
        let retained = fs::symlink_metadata(
            self.host
                .releases
                .join(flags.text("app"))
                .join("operation.json"),
        )
        .is_ok()
            || fs::symlink_metadata(Path::new(&base.app_dir).join(".komizo-image-retention"))
                .is_ok();
        transaction::check_bootstrap(
            &base,
            &existing,
            &next,
            transaction::bootstrap_serving(&compose, &environment, retained)?,
        )?;
        resource_authority::installed_serving_budget(&self.host.root, &next)?;
        files::write_json(&path, &next)?;
        self.emit(&json!({"version":1,"app":flags.text("app"),"installed":true,"deployment_enabled":true}))
    }
    fn resources(&mut self, args: &[String], parent: &Context) -> Result<()> {
        let flags = Flags::parse(
            &[
                Flag::boolean("apply", false),
                Flag::boolean("check", false),
                Flag::text("policy", ""),
                Flag::boolean("check-usage", false),
                Flag::boolean("reclaim-controls", false),
                Flag::text("policy-sha256", ""),
            ],
            args,
        )?;
        root("host resources require the root operator")?;
        let (apply, check, usage, reclaim) = (
            flags.boolean("apply"),
            flags.boolean("check"),
            flags.boolean("check-usage"),
            flags.boolean("reclaim-controls"),
        );
        let candidate = flags.text("policy");
        let expected = flags.text("policy-sha256");
        ensure!(
            flags.args.is_empty()
                && !(apply && check)
                && !(!check && !reclaim && (!candidate.is_empty() || usage))
                && !(reclaim
                    && (apply
                        || check
                        || usage
                        || candidate.is_empty()
                        || !crate::workload::policy::content_identity(expected)))
                && (reclaim || expected.is_empty()),
            "host resources require the root operator"
        );
        let path = self.host.path("/etc/komizo/resources.json");
        let body = if (check || reclaim) && !candidate.is_empty() {
            let p = Path::new(candidate);
            ensure!(
                p.is_absolute() && crate::host::inventory::clean_path(candidate) == candidate,
                "candidate resource policy must be an absolute canonical path"
            );
            super::operations::protected_path(p, false)?;
            self.host.effects.read(p, 1 << 20)?
        } else if apply {
            let info = fs::symlink_metadata(&path)?;
            ensure!(
                info.is_file() && info.mode() & 0o077 == 0 && files::owned(&info),
                "host resource policy must be a root-owned private regular file"
            );
            self.host.effects.read(&path, 1 << 20)?
        } else {
            self.body(parent, 1 << 20)?
        };
        ensure!(
            !reclaim || hash(&body) == expected,
            "reviewed resource policy changed"
        );
        let policy = resource_authority::read_resources(&body)?;
        let memory = resource_authority::host_memory(&crate::host::Probe {
            root: self.host.root.clone(),
        })?;
        let cpu = resource_authority::measured_cpu();
        let cgroup = self.host.path("/sys/fs/cgroup");
        if check {
            return if usage {
                policy.preflight(&cgroup, memory, cpu)
            } else {
                policy.check(memory, cpu)
            };
        }
        if reclaim {
            policy.check(memory, cpu)?;
            let (rows, status) = policy.reclaim_control_cache(&cgroup);
            self.emit(&json!({"version":1,"policy_sha256":expected,"limits_applied":false,"groups":rows,"complete":status.is_ok()}))?;
            return status;
        }
        policy.apply(&cgroup, memory, cpu)?;
        let live_root = if self.host.root.as_os_str().is_empty() {
            Path::new("/")
        } else {
            &self.host.root
        };
        resource_authority::kernel_memory(live_root, memory, 0)?;
        if cfg!(target_os = "linux") && memory <= 2 << 30 {
            ensure!(
                self.host.root.as_os_str().is_empty(),
                "compressed swap application requires the live root executor"
            );
            let ctx = context(parent, 60);
            let mut command = std::process::Command::new("/usr/bin/python3");
            command
                .args([
                    "-I",
                    "-c",
                    crate::scripts::COMPRESSED_SWAP,
                    &memory.to_string(),
                ])
                .env_clear()
                .env("PATH", "/usr/sbin:/sbin:/usr/bin:/bin")
                .env("LC_ALL", "C")
                .current_dir("/");
            let output =
                crate::process::capture(&mut command, None, 1 << 20, ctx.deadline, || {
                    ctx.cancelled.load(Ordering::Acquire)
                })?;
            ensure!(
                output.status.success(),
                "compressed swap application failed"
            );
        }
        if !apply {
            files::write_json(&path, &policy)?
        }
        Ok(())
    }
    fn delivery(&mut self, verb: &str, args: &[String]) -> Result<()> {
        let flags = Flags::parse(
            &[Flag::text("policy", ""), Flag::text("authorization", "")],
            args,
        )?;
        root("delivery authority requires the root operator and policy")?;
        ensure!(
            flags.args.is_empty() && !flags.text("policy").is_empty(),
            "delivery authority requires the root operator and policy"
        );
        let mut p = self.policy(flags.text("policy"))?;
        if verb == "delivery-enable" {
            ensure!(
                flags.text("authorization").is_empty() && !p.source_repository.is_empty(),
                "delivery authorization requires authenticated source authority"
            );
            p.require_delivery_authorization = true;
            return files::write_json(Path::new(flags.text("policy")), &p);
        }
        ensure!(
            flags.text("authorization").len() <= 65536,
            "invalid delivery authorization command"
        );
        let body = decode_base64(flags.text("authorization"))
            .map_err(|_| anyhow!("invalid delivery authorization encoding"))?;
        let authorization: DeliveryAuthorization = files::decode(&body, 64 << 10)?;
        authorization.check(&p, &authorization.revision, (self.host.now)())?;
        let directory = self.host.path(super::DELIVERY).join(&p.app);
        files::protected_directory(&directory)?;
        files::write_json(
            &directory.join(format!("{}.json", authorization.revision)),
            &authorization,
        )
    }
    fn release(&mut self, verb: &str, args: &[String], parent: &Context) -> Result<()> {
        let flags = Flags::parse(
            &[
                Flag::text("policy", ""),
                Flag::text("source-repository", ""),
                Flag::text("repository-id", ""),
                Flag::text("version", ""),
                Flag::text("previous", ""),
                Flag::text("phase", ""),
                Flag::text("store", self.host.releases.to_string_lossy()),
                Flag::text("output", ""),
                Flag::text("release", ""),
                Flag::text("config-image", ""),
                Flag::text("compose", ""),
                Flag::boolean("local-only", false),
            ],
            args,
        )?;
        ensure!(
            flags.args.is_empty() && !flags.text("policy").is_empty(),
            "workload release command needs a policy"
        );
        ensure!(
            !flags.boolean("local-only") || verb == "release-bind",
            "local-only applies only to release-bind"
        );
        let mut p = self.policy(flags.text("policy"))?;
        if verb == "trust" {
            p.source_repository = flags.text("source-repository").into();
            p.repository_id = flags.text("repository-id").into();
            p.check()?;
            ensure!(
                !p.source_repository.is_empty(),
                "source identity is required"
            );
            return files::write_json(Path::new(flags.text("policy")), &p);
        }
        let version = flags.text("version");
        let directory = Path::new(flags.text("store")).join(&p.app);
        if verb == "release-admit" {
            self.host.check_delivery(&p, version, (self.host.now)())?
        }
        files::protected_directory(&directory)?;
        let ctx = context(parent, 120);
        match verb {
            "owner-recovery-admit" => {
                root("owner recovery requires a retained current/previous accepted revision")?;
                ensure!(
                    !flags.text("output").is_empty() && transaction::rollback_allowed(&p, version),
                    "owner recovery requires a retained current/previous accepted revision"
                );
                let accepted: ReleaseAcceptance = self
                    .host
                    .read_json(&directory.join(format!("{version}.json")))?;
                accepted.check(&p, version)?;
                files::write_json(Path::new(flags.text("output")), &accepted)
            }
            "release-admit" => {
                let ctx = context(parent, 60);
                let body = self.body(&ctx, 128 << 10)?;
                self.host.admit(
                    &ctx,
                    &p,
                    Admission {
                        revision: version,
                        directory: &directory,
                        output: Path::new(flags.text("output")),
                    },
                    &body,
                )?;
                Ok(())
            }
            "operation" => operation::record(
                &directory.join("operation.json"),
                &p.app,
                version,
                flags.text("previous"),
                flags.text("phase"),
                Time((self.host.now)().fixed_offset()),
            ),
            "ready" => self.ready(
                &p,
                version,
                flags.text("previous"),
                &directory,
                Path::new(flags.text("compose")),
                parent,
            ),
            "release-bootstrap" => {
                ensure!(
                    !flags.text("compose").is_empty() && !flags.text("config-image").is_empty(),
                    "bootstrap needs local compose and configuration image"
                );
                let body = crate::statefile::read(Path::new(flags.text("compose")), 1 << 20)?
                    .ok_or_else(|| anyhow!("configuration unavailable"))?;
                let accepted = release_bind::bootstrap_release(
                    &mut |args| self.host.effects.docker(&ctx, args),
                    &p,
                    version,
                    flags.text("config-image"),
                    &body,
                    (self.host.now)(),
                )?;
                let path = directory.join(format!("{version}.json"));
                ensure!(
                    fs::symlink_metadata(&path)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "existing accepted release cannot be replaced by bootstrap"
                );
                files::write_json(&path, &accepted)
            }
            "release-bind" => {
                ensure!(
                    !flags.text("output").is_empty()
                        && !flags.text("compose").is_empty()
                        && !flags.text("release").is_empty(),
                    "release binding needs accepted release, compose and output"
                );
                let accepted: ReleaseAcceptance =
                    self.host.read_json(Path::new(flags.text("release")))?;
                let body = crate::statefile::read(Path::new(flags.text("compose")), 1 << 20)?
                    .ok_or_else(|| anyhow!("configuration unavailable"))?;
                if flags.boolean("local-only") {
                    root(
                        "local binding requires the root operator's current/previous accepted revision",
                    )?;
                    ensure!(
                        transaction::rollback_allowed(&p, version),
                        "local binding requires the root operator's current/previous accepted revision"
                    )
                }
                let pinned = release_bind::bind_release(
                    &mut |args| self.host.effects.docker(&ctx, args),
                    &p,
                    &accepted,
                    version,
                    flags.text("config-image"),
                    &body,
                    !flags.boolean("local-only"),
                )?;
                files::create_private(Path::new(flags.text("output")), &pinned)
            }
            _ => anyhow::bail!("unknown workload release command"),
        }
    }
    fn ready(
        &mut self,
        p: &Policy,
        candidate: &str,
        previous: &str,
        directory: &Path,
        compose: &Path,
        parent: &Context,
    ) -> Result<()> {
        if p.readiness.is_none() {
            return Ok(());
        }
        ensure!(
            compose == Path::new(&p.app_dir).join("compose.yml"),
            "readiness uses only the active app configuration"
        );
        let body = self.host.effects.read(compose, 1 << 20)?;
        let ctx = context(parent, 90);
        loop {
            let effects = std::cell::RefCell::new(&mut self.host.effects);
            let result = readiness::verify_readiness(
                &mut |args| effects.borrow_mut().docker(&ctx, args),
                &mut |probe| {
                    effects
                        .borrow_mut()
                        .probe(&ctx, &self.host.client, candidate, probe)
                },
                p,
                candidate,
                compose.to_str().unwrap(),
                &body,
            );
            match result {
                Ok(()) => {
                    return operation::record(
                        &directory.join("operation.json"),
                        &p.app,
                        candidate,
                        previous,
                        "ready",
                        Time((self.host.now)().fixed_offset()),
                    );
                }
                Err(error) => {
                    if activation::sleep(&ctx, Duration::from_secs(2)).is_err() {
                        let _ = operation::record(
                            &directory.join("operation.json"),
                            &p.app,
                            candidate,
                            previous,
                            "readiness_failed",
                            Time((self.host.now)().fixed_offset()),
                        );
                        return Err(error);
                    }
                }
            }
        }
    }
    fn activation(&mut self, verb: &str, args: &[String], parent: &Context) -> Result<()> {
        root("host activation requires the local root operator")?;
        let queue = self.host.path(super::ACTIVATIONS);
        if verb == "activation-idle" {
            ensure!(args.is_empty(), "activation-idle accepts no arguments");
            return files::activation_idle(&queue);
        }
        let flags = Flags::parse(
            &[
                Flag::text("policy", ""),
                Flag::text("version", ""),
                Flag::text("previous", ""),
                Flag::text("route", ""),
                Flag::text("proxy", ""),
                Flag::text("id", ""),
            ],
            args,
        )?;
        flags.no_args("activation accepts no positional arguments")?;
        if verb == "activation-wait" {
            let result = activation::wait(&context(parent, 25 * 60), &queue, flags.text("id"))?;
            ensure!(
                result.ok && result.started.is_some(),
                "activation {}: {}; inspect the durable operation before retrying",
                result.id,
                result.phase
            );
            if !result.scoped_generation.is_empty() {
                ensure!(
                    operation_identity(&result.scoped_generation),
                    "invalid scoped generation in activation receipt"
                );
                writeln!(
                    self.output,
                    "deploy: scoped-generation={}",
                    result.scoped_generation
                )?
            }
            writeln!(
                self.output,
                "deploy: started={}",
                if result.started == Some(true) {
                    "yes"
                } else {
                    "no"
                }
            )?;
            writeln!(
                self.output,
                "deploy: operation={} phase={}",
                result.id, result.phase
            )?;
            return Ok(());
        }
        let p = self.policy(flags.text("policy"))?;
        self.installed(flags.text("policy"), &p)?;
        let operation: Operation = self
            .host
            .read_json(&self.host.releases.join(&p.app).join("operation.json"))?;
        ensure!(
            operation.phase == "configured"
                && operation.candidate == flags.text("version")
                && operation.previous == flags.text("previous"),
            "activation needs the matching configured operation"
        );
        let mut request = ActivationRequest {
            version: 1,
            id: operation.id,
            app: p.app.clone(),
            candidate: operation.candidate,
            previous: operation.previous,
            deadline: operation.deadline,
            route_path: flags.text("route").into(),
            proxy: flags.text("proxy").into(),
            ..Default::default()
        };
        request.policy_sha256 = hash(
            &self
                .host
                .effects
                .read(Path::new(flags.text("policy")), 1 << 20)?,
        );
        request.compose_sha256 = hash(
            &self
                .host
                .effects
                .read(&Path::new(&p.app_dir).join("compose.yml"), 1 << 20)?,
        );
        request.route_sha256 = hash(
            &self
                .host
                .effects
                .read(Path::new(flags.text("route")), 1 << 20)?,
        );
        request.check((self.host.now)())?;
        files::protected_directory(&queue)?;
        files::activation_idle(&queue)?;
        files::write_json(&queue.join("pending.json"), &request)?;
        writeln!(self.output, "{}", request.id)?;
        Ok(())
    }
    fn deployment(&mut self, verb: &str, args: &[String], parent: &Context) -> Result<()> {
        root("typed deployment requires the local root operator")?;
        let flags = Flags::parse(
            &[
                Flag::text("policy", ""),
                Flag::text("version", ""),
                Flag::text("registry", ""),
                Flag::text("registry-user", ""),
                Flag::text("generation", ""),
                Flag::boolean("owner-approval", false),
                Flag::boolean("local-only", false),
            ],
            args,
        )?;
        flags.no_args("deployment accepts no positional arguments")?;
        let local = flags.boolean("local-only");
        ensure!(
            !local
                || (verb == "deployment-submit"
                    && flags.text("registry").is_empty()
                    && flags.text("registry-user").is_empty()),
            "local owner reconfiguration accepts no registry credential or other operation"
        );
        let mut p = self.policy(flags.text("policy"))?;
        self.installed(flags.text("policy"), &p)?;
        let queue = self.host.path(super::ACTIVATIONS);
        if verb == "deployment-enable" {
            ensure!(
                flags.text("version").is_empty()
                    && flags.text("registry").is_empty()
                    && flags.text("registry-user").is_empty()
                    && flags.text("generation").is_empty(),
                "deployment-enable accepts only the policy"
            );
            let ctx = context(parent, 10);
            let _lock = self.lock(&ctx, &p.app)?;
            p = self.policy(flags.text("policy"))?;
            files::activation_idle(&queue)?;
            let next = enabled_policy(p.clone())?;
            if p.deployment.is_some() {
                return Ok(());
            }
            let operation = self
                .host
                .read_json::<Operation>(&self.host.releases.join(&p.app).join("operation.json"));
            match operation {
                Ok(op) => ensure!(
                    matches!(
                        op.phase.as_str(),
                        "ready" | "prepared_stopped" | "reconciled"
                    ),
                    "reconcile the existing operation before changing deployment authority"
                ),
                Err(e) if missing(&e) => {}
                Err(e) => return Err(e),
            }
            return files::write_json(Path::new(flags.text("policy")), &next);
        }
        if verb == "deployment-submit" && !local {
            ensure!(
                flags.boolean("owner-approval") == p.owner_approval,
                "owner approval requires an explicit root SSH submission and matching protected policy"
            )
        }
        ensure!(
            !flags.boolean("owner-approval") || verb == "deployment-submit",
            "owner approval applies only to deployment submission"
        );
        ensure!(
            p.deployment.is_some(),
            "typed deployment is not enabled in the installed root policy"
        );
        if verb == "deployment-enabled" {
            return Ok(());
        }
        resource_authority::installed_serving_budget(&self.host.root, &p)?;
        let version = flags.text("version");
        ensure!(
            commit_id(version),
            "deployment needs an exact source revision"
        );
        if !local {
            self.host.check_delivery(&p, version, (self.host.now)())?
        }
        let ctx = context(parent, 60);
        let wire = self.body(&ctx, 160 << 10)?;
        let mut credentials = Credentials {
            registry: flags.text("registry").into(),
            user: flags.text("registry-user").into(),
            ..Default::default()
        };
        let proof = if !credentials.registry.is_empty() {
            let end = wire
                .iter()
                .position(|b| *b == b'\n')
                .filter(|n| *n <= 16384)
                .ok_or_else(|| anyhow!("registry token is missing or exceeds its bound"))?;
            credentials.password = Secret::new(
                String::from_utf8(wire[..end].to_vec())
                    .map_err(|_| anyhow!("invalid operation-private registry credential"))?,
            );
            &wire[end + 1..]
        } else {
            &wire[..]
        };
        credentials.check(&p)?;
        ensure!(proof.len() <= 128 << 10, "release proof exceeds its bound");
        ensure!(
            !local || crate::wire::trim_space(proof).is_empty(),
            "local owner reconfiguration accepts no CI proof"
        );
        if !crate::wire::trim_space(proof).is_empty() && !p.owner_approval {
            self.host.verify_task_release(&ctx, &p, proof)?;
        }
        let _lock = self.lock(&ctx, &p.app)?;
        files::activation_idle(&queue)?;
        files::protected_directory(&queue)?;
        let env = self
            .host
            .effects
            .read(&Path::new(&p.app_dir).join(".env"), 1 << 20)?;
        let previous = transaction::deployment_version(&env)?;
        let directory = self.host.releases.join(&p.app);
        files::protected_directory(&directory)?;
        let output = tempfile::Builder::new()
            .prefix(".admitted-")
            .tempfile_in(&directory)?;
        let output = output.into_temp_path();
        fs::remove_file(&output)?;
        if local {
            ensure!(
                crate::wire::trim_space(proof).is_empty()
                    && version == previous
                    && transaction::rollback_allowed(&p, version),
                "local owner reconfiguration requires the retained current revision and no CI proof"
            );
            let prior: Operation = self.host.read_json(&directory.join("operation.json"))?;
            ensure!(
                transaction::local_current_allowed(&prior, &previous),
                "reconcile the current deployment before local reconfiguration"
            );
            let accepted: ReleaseAcceptance = self
                .host
                .read_json(&directory.join(format!("{version}.json")))?;
            accepted.check(&p, version)?;
            files::write_json(&output, &accepted)?;
        } else {
            self.host.admit(
                &ctx,
                &p,
                Admission {
                    revision: version,
                    directory: &directory,
                    output: &output,
                },
                proof,
            )?;
        }
        operation::record(
            &directory.join("operation.json"),
            &p.app,
            version,
            &previous,
            "admitted",
            Time((self.host.now)().fixed_offset()),
        )?;
        let operation: Operation = self.host.read_json(&directory.join("operation.json"))?;
        let policy = self
            .host
            .effects
            .read(Path::new(flags.text("policy")), 1 << 20)?;
        let slot = transaction::credential_path(&queue, &operation.id);
        files::protected_directory(slot.parent().unwrap())?;
        files::write_json(&slot, &credentials)?;
        let body = self.host.effects.read(&slot, 1 << 20)?;
        let request = ActivationRequest {
            version: 2,
            id: operation.id,
            app: p.app.clone(),
            candidate: version.into(),
            previous: previous.clone(),
            policy_sha256: hash(&policy),
            route_path: p.deployment.as_ref().unwrap().route_path.clone(),
            proxy: p.deployment.as_ref().unwrap().proxy.clone(),
            deadline: operation.deadline,
            stage: Some(DeploymentStage {
                credential_sha256: hash(&body),
                generation: flags.text("generation").into(),
                local_only: local,
            }),
            ..Default::default()
        };
        let submitted = (|| -> Result<()> {
            request.check((self.host.now)())?;
            files::write_json(&queue.join("pending.json"), &request)
        })();
        if let Err(error) = submitted {
            let _ = fs::remove_dir_all(slot.parent().unwrap());
            return Err(error);
        }
        writeln!(
            self.output,
            "deploy: previous-version={previous}\ndeploy: submitted={}\n{}",
            request.id, request.id
        )?;
        Ok(())
    }
    fn reconcile(&mut self, verb: &str, args: &[String], parent: &Context) -> Result<()> {
        root("reconciliation requires the local root operator")?;
        let flags = Flags::parse(
            &[
                Flag::text("policy", ""),
                Flag::text("id", ""),
                Flag::text("version", ""),
                Flag::text("policy-sha256", ""),
                Flag::text("expected-phase", ""),
                Flag::text("serving-version", ""),
                Flag::text("outcome", ""),
            ],
            args,
        )?;
        flags.no_args("reconciliation accepts no positional arguments")?;
        let p = self.policy(flags.text("policy"))?;
        self.installed(flags.text("policy"), &p)?;
        self.host.policy = p;
        if verb == "inspect" {
            let operation: Operation = self.host.read_json(
                &self
                    .host
                    .releases
                    .join(&self.host.policy.app)
                    .join("operation.json"),
            )?;
            ensure!(
                operation.app == self.host.policy.app
                    && operation.version == 1
                    && operation_identity(&operation.id)
                    && operation::phases().contains_key(&operation.phase),
                "unknown operation identity or vocabulary; mutation refused"
            );
            let body = self
                .host
                .effects
                .read(Path::new(flags.text("policy")), 1 << 20)?;
            return self.emit(&json!({"policy_sha256":hash(&body),"snapshot_retained":fs::symlink_metadata(self.host.releases.join(&self.host.policy.app).join(format!("staging-{}.json",operation.id))).is_ok(),"operation":operation,"private_bodies_omitted":true}));
        }
        let request = reconciliation::Request {
            id: flags.text("id").into(),
            candidate: flags.text("version").into(),
            policy_sha256: flags.text("policy-sha256").into(),
            phase: flags.text("expected-phase").into(),
            serving: flags.text("serving-version").into(),
            outcome: flags.text("outcome").into(),
        };
        let result = self
            .host
            .reconcile(parent, &request, &self.host.path(super::ACTIVATIONS))?;
        self.emit(&result)
    }
    fn secrets(&mut self, verb: &str, args: &[String], parent: &Context) -> Result<()> {
        let flags = Flags::parse(
            &[
                Flag::text("policy", ""),
                Flag::text("name", ""),
                Flag::boolean("file", false),
                Flag::integer("uid", 0),
            ],
            args,
        )?;
        root("secret authority requires the root executor and policy")?;
        ensure!(
            !flags.text("policy").is_empty() && flags.args.is_empty(),
            "secret authority requires the root executor and policy"
        );
        let p = self.policy(flags.text("policy"))?;
        if verb == "legacy-secrets-allowed" {
            files::activation_idle(&self.host.path(super::ACTIVATIONS))?;
            ensure!(
                !p.require_delivery_authorization,
                "legacy secret writes require migration to authenticated delivery"
            );
            return Ok(());
        }
        let ctx = context(parent, 60);
        let body = self.body(&ctx, 2 << 20)?;
        if verb == "owner-secret" {
            let _lock = self.lock(&ctx, &p.app)?;
            if flags.boolean("file") {
                ensure!(
                    secrets::valid_file_name(flags.text("name"))
                        && flags.integer("uid") >= 0
                        && !body.is_empty()
                        && body.len() <= 1 << 20,
                    "invalid owner secret file"
                );
                let uid: u32 = flags.integer("uid").try_into()?;
                let dir = Path::new(&p.app_dir).join("secrets");
                files::protected_directory(&dir)?;
                return secrets::write_file(&dir.join(flags.text("name")), &body, uid);
            }
            ensure!(
                flags.integer("uid") == 0,
                "UID applies only to file secrets"
            );
            let mut bytes = body;
            while bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            return secrets::SecretSet(std::collections::BTreeMap::from([(
                flags.text("name").into(),
                bytes.into(),
            )]))
            .write(Path::new(&p.app_dir));
        }
        ensure!(
            flags.text("name").is_empty() && !flags.boolean("file") && flags.integer("uid") == 0,
            "invalid release secret command"
        );
        let split = body
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(|| anyhow!("release secrets require authenticated source proof"))?;
        let (proof, payload) = (&body[..split], &body[split + 1..]);
        ensure!(
            proof.len() <= 128 << 10 && proof.starts_with(b"komizo-release/v1:"),
            "release secrets require authenticated source proof"
        );
        let envelope = release::read_envelope(&decode_base64(std::str::from_utf8(
            &proof[b"komizo-release/v1:".len()..],
        )?)?)?;
        let manifest = release::read_manifest(&decode_base64(&envelope.manifest)?)?;
        self.host
            .check_delivery(&p, &manifest.revision, (self.host.now)())?;
        let set = secrets::decode_set(payload)?;
        self.host.verify_task_release(&ctx, &p, proof)?;
        let _lock = self.lock(&ctx, &p.app)?;
        self.host.verify_task_release(&ctx, &p, proof)?;
        let dir = self.host.releases.join(&p.app);
        files::protected_directory(&dir)?;
        let stage = tempfile::Builder::new()
            .prefix(".secret-admission-")
            .tempdir_in(&dir)?;
        self.host.admit(
            &ctx,
            &p,
            Admission {
                revision: &manifest.revision,
                directory: &dir,
                output: &stage.path().join("accepted.json"),
            },
            proof,
        )?;
        ctx.check()?;
        set.write(Path::new(&p.app_dir))
    }
}
