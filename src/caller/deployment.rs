use super::{
    client::{Cli, common},
    protocol, state,
    transport::Remote,
    validate,
};
use crate::{
    flags::Flag,
    wire_struct,
    workload::{
        operation::{self, Operation},
        policy::{commit_id, content_identity, operation_identity},
    },
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, process::Command};
wire_struct!(Inspection{operation:"operation":Operation=>required,policy_sha256:"policy_sha256":String=>required,snapshot_retained:"snapshot_retained":bool=>required,private_bodies_omitted:"private_bodies_omitted":bool=>required});
pub fn acknowledgement(body: &[u8]) -> Result<(String, String)> {
    let body = std::str::from_utf8(body)?;
    let lines: Vec<_> = body.trim().split('\n').collect();
    if lines.len() == 3
        && let Some(previous) = lines[0].strip_prefix("deploy: previous-version=")
        && operation_identity(lines[2])
        && lines[1] == format!("deploy: submitted={}", lines[2])
        && (previous.is_empty() || commit_id(previous))
    {
        return Ok((lines[2].into(), previous.into()));
    }
    anyhow::bail!("unknown or conflicting deployment acknowledgement")
}
pub fn inspect(cli: &Cli<'_>, remote: &Remote, app: &str) -> Result<Inspection> {
    let body = remote.journey(
        &cli.context,
        &[
            "workload".into(),
            "inspect".into(),
            "--policy".into(),
            format!("/etc/komizo/workloads/{app}.json"),
        ],
        &[],
    )?;
    let result: Inspection = serde_json::from_value(crate::strict::value(&body, 4 << 20)?)?;
    ensure!(
        result.operation.app == app
            && result.operation.version == 1
            && operation_identity(&result.operation.id)
            && content_identity(&result.policy_sha256)
            && operation::phases().contains_key(&result.operation.phase)
            && result.private_bodies_omitted,
        "invalid operation inspection identity or vocabulary"
    );
    Ok(result)
}
pub fn view(remote: &Remote, inspection: &Inspection) -> Value {
    let op = &inspection.operation;
    let meaning = &operation::phases()[&op.phase];
    let mut value = json!({"version":1,"inspection":inspection,"decision":meaning.decision,"reconciliation_required":meaning.reconciliation_required});
    if meaning.reconciliation_required {
        let mut options = serde_json::Map::new();
        for outcome in ["restore-serving", "accept-candidate"] {
            let serving = if outcome == "restore-serving" {
                &op.previous
            } else {
                &op.candidate
            };
            if !commit_id(serving) {
                continue;
            }
            options.insert(
                outcome.into(),
                json!([
                    "komizo",
                    "--json",
                    "operation",
                    "recover",
                    "--host",
                    remote.target.addr(),
                    "--port",
                    remote.target.port.to_string(),
                    "--app",
                    op.app,
                    "--id",
                    op.id,
                    "--version",
                    op.candidate,
                    "--policy-sha256",
                    inspection.policy_sha256,
                    "--expected-phase",
                    op.phase,
                    "--serving-version",
                    serving,
                    "--outcome",
                    outcome
                ]),
            );
        }
        value["review_required_options"] = options.into();
        value["instruction"]="Review the intended serving revision and stateful compatibility before selecting an option. Host postconditions remain mandatory. These commands do not restore database data or replay activation.".into();
    }
    value
}
pub fn revision(cli: &Cli<'_>, directory: &str) -> Result<String> {
    let result = crate::process::capture(
        Command::new("git").args([
            "-C",
            directory,
            "status",
            "--porcelain",
            "--untracked-files=normal",
        ]),
        None,
        1 << 20,
        cli.context.deadline,
        || cli.context.check().is_err(),
    )?;
    ensure!(
        result.status.success(),
        "could not inspect the project worktree"
    );
    ensure!(
        crate::wire::trim_space(&result.stdout).is_empty(),
        "commit project changes before selecting a deployment revision"
    );
    let result = crate::process::capture(
        Command::new("git").args(["-C", directory, "rev-parse", "HEAD"]),
        None,
        4096,
        cli.context.deadline,
        || cli.context.check().is_err(),
    )?;
    ensure!(
        result.status.success(),
        "could not select the project revision"
    );
    let revision = String::from_utf8(result.stdout)?.trim().to_string();
    ensure!(commit_id(&revision), "exact source revision is required");
    Ok(revision)
}
pub fn deploy(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.extend([
        Flag::text("directory", "."),
        Flag::text("app", ""),
        Flag::text("version", ""),
        Flag::text("approval", ""),
        Flag::text("proof", ""),
        Flag::text("registry-user", ""),
        Flag::text("registry-token-file", ""),
        Flag::text("generation", ""),
        Flag::boolean("wait", true),
    ]);
    let mut flags = cli.parse(&spec, args, "deploy accepts only flags")?;
    (|| -> Result<()> {
        ensure!(
            flags.text("proof").is_empty() || flags.text("approval").is_empty(),
            "choose one release admission proof"
        );
        ensure!(
            flags.text("approval").is_empty() || !flags.text("host").is_empty(),
            "owner approval requires an explicit root SSH host"
        );
        Ok(())
    })()
    .map_err(protocol::local)?;
    let project_default = flags.text("host").is_empty();
    let directory = flags.text("directory").to_string();
    let remote = cli.bound_target(&mut flags, &directory)?;
    let app = flags.text("app");
    let candidate = if project_default && flags.text("version").is_empty() {
        revision(cli, &directory).map_err(protocol::local)?
    } else {
        flags.text("version").to_string()
    };
    let generation = flags.text("generation");
    (|| -> Result<()> {
        validate::app(app)?;
        ensure!(
            commit_id(&candidate) && (generation.is_empty() || operation_identity(generation)),
            "deploy requires exact source and scoped generation identities"
        );
        ensure!(
            flags.text("registry-user").is_empty() == flags.text("registry-token-file").is_empty(),
            "registry user and token file must be supplied together"
        );
        ensure!(
            flags.text("approval").is_empty() || remote.target.user == "root",
            "owner approval requires root SSH"
        );
        Ok(())
    })()
    .map_err(protocol::local)?;
    let mut input = vec![];
    let mut request = vec![
        "workload".into(),
        "deployment-submit".into(),
        "--policy".into(),
        format!("/etc/komizo/workloads/{app}.json"),
        "--version".into(),
        candidate.clone(),
    ];
    if !flags.text("registry-token-file").is_empty() {
        let mut body = state::read_file(Path::new(flags.text("registry-token-file")), 16384, true)
            .map_err(protocol::local)?;
        if body.last() == Some(&b'\n') {
            body.pop();
        }
        ensure!(
            !body.is_empty() && !body.iter().any(|b| matches!(b, 0 | b'\r' | b'\n')),
            "registry token must be one bounded line"
        );
        input.extend(body);
        input.push(b'\n');
        request.extend([
            "--registry".into(),
            "ghcr.io".into(),
            "--registry-user".into(),
            flags.text("registry-user").into(),
        ]);
    }
    let admission = if !flags.text("approval").is_empty() {
        request.push("--owner-approval".into());
        flags.text("approval")
    } else {
        flags.text("proof")
    };
    if !admission.is_empty() {
        input.extend(
            state::read_file(Path::new(admission), 128 << 10, false).map_err(protocol::local)?,
        );
    }
    if !generation.is_empty() {
        request.extend(["--generation".into(), generation.into()]);
    }
    cli.reachable(&remote, false)?;
    let body=remote.journey(&cli.context,&request,&input).map_err(|_|anyhow::anyhow!("deployment submission did not acknowledge; inspect the app operation before retrying"))?;
    let (id, previous) = acknowledgement(&body).map_err(|_| {
        anyhow::anyhow!(
            "invalid deployment acknowledgement; inspect the app operation before retrying"
        )
    })?;
    let mut result = json!({"version":1,"app":app,"operation_id":id,"previous_revision":previous,"submitted":true,"completed":false,"next_action":["komizo","--json","operation","inspect","--host",remote.target.addr(),"--port",remote.target.port.to_string(),"--app",app]});
    if flags.boolean("wait") {
        if remote
            .journey(
                &cli.context,
                &[
                    "workload".into(),
                    "activation-wait".into(),
                    "--id".into(),
                    id.clone(),
                ],
                &[],
            )
            .is_err()
        {
            cli.emit(result)?;
            anyhow::bail!("deployment outcome needs inspection; do not resubmit");
        }
        let inspection = inspect(cli, &remote, app)?;
        ensure!(
            inspection.operation.id == id && inspection.operation.candidate == candidate,
            "deployment operation changed; inspect current state"
        );
        ensure!(
            matches!(
                inspection.operation.phase.as_str(),
                "ready" | "prepared_stopped" | "reconciled"
            ),
            "deployment is not in an accepted terminal state; inspect before proceeding"
        );
        result["completed"] = true.into();
        result["operation"] = serde_json::to_value(inspection)?;
    }
    cli.emit(result)
}
pub fn operation(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let Some((verb, args)) = args.split_first() else {
        return Err(protocol::local(anyhow::anyhow!(
            "operation requires inspect or recover; start with operation inspect --host HOST --app APP"
        )));
    };
    ensure!(
        matches!(verb.as_str(), "inspect" | "recover"),
        "operation requires inspect or recover; start with operation inspect --host HOST --app APP"
    );
    let mut spec = common();
    spec.push(Flag::text("app", ""));
    let names = [
        "id",
        "version",
        "policy-sha256",
        "expected-phase",
        "serving-version",
        "outcome",
    ];
    for name in names {
        spec.push(Flag::text(name, ""));
    }
    let flags = cli.parse(&spec, args, "operation accepts only flags")?;
    let app = flags.text("app");
    validate::app(app).map_err(protocol::local)?;
    let mut request = vec![
        "workload".into(),
        "inspect".into(),
        "--policy".into(),
        format!("/etc/komizo/workloads/{app}.json"),
    ];
    (|| -> Result<()> {
        if verb == "recover" {
            ensure!(
                operation_identity(flags.text("id"))
                    && commit_id(flags.text("version"))
                    && content_identity(flags.text("policy-sha256"))
                    && commit_id(flags.text("serving-version"))
                    && operation::phases().contains_key(flags.text("expected-phase"))
                    && matches!(
                        flags.text("outcome"),
                        "restore-serving" | "accept-candidate"
                    ),
                "recovery requires all exact reviewed operation identities and an explicit outcome"
            );
            request[1] = "reconcile".into();
            for name in names {
                request.extend([format!("--{name}"), flags.text(name).into()]);
            }
        } else {
            ensure!(
                names.iter().all(|name| flags.text(name).is_empty()),
                "inspect accepts no recovery authority"
            );
        }
        Ok(())
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    cli.reachable(&remote, false)?;
    if verb == "inspect" {
        let result = inspect(cli, &remote, app)?;
        return cli.emit(view(&remote, &result));
    }
    let body = remote.journey(&cli.context, &request, &[])?;
    let value = crate::strict::value(&body, 4 << 20)
        .map_err(|_| anyhow::anyhow!("invalid reconciliation receipt"))?;
    cli.emit(value)
}
