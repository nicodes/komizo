use crate::{statefile, strict, wire::Time, wire_struct};
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path, sync::OnceLock};
wire_struct!(Operation {id:"operation_id":String=>optional,started_at:"started_at":Time=>time_optional,deadline:"deadline":Time=>time_optional,version:"version":i64=>required,app:"app":String=>required,candidate:"candidate":String=>required,previous:"previous":String=>optional,phase:"phase":String=>required,at:"at":Time=>required});
#[derive(Deserialize)]
pub struct Phase {
    pub decision: String,
    pub reconciliation_required: bool,
}
pub fn contract() -> &'static [u8] {
    include_bytes!("operation-contract.json")
}
pub fn phases() -> &'static BTreeMap<String, Phase> {
    static PHASES: OnceLock<BTreeMap<String, Phase>> = OnceLock::new();
    PHASES.get_or_init(|| {
        #[derive(Deserialize)]
        struct Contract {
            version: i64,
            phases: BTreeMap<String, Phase>,
        }
        let contract: Contract =
            serde_json::from_slice(contract()).expect("compiled operation contract");
        assert_eq!(contract.version, 1);
        assert_eq!(contract.phases.len(), 12);
        contract.phases
    })
}
pub fn legal(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    match to {
        "reconciled" => {
            return matches!(
                from,
                "activating"
                    | "activation_failed"
                    | "readiness_failed"
                    | "failed"
                    | "staging"
                    | "staging_failed"
                    | "configured"
            );
        }
        "failed" => return !matches!(from, "ready" | "prepared_stopped" | "reconciled"),
        "activation_failed" => return from == "activating",
        "staging_failed" => return from == "staging",
        _ => {}
    }
    match from {
        "admitted" => matches!(to, "configured" | "staging"),
        "staging" => to == "configured",
        "configured" => matches!(to, "activating" | "prepared_stopped"),
        "activating" => matches!(to, "activated" | "prepared_stopped"),
        "activated" => matches!(to, "ready" | "readiness_failed" | "prepared_stopped"),
        "readiness_failed" => to == "ready",
        _ => false,
    }
}
pub fn decode(body: &[u8]) -> Result<Operation> {
    let value = strict::value(body, strict::RELEASE_MAX_BYTES)?;
    let value = strict::fields(
        value,
        &[
            "operation_id",
            "started_at",
            "deadline",
            "version",
            "app",
            "candidate",
            "previous",
            "phase",
            "at",
        ],
    )?;
    Ok(serde_json::from_value(value)?)
}
pub fn record(
    path: &Path,
    app: &str,
    candidate: &str,
    previous: &str,
    phase: &str,
    now: Time,
) -> Result<()> {
    ensure!(
        super::identifier(app)
            && super::revision(candidate)
            && (previous.is_empty() || super::revision(previous)),
        "invalid deployment operation identity"
    );
    ensure!(
        phases().contains_key(phase),
        "invalid deployment operation phase"
    );
    let mut operation = Operation {
        version: 1,
        app: app.into(),
        candidate: candidate.into(),
        previous: previous.into(),
        phase: phase.into(),
        at: now,
        ..Default::default()
    };
    match statefile::read(path, strict::RELEASE_MAX_BYTES)? {
        Some(body) => {
            let old = decode(&body)
                .map_err(|_| anyhow::anyhow!("invalid existing deployment operation"))?;
            ensure!(
                old.version == 1 && old.app == app,
                "invalid existing deployment operation"
            );
            if phase == "failed" && old.phase == "activating" {
                operation.phase = "activation_failed".into();
            }
            let phase = operation.phase.as_str();
            ensure!(
                phase == "admitted" || old.candidate == candidate,
                "deployment operation candidate changed"
            );
            ensure!(
                phase != "admitted"
                    || !matches!(
                        old.phase.as_str(),
                        "activating"
                            | "activation_failed"
                            | "staging"
                            | "staging_failed"
                            | "configured"
                    ),
                "interrupted activation needs reconciliation before another version"
            );
            if phase != "admitted" {
                ensure!(
                    previous == old.previous && legal(&old.phase, phase),
                    "invalid deployment operation transition"
                );
                ensure!(
                    old.deadline.is_zero()
                        || now <= old.deadline
                        || matches!(
                            phase,
                            "failed"
                                | "staging_failed"
                                | "activation_failed"
                                | "readiness_failed"
                                | "reconciled"
                        ),
                    "deployment operation deadline expired"
                );
                operation.id = old.id;
                operation.started_at = old.started_at;
                operation.deadline = old.deadline;
            }
        }
        None => ensure!(
            phase == "admitted",
            "deployment operation must start with admission"
        ),
    }
    if operation.phase == "admitted" {
        let mut identity = [0_u8; 16];
        getrandom::fill(&mut identity)
            .map_err(|error| anyhow::anyhow!("operation identity: {error}"))?;
        operation.id = identity.iter().map(|byte| format!("{byte:02x}")).collect();
        operation.started_at = now;
        operation.deadline = Time(now.0 + chrono::TimeDelta::minutes(25));
    }
    statefile::write_private_json(path, &operation)
}
