//! Root independently verifies every envelope and durably claims its ID before any effect.
use super::{
    AgentConf, Result as CommandResult,
    authority::{self, Command},
    results,
};
use crate::{wire::Time, workload::activation::Context};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::{fs, path::Path};
pub const INBOX_DIR: &str = "/run/komizo/inbox";
pub const MAX_PENDING: usize = 32;
pub const MAX_INBOX: usize = 256;
pub const MAX_SCAN: usize = 4096;
pub const APPLYING_DETAIL: &str = "applying";
pub trait Executor {
    fn perform(&mut self, ctx: &Context, command: &Command, actor: &str) -> Result<()>;
}
pub fn actor(command: &Command, signer: &[u8; 32]) -> String {
    if !command.sub.is_empty() {
        format!("account {}", command.sub)
    } else {
        format!(
            "device {}",
            authority::keys::fingerprint(&authority::keys::format_device_key(signer))
        )
    }
}
pub fn apply_pending(
    ctx: &Context,
    configuration: &AgentConf,
    directory: &Path,
    result_directory: &Path,
    executor: &mut impl Executor,
) -> Vec<String> {
    apply_pending_with_clock(
        ctx,
        configuration,
        directory,
        result_directory,
        executor,
        Utc::now,
    )
}
pub fn apply_pending_with_clock(
    ctx: &Context,
    configuration: &AgentConf,
    directory: &Path,
    result_directory: &Path,
    executor: &mut impl Executor,
    mut clock: impl FnMut() -> DateTime<Utc>,
) -> Vec<String> {
    let mut errors = vec![];
    let Ok(entries) = fs::read_dir(directory) else {
        return errors;
    };
    let mut entries = entries
        .take(MAX_SCAN)
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    if entries.is_empty() {
        return errors;
    }
    let now = clock();
    let mut kept = 0;
    for entry in entries {
        let info = entry.metadata().ok();
        let directory_entry = entry.file_type().is_ok_and(|ty| ty.is_dir());
        let stale = info
            .and_then(|info| info.modified().ok())
            .is_none_or(|modified| {
                let modified: DateTime<Utc> = modified.into();
                now - modified > Duration::minutes(6)
            });
        let over = kept >= MAX_INBOX;
        if !directory_entry && (stale || over) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if authority::valid_command_id(&name).is_ok()
                && !results::applied(result_directory, &name)
            {
                let why = if stale {
                    "this box did not get to this command before it expired"
                } else {
                    "this box had too many commands waiting"
                };
                let _ = results::write_result(
                    result_directory,
                    CommandResult {
                        id: name,
                        at: Time(now.fixed_offset()),
                        ok: false,
                        detail: why.into(),
                        ..Default::default()
                    },
                );
            }
        }
        if directory_entry || stale || over {
            if directory_entry {
                let _ = fs::remove_dir_all(entry.path());
            } else {
                let _ = fs::remove_file(entry.path());
            }
        } else {
            kept += 1;
        }
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return errors;
    };
    let mut pending = entries
        .take(MAX_SCAN)
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || entry.file_type().is_ok_and(|ty| ty.is_dir()) {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, name))
        })
        .collect::<Vec<_>>();
    pending.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    pending.truncate(MAX_PENDING);
    if !configuration.can_command() {
        return errors;
    }
    let keys = match configuration.trusted_keys() {
        Ok(keys) => keys,
        Err(error) => {
            errors.push(error.to_string());
            return errors;
        }
    };
    for (_, name) in pending {
        apply_one(
            ctx,
            Identity {
                keys: &keys,
                server: &configuration.server_id,
            },
            &directory.join(name),
            result_directory,
            executor,
            &mut clock,
            &mut errors,
        );
    }
    errors
}
struct Identity<'a> {
    keys: &'a [[u8; 32]],
    server: &'a str,
}
fn apply_one(
    ctx: &Context,
    identity: Identity<'_>,
    path: &Path,
    result_directory: &Path,
    executor: &mut impl Executor,
    clock: &mut impl FnMut() -> DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    let raw = crate::statefile::read(path, authority::MAX_COMMAND_BYTES);
    let _ = fs::remove_file(path);
    let Ok(Some(raw)) = raw else { return };
    let verified = match authority::verify_command(
        identity.keys,
        &raw,
        identity.server,
        Time(clock().fixed_offset()),
    ) {
        Ok(verified) => verified,
        Err(error) => {
            errors.push(format!("refusing a command: {error}"));
            return;
        }
    };
    let command = verified.command;
    if let Some(error) = verified.unsupported {
        errors.push(format!("refusing a command: {error}"));
        if !command.id.is_empty() {
            let _ = results::write_result(
                result_directory,
                CommandResult {
                    id: command.id,
                    op: command.op,
                    at: Time(clock().fixed_offset()),
                    ok: false,
                    detail: error,
                    ..Default::default()
                },
            );
        }
        return;
    }
    if results::applied(result_directory, &command.id) {
        return;
    }
    let claim = CommandResult {
        id: command.id.clone(),
        op: command.op.clone(),
        at: Time(clock().fixed_offset()),
        ok: false,
        detail: APPLYING_DETAIL.into(),
        ..Default::default()
    };
    match results::claim_result(result_directory, claim) {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            errors.push(format!(
                "could not claim {}, so it was not applied: {error}",
                command.id
            ));
            return;
        }
    }
    let result = executor.perform(ctx, &command, &actor(&command, &verified.signer));
    let result = CommandResult {
        id: command.id.clone(),
        op: command.op.clone(),
        at: Time(clock().fixed_offset()),
        ok: result.is_ok(),
        detail: result.err().map(|e| e.to_string()).unwrap_or_default(),
        ..Default::default()
    };
    if let Err(error) = results::write_result(result_directory, result) {
        errors.push(format!(
            "could not record the result of {}: {error}",
            command.id
        ));
    }
}
