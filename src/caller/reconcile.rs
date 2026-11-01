use super::{
    client::{Cli, common},
    protocol, state, validate,
};
use crate::{
    flags::Flag,
    host::{App, Report},
    wire::Slice,
    wire_struct,
};
use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
wire_struct!(ExpectedApp{name:"name":String=>required,config:"config":String=>required,hosts:"hosts":Slice<String> =>required});
wire_struct!(Inventory{apps:"apps":Slice<ExpectedApp> =>required});
pub fn decode(body: &[u8]) -> Result<Inventory> {
    ensure!(
        !body.windows(10).any(|s| s == b"-----BEGIN"),
        "inventory contains a PEM block; keys and secrets do not belong in an inventory"
    );
    let mut value = crate::strict::fields(crate::strict::value(body, 1 << 20)?, &["apps"])?;
    if let Some(apps) = value
        .get_mut("apps")
        .and_then(serde_json::Value::as_array_mut)
    {
        for app in apps {
            *app = crate::strict::fields(app.take(), &["name", "config", "hosts"])?;
        }
    }
    let inventory: Inventory = serde_json::from_value(value)?;
    let mut names = BTreeSet::new();
    for app in inventory.apps.iter() {
        ensure!(names.insert(&app.name), "duplicate expected app");
        validate::app(&app.name)?;
        validate::config_image(&app.config)?;
        let mut hosts = BTreeSet::new();
        for host in app.hosts.iter() {
            ensure!(hosts.insert(host), "duplicate expected hostname");
            let rest = host.strip_prefix("*.").unwrap_or(host);
            ensure!(!rest.contains('*'), "wildcard route must start with *.");
            validate::host(rest)?;
        }
    }
    Ok(inventory)
}
pub fn compare(inventory: &Inventory, registered: &[App]) -> Vec<String> {
    let mut findings = vec![];
    let mut indexed = BTreeMap::new();
    let mut duplicates = BTreeSet::new();
    for app in registered {
        if let std::collections::btree_map::Entry::Vacant(entry) = indexed.entry(&app.name) {
            entry.insert(app);
        } else {
            duplicates.insert(&app.name);
        }
    }
    for name in duplicates {
        findings.push(format!("duplicate registered app: {name}"));
    }
    let mut expected: Vec<_> = inventory.apps.iter().collect();
    expected.sort_by(|a, b| a.name.cmp(&b.name));
    for e in expected {
        let Some(a) = indexed.get(&e.name) else {
            findings.push(format!("missing registered app: {}", e.name));
            continue;
        };
        if a.config_image != e.config {
            findings.push(format!(
                "wrong config image for {}: expected {}, registered {}",
                e.name, e.config, a.config_image
            ));
        }
        let routes = a.routes();
        let want: BTreeSet<_> = e.hosts.iter().collect();
        for host in e.hosts.iter() {
            if !routes.contains(host) {
                findings.push(format!(
                    "wrong hostname for {}: {} is expected but not a published route",
                    e.name, host
                ));
            }
        }
        for host in routes {
            if !want.contains(&host) {
                findings.push(format!(
                    "wrong hostname for {}: {} is a published route but not expected",
                    e.name, host
                ));
            }
        }
    }
    let names: BTreeSet<_> = inventory.apps.iter().map(|a| &a.name).collect();
    let extra: BTreeSet<_> = registered
        .iter()
        .filter(|a| !names.contains(&a.name))
        .map(|a| &a.name)
        .collect();
    for name in extra {
        findings.push(format!("unexpected registered app: {name}"));
    }
    findings
}
pub fn run(cli: &mut Cli<'_>, args: &[String]) -> Result<()> {
    let mut spec = common();
    spec.push(Flag::text("inventory", ""));
    let flags = cli.parse(&spec, args, "reconcile accepts only flags")?;
    let inventory = (|| -> Result<Inventory> {
        ensure!(
            !flags.text("inventory").is_empty(),
            "--inventory is required"
        );
        decode(&state::read_file(
            Path::new(flags.text("inventory")),
            1 << 20,
            false,
        )?)
    })()
    .map_err(protocol::local)?;
    let remote = cli.target(&flags)?;
    ensure!(
        !remote.target.user.starts_with("komizo-"),
        "reconcile requires the operator login, not an application deploy account"
    );
    cli.reachable(&remote, flags.boolean("accept-host-key"))?;
    let report: Report = remote.fetch(&cli.context, &["report".into()])?;
    let findings = compare(&inventory, &report.apps);
    if cli.machine {
        cli.emit(json!({"version":1,"host":remote.target.addr(),"matched":findings.is_empty(),"expected_apps":inventory.apps.len(),"registered_apps":report.apps.len(),"findings":findings}))?;
        if !findings.is_empty() {
            return Err(protocol::mismatch(anyhow::anyhow!(
                "{} reconciliation findings",
                findings.len()
            )));
        }
    } else if findings.is_empty() {
        cli.note(&format!(
            "reconciled {}: {} app(s) registered, all matching the inventory.",
            remote.target.host,
            inventory.apps.len()
        ))?;
    } else {
        for finding in &findings {
            cli.note(finding)?;
        }
        anyhow::bail!(
            "{} reconciliation finding(s) -- {} does not match the inventory",
            findings.len(),
            remote.target.host
        );
    }
    Ok(())
}
