//! Finite host allocation for preview hostname growth. This counts admitted
//! names, not CA orders, and cannot establish remaining global issuer quota.
use super::{
    model::ReleaseDocument,
    store::{self, Store},
    validation::*,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

const WINDOW: i64 = 7 * 24 * 60 * 60;
const POLICY: &str = "/etc/komizo/preview-tls.json";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    kind: String,
    version: u32,
    domains: Vec<Domain>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    registered_domain: String,
    max_new_names_per_seven_days: usize,
}
impl Policy {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.preview-tls" && self.version == 1 && self.domains.len() <= 32,
            "invalid protected preview TLS allocation"
        );
        for (i, domain) in self.domains.iter().enumerate() {
            ensure!(
                hostname(&domain.registered_domain)
                    && domain.registered_domain.contains('.')
                    && !local(&domain.registered_domain)
                    && (1..=40).contains(&domain.max_new_names_per_seven_days),
                "preview TLS requires an explicit bounded registered-domain allocation"
            );
            for other in &self.domains[..i] {
                ensure!(
                    !within(&domain.registered_domain, &other.registered_domain)
                        && !within(&other.registered_domain, &domain.registered_domain),
                    "overlapping preview TLS allocations cannot multiply a domain allowance"
                );
            }
        }
        Ok(())
    }
    fn domain(&self, host: &str) -> Result<&Domain> {
        self.domains
            .iter()
            .find(|d| within(host, &d.registered_domain))
            .ok_or_else(|| {
                anyhow!("public preview has no protected registered-domain TLS allocation")
            })
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    kind: String,
    version: u32,
    names: BTreeMap<String, Reservation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    registered_domain: String,
    reserved_at: i64,
    application: String,
    instance: String,
}
impl Ledger {
    fn empty() -> Self {
        Self {
            kind: "komizo.preview-tls-reservations".into(),
            version: 1,
            names: BTreeMap::new(),
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.kind == "komizo.preview-tls-reservations"
                && self.version == 1
                && self.names.len() <= 16384,
            "invalid retained preview TLS ledger"
        );
        for (host, record) in &self.names {
            ensure!(
                hostname(host)
                    && !local(host)
                    && hostname(&record.registered_domain)
                    && within(host, &record.registered_domain)
                    && record.reserved_at > 0
                    && name(&record.application)
                    && name(&record.instance)
                    && record.instance != "production",
                "invalid retained preview hostname reservation"
            );
        }
        Ok(())
    }
}
fn local(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}
fn within(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|s| s.ends_with('.'))
}
fn hosts(document: &ReleaseDocument, instance: &str) -> BTreeSet<String> {
    if instance == "production" {
        return BTreeSet::new();
    }
    document
        .release
        .workload
        .routes
        .iter()
        .filter(|r| !local(&r.host))
        .map(|r| r.host.clone())
        .collect()
}
fn policy() -> Result<Policy> {
    let p: Policy = serde_json::from_value(crate::strict::value(
        &store::read_protected(Path::new(POLICY), 64 << 10)?,
        64 << 10,
    )?)?;
    p.validate()?;
    Ok(p)
}
fn ledger(store: &Store) -> Result<Ledger> {
    let path = store.root.join("preview-tls.json");
    let value = if path.try_exists()? {
        serde_json::from_value(crate::strict::value(
            &store::read_protected(&path, 4 << 20)?,
            4 << 20,
        )?)?
    } else {
        Ledger::empty()
    };
    value.validate()?;
    Ok(value)
}

/// Reserve all actual route names atomically before any preview preparation or
/// activation. Failed attempts remain charged; removal/expiry never refunds.
pub fn reserve(store: &Store, document: &ReleaseDocument, instance: &str, now: i64) -> Result<()> {
    let names = hosts(document, instance);
    if names.is_empty() {
        return Ok(());
    }
    let p = policy()?;
    let _lock = store.lock("platform", "preview-tls")?;
    let mut value = ledger(store)?;
    allocate(
        &p,
        &mut value,
        &names,
        &document.release.application,
        instance,
        now,
    )?;
    store::atomic(
        &store.root.join("preview-tls.json"),
        &serde_json::to_vec(&value)?,
        0o600,
    )
}

/// Boot and route refresh consume only names with prior protected admission.
pub fn require(store: &Store, document: &ReleaseDocument, instance: &str) -> Result<()> {
    let names = hosts(document, instance);
    if names.is_empty() {
        return Ok(());
    }
    let p = policy()?;
    let _lock = store.lock("platform", "preview-tls")?;
    let value = ledger(store)?;
    for host in names {
        let domain = p.domain(&host)?;
        let record = value
            .names
            .get(&host)
            .ok_or_else(|| anyhow!("public preview hostname has no prior TLS admission"))?;
        ensure!(
            record.registered_domain == domain.registered_domain
                && record.application == document.release.application
                && record.instance == instance,
            "preview TLS reservation differs from its installed owner"
        );
    }
    Ok(())
}

fn allocate(
    p: &Policy,
    ledger: &mut Ledger,
    hosts: &BTreeSet<String>,
    application: &str,
    instance: &str,
    now: i64,
) -> Result<()> {
    p.validate()?;
    ledger.validate()?;
    ensure!(
        now > 0
            && name(application)
            && name(instance)
            && instance != "production"
            && ledger.names.values().all(|v| v.reserved_at <= now),
        "preview TLS clock or scope is invalid"
    );
    let mut counts = BTreeMap::<&str, usize>::new();
    for record in ledger
        .names
        .values()
        .filter(|v| now - v.reserved_at < WINDOW)
    {
        *counts.entry(&record.registered_domain).or_default() += 1;
    }
    let mut changes = Vec::new();
    for host in hosts {
        ensure!(
            hostname(host) && !local(host),
            "invalid public preview hostname"
        );
        let domain = p.domain(host)?;
        if let Some(previous) = ledger.names.get(host) {
            ensure!(
                previous.application == application
                    && previous.instance == instance
                    && previous.registered_domain == domain.registered_domain,
                "preview hostname reservation belongs to another protected scope"
            );
            if now - previous.reserved_at < WINDOW {
                continue;
            }
        }
        *counts.entry(&domain.registered_domain).or_default() += 1;
        changes.push((
            host.clone(),
            Reservation {
                registered_domain: domain.registered_domain.clone(),
                reserved_at: now,
                application: application.into(),
                instance: instance.into(),
            },
        ));
    }
    for domain in &p.domains {
        ensure!(
            counts
                .get(domain.registered_domain.as_str())
                .copied()
                .unwrap_or(0)
                <= domain.max_new_names_per_seven_days,
            "host preview TLS hostname-growth allocation exhausted; issuer quota is a separate external limit"
        );
    }
    ensure!(
        ledger.names.len()
            + changes
                .iter()
                .filter(|(host, _)| !ledger.names.contains_key(host))
                .count()
            <= 16384,
        "retained preview TLS inventory is full; owner review is required"
    );
    ledger.names.extend(changes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(limit: usize) -> Policy {
        Policy {
            kind: "komizo.preview-tls".into(),
            version: 1,
            domains: vec![Domain {
                registered_domain: "example.com".into(),
                max_new_names_per_seven_days: limit,
            }],
        }
    }
    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).into()).collect()
    }
    #[test]
    fn sibling_apps_share_atomic_budget_and_retries_expiry_and_failure_do_not_refund() {
        let mut ledger = Ledger::empty();
        let now = 1800000000;
        let backend = set(&["pr-1.one.example.com", "pr-1-api.one.example.com"]);
        allocate(&p(3), &mut ledger, &backend, "one", "pr-1", now).unwrap();
        allocate(&p(3), &mut ledger, &backend, "one", "pr-1", now + 60).unwrap();
        assert_eq!(ledger.names.len(), 2);
        assert!(ledger.names.values().all(|v| v.reserved_at == now));
        let protected = serde_json::to_vec(&ledger).unwrap();
        assert!(
            allocate(
                &p(3),
                &mut ledger,
                &set(&["pr-2.two.example.com", "pr-2-api.two.example.com"]),
                "two",
                "pr-2",
                now + 60
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&ledger).unwrap(), protected);
        allocate(
            &p(3),
            &mut ledger,
            &set(&["pr-2.two.example.com"]),
            "two",
            "pr-2",
            now + 60,
        )
        .unwrap();
        assert!(
            allocate(
                &p(3),
                &mut ledger,
                &set(&["pr-3.three.example.com"]),
                "three",
                "pr-3",
                now + WINDOW - 1
            )
            .is_err()
        );
        allocate(
            &p(3),
            &mut ledger,
            &set(&["pr-3.three.example.com"]),
            "three",
            "pr-3",
            now + WINDOW,
        )
        .unwrap();
        assert_eq!(ledger.names.len(), 4);
    }
    #[test]
    fn label_boundaries_owner_scope_and_clock_cannot_bypass_allocation() {
        let mut ledger = Ledger::empty();
        let now = 1800000000;
        assert!(
            allocate(
                &p(2),
                &mut ledger,
                &set(&["badexample.com"]),
                "one",
                "pr-1",
                now
            )
            .is_err()
        );
        allocate(
            &p(2),
            &mut ledger,
            &set(&["pr-1.example.com"]),
            "one",
            "pr-1",
            now,
        )
        .unwrap();
        assert!(
            allocate(
                &p(2),
                &mut ledger,
                &set(&["pr-1.example.com"]),
                "two",
                "pr-1",
                now
            )
            .is_err()
        );
        assert!(
            allocate(
                &p(2),
                &mut ledger,
                &set(&["pr-2.example.com"]),
                "one",
                "pr-2",
                now - 1
            )
            .is_err()
        );
        let mut overlapping = p(2);
        overlapping.domains.push(Domain {
            registered_domain: "preview.example.com".into(),
            max_new_names_per_seven_days: 2,
        });
        assert!(overlapping.validate().is_err());
        assert!(p(41).validate().is_err());
    }
    #[test]
    fn only_actual_preview_route_hosts_consume_budget() {
        let mut document = read_release(include_bytes!(
            "../../tests/fixtures/deployment/release.json"
        ))
        .unwrap();
        document.release.workload.routes.truncate(1);
        assert!(hosts(&document, "production").is_empty());
        document.release.workload.routes[0].host = "pr-1.preview.localhost".into();
        assert!(hosts(&document, "pr-1").is_empty());
        document.release.workload.routes[0].host = "pr-1.example.com".into();
        assert_eq!(hosts(&document, "pr-1"), set(&["pr-1.example.com"]));
    }
}
