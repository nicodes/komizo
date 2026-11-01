//! Audience-bound data and credential interfaces never grant restore authority.
use super::policy::{commit_id, content_identity};
use crate::{wire::Slice, wire_struct};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
wire_struct!(StatefulContract{version:"version":i64=>required,source_revision:"source_revision":String=>required,schema:"schema":SchemaRange=>required,data_revision:"data_revision":String=>required,credential_revision:"credential_revision":String=>required,migrations:"migrations":Slice<MigrationIdentity> =>required,recovery_action:"recovery_action":String=>required});
wire_struct!(SchemaRange{minimum:"minimum":i64=>required,maximum:"maximum":i64=>required,write:"write":i64=>required});
wire_struct!(MigrationIdentity{identity:"identity":String=>required,sha256:"sha256":String=>required});
fn identity(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}
impl StatefulContract {
    pub fn check(&self, revision: &str) -> Result<()> {
        ensure!(
            self.version == 1
                && commit_id(&self.source_revision)
                && self.source_revision == revision
                && identity(&self.data_revision)
                && identity(&self.credential_revision)
                && (1..=128).contains(&self.migrations.len()),
            "invalid stateful release identity"
        );
        ensure!(
            self.schema.minimum >= 1
                && self.schema.maximum <= 1_000_000
                && self.schema.minimum <= self.schema.write
                && self.schema.write <= self.schema.maximum,
            "invalid required schema range"
        );
        ensure!(
            matches!(
                self.recovery_action.as_str(),
                "forward_only" | "image_rollback"
            ),
            "unsupported data recovery authority"
        );
        let mut names = BTreeSet::new();
        for migration in self.migrations.iter() {
            ensure!(
                identity(&migration.identity)
                    && content_identity(&migration.sha256)
                    && names.insert(&migration.identity),
                "invalid or duplicate migration identity/checksum"
            );
        }
        Ok(())
    }
    pub fn sha256(&self) -> Result<String> {
        self.check(&self.source_revision)?;
        Ok(format!(
            "{:x}",
            Sha256::digest(super::json::compact(&serde_json::to_value(self)?)?)
        ))
    }
    pub fn supports_post_write_state(&self, current: &Self, observed_schema: i64) -> Result<()> {
        self.check(&self.source_revision)?;
        current.check(&current.source_revision)?;
        ensure!(
            observed_schema == current.schema.write
                && observed_schema >= self.schema.minimum
                && observed_schema <= self.schema.maximum
                && self.data_revision == current.data_revision
                && self.credential_revision == current.credential_revision,
            "rollback target does not support post-write state"
        );
        let migrations: BTreeMap<_, _> = current
            .migrations
            .iter()
            .map(|m| (&m.identity, &m.sha256))
            .collect();
        for migration in self.migrations.iter() {
            ensure!(
                migrations.get(&migration.identity) == Some(&&migration.sha256),
                "applied migration changed or disappeared"
            );
        }
        Ok(())
    }
}
