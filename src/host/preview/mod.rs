//! Preview identities and reservations are independent of product-specific topology.
pub mod knob;
use crate::{
    wire::{Secret, Slice, Time},
    wire_struct,
};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
pub const PREVIEWS_DIR: &str = "/var/lib/komizo/previews";
pub const KNOB_PATH: &str = "/etc/komizo/preview";
pub const DB_CONTAINER: &str = "komizo-previews";
pub const DB_SUPERUSER: &str = "postgres";
pub const DB_MAINTENANCE: &str = "postgres";
wire_struct!(RecordValues{v:"v":i64=>required,app:"app":String=>required,pr:"pr":i64=>required,project:"project":String=>required,host:"host":String=>optional,api_host:"api_host":String=>required,base_path:"base_path":String=>optional,db_name:"db_name":String=>required,gate_port:"gate_port":i64=>required,images:"images":Slice<String> =>required,created_at:"created_at":Time=>required,last_used:"last_used":Time=>required,route_file:"route_file":String=>required,private_profile:"private_profile":bool=>optional,profile_sha256:"profile_sha256":String=>optional,memory_reserved_bytes:"memory_reserved_bytes":i64=>optional});
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Record {
    #[serde(flatten)]
    pub values: RecordValues,
    #[serde(skip)]
    pub db_password: Secret,
}
impl Deref for Record {
    type Target = RecordValues;
    fn deref(&self) -> &RecordValues {
        &self.values
    }
}
impl DerefMut for Record {
    fn deref_mut(&mut self) -> &mut RecordValues {
        &mut self.values
    }
}
wire_struct!(Target{app:"app":String=>required,pr:"pr":i64=>required,domain:"domain":String=>required,host:"host":String=>required,api_host:"api_host":String=>required,base_path:"base_path":String=>optional});
pub fn project(app: &str, pr: i64) -> String {
    format!("{app}-pr-{pr}")
}
pub fn db_name(app: &str, pr: i64) -> String {
    format!("{}_pr_{pr}", app.replace('-', "_"))
}
pub fn preview_host(pr: i64, domain: &str) -> String {
    format!("pr-{pr}.{domain}")
}
pub fn valid_app(app: &str) -> bool {
    !app.is_empty()
        && app.as_bytes()[0].is_ascii_lowercase()
        && app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn validate_args(app: &str, pr: i64) -> anyhow::Result<()> {
    anyhow::ensure!(
        valid_app(app),
        "app name {} is not letters, digits or hyphens starting with a letter",
        super::authority::quote(app)
    );
    anyhow::ensure!(pr >= 1, "PR number {pr} is not a positive integer");
    Ok(())
}
impl Record {
    pub fn web_host(&self, k: &knob::Knob) -> String {
        if self.host.is_empty() {
            preview_host(self.pr, &k.legacy_domain_for(&self.app))
        } else {
            self.host.clone()
        }
    }
    pub fn public_api_host(&self, k: &knob::Knob) -> String {
        if self.images.len() < 2 {
            return String::new();
        }
        if !self.api_host.is_empty() {
            return self.api_host.clone();
        }
        let host = self.web_host(k);
        let (label, domain) = host.split_once('.').unwrap_or((&host, ""));
        format!("{label}-api.{domain}")
    }
}
