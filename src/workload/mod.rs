pub mod compose;
pub mod host_resources;
pub(crate) mod json;
pub mod operation;
pub mod policy;
pub mod policy_read;
pub mod resources;
pub mod yaml;
use std::sync::OnceLock;
fn matches(pattern: &str, value: &str, compiled: &'static OnceLock<regex::Regex>) -> bool {
    compiled
        .get_or_init(|| regex::Regex::new(pattern).unwrap())
        .is_match(value)
}
pub fn identifier(value: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    matches(r"^[a-z][a-z0-9_-]{0,62}$", value, &RE)
}
pub fn revision(value: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    matches(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", value, &RE)
}
