//! Privileged workload adapters retain host-owned authority and durable operation fences.
pub mod activation;
mod deployment;
pub mod effects;
pub mod files;
pub mod image_cache;
mod owner;
pub mod reconciliation;
mod static_serving;
pub mod transaction;
pub const ACTIVATIONS: &str = "/var/lib/komizo/activations";
pub const RELEASES: &str = "/var/lib/komizo/releases";
pub const POLICIES: &str = "/etc/komizo/workloads";
pub const DELIVERY: &str = "/var/lib/komizo/delivery-authorizations";
pub const IMAGE_CONFIGS: &str = "/var/lib/komizo/image-configs";
