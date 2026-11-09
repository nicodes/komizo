//! Authenticated application releases and policy-constrained native execution.
pub const VERSION: &str = match option_env!("KOMIZO_VERSION") {
    Some(version) => version,
    None => "dev",
};
pub mod assets;
pub mod authority;
pub mod bootstrap;
pub mod capacity;
pub mod commands;
pub mod controller;
pub mod daemon;
pub mod data;
pub mod engine;
pub mod jobs;
pub mod model;
pub mod native;
pub mod observation;
pub mod operator;
pub mod proxy;
pub mod recovery;
pub mod registry;
pub mod render;
pub mod secrets;
pub mod store;
pub mod system;
pub mod tls;
pub mod transport;
pub mod units;
pub mod validation;

pub use model::*;
pub use validation::{canonical, document_digest, read_release};
