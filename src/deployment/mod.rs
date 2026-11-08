//! Authenticated application releases and policy-constrained native execution.
pub mod assets;
pub mod authority;
pub mod capacity;
pub mod commands;
pub mod controller;
pub mod engine;
pub mod jobs;
pub mod model;
pub mod observation;
pub mod registry;
pub mod render;
pub mod secrets;
pub mod store;
pub mod system;
pub mod transport;
pub mod units;
pub mod validation;

pub use model::*;
pub use validation::{canonical, document_digest, read_release};
