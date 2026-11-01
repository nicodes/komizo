//! Additive v1 host observation schemas are shared by the native caller and host processes.
pub mod types;
pub use types::*;
pub const REPORT_VERSION: i64 = 1;
pub const RESULT_VERSION: i64 = 1;
pub const METRICS_WINDOW: i64 = 60 * 60;
