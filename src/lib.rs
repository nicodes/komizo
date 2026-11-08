//! Native Komizo host and caller implementation; the existing API is packaged from crates/api/.
pub mod caller;
mod cgroupfs;
pub mod deployment;
pub mod flags;
pub mod host;
pub mod input;
pub mod nativeapi;
pub mod process;
pub mod runtime;
pub mod scripts;
pub mod source_toml;
pub mod statefile;
pub mod strict;
pub mod template;
pub mod wire;
pub mod workload;
