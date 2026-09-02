//! The command-line interface: argument model, command implementations, and
//! crash-safe output.
//!
//! `src/main.rs` stays a thin process entrypoint; everything CLI-shaped lives
//! here, split by responsibility.

pub(crate) mod atomic;
pub(crate) mod commands;
pub(crate) mod model;

pub use commands::run;
pub use model::{Cli, CliError};
