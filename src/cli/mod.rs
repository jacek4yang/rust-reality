//! The command-line interface: argument model, command implementations,
//! configuration generation, and crash-safe output.
//!
//! `src/main.rs` stays a thin process entrypoint; everything CLI-shaped lives
//! here, split by responsibility.

pub(crate) mod atomic;
pub(crate) mod commands;
pub(crate) mod generate;
pub(crate) mod model;

pub use commands::run;
pub use model::{Cli, CliError};
