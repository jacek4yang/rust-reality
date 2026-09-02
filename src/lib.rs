//! Core library for the rust-reality server.

/// The source commit this binary was built from, or `unknown`.
///
/// Release and measurement builds set `RUST_REALITY_GIT_COMMIT`; `rustc` records
/// the read in its dependency info, so changing it rebuilds rather than leaving
/// a stale stamp behind. An ordinary `cargo build` does not set it and honestly
/// reports `unknown` rather than guessing.
///
/// This exists because performance evidence is only trustworthy if a measured
/// binary can state which source produced it. Without the stamp, a benchmark
/// harness pointed at a stale executable attributes its numbers to whatever the
/// repository happens to have checked out — the exact mislabelling that
/// AGENTS.md §16's exact-binary-identity requirement exists to prevent.
pub const BUILD_COMMIT: &str = match option_env!("RUST_REALITY_GIT_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};

pub mod assets;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod explain;
pub mod logging;
pub mod network;
pub mod protocol;
pub mod runtime;
pub mod server;
mod server_name;
pub mod transport;
mod user_map;
