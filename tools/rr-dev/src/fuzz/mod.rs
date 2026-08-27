//! The fuzz subsystem — one typed domain replacing the fuzz scripts.
//!
//! ```text
//! targets  validate fuzz/Cargo.toml + shard   (fuzz-targets.py)
//! smoke    deterministic short libFuzzer run   (fuzz-smoke.sh)
//! ```
//!
//! The target list is the single source of truth for which cargo-fuzz binaries
//! exist; both the `check` gate and the sharded `security.yml` smoke job resolve
//! it through this module, so there is one implementation of target discovery,
//! validation and sharding.

pub mod smoke;
pub mod targets;
