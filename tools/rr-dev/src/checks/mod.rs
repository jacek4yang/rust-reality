//! Native repository validators, migrated out of `scripts/*.py`.
//!
//! Each submodule owns exactly one policy that used to live in a standalone
//! Python validator invoked by `scripts/check.sh`. They read declared repository
//! files and return a typed pass/fail with a rendered reason, so the same
//! function backs both a `cargo dev check` step and a unit test. There is one
//! source of truth for each rule and no second process per check.
//!
//! The migrated Python scripts are deleted in the same change that adds their
//! Rust replacement, so no compatibility wrapper or dual authority survives.

pub mod perf_contract;
pub mod probe_manifest;
