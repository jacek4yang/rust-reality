//! Runtime-independent rust-reality session semantics.
//!
//! This crate owns data-only protocol/session decisions. Runtime adapters may
//! translate async or OS results into these values, but the values themselves
//! do not depend on a runtime, socket type, descriptor, or scheduler.

#![no_std]

mod write_progress;

pub use write_progress::WriteProgress;
