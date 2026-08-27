//! The benchmark subsystem — one typed lifecycle replacing the benchmark scripts.
//!
//! The legacy `scripts/benchmark-*.sh` family duplicated one elaborate lifecycle
//! (host-exclusive lock, immutable-input identity, isolated workspace, helper and
//! implementation processes, readiness, workload, integrity, evidence, cleanup)
//! across a dozen scripts. This module owns that lifecycle once:
//!
//! ```text
//! host_lock   dedicated-keeper host-exclusive lock   (benchmark-contract.sh)
//! process     long-lived child processes owned by RAII, exact-identity teardown
//! workspace   isolated ephemeral run directory under the cache/runtime root
//! runner      the shared plan -> run -> evidence lifecycle
//! ```
//!
//! Every temporary resource a run creates is owned by an RAII guard, so a
//! successful run leaves nothing behind and a failed run cleans up too. The
//! runtime-only facts (lock device/inode, keeper identity, PIDs) are recorded as
//! attestation; durable artifacts are identified by content SHA-256, so archived
//! evidence never depends on an ephemeral inode surviving (ADR 0009).
//!
//! This module is the shared benchmark foundation. Some of its public surface is
//! consumed by the suite definitions that land on top of it in the following
//! change rather than by the environment preflight in this one, so `dead_code` is
//! allowed here: the API is deliberately staged, not unused.
#![allow(dead_code)]

pub mod host_lock;
pub mod process;
pub mod runner;
pub mod workspace;
