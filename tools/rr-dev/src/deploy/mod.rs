//! The deployment subsystem — typed deployment domain replacing the deploy scripts.
//!
//! The release-canary evaluator is a pure, fail-closed function from a recorded
//! report to a verdict. Read-only inspection and planning remain separate from
//! the explicitly mutation-gated apply and active-canary paths, and all remote
//! work uses the fixed OpenSSH-alias transport.

pub mod canary;
pub mod canary_run;
pub mod executor;
pub mod host;
pub mod netem;
pub mod plan;
pub mod remote;
pub mod snapshot;
pub mod summary;
