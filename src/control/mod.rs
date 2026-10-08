//! The local control protocol: a versioned, line-delimited JSON interface that
//! local programs use to inspect the running generation and to publish user
//! and short-ID changes into a new one.
//!
//! This module is the pure half of the control plane. It owns the wire shapes
//! ([`protocol`]), the non-secret user identity ([`handle`]), and the
//! translation of one requested change into one complete candidate
//! configuration ([`mutation`]). It performs no I/O, holds no lock, and knows
//! nothing about sockets, Tokio, or the generation store; the production
//! server owns serving it (see `server::production::control`).
//!
//! The boundary is deliberate. A control request never edits a live data
//! structure: it produces a whole new validated configuration, which the
//! store compiles and atomically publishes exactly as it would a `SIGHUP`
//! reload. Connections accepted earlier keep the generation they started
//! with. Nothing in this module is reachable from a relay, record, or
//! handshake path.
//!
//! The rationale, the rejected alternatives, and the compatibility plan for
//! later telemetry and guard work are recorded in ADR 0031.

pub mod handle;
pub mod mutation;
pub mod protocol;

pub use handle::{HandleIndex, UserHandles};
pub use mutation::{ControlError, ControlOutcome};
pub use protocol::{ErrorCode, Operation, Request, RequestError, decode_request};
