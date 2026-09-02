//! How this process decides what it may consume, from the machine alone.
//!
//! Everything here is pure: the same capabilities, limits, mode, objective,
//! and pins always produce the same policy, and nothing touches the host. No
//! benchmark runs and no socket is opened, so a slow disk or a busy network
//! can never delay readiness — which is why the derivation is safe to run
//! before the first listener binds.
//!
//! Read it in the order it runs:
//!
//! - `inputs` — what the host offers, and the ceilings this project will plan
//!   within whatever it claims.
//! - `derive` — the balanced derivation, then the objective scaling, then the
//!   caps, then the floors. That order is the contract.
//! - `resolve` — the operator's pins merged over the derivation, with the
//!   provenance `explain` reports.
//! - `topology` — thread counts, decided before the runtime exists.

mod derive;
mod inputs;
mod resolve;
mod topology;

pub use derive::{PlannedPolicy, StartupPlan};
pub use inputs::{MachineCapabilities, SafetyLimits};
pub use resolve::{FieldResolution, FieldSource, PolicyResolution, resolve_policy};
pub use topology::RuntimeTopology;

#[cfg(test)]
mod tests;
