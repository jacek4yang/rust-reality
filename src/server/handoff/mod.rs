//! LINE-side transfer and LANDING-side landing for the Handoff prototype.
//!
//! A LINE node transfers one authenticated session at the Vision boundary
//! (after routing, before any steady-state Vision processing) to a LANDING
//! node over the authenticated single-flight channel of
//! [`crate::protocol::handoff`]. After a successful transfer LINE relays the
//! client socket against the handoff socket raw and never touches TLS or
//! Vision state for the session again; LANDING reconstructs the record layers,
//! feeds the transferred pending bytes first, and runs the standard Vision
//! relay against the transferred destination — dialed directly, or through the
//! listener's configured egress outbound.

mod landing;
mod line;

pub use landing::{HandoffLandingConfigError, HandoffLandingError, HandoffLandingHandler};
pub use line::{HandoffLine, HandoffLineError};

pub(crate) use line::first_downlink_landed;

#[cfg(test)]
mod tests;
