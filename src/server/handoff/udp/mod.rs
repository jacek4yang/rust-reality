//! Native LINE↔LANDING UDP channel for Handoff XUDP traffic (ADR 0069).
//!
//! The wire format and key schedule live in
//! [`crate::protocol::handoff::udp`]; this module owns sockets, sessions,
//! packetization under the discovered path MTU, and the LINE/LANDING roles.

mod endpoint;
mod landing;
mod line;

pub use landing::{
    LANDING_UDP_SESSION_IDLE, LandingUdpPolicy, LandingUdpStats, MAX_LANDING_UDP_SESSIONS,
    bind_landing_udp, run_landing_udp,
};
pub use line::XudpHandoffUdpAssociation;

#[cfg(test)]
mod tests;
