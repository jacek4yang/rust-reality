//! Network transport primitives.

pub mod backend;
pub mod relay;
pub mod tcp;
pub mod tcp_relay;

pub use backend::{
    BackendCapability, BackendDeclineReason, BackendReport, BackendRequest,
    DirectionalRelayOutcome, RelayBackend, RelayContext, RelayDirection, RelayOutcome,
};
pub use relay::{RelayStats, relay_bidirectional};
pub use tcp::{AcceptBackoff, AcceptErrorClass, EmergencyDescriptor, TcpAcceptor};
pub use tcp_relay::{TcpRelay, TcpRelayConfigError};
