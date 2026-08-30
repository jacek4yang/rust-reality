//! Network transport primitives.

pub mod backend;
mod fd_budget;
pub mod relay;
pub mod tcp;
pub mod tcp_relay;

pub use backend::{
    BackendCapability, BackendDeclineReason, BackendReport, BackendRequest,
    DirectionalRelayContext, DirectionalRelayOutcome, RelayBackend, RelayContext, RelayDirection,
    RelayOutcome,
};
pub use fd_budget::{
    FdBudget, FdPermit, FdPressure, UNITS_INBOUND_SOCKET, UNITS_OUTBOUND_SOCKET,
    UNITS_SPLICE_DIRECTION, UNITS_SPLICE_RELAY,
};
pub use relay::RelayStats;
pub use tcp::{AcceptBackoff, AcceptErrorClass, EmergencyDescriptor, TcpAcceptor};
pub use tcp_relay::{TcpRelay, TcpRelayConfigError};
