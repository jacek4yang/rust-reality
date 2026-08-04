//! Network transport primitives.

pub mod backend;
pub mod relay;
pub mod tcp;
pub mod tcp_relay;

pub use backend::{
    BackendCapability, BackendDeclineReason, BackendReport, BackendRequest, RelayBackend,
    RelayContext, RelayOutcome,
};
pub use relay::{RelayStats, relay_bidirectional};
pub use tcp::TcpAcceptor;
pub use tcp_relay::{TcpRelay, TcpRelayConfigError};
