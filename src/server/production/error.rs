//! What can go wrong building, publishing, or running the server.
//!
//! Three levels, and the level is the audience. [`ProductionServerError`]
//! reaches the operator through the CLI, so it names the startup step that
//! failed. [`RuntimeUpdateError`] reaches the operator through a rejected
//! reload, so it names the field they must change or the restart they must
//! perform. `ConnectionRunError` never reaches a human directly — it is
//! classified into one bounded [`RejectionReason`] per connection, and lives
//! beside the connection task in [`super::connection`].

use std::{error::Error, fmt, io, net::SocketAddr};

use tokio::task::JoinError;

use crate::{
    assets::AssetLoadError, config::LoadError, logging::LogWriteError, runtime::FdBudgetError,
    transport::tcp_relay::TcpRelayConfigError,
};

use crate::server::{
    dns::DnsResolverConfigError, handoff::HandoffLandingConfigError, nxr::NxrLandingConfigError,
    reality::RealityAcceptorConfigError, routing::RoutingCompileError,
};

/// One last-good runtime update failed before publication.
#[derive(Debug)]
pub enum RuntimeUpdateError {
    Load(LoadError),
    Log(LogWriteError),
    Assets(AssetLoadError),
    Routing(RoutingCompileError),
    Reality(RealityAcceptorConfigError),
    Nxr(NxrLandingConfigError),
    Handoff(HandoffLandingConfigError),
    DuplicateListener(SocketAddr),
    MissingNxrReplay(SocketAddr),
    MissingHandoffReplay(SocketAddr),
    ListenerTopologyChanged,
    NetworkDialPolicyChanged,
    DnsPolicyChanged,
    ResourceModeChanged,
    Relay(TcpRelayConfigError),
    GenerationExhausted,
    Unavailable,
}

impl fmt::Display for RuntimeUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(source) => source.fmt(formatter),
            Self::Log(source) => source.fmt(formatter),
            Self::Assets(source) => source.fmt(formatter),
            Self::Routing(source) => source.fmt(formatter),
            Self::Reality(source) => source.fmt(formatter),
            Self::Nxr(source) => source.fmt(formatter),
            Self::Handoff(source) => source.fmt(formatter),
            Self::DuplicateListener(address) => write!(formatter, "duplicate listener {address}"),
            Self::MissingNxrReplay(address) => {
                write!(
                    formatter,
                    "NXR replay cache is missing for listener {address}"
                )
            }
            Self::MissingHandoffReplay(address) => {
                write!(
                    formatter,
                    "Handoff replay cache is missing for listener {address}"
                )
            }
            Self::ListenerTopologyChanged => {
                formatter.write_str("listener addresses require a process restart")
            }
            Self::NetworkDialPolicyChanged => {
                formatter.write_str("network dial policy requires a process restart")
            }
            Self::DnsPolicyChanged => {
                formatter.write_str("DNS resolver policy requires a process restart")
            }
            Self::ResourceModeChanged => formatter.write_str(
                "runtime profile, tuning, or resource-mode changes require a process restart",
            ),
            Self::Relay(source) => source.fmt(formatter),
            Self::GenerationExhausted => formatter.write_str("runtime generation exhausted"),
            Self::Unavailable => formatter.write_str("runtime update is unavailable"),
        }
    }
}

impl Error for RuntimeUpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Load(source) => Some(source),
            Self::Log(source) => Some(source),
            Self::Assets(source) => Some(source),
            Self::Routing(source) => Some(source),
            Self::Reality(source) => Some(source),
            Self::Nxr(source) => Some(source),
            Self::Handoff(source) => Some(source),
            Self::Relay(source) => Some(source),
            Self::DuplicateListener(_)
            | Self::MissingNxrReplay(_)
            | Self::MissingHandoffReplay(_)
            | Self::ListenerTopologyChanged
            | Self::NetworkDialPolicyChanged
            | Self::DnsPolicyChanged
            | Self::ResourceModeChanged
            | Self::GenerationExhausted
            | Self::Unavailable => None,
        }
    }
}

impl From<LoadError> for RuntimeUpdateError {
    fn from(source: LoadError) -> Self {
        Self::Load(source)
    }
}

impl From<LogWriteError> for RuntimeUpdateError {
    fn from(source: LogWriteError) -> Self {
        Self::Log(source)
    }
}

impl From<AssetLoadError> for RuntimeUpdateError {
    fn from(source: AssetLoadError) -> Self {
        Self::Assets(source)
    }
}

impl From<RoutingCompileError> for RuntimeUpdateError {
    fn from(source: RoutingCompileError) -> Self {
        Self::Routing(source)
    }
}

impl From<RealityAcceptorConfigError> for RuntimeUpdateError {
    fn from(source: RealityAcceptorConfigError) -> Self {
        Self::Reality(source)
    }
}

impl From<NxrLandingConfigError> for RuntimeUpdateError {
    fn from(source: NxrLandingConfigError) -> Self {
        Self::Nxr(source)
    }
}

impl From<HandoffLandingConfigError> for RuntimeUpdateError {
    fn from(source: HandoffLandingConfigError) -> Self {
        Self::Handoff(source)
    }
}

impl From<TcpRelayConfigError> for RuntimeUpdateError {
    fn from(source: TcpRelayConfigError) -> Self {
        Self::Relay(source)
    }
}

/// Production server construction or lifecycle failed.
#[derive(Debug)]
pub enum ProductionServerError {
    /// The process descriptor limit cannot support a usable admission budget.
    ///
    /// This is returned before any listener is bound, so an impossible limit is
    /// a startup failure with a concrete recommendation rather than an
    /// `accept4` failure under load.
    DescriptorBudget(FdBudgetError),
    /// The configured DNS resolver could not be constructed at startup.
    Dns(DnsResolverConfigError),
    Runtime(RuntimeUpdateError),
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
    ListenerAddress(io::Error),
    Accept(io::Error),
    Signal(io::Error),
    Task(JoinError),
    ListenerStopped,
}

impl fmt::Display for ProductionServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(source) => source.fmt(formatter),
            Self::DescriptorBudget(source) => source.fmt(formatter),
            Self::Dns(source) => source.fmt(formatter),
            Self::Bind { address, .. } => write!(formatter, "failed to bind listener {address}"),
            Self::ListenerAddress(_) => formatter.write_str("failed to read listener address"),
            Self::Accept(_) => formatter.write_str("listener accept failed"),
            Self::Signal(_) => formatter.write_str("failed to install process signal"),
            Self::Task(_) => formatter.write_str("listener task failed"),
            Self::ListenerStopped => formatter.write_str("listener stopped unexpectedly"),
        }
    }
}

impl Error for ProductionServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(source) => Some(source),
            Self::Bind { source, .. }
            | Self::ListenerAddress(source)
            | Self::Accept(source)
            | Self::Signal(source) => Some(source),
            Self::Task(source) => Some(source),
            Self::DescriptorBudget(source) => Some(source),
            Self::Dns(source) => Some(source),
            Self::ListenerStopped => None,
        }
    }
}

impl From<RuntimeUpdateError> for ProductionServerError {
    fn from(source: RuntimeUpdateError) -> Self {
        Self::Runtime(source)
    }
}
