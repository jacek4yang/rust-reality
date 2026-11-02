use std::time::Duration;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::{
    config::node::landing::NxrLandingConfig,
    network::NetworkEnvironment,
    protocol::{
        nxr::{FLAG_TCP, FLAG_UDP, NxrKey, NxrProtocolError, REQUEST_HEADER_LEN, peek_open_flags},
        vless::Destination,
    },
    transport::{RelayContext, relay::RelayStats, tcp_relay::TcpRelay},
};

use crate::runtime::{PressureGauge, ResourceGovernor};

use super::{
    connector::{DestinationConnectError, DestinationConnector},
    pre_auth::{PreAuthGeneration, begin_authentication},
};
use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::ResourceGovernorPolicy;

mod auth;
mod error;
mod replay;
mod request;
#[cfg(test)]
mod tests;
mod udp;
#[cfg(test)]
mod udp_tests;

pub use auth::NxrAuthenticator;
pub use replay::NxrReplayCache;
pub(crate) use replay::{REPLAY_NONCE_CAPACITY, replay_retention_seconds};

pub use error::{NxrAuthenticationError, NxrLandingConfigError, NxrLandingError, NxrReplayError};

use request::{read_request_after_first, unix_seconds};

/// One NXR landing connection: authenticate once, connect once, then relay raw
/// bytes with normal TCP half-close semantics.
#[derive(Clone)]
pub struct NxrLandingHandler {
    authenticator: NxrAuthenticator,
    connector: DestinationConnector,
    pre_auth_idle_timeout: Duration,
    authentication_timeout: Duration,
    governor: ResourceGovernor,
    pressure: PressureGauge,
    generation: PreAuthGeneration,
    relay: TcpRelay,
    /// Pending-write stall bound. Quiet reads retain normal TCP lifetime.
    write_stall: Duration,
}

impl NxrLandingHandler {
    /// Compiles one validated listener while retaining its process-lifetime
    /// replay history across immutable runtime generations.
    ///
    /// # Errors
    ///
    /// Rejects malformed or incorrectly sized PSK material.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per immutable landing policy and process authority"
    )]
    pub(crate) fn from_landing_with_replay(
        inbound: &NxrLandingConfig,
        replay: NxrReplayCache,
        relay: TcpRelay,
        write_stall: Duration,
        network: &NetworkConfig,
        network_environment: NetworkEnvironment,
        governor: ResourceGovernor,
        pressure: PressureGauge,
        generation: PreAuthGeneration,
    ) -> Result<Self, NxrLandingConfigError> {
        let decoded = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(inbound.psk.expose())
                .map_err(|_| NxrLandingConfigError::Key)?,
        );
        let key: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| NxrLandingConfigError::Key)?;
        let mut handler = Self::new(
            NxrAuthenticator::new(
                NxrKey::new(key),
                replay,
                inbound.timing().max_time_difference_seconds,
            ),
            Duration::from_millis(inbound.timing().connect_timeout_ms),
            Duration::from_millis(inbound.timing().authentication_timeout_ms),
            relay,
            write_stall,
        );
        handler.pre_auth_idle_timeout =
            Duration::from_millis(inbound.timing().pre_auth_idle_timeout_ms);
        handler.governor = governor;
        handler.pressure = pressure;
        handler.generation = generation;
        handler.connector = DestinationConnector::with_environment(
            Duration::from_millis(inbound.timing().connect_timeout_ms),
            *network,
            network_environment,
        );
        Ok(handler)
    }

    /// Creates a landing handler from already compiled policy.
    #[must_use]
    pub fn new(
        authenticator: NxrAuthenticator,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        relay: TcpRelay,
        write_stall: Duration,
    ) -> Self {
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        Self {
            authenticator,
            connector: DestinationConnector::new(connect_timeout),
            pre_auth_idle_timeout: Duration::from_secs(60),
            authentication_timeout,
            governor,
            pressure: PressureGauge::new(),
            generation: PreAuthGeneration::default(),
            relay,
            write_stall,
        }
    }

    /// Processes a single NXR TCP connection. Authentication failures return
    /// without writing a response and occur before destination DNS or connect.
    ///
    /// # Errors
    ///
    /// Returns bounded request-read, clock, authentication, destination, or relay
    /// errors. Callers must silently close on every error.
    pub async fn handle(&self, mut inbound: TcpStream) -> Result<RelayStats, NxrLandingError> {
        let authentication = begin_authentication(
            &mut inbound,
            self.pre_auth_idle_timeout,
            self.authentication_timeout,
            &self.governor,
            &self.pressure,
            &self.generation,
        )
        .await
        .map_err(NxrLandingError::from_pre_auth)?;
        let request = read_request_after_first(
            &mut inbound,
            authentication.first_byte,
            authentication.deadline,
        )
        .await?;
        let now = unix_seconds()?;
        let flags = request
            .get(..REQUEST_HEADER_LEN)
            .and_then(peek_open_flags)
            .ok_or(NxrLandingError::Protocol(NxrProtocolError::Version))?;
        match flags {
            FLAG_TCP => {
                let destination = self.authenticator.authenticate(&request, now)?;
                drop(authentication);
                self.handle_tcp_relay(inbound, destination).await
            }
            FLAG_UDP => {
                let (open, session) = self.authenticator.authenticate_udp(&request, now)?;
                drop(authentication);
                self.handle_udp_association(inbound, open.destination().clone(), session)
                    .await
            }
            _ => Err(NxrLandingError::Protocol(NxrProtocolError::Flags)),
        }
    }

    async fn handle_tcp_relay(
        &self,
        inbound: TcpStream,
        destination: Destination,
    ) -> Result<RelayStats, NxrLandingError> {
        // The descriptor unit is reserved before connect(2) and outlives the
        // relay: the outbound socket closes before its unit is released.
        let connected = self
            .connector
            .connect_resolved_accounted(&destination, &[], self.relay.fd_budget())
            .await
            .map_err(|error| match error {
                DestinationConnectError::DescriptorBudget => NxrLandingError::DescriptorBudget,
                error => NxrLandingError::Destination(error),
            })?;
        let (outbound, _fd_permit) = connected.into_parts();
        let outcome = self
            .relay
            .relay_owned(
                inbound,
                outbound,
                RelayContext::owned().with_write_stall(self.write_stall),
            )
            .await
            .map_err(NxrLandingError::Relay)?;
        Ok(RelayStats::new(
            outcome.inbound_to_outbound(),
            outcome.outbound_to_inbound(),
        ))
    }
}
