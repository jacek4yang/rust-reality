use std::{sync::Arc, time::Duration};

use crate::protocol::vless::VERSION;

use super::{
    direct::DirectHandoff,
    outbound::{OutboundConnectOutcome, OutboundRegistry, SessionOutboundOutcome},
    reality::RealityEstablished,
    routing::{AssetMatcher, RoutingCompileError, RoutingTable},
};
use crate::config::node::entry::EntryConfig;
use crate::config::node::routing::DomainStrategy;
use crate::io_activity::{SessionActivity, WRITE_STALL_TIMEOUT};
use crate::runtime::policy::EffectivePolicy;
use crate::runtime::policy::ResourceGovernorPolicy;
use crate::transport::TcpRelay;

mod nested;

#[cfg(feature = "fuzzing")]
pub use nested::fuzz_nested_tls_header_prefix;
pub(crate) use nested::{NestedRead, NestedRecordReader, NestedTlsDetector, PaddingDecision};

mod abort;

mod request;

use request::{AcceptedVisionRequest, read_vision_request};

mod error;

pub use error::VisionSessionError;
use error::idle_failure;
#[cfg(test)]
use error::is_benign_teardown;

mod stats;

#[cfg(test)]
use stats::BoundaryBytes;
pub use stats::VisionRelayStats;
use stats::session_stats;

mod framing;

mod relay;
mod relay_downlink;
mod relay_uplink;

#[cfg(test)]
use framing::length_u64;
#[cfg(test)]
use relay::run_directional;
use relay::{SessionContext, join_directions};
use relay_downlink::relay_downlink;
use relay_uplink::relay_uplink;

mod handoff_relay;
mod handoff_resume;
mod xudp_session;

pub(crate) use handoff_resume::{run_resumed_session, run_resumed_xudp_session};

/// Immutable Vision data path with UUID-grouped routing and outbound selection.
#[derive(Clone)]
pub struct VisionHandler {
    outbounds: OutboundRegistry,
    routing: RoutingTable,
    relay: TcpRelay,
    request_timeout: Duration,
    io_timeout: Duration,
    dns_strategy: DomainStrategy,
    dns_timeout: Duration,
}

impl VisionHandler {
    /// Compiles validated config and one immutable asset snapshot.
    ///
    /// # Errors
    ///
    /// Returns a routing matcher or UUID compilation error.
    pub fn from_config(
        entry: &EntryConfig,
        policy: &EffectivePolicy,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
    ) -> Result<Self, RoutingCompileError> {
        Self::build(entry, policy, assets, relay, None)
    }

    /// Compiles the data path with a pressure-aware outbound registry.
    ///
    /// # Errors
    ///
    /// Returns a routing matcher or UUID compilation error.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per process-lifetime authority and generation input"
    )]
    pub(crate) fn from_config_with_pressure(
        entry: &EntryConfig,
        policy: &EffectivePolicy,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
        pressure: &crate::runtime::PressureGauge,
        direct_barrier: crate::runtime::DirectBarrier,
        governor: crate::runtime::ResourceGovernor,
        network_environment: crate::network::NetworkEnvironment,
        generation: u64,
        warm_authority: super::warm_pool::WarmPoolAuthority,
    ) -> Result<Self, RoutingCompileError> {
        Self::build(
            entry,
            policy,
            assets,
            relay,
            Some((
                pressure.clone(),
                direct_barrier,
                governor,
                network_environment,
                generation,
                warm_authority,
            )),
        )
    }

    fn build(
        entry: &EntryConfig,
        policy: &EffectivePolicy,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
        authorities: Option<(
            crate::runtime::PressureGauge,
            crate::runtime::DirectBarrier,
            crate::runtime::ResourceGovernor,
            crate::network::NetworkEnvironment,
            u64,
            super::warm_pool::WarmPoolAuthority,
        )>,
    ) -> Result<Self, RoutingCompileError> {
        let governor = &policy.governor;
        let connect_timeout = Duration::from_millis(governor.connect_timeout_ms);
        let declared = entry.outbounds.clone().unwrap_or_default();
        let network = entry.network.unwrap_or_default();
        let (outbounds, dns_governor) = match authorities {
            Some((
                _pressure,
                direct_barrier,
                dns_governor,
                network_environment,
                generation,
                warm_authority,
            )) => (
                OutboundRegistry::with_warm_pools(
                    &declared,
                    direct_barrier,
                    connect_timeout,
                    relay.fd_budget().clone(),
                    &network,
                    network_environment,
                    generation,
                    warm_authority,
                    &policy.warm_connections,
                ),
                dns_governor,
            ),
            None => (
                OutboundRegistry::with_barrier_and_network(
                    &declared,
                    crate::runtime::DirectBarrier::new(&policy.direct_barrier),
                    connect_timeout,
                    relay.fd_budget().clone(),
                    &network,
                    crate::network::NetworkEnvironment::detect(),
                ),
                crate::runtime::ResourceGovernor::new(governor),
            ),
        };
        Ok(Self::new_with_dns(
            outbounds,
            RoutingTable::compile(&entry.routing, &entry.users, assets, dns_governor)?,
            relay,
            governor,
            entry.routing.strategy(),
            Duration::from_millis(entry.dns.clone().unwrap_or_default().timeout_ms()),
        ))
    }

    /// Returns the shared outbound registry, for Handoff landings whose
    /// configured egress dials through the same compiled transports.
    #[must_use]
    pub const fn outbounds(&self) -> &OutboundRegistry {
        &self.outbounds
    }

    /// Binds compiled routing and outbound snapshots to bounded session timeouts.
    #[must_use]
    pub fn new(
        outbounds: OutboundRegistry,
        routing: RoutingTable,
        relay: TcpRelay,
        governor: &ResourceGovernorPolicy,
    ) -> Self {
        Self::new_with_dns(
            outbounds,
            routing,
            relay,
            governor,
            DomainStrategy::AsIs,
            Duration::from_secs(5),
        )
    }

    /// Binds routing to an explicit bounded DNS strategy.
    #[must_use]
    pub fn new_with_dns(
        outbounds: OutboundRegistry,
        routing: RoutingTable,
        relay: TcpRelay,
        governor: &ResourceGovernorPolicy,
        dns_strategy: DomainStrategy,
        dns_timeout: Duration,
    ) -> Self {
        Self {
            outbounds,
            routing,
            relay,
            request_timeout: Duration::from_millis(governor.handshake_timeout_ms),
            io_timeout: WRITE_STALL_TIMEOUT,
            dns_strategy,
            dns_timeout,
        }
    }

    /// Reads, authorizes, connects, and relays one established REALITY session.
    ///
    /// The outbound descriptor permit is retained for the entire session; the
    /// direct-dial barrier permit ended when the dial resolved. Vision
    /// Direct unwraps outer TLS only after the authenticated command record has
    /// completed, and destination TLS is switched only on an exact record boundary.
    ///
    /// # Errors
    ///
    /// Returns bounded request, admission, destination, framing, TLS, or socket errors.
    pub async fn handle(
        &self,
        established: RealityEstablished,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let client_random = *established.client_random();
        let (application, inbound_tag, authenticated_user_id) = established.into_parts();
        let (mut client_reader, mut client_writer) = application.into_owned_split();
        let request = read_vision_request(
            &mut client_reader,
            authenticated_user_id,
            self.request_timeout,
        )
        .await?;
        if let AcceptedVisionRequest::Xudp {
            user_id,
            buffer,
            prefetched,
        } = request
        {
            return self
                .handle_xudp(
                    client_reader,
                    client_writer,
                    inbound_tag.as_ref(),
                    user_id,
                    buffer,
                    prefetched,
                    client_random,
                )
                .await;
        }
        let AcceptedVisionRequest::Tcp {
            user_id,
            destination,
            buffer,
            prefetched,
        } = request
        else {
            unreachable!("Xudp branch returned above");
        };
        let route = self
            .routing
            .select_with_dns(
                user_id,
                inbound_tag.as_ref(),
                &destination,
                self.dns_strategy,
                self.dns_timeout,
            )
            .await
            .map_err(VisionSessionError::Route)?;
        let outcome = self
            .outbounds
            .connect_session_resolved(
                route.decision().outbound(),
                &destination,
                route.resolved_ips(),
            )
            .await
            .map_err(VisionSessionError::Outbound)?;
        // The session-handoff boundary: routing has selected the outbound, no
        // client-visible response has been written, and no Vision encoder or
        // decoder exists yet. The downlink TLS sequence is zero normally or
        // one after a cover-shaped empty ApplicationData record. A handoff
        // outbound transfers that exact state to the landing node here.
        let outcome = match outcome {
            SessionOutboundOutcome::Handoff(line) => {
                return self
                    .relay_via_handoff(
                        &line,
                        client_reader,
                        client_writer,
                        AcceptedVisionRequest::Tcp {
                            user_id,
                            destination,
                            buffer,
                            prefetched,
                        },
                        client_random,
                        inbound_tag.as_ref(),
                    )
                    .await;
            }
            SessionOutboundOutcome::Connected(outcome) => outcome,
        };
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            client_writer
                .shutdown(self.io_timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(VisionRelayStats::default());
        };
        let (destination_stream, outbound_permit) = connection.into_parts();
        let (destination_reader, destination_writer) = destination_stream.into_split();
        // The decoder accepted VLESS v0 and this inbound never negotiates
        // response Addons, so the response is a fixed stack value.
        let response_header = [VERSION, 0];

        // One coordinator per session. It holds two atomics, four socket-half
        // slots, and a version watch; never a queue and never a payload.
        let handoff = DirectHandoff::new();
        let activity = Arc::new(SessionActivity::default());
        let context = SessionContext {
            activity: &activity,
            timeout: self.io_timeout,
            handoff: &handoff,
            relay: &self.relay,
        };
        let uplink = relay_uplink(
            client_reader,
            destination_writer,
            user_id,
            buffer,
            prefetched,
            &context,
        );
        let downlink = relay_downlink(
            destination_reader,
            client_writer,
            user_id,
            &response_header,
            &context,
        );
        let (uplink, downlink) = join_directions(uplink, downlink, &activity).await?;
        drop(outbound_permit);
        Ok(session_stats(uplink, downlink))
    }
}

#[cfg(test)]
mod tests;
