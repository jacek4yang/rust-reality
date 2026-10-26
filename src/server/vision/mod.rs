use std::{sync::Arc, time::Duration};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::protocol::{
    handoff::{ContinuationState, HandoffError, HandoffPolicySnapshot, SessionKind},
    reality::tls13::{TlsApplicationReader, TlsApplicationWriter},
    vless::{Destination, UserId, VERSION},
};

use super::{
    direct::DirectHandoff,
    handoff::HandoffLineError,
    outbound::{OutboundConnectOutcome, OutboundRegistry, SessionOutboundOutcome},
    reality::RealityEstablished,
    routing::{AssetMatcher, RoutingCompileError, RoutingTable},
    xudp::XudpSessionError,
};
use crate::config::node::entry::EntryConfig;
use crate::config::node::routing::DomainStrategy;
use crate::io_activity::{SessionActivity, WRITE_STALL_TIMEOUT};
use crate::runtime::policy::EffectivePolicy;
use crate::runtime::policy::ResourceGovernorPolicy;
use crate::transport::{RelayContext, TcpRelay};

mod nested;

#[cfg(feature = "fuzzing")]
pub use nested::fuzz_nested_tls_header_prefix;
pub(crate) use nested::{NestedRead, NestedRecordReader, NestedTlsDetector, PaddingDecision};

mod abort;

mod request;

use abort::SocketAbortGuard;
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

#[cfg(test)]
use framing::length_u64;
#[cfg(test)]
use relay::run_directional;
use relay::{SessionContext, join_directions, relay_downlink, relay_uplink};

mod handoff_resume;
mod xudp_session;

use handoff_resume::reunite_handoff_client;
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

    /// Transfers one boundary-session to a Handoff landing node, then relays
    /// the client socket against the handoff socket raw in both directions.
    ///
    /// The continuation carries both current traffic secrets and record
    /// sequences, any owed KeyUpdate response, the reader's read-ahead
    /// ciphertext, and the prefetched VLESS payload; afterwards this node
    /// never decrypts or frames the session again. Any failure — dial, seal,
    /// or write — leaves the abort guard armed, so the client socket is reset
    /// rather than half-closed and the session is never served locally with
    /// consumed state. A successful transfer always produces immediate
    /// downlink (an owed KeyUpdate response, otherwise the response header and
    /// opening Vision frame), while every rejection closes the connection
    /// silently; the first landing byte is therefore awaited with a bounded
    /// deadline before the relay starts, and its absence — close, stall, or
    /// non-TLS bytes — is classified as rejection while every descriptor is
    /// still open, so the armed guard resets the client socket instead of
    /// FIN-ing it and the sockets, permits, and pipes release immediately.
    /// The client halves are reunited before the probe so the abortive close
    /// is not preceded by `OwnedWriteHalf`'s shutdown-on-drop FIN.
    async fn relay_via_handoff(
        &self,
        line: &super::handoff::HandoffLine,
        client_reader: TlsApplicationReader<OwnedReadHalf>,
        client_writer: TlsApplicationWriter<OwnedWriteHalf>,
        request: AcceptedVisionRequest,
        client_random: [u8; 32],
        inbound_tag: &str,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let AcceptedVisionRequest::Tcp {
            user_id,
            destination,
            buffer,
            prefetched,
        } = request
        else {
            return Err(VisionSessionError::Xudp(XudpSessionError::Outbound(
                crate::server::xudp::XudpOutboundUnsupported::Handoff,
            )));
        };
        let (pending, client_read_half, client_records) = client_reader.into_handoff_parts();
        let (client_write_half, server_records, key_update_response_pending) =
            client_writer.into_handoff_parts();
        // Phase one: the client socket is the only descriptor that exists, so
        // it is the only thing to reset. Its guard borrows the read half, so
        // the transfer below cannot consume or close the socket while the
        // guard could still fire.
        let (transferred, server_sequence) = {
            let mut client_abort = SocketAbortGuard::new(&client_read_half);
            let (suite, client_traffic_secret, client_sequence) = client_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let (_suite, server_traffic_secret, server_sequence) = server_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let prefetched = buffer.get(prefetched).unwrap_or_default().to_vec();
            let policy = HandoffPolicySnapshot::tcp_placeholder(destination.clone());
            let state = ContinuationState::new(
                suite,
                client_traffic_secret,
                client_sequence,
                server_traffic_secret,
                server_sequence,
                key_update_response_pending,
                SessionKind::Tcp,
                *user_id.as_bytes(),
                inbound_tag,
                destination,
                pending,
                prefetched,
                policy,
            )
            .map_err(HandoffLineError::Transfer)
            .map_err(VisionSessionError::HandoffLine)?;
            let transferred = line
                .transfer(self.relay.fd_budget(), &state, client_random)
                .await
                .map_err(VisionSessionError::HandoffLine)?;
            // The sealed continuation is on the wire; its generation secrets
            // must not live across the first-byte probe and session relay.
            drop(state);
            client_abort.disarm();
            (transferred, server_sequence)
        };
        // Declared before the stream so every error path closes the handoff
        // descriptor before its budget unit is released.
        let _fd_permit = transferred.1;
        let handoff_stream = transferred.0;
        // Reuniting consumes both client halves, so the landing descriptor —
        // which now exists and would otherwise leak a FIN — carries its own
        // guard across the only fallible step between the two phases.
        let client_stream =
            reunite_handoff_client(client_read_half, client_write_half, &handoff_stream)?;
        // Classify the silent protocol's only failure signal before any socket
        // moves into the relay: no TLS downlink byte within the configured
        // first-byte deadline means rejection. Both guards borrow their
        // sockets, so a rejection — or a cancellation inside the probe — resets
        // descriptors that are provably still open (SO_LINGER {on,0}); they
        // close as whole streams right after, delivering RST — never FIN — and
        // the session's descriptors, permits, and pipes are not held until the
        // idle timeout.
        let landed = {
            let mut landing_abort = SocketAbortGuard::new(&handoff_stream);
            let mut client_abort = SocketAbortGuard::new(&client_stream);
            let landed =
                super::handoff::first_downlink_landed(&handoff_stream, line.first_byte_timeout())
                    .await;
            if landed {
                // Ownership passes to the relay below, which owns abort
                // semantics for both sockets from here on.
                client_abort.disarm();
                landing_abort.disarm();
            }
            landed
        };
        if !landed {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        // The relay consumes both sockets: it aborts them itself on a
        // mid-transfer error, and on every return their descriptors are
        // already closed. No guard is armed here, so nothing can fire on what
        // another connection may have recycled those descriptor numbers into.
        let result = self
            .relay
            .relay_owned(
                client_stream,
                handoff_stream,
                // Both sockets carry the session's TLS records, whose own
                // close semantics LANDING and the client enforce; a teardown
                // reset from either side ends its direction like an EOF.
                RelayContext::owned()
                    .with_write_stall(self.io_timeout)
                    .with_source_reset_as_eof(),
            )
            .await;
        let outcome = result
            .map_err(HandoffLineError::Relay)
            .map_err(VisionSessionError::HandoffLine)?;
        // Backstop for the first-byte probe above: a completed relay that
        // moved zero downlink bytes still reads as a rejection.
        if outcome.outbound_to_inbound() == 0 {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        // The counts are raw ciphertext bytes moved by the splice, matching how
        // the Direct transition counts its raw phase.
        Ok(VisionRelayStats {
            uplink_bytes: outcome.inbound_to_outbound(),
            downlink_bytes: outcome.outbound_to_inbound(),
            relay_backend: Some(outcome.backend()),
            handoff_server_sequence: Some(server_sequence),
            pipe_capacity_downgraded: outcome.pipe_downgrade().is_some(),
            ..VisionRelayStats::default()
        })
    }

    /// Transfers one XUDP Vision session to a Handoff landing node.
    ///
    /// LINE never sends a client-visible Vision response; LANDING resumes TLS,
    /// writes the first success, owns UDP, and frames XUDP (ADR 0060). After a
    /// successful transfer this node only splices ciphertext.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit transfer boundary fields"
    )]
    async fn relay_via_handoff_xudp(
        &self,
        line: &super::handoff::HandoffLine,
        client_reader: TlsApplicationReader<OwnedReadHalf>,
        client_writer: TlsApplicationWriter<OwnedWriteHalf>,
        user_id: UserId,
        destination: Destination,
        inbound_tag: &str,
        outbound_tag: &str,
        prefetched_vision_wire: Vec<u8>,
        client_random: [u8; 32],
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let (pending, client_read_half, client_records) = client_reader.into_handoff_parts();
        let (client_write_half, server_records, key_update_response_pending) =
            client_writer.into_handoff_parts();
        let (transferred, server_sequence) = {
            let mut client_abort = SocketAbortGuard::new(&client_read_half);
            let (suite, client_traffic_secret, client_sequence) = client_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let (_suite, server_traffic_secret, server_sequence) = server_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let policy =
                self.routing
                    .seal_handoff_xudp_policy(user_id, outbound_tag, destination.clone());
            let state = ContinuationState::new(
                suite,
                client_traffic_secret,
                client_sequence,
                server_traffic_secret,
                server_sequence,
                key_update_response_pending,
                SessionKind::Xudp,
                *user_id.as_bytes(),
                inbound_tag,
                destination,
                pending,
                prefetched_vision_wire,
                policy,
            )
            .map_err(HandoffLineError::Transfer)
            .map_err(VisionSessionError::HandoffLine)?;
            let transferred = line
                .transfer(self.relay.fd_budget(), &state, client_random)
                .await
                .map_err(VisionSessionError::HandoffLine)?;
            drop(state);
            client_abort.disarm();
            (transferred, server_sequence)
        };
        let _fd_permit = transferred.1;
        let handoff_stream = transferred.0;
        let client_stream =
            reunite_handoff_client(client_read_half, client_write_half, &handoff_stream)?;
        let landed = {
            let mut landing_abort = SocketAbortGuard::new(&handoff_stream);
            let mut client_abort = SocketAbortGuard::new(&client_stream);
            let landed =
                super::handoff::first_downlink_landed(&handoff_stream, line.first_byte_timeout())
                    .await;
            if landed {
                client_abort.disarm();
                landing_abort.disarm();
            }
            landed
        };
        if !landed {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        let result = self
            .relay
            .relay_owned(
                client_stream,
                handoff_stream,
                RelayContext::owned()
                    .with_write_stall(self.io_timeout)
                    .with_source_reset_as_eof(),
            )
            .await;
        let outcome = result
            .map_err(HandoffLineError::Relay)
            .map_err(VisionSessionError::HandoffLine)?;
        if outcome.outbound_to_inbound() == 0 {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        Ok(VisionRelayStats {
            uplink_bytes: outcome.inbound_to_outbound(),
            downlink_bytes: outcome.outbound_to_inbound(),
            relay_backend: Some(outcome.backend()),
            handoff_server_sequence: Some(server_sequence),
            pipe_capacity_downgraded: outcome.pipe_downgrade().is_some(),
            ..VisionRelayStats::default()
        })
    }
}

#[cfg(test)]
mod tests;
