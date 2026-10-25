use std::{net::IpAddr, ops::Range, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    time::Instant,
};

use crate::protocol::{
    handoff::{ContinuationState, HandoffError, HandoffPolicySnapshot, SessionKind},
    reality::tls13::{
        IdleDeadline, MAX_PLAINTEXT_LEN, TlsApplicationIoError, TlsApplicationReader,
        TlsApplicationWriter, VectoredRead,
    },
    vless::{
        Command, DecodeError, Destination, RequestValidationError, UserId, VERSION,
        VISION_FRAME_SIZE, VisionCommand, VisionDecoder, VisionEncoder, VisionMode, VisionPayload,
        authorize_authenticated_vision_xudp, decode_request, decode_request_ref,
        validate_authenticated_vision_fields,
    },
};

use rr_session::{PairRendezvous, RendezvousStep};

use super::{
    direct::{
        DirectHandoff, Direction, DirectionState, InvalidTransition, RawDecision, RawRelayGrant,
    },
    handoff::HandoffLineError,
    outbound::{OutboundConnectOutcome, OutboundRegistry, SessionOutboundOutcome},
    reality::RealityEstablished,
    routing::{AssetMatcher, RoutingCompileError, RoutingTable},
    xudp::{
        XUDP_ASSOCIATION_IDLE, XudpDirectAssociation, XudpEgressCapability, XudpNxrAssociation,
        XudpSessionError, authorize_xudp_egress, drain_xudp_frames, process_xudp_global_map,
        require_direct_xudp_landward, require_handoff_xudp_landward, require_nxr_xudp_landward,
    },
};
use crate::config::node::entry::EntryConfig;
use crate::config::node::routing::DomainStrategy;
use crate::io_activity::{SESSION_IDLE_WINDOW, SessionActivity, WRITE_STALL_TIMEOUT};
use crate::runtime::policy::EffectivePolicy;
use crate::runtime::policy::ResourceGovernorPolicy;
use crate::transport::{DirectionalRelayContext, RelayContext, RelayDirection, TcpRelay};

mod nested;

#[cfg(feature = "fuzzing")]
pub use nested::fuzz_nested_tls_header_prefix;
pub(crate) use nested::{NestedRead, NestedRecordReader, NestedTlsDetector, PaddingDecision};

mod abort;

use abort::{AbortableSocket as _, DirectionAbortGuard, SocketAbortGuard};

mod error;

pub use error::VisionSessionError;
use error::{idle_failure, is_benign_teardown, operation_deadline};

mod stats;

pub use stats::VisionRelayStats;
use stats::{BoundaryBytes, DirectionStats, session_stats};

const MAX_REQUEST_HEADER_SIZE: usize = 533;
const MAX_REQUEST_BUFFER_SIZE: usize = MAX_REQUEST_HEADER_SIZE + MAX_PLAINTEXT_LEN;
const VISION_HEADER_SIZE: usize = 5;
const MAX_VISION_CONTENT_AFTER_FIRST_FRAME: usize = VISION_FRAME_SIZE - VISION_HEADER_SIZE;

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

    /// Authorize an XUDP New/Keep destination: canonical routing, DNS, egress class.
    ///
    /// Keep rewrites MUST call this again; a prior decision must not be inherited
    /// when the new destination routes to Block or another outbound. Returns a
    /// distinct [`XudpEgressCapability`] (Direct / NXR / Handoff), the resolved
    /// destination, and the outbound tag — never remaps NXR/Handoff to Direct
    /// (ADR 0060).
    pub(crate) async fn authorize_xudp_destination(
        &self,
        user_id: UserId,
        inbound_tag: &str,
        dest: &crate::protocol::vless::Destination,
    ) -> Result<
        (
            XudpEgressCapability,
            crate::protocol::vless::Destination,
            String,
        ),
        VisionSessionError,
    > {
        let route = self
            .routing
            .select_with_dns(
                user_id,
                inbound_tag,
                dest,
                self.dns_strategy,
                self.dns_timeout,
            )
            .await
            .map_err(VisionSessionError::Route)?;
        let outbound_tag = route.decision().outbound().to_owned();
        let capability = authorize_xudp_egress(self.outbounds.xudp_route_class(&outbound_tag))
            .map_err(|error| VisionSessionError::Xudp(XudpSessionError::Outbound(error)))?;
        let resolved = if let Some(ip) = route.resolved_ips().first().copied() {
            match ip {
                IpAddr::V4(v4) => crate::protocol::vless::Destination::new(
                    crate::protocol::vless::Address::Ipv4(v4),
                    dest.port(),
                ),
                IpAddr::V6(v6) => crate::protocol::vless::Destination::new(
                    crate::protocol::vless::Address::Ipv6(v6),
                    dest.port(),
                ),
            }
        } else {
            dest.clone()
        };
        Ok((capability, resolved, outbound_tag))
    }

    /// Serves one REALITY-authenticated Vision **XUDP** (Mux) session.
    ///
    /// XUDP frames ride inside Vision padding. Routing may authorize Direct or
    /// NXR (ADR 0060 Option A framed carrier). Handoff transfers TLS ownership
    /// to LANDING before any client-visible Vision response (ADR 0060 Option B);
    /// LINE never decrypts that session again after a successful transfer.
    /// Keep rewrites re-authorize; capability changes and Block fail closed
    /// with zero landward packets (no silent Direct fallback).
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit XUDP session boundary fields"
    )]
    async fn handle_xudp(
        &self,
        mut client_reader: TlsApplicationReader<OwnedReadHalf>,
        mut client_writer: TlsApplicationWriter<OwnedWriteHalf>,
        inbound_tag: &str,
        user_id: UserId,
        request_buffer: Vec<u8>,
        prefetched: Range<usize>,
        client_random: [u8; 32],
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let activity = Arc::new(SessionActivity::default());
        client_writer.set_activity(Arc::clone(&activity));

        let mut decoder = VisionDecoder::new(user_id);
        let mut encoder = VisionEncoder::new(user_id).map_err(VisionSessionError::VisionEncode)?;

        // Delay the Vision response until egress is known. For Handoff, LANDING
        // writes the first client-visible success after accepting the transfer.
        let response_header = [VERSION, 0];
        let mut response_sent = false;

        let mut vision_plaintext = Vec::new();
        // Vision wire bytes observed on LINE before transfer — LANDING re-decodes.
        let mut vision_wire_for_transfer = Vec::new();
        if let Some(initial) = request_buffer.get(prefetched)
            && !initial.is_empty()
        {
            vision_wire_for_transfer.extend_from_slice(initial);
            let mode = decoder
                .decode_append(initial, &mut vision_plaintext)
                .map_err(VisionSessionError::VisionDecode)?;
            if mode == VisionMode::Direct {
                return Err(VisionSessionError::Xudp(
                    XudpSessionError::UnexpectedVisionDirect,
                ));
            }
        }
        drop(request_buffer);

        let mut packets =
            drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;

        let mut association = None::<XudpLandwardAssociation>;
        let globals = process_xudp_global_map();
        let mut uplink_bytes = 0_u64;
        let mut downlink_bytes = 0_u64;

        loop {
            for packet in packets.drain(..) {
                let authorized = if let Some(dest) = packet.destination.as_ref() {
                    let (capability, resolved, outbound_tag) = self
                        .authorize_xudp_destination(user_id, inbound_tag, dest)
                        .await?;
                    Some((capability, resolved, outbound_tag, dest.clone()))
                } else {
                    None
                };
                if association.is_none() {
                    let (capability, bind_dest, outbound_tag, route_dest) =
                        authorized.clone().ok_or(VisionSessionError::Xudp(
                            XudpSessionError::MissingNewDestination,
                        ))?;
                    if capability == XudpEgressCapability::Handoff {
                        // LINE does not open landward UDP; transfer then splice.
                        // Seal the DNS-resolved destination so LANDING can bind
                        // UDP without re-resolving (domain addresses fail closed).
                        let outcome = self
                            .outbounds
                            .connect_session_resolved(&outbound_tag, &bind_dest, &[])
                            .await
                            .map_err(VisionSessionError::Outbound)?;
                        let SessionOutboundOutcome::Handoff(line) = outcome else {
                            return Err(VisionSessionError::Xudp(XudpSessionError::Outbound(
                                crate::server::xudp::XudpOutboundUnsupported::Handoff,
                            )));
                        };
                        let _ = route_dest;
                        // No client-visible success before LANDING accepts.
                        return self
                            .relay_via_handoff_xudp(
                                &line,
                                client_reader,
                                client_writer,
                                user_id,
                                bind_dest,
                                inbound_tag,
                                &outbound_tag,
                                vision_wire_for_transfer,
                                client_random,
                            )
                            .await;
                    }
                    if !response_sent {
                        let preamble = encoder
                            .plan(0, VisionCommand::Continue, true)
                            .map_err(VisionSessionError::VisionEncode)?;
                        let preamble_len = response_header
                            .len()
                            .checked_add(preamble.wire_len())
                            .ok_or(VisionSessionError::AllocationFailed)?;
                        client_writer
                            .write_assembled(
                                preamble_len,
                                |destination| {
                                    let Some((header, frame)) =
                                        destination.split_at_mut_checked(response_header.len())
                                    else {
                                        return;
                                    };
                                    header.copy_from_slice(&response_header);
                                    encoder.assemble(&preamble, &[], frame);
                                },
                                self.io_timeout,
                            )
                            .await
                            .map_err(VisionSessionError::Tls)?;
                        encoder.commit(&preamble);
                        response_sent = true;
                    }
                    let now = std::time::Instant::now();
                    let assoc = match capability {
                        XudpEgressCapability::Direct => {
                            require_direct_xudp_landward(capability).map_err(|error| {
                                VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                            })?;
                            XudpLandwardAssociation::Direct(
                                XudpDirectAssociation::open(
                                    &bind_dest,
                                    packet.global_id,
                                    *user_id.as_bytes(),
                                    globals,
                                    now,
                                    None,
                                )
                                .await
                                .map_err(VisionSessionError::Xudp)?,
                            )
                        }
                        XudpEgressCapability::Nxr => {
                            require_nxr_xudp_landward(capability).map_err(|error| {
                                VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                            })?;
                            XudpLandwardAssociation::Nxr(
                                XudpNxrAssociation::open(
                                    &self.outbounds,
                                    &outbound_tag,
                                    &bind_dest,
                                    *user_id.as_bytes(),
                                    packet.global_id,
                                    globals,
                                    now,
                                )
                                .await
                                .map_err(VisionSessionError::Xudp)?,
                            )
                        }
                        XudpEgressCapability::Handoff => {
                            unreachable!("Handoff transfers above before landward open")
                        }
                    };
                    association = Some(assoc);
                }
                if let Some(assoc) = association.as_mut() {
                    let now = std::time::Instant::now();
                    let resolved = if let Some((capability, resolved, _, _)) = authorized.as_ref() {
                        if *capability != assoc.capability() {
                            return Err(VisionSessionError::Xudp(
                                XudpSessionError::EgressCapabilityChanged,
                            ));
                        }
                        match capability {
                            XudpEgressCapability::Direct => {
                                require_direct_xudp_landward(*capability).map_err(|error| {
                                    VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                                })?;
                            }
                            XudpEgressCapability::Nxr => {
                                require_nxr_xudp_landward(*capability).map_err(|error| {
                                    VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                                })?;
                            }
                            XudpEgressCapability::Handoff => {
                                require_handoff_xudp_landward(*capability).map_err(|error| {
                                    VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                                })?;
                            }
                        }
                        Some(resolved.clone())
                    } else {
                        None
                    };
                    assoc
                        .handle_uplink_packet(&packet, resolved.as_ref(), now)
                        .await
                        .map_err(VisionSessionError::Xudp)?;
                    uplink_bytes = uplink_bytes.saturating_add(packet.payload.len() as u64);
                }
            }

            if association.is_some() {
                break;
            }

            let record = client_reader
                .read_application(self.request_timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            if record.is_empty() {
                continue;
            }
            vision_wire_for_transfer.extend_from_slice(record.plaintext());
            let (mode, payload) = decoder
                .decode_borrowed_append(record.plaintext(), &mut vision_plaintext)
                .map_err(VisionSessionError::VisionDecode)?;
            if let VisionPayload::Borrowed(content) = payload {
                vision_plaintext.extend_from_slice(content);
            }
            if mode == VisionMode::Direct {
                return Err(VisionSessionError::Xudp(
                    XudpSessionError::UnexpectedVisionDirect,
                ));
            }
            packets = drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;
        }

        let mut assoc = association.expect("opened above");
        let mut udp_buf = vec![0_u8; 64 * 1024];
        let mut downlink_frame = Vec::new();
        let mut vision_frame = Vec::new();
        let idle = XUDP_ASSOCIATION_IDLE;

        loop {
            tokio::select! {
                biased;
                record = client_reader.read_application(self.io_timeout) => {
                    match record {
                        Ok(record) => {
                            if record.is_empty() {
                                continue;
                            }
                            let (mode, payload) = decoder
                                .decode_borrowed_append(record.plaintext(), &mut vision_plaintext)
                                .map_err(VisionSessionError::VisionDecode)?;
                            if let VisionPayload::Borrowed(content) = payload {
                                vision_plaintext.extend_from_slice(content);
                            }
                            if mode == VisionMode::Direct {
                                break;
                            }
                            let more = drain_xudp_frames(&mut vision_plaintext)
                                .map_err(VisionSessionError::Xudp)?;
                            let now = std::time::Instant::now();
                            for packet in more {
                                let resolved = if let Some(dest) = packet.destination.as_ref() {
                                    let (capability, resolved, _) = self
                                        .authorize_xudp_destination(
                                            user_id,
                                            inbound_tag,
                                            dest,
                                        )
                                        .await?;
                                    if capability != assoc.capability() {
                                        return Err(VisionSessionError::Xudp(
                                            XudpSessionError::EgressCapabilityChanged,
                                        ));
                                    }
                                    match capability {
                                        XudpEgressCapability::Direct => {
                                            require_direct_xudp_landward(capability).map_err(
                                                |error| {
                                                    VisionSessionError::Xudp(
                                                        XudpSessionError::Outbound(error),
                                                    )
                                                },
                                            )?;
                                        }
                                        XudpEgressCapability::Nxr => {
                                            require_nxr_xudp_landward(capability).map_err(
                                                |error| {
                                                    VisionSessionError::Xudp(
                                                        XudpSessionError::Outbound(error),
                                                    )
                                                },
                                            )?;
                                        }
                                        XudpEgressCapability::Handoff => {
                                            require_handoff_xudp_landward(capability).map_err(
                                                |error| {
                                                    VisionSessionError::Xudp(
                                                        XudpSessionError::Outbound(error),
                                                    )
                                                },
                                            )?;
                                        }
                                    }
                                    Some(resolved)
                                } else {
                                    None
                                };
                                assoc
                                    .handle_uplink_packet(&packet, resolved.as_ref(), now)
                                    .await
                                    .map_err(VisionSessionError::Xudp)?;
                                uplink_bytes =
                                    uplink_bytes.saturating_add(packet.payload.len() as u64);
                            }
                            activity.progress();
                        }
                        Err(TlsApplicationIoError::PeerAlert { description: 0, .. }) => break,
                        Err(error) => return Err(VisionSessionError::Tls(error)),
                    }
                }
                recv = assoc.recv_downlink_frame(&mut udp_buf, &mut downlink_frame, std::time::Instant::now()) => {
                    let _ = recv.map_err(VisionSessionError::Xudp)?;
                    encoder
                        .encode(
                            &downlink_frame,
                            VisionCommand::Continue,
                            false,
                            &mut vision_frame,
                        )
                        .map_err(VisionSessionError::VisionEncode)?;
                    client_writer
                        .write_application(&vision_frame, self.io_timeout)
                        .await
                        .map_err(VisionSessionError::Tls)?;
                    downlink_bytes =
                        downlink_bytes.saturating_add(downlink_frame.len() as u64);
                    activity.progress();
                }
                () = activity.expired(idle) => {
                    break;
                }
            }
        }

        assoc.close(globals, std::time::Instant::now()).await;
        let _ = client_writer.shutdown(self.io_timeout).await;
        Ok(VisionRelayStats {
            uplink_bytes,
            downlink_bytes,
            ..VisionRelayStats::default()
        })
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

/// Keeps the landing carrier abortable until client socket ownership is whole.
fn reunite_handoff_client(
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    landing: &TcpStream,
) -> Result<TcpStream, VisionSessionError> {
    let mut landing_abort = SocketAbortGuard::new(landing);
    let client = reader
        .reunite(writer)
        .map_err(|_| VisionSessionError::HandoffLine(HandoffLineError::Reunite))?;
    // A guard's Drop changes the kernel socket option permanently. Disarm
    // this temporary guard before the first-downlink and relay guards take
    // over, so successful sessions retain normal FIN/half-close semantics.
    landing_abort.disarm();
    Ok(client)
}

enum AcceptedVisionRequest {
    /// Ordinary Vision TCP with a VLESS destination.
    Tcp {
        user_id: UserId,
        destination: Destination,
        /// The retained request buffer. Prefetched payload is a range inside it.
        buffer: Vec<u8>,
        prefetched: Range<usize>,
    },
    /// Vision XUDP (Mux command) — destination comes from the first XUDP New frame.
    Xudp {
        user_id: UserId,
        buffer: Vec<u8>,
        prefetched: Range<usize>,
    },
}

/// Runs the standard Vision relay for a session resumed from a Handoff
/// transfer on a landing node.
///
/// The resumed halves carry the transferred generation secrets and record
/// sequences, and the reader is preloaded with the read-ahead ciphertext the
/// previous owner had already consumed from the kernel, so the client-visible
/// record stream continues exactly at the boundary. `prefetched_plaintext`
/// enters the fresh Vision decoder before any decrypted record, mirroring the
/// freshly accepted path. An owed KeyUpdate response precedes application
/// output; otherwise the response header and opening Vision frame are the
/// first client-visible server record. The transfer preserves whether it is
/// sealed at sequence zero or, after a cover-shaped empty ApplicationData
/// record, one.
pub(crate) async fn run_resumed_session(
    client_reader: TlsApplicationReader<OwnedReadHalf>,
    client_writer: TlsApplicationWriter<OwnedWriteHalf>,
    destination: tokio::net::TcpStream,
    user_id: UserId,
    prefetched_plaintext: Vec<u8>,
    relay: &TcpRelay,
    timeout: Duration,
) -> Result<VisionRelayStats, VisionSessionError> {
    let (destination_reader, destination_writer) = destination.into_split();
    // The VLESS version is fixed and this implementation never negotiates
    // response Addons.
    let response_header = [crate::protocol::vless::VERSION, 0];
    let prefetched = 0..prefetched_plaintext.len();
    let handoff = DirectHandoff::new();
    let activity = Arc::new(SessionActivity::default());
    let context = SessionContext {
        activity: &activity,
        timeout,
        handoff: &handoff,
        relay,
    };
    let uplink = relay_uplink(
        client_reader,
        destination_writer,
        user_id,
        prefetched_plaintext,
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
    Ok(session_stats(uplink, downlink))
}

/// Resumes an XUDP Vision session on LANDING after a Handoff transfer.
///
/// TLS ownership, Vision framing, and UDP sockets live here. Destination
/// authorization uses the sealed [`HandoffPolicySnapshot`] (ADR 0060 Option B
/// foundation). PR4 serves the initial destination only (`allow_destination_rewrites
/// = false`); richer multi-destination sealed policy is PR5.
pub(crate) async fn run_resumed_xudp_session(
    mut client_reader: TlsApplicationReader<OwnedReadHalf>,
    mut client_writer: TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    prefetched_plaintext: Vec<u8>,
    policy: HandoffPolicySnapshot,
    timeout: Duration,
    udp_bind_ip: Option<std::net::IpAddr>,
) -> Result<VisionRelayStats, VisionSessionError> {
    let activity = Arc::new(SessionActivity::default());
    client_writer.set_activity(Arc::clone(&activity));

    let mut decoder = VisionDecoder::new(user_id);
    let mut encoder = VisionEncoder::new(user_id).map_err(VisionSessionError::VisionEncode)?;

    let response_header = [VERSION, 0];
    let preamble = encoder
        .plan(0, VisionCommand::Continue, true)
        .map_err(VisionSessionError::VisionEncode)?;
    let preamble_len = response_header
        .len()
        .checked_add(preamble.wire_len())
        .ok_or(VisionSessionError::AllocationFailed)?;
    client_writer
        .write_assembled(
            preamble_len,
            |destination| {
                let Some((header, frame)) = destination.split_at_mut_checked(response_header.len())
                else {
                    return;
                };
                header.copy_from_slice(&response_header);
                encoder.assemble(&preamble, &[], frame);
            },
            timeout,
        )
        .await
        .map_err(VisionSessionError::Tls)?;
    encoder.commit(&preamble);

    let mut vision_plaintext = Vec::new();
    if !prefetched_plaintext.is_empty() {
        let mode = decoder
            .decode_append(&prefetched_plaintext, &mut vision_plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        if mode == VisionMode::Direct {
            return Err(VisionSessionError::Xudp(
                XudpSessionError::UnexpectedVisionDirect,
            ));
        }
    }
    drop(prefetched_plaintext);

    let mut packets = drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;
    let mut association = None::<XudpDirectAssociation>;
    let globals = process_xudp_global_map();
    let mut uplink_bytes = 0_u64;
    let mut downlink_bytes = 0_u64;

    loop {
        for packet in packets.drain(..) {
            // First New: LINE already authorized transfer; dial the sealed
            // (DNS-resolved) initial destination. Later Keep rewrites must pass
            // the sealed policy snapshot (ordered rules + default outbound).
            let authorized = if association.is_none() {
                if packet.destination.is_none() {
                    return Err(VisionSessionError::Xudp(
                        XudpSessionError::MissingNewDestination,
                    ));
                }
                Some(policy.initial_destination().clone())
            } else if let Some(dest) = packet.destination.as_ref() {
                policy
                    .authorize_udp_destination(dest)
                    .map_err(|_| VisionSessionError::Xudp(XudpSessionError::UnauthorizedRewrite))?;
                Some(dest.clone())
            } else {
                None
            };
            if association.is_none() {
                let bind_dest = authorized.clone().expect("first New sets authorized");
                let now = std::time::Instant::now();
                association = Some(
                    XudpDirectAssociation::open(
                        &bind_dest,
                        packet.global_id,
                        *user_id.as_bytes(),
                        globals,
                        now,
                        udp_bind_ip,
                    )
                    .await
                    .map_err(VisionSessionError::Xudp)?,
                );
            }
            if let Some(assoc) = association.as_mut() {
                let now = std::time::Instant::now();
                assoc
                    .handle_uplink_packet(&packet, authorized.as_ref(), now)
                    .await
                    .map_err(VisionSessionError::Xudp)?;
                uplink_bytes = uplink_bytes.saturating_add(packet.payload.len() as u64);
            }
        }
        if association.is_some() {
            break;
        }
        let record = client_reader
            .read_application(timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        if record.is_empty() {
            continue;
        }
        let (mode, payload) = decoder
            .decode_borrowed_append(record.plaintext(), &mut vision_plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        if let VisionPayload::Borrowed(content) = payload {
            vision_plaintext.extend_from_slice(content);
        }
        if mode == VisionMode::Direct {
            return Err(VisionSessionError::Xudp(
                XudpSessionError::UnexpectedVisionDirect,
            ));
        }
        packets = drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;
    }

    let mut assoc = association.expect("opened above");
    let mut udp_buf = vec![0_u8; 64 * 1024];
    let mut downlink_frame = Vec::new();
    let mut vision_frame = Vec::new();
    let idle = XUDP_ASSOCIATION_IDLE;

    loop {
        tokio::select! {
            biased;
            record = client_reader.read_application(timeout) => {
                match record {
                    Ok(record) => {
                        if record.is_empty() {
                            continue;
                        }
                        let (mode, payload) = decoder
                            .decode_borrowed_append(record.plaintext(), &mut vision_plaintext)
                            .map_err(VisionSessionError::VisionDecode)?;
                        if let VisionPayload::Borrowed(content) = payload {
                            vision_plaintext.extend_from_slice(content);
                        }
                        if mode == VisionMode::Direct {
                            break;
                        }
                        let more = drain_xudp_frames(&mut vision_plaintext)
                            .map_err(VisionSessionError::Xudp)?;
                        let now = std::time::Instant::now();
                        for packet in more {
                            let authorized = if let Some(dest) = packet.destination.as_ref() {
                                policy
                                    .authorize_udp_destination(dest)
                                    .map_err(|_| {
                                        VisionSessionError::Xudp(
                                            XudpSessionError::UnauthorizedRewrite,
                                        )
                                    })?;
                                Some(dest.clone())
                            } else {
                                None
                            };
                            assoc
                                .handle_uplink_packet(&packet, authorized.as_ref(), now)
                                .await
                                .map_err(VisionSessionError::Xudp)?;
                            uplink_bytes =
                                uplink_bytes.saturating_add(packet.payload.len() as u64);
                        }
                        activity.progress();
                    }
                    Err(TlsApplicationIoError::PeerAlert { description: 0, .. }) => break,
                    Err(error) => return Err(VisionSessionError::Tls(error)),
                }
            }
            recv = assoc.recv_downlink_frame(&mut udp_buf, &mut downlink_frame, std::time::Instant::now()) => {
                let _ = recv.map_err(VisionSessionError::Xudp)?;
                encoder
                    .encode(
                        &downlink_frame,
                        VisionCommand::Continue,
                        false,
                        &mut vision_frame,
                    )
                    .map_err(VisionSessionError::VisionEncode)?;
                client_writer
                    .write_application(&vision_frame, timeout)
                    .await
                    .map_err(VisionSessionError::Tls)?;
                downlink_bytes =
                    downlink_bytes.saturating_add(downlink_frame.len() as u64);
                activity.progress();
            }
            () = activity.expired(idle) => {
                break;
            }
        }
    }

    assoc.close(globals, std::time::Instant::now());
    let _ = client_writer.shutdown(timeout).await;
    Ok(VisionRelayStats {
        uplink_bytes,
        downlink_bytes,
        ..VisionRelayStats::default()
    })
}

async fn join_directions(
    uplink: impl std::future::Future<Output = Result<DirectionStats, VisionSessionError>>,
    downlink: impl std::future::Future<Output = Result<DirectionStats, VisionSessionError>>,
    activity: &SessionActivity,
) -> Result<(DirectionStats, DirectionStats), VisionSessionError> {
    // A real EOF completes only its direction. Errors still cancel the pair
    // under the existing abort guards; quiet reads never manufacture an EOF.
    tokio::select! {
        biased;
        result = async { tokio::try_join!(uplink, downlink) } => result,
        () = activity.expired(SESSION_IDLE_WINDOW) => Err(VisionSessionError::Timeout),
    }
}

async fn read_vision_request<R>(
    reader: &mut TlsApplicationReader<R>,
    authenticated_user_id: UserId,
    timeout: Duration,
) -> Result<AcceptedVisionRequest, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let deadline = operation_deadline(timeout)?;
    // Small/setup-only sessions pay for the maximum header, not a speculative
    // full TLS record. A coalesced payload grows this same retained buffer on
    // demand and still stays under MAX_REQUEST_BUFFER_SIZE.
    let mut buffer = Vec::with_capacity(MAX_REQUEST_HEADER_SIZE);

    loop {
        match decode_request_ref(&buffer) {
            Ok(decoded) => {
                let payload_len = decoded.payload().len();
                let user_id = decoded.user_id();
                let command = decoded.command();
                let prefetched_start = buffer.len().saturating_sub(payload_len);
                let prefetched = prefetched_start..buffer.len();
                match command {
                    Command::Tcp => {
                        validate_authenticated_vision_fields(
                            user_id,
                            decoded.addons(),
                            command,
                            decoded.destination().is_some(),
                            authenticated_user_id,
                        )
                        .map_err(VisionSessionError::Validate)?;
                        let destination = decoded
                            .destination()
                            .map(|destination| destination.into_owned())
                            .ok_or(VisionSessionError::Validate(
                                RequestValidationError::MissingDestination,
                            ))?;
                        return Ok(AcceptedVisionRequest::Tcp {
                            user_id,
                            destination,
                            prefetched,
                            buffer,
                        });
                    }
                    Command::Mux => {
                        // Re-parse owned header for the shared XUDP authorizer.
                        let owned = decode_request(&buffer).map_err(VisionSessionError::Decode)?;
                        authorize_authenticated_vision_xudp(owned.header(), authenticated_user_id)
                            .map_err(VisionSessionError::Validate)?;
                        return Ok(AcceptedVisionRequest::Xudp {
                            user_id,
                            prefetched,
                            buffer,
                        });
                    }
                    other => {
                        return Err(VisionSessionError::Validate(
                            RequestValidationError::UnsupportedCommand(other),
                        ));
                    }
                }
            }
            Err(DecodeError::UnexpectedEnd { .. }) if buffer.len() < MAX_REQUEST_HEADER_SIZE => {}
            Err(DecodeError::UnexpectedEnd { .. }) => {
                return Err(VisionSessionError::RequestTooLarge {
                    limit: MAX_REQUEST_HEADER_SIZE,
                });
            }
            Err(error) => return Err(VisionSessionError::Decode(error)),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VisionSessionError::Timeout);
        }
        let record = reader
            .read_application(remaining)
            .await
            .map_err(VisionSessionError::Tls)?;
        let next_length =
            buffer
                .len()
                .checked_add(record.len())
                .ok_or(VisionSessionError::RequestTooLarge {
                    limit: MAX_REQUEST_BUFFER_SIZE,
                })?;
        if next_length > MAX_REQUEST_BUFFER_SIZE {
            return Err(VisionSessionError::RequestTooLarge {
                limit: MAX_REQUEST_BUFFER_SIZE,
            });
        }
        buffer
            .try_reserve(record.len())
            .map_err(|_| VisionSessionError::AllocationFailed)?;
        buffer.extend_from_slice(record.plaintext());
    }
}

/// Immutable per-session state shared by both relay directions.
///
/// Bundling these three keeps the direction entry points inside the repository's
/// argument-count lint without hiding anything: the coordinator and the relay
/// are borrowed, never cloned per connection.
struct SessionContext<'session> {
    activity: &'session Arc<SessionActivity>,
    timeout: Duration,
    handoff: &'session DirectHandoff,
    relay: &'session TcpRelay,
}

/// Owns the uplink sockets so the abort guard can only ever borrow live ones.
///
/// The framed loop borrows them; on error or cancellation the guard drops
/// first — the borrow checker guarantees it cannot outlive what it borrows —
/// and resets sockets that are still open. Only when the framed phase asks for
/// the Direct transition does ownership leave this frame, and by then the
/// guard is gone and the raw relay owns abort semantics.
async fn relay_uplink(
    mut client: TlsApplicationReader<OwnedReadHalf>,
    mut destination: OwnedWriteHalf,
    user_id: UserId,
    request_buffer: Vec<u8>,
    prefetched: Range<usize>,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    client.set_activity(Arc::clone(context.activity));
    let step = {
        let mut guard = DirectionAbortGuard::new(&mut client, &mut destination);
        let (client, destination) = guard.parts_mut();
        let step = relay_uplink_framed(
            client,
            destination,
            user_id,
            request_buffer,
            prefetched,
            context,
        )
        .await;
        if step.is_ok() {
            guard.disarm();
        }
        step
    };
    match step {
        Ok(UplinkStep::Framed(stats)) => Ok(stats),
        Ok(UplinkStep::Direct { bytes }) => {
            finish_uplink_direct(client, destination, bytes, context).await
        }
        Err(error) => {
            // The guard reset both sockets while they were provably live.
            // Release them without tokio's shutdown-on-drop so the abortive
            // close is not preceded by a FIN the peer would read as a clean
            // end of stream.
            client.release_aborted();
            destination.release_aborted();
            Err(error)
        }
    }
}

/// What the framed uplink phase decided.
enum UplinkStep {
    /// The direction finished inside the framed protocol.
    Framed(DirectionStats),
    /// An authenticated Direct boundary was reached after `bytes` framed bytes;
    /// the caller owns the sockets and performs the raw transfer.
    Direct { bytes: u64 },
}

async fn relay_uplink_framed(
    client: &mut TlsApplicationReader<OwnedReadHalf>,
    destination: &mut OwnedWriteHalf,
    user_id: UserId,
    request_buffer: Vec<u8>,
    prefetched: Range<usize>,
    context: &SessionContext<'_>,
) -> Result<UplinkStep, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let mut decoder = VisionDecoder::new(user_id);
    // Decoded uplink payloads are staged across records and leave in one
    // destination write per batch: Xray's Vision client emits one 8 KiB
    // frame per record, so an unbatched framed uplink costs one 8 KiB write
    // syscall per record while the batched downlink writes four records per
    // syscall. The staging buffer starts at one record payload and only a
    // completely-full staging buffer — evidence of a bulk flow — grows the
    // connection to the batched layout once, following the lazy-growth
    // discipline of the downlink's batched record storage; idle or
    // small-flow connections never pay the extra capacity.
    let mut stage = Vec::new();
    stage
        .try_reserve_exact(MAX_PLAINTEXT_LEN)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    let mut idle = IdleDeadline::new();
    idle.set_activity(Arc::clone(context.activity));
    let mut bytes = 0_u64;

    // The prefetched payload is a borrowed range inside the retained request
    // buffer. It is decoded before the record loop starts so that the loop below
    // never has to reconcile two different input lifetimes, and so that no copy
    // of the payload is ever made.
    if let Some(initial) = request_buffer.get(prefetched.clone())
        && !initial.is_empty()
    {
        let mode = decoder
            .decode_append(initial, &mut stage)
            .map_err(VisionSessionError::VisionDecode)?;
        flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
        if mode == VisionMode::Direct {
            // The caller owns the sockets and performs the transfer; the guard
            // it holds is disarmed on this `Ok`, so abort authority passes to
            // the raw relay with no window in which nobody owns it.
            return Ok(UplinkStep::Direct { bytes });
        }
    }
    drop(request_buffer);

    loop {
        // Flush before any read that could block: while a complete record is
        // still buffered the loop keeps batching, and a sparse flow never
        // waits behind staged bytes.
        if !client.has_buffered_record() {
            flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
        }
        let record = match client.read_application(timeout).await {
            Ok(record) => record,
            Err(TlsApplicationIoError::PeerAlert {
                level: _,
                description: 0,
            }) => {
                flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
                idle.reset(timeout).map_err(idle_failure)?;
                idle.shutdown(destination).await.map_err(idle_failure)?;
                settle(handoff, Direction::Uplink, DirectionState::Closed);
                return Ok(UplinkStep::Framed(DirectionStats::framed(bytes)));
            }
            Err(error) => {
                settle(handoff, Direction::Uplink, DirectionState::Failed);
                return Err(VisionSessionError::Tls(error));
            }
        };
        if record.is_empty() {
            continue;
        }
        if stage.len() + record.len() > stage.capacity() {
            flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
            // A completely-full staging buffer is bulk-flow evidence: grow to
            // the batched layout exactly once and never shrink back.
            if stage.capacity() < UPLINK_STAGE_CAPACITY {
                stage
                    .try_reserve_exact(UPLINK_STAGE_CAPACITY - stage.capacity())
                    .map_err(|_| VisionSessionError::AllocationFailed)?;
            }
        }
        let (mode, payload) = decoder
            .decode_borrowed_append(record.plaintext(), &mut stage)
            .map_err(VisionSessionError::VisionDecode)?;
        if let VisionPayload::Borrowed(content) = payload {
            // Raw-mode records join the batch as well: one bounded copy per
            // record replaces one destination write syscall per record. The
            // borrow of the record storage ends before the next read or the
            // socket handoff.
            stage.extend_from_slice(content);
        }
        if mode == VisionMode::Direct {
            // The decoded bytes precede every raw byte finish_uplink_direct
            // drains, so the staging buffer is flushed first; see the
            // prefetched branch above for the ownership handoff.
            flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
            return Ok(UplinkStep::Direct { bytes });
        }
    }
}

/// Capacity of the uplink staging buffer after a bulk flow grows it.
///
/// Four maximum-sized record payloads per destination write, mirroring the
/// downlink's four-slot batching (experiment D11).
const UPLINK_STAGE_CAPACITY: usize = 4 * MAX_PLAINTEXT_LEN;

/// Writes the staged uplink payloads to the destination in one operation.
///
/// Staged bytes are counted exactly once, when they are on the wire; the
/// staging buffer keeps its capacity across flushes. An empty staging buffer
/// costs no timer registration and no syscall.
async fn flush_uplink(
    stage: &mut Vec<u8>,
    destination: &mut OwnedWriteHalf,
    idle: &mut IdleDeadline,
    timeout: Duration,
    bytes: &mut u64,
) -> Result<(), VisionSessionError> {
    if stage.is_empty() {
        return Ok(());
    }
    idle.reset(timeout).map_err(idle_failure)?;
    idle.write_all(destination, stage.as_slice())
        .await
        .map_err(idle_failure)?;
    *bytes = bytes.saturating_add(length_u64(stage.len()));
    stage.clear();
    Ok(())
}

/// Relays the raw uplink after an authenticated Direct boundary.
///
/// Every decoded plaintext byte was already written to the destination in order
/// by the caller, so this direction is at the exact raw boundary. The buffered
/// reader behind `client` may already hold post-boundary raw bytes the client
/// pipelined after its boundary record; this is the re-derived equivalent of
/// Xray's input/rawInput drain: those pending bytes are written to the
/// destination first, so they arrive ahead of every byte any raw relay moves.
///
/// The direction then decides exactly once, after the bounded pair window
/// [`decide_raw_relay`]: when the peer is at its own raw boundary or already
/// committed to the pair, this direction deposits its halves for the bilateral
/// relay; otherwise it relays the direction independently. Neither branch ever
/// waits for the peer.
async fn finish_uplink_direct(
    client: TlsApplicationReader<OwnedReadHalf>,
    mut destination: OwnedWriteHalf,
    bytes: u64,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let handoff_started = Instant::now();
    handoff
        .advance(Direction::Uplink, DirectionState::DirectPending)
        .map_err(VisionSessionError::DirectTransition)?;

    // Drain first, then declare the raw boundary: the pending bytes precede
    // every byte the pair or directional relay will move.
    let (pending, raw_client) = client.into_inner_with_pending();
    if !pending.is_empty() {
        let mut idle = IdleDeadline::new();
        idle.set_activity(Arc::clone(context.activity));
        idle.reset(timeout).map_err(idle_failure)?;
        idle.write_all(&mut destination, &pending)
            .await
            .map_err(idle_failure)?;
    }
    let total = bytes.saturating_add(length_u64(pending.len()));
    handoff
        .advance(Direction::Uplink, DirectionState::RawReady)
        .map_err(VisionSessionError::DirectTransition)?;

    match decide_raw_relay(handoff, Direction::Uplink)
        .await
        .map_err(VisionSessionError::DirectTransition)?
        .into_decision()
    {
        RawDecision::Pair => {
            let recovered = handoff
                .deposit_uplink(raw_client, destination)
                .map_err(VisionSessionError::Handoff)?;
            run_handoff(
                context,
                Direction::Uplink,
                recovered,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
        RawDecision::Directional => {
            run_directional(
                context,
                Direction::Uplink,
                raw_client,
                destination,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
    }
}

/// Owns the downlink sockets so the abort guard can only ever borrow live ones.
///
/// The mirror of [`relay_uplink`]: the framed phase borrows, the guard cannot
/// outlive what it borrows, and ownership leaves this frame only for the
/// Direct transition, after the guard is gone.
async fn relay_downlink(
    destination: OwnedReadHalf,
    mut client: TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    response_header: &[u8],
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    client.set_activity(Arc::clone(context.activity));
    let mut nested = NestedRecordReader::new(destination);
    nested.idle.set_activity(Arc::clone(context.activity));
    let step = {
        let mut guard = DirectionAbortGuard::new(&mut client, &mut nested);
        let (client, destination) = guard.parts_mut();
        let step =
            relay_downlink_framed(destination, client, user_id, response_header, context).await;
        if step.is_ok() {
            guard.disarm();
        }
        step
    };
    match step {
        Ok(DownlinkStep::Framed(stats)) => Ok(stats),
        Ok(DownlinkStep::Direct { bytes }) => {
            finish_downlink_direct(nested, client, bytes, context).await
        }
        Err(error) => {
            // See `relay_uplink`: the reset is already armed, and this is what
            // keeps a FIN from reaching the peer ahead of it.
            client.release_aborted();
            nested.release_aborted();
            Err(error)
        }
    }
}

/// What the framed downlink phase decided.
enum DownlinkStep {
    /// The direction finished inside the framed protocol.
    Framed(DirectionStats),
    /// An authenticated Direct boundary was reached after `bytes` framed bytes;
    /// the caller owns the sockets and performs the raw transfer.
    Direct { bytes: u64 },
}

async fn relay_downlink_framed(
    destination: &mut NestedRecordReader,
    client: &mut TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    response_header: &[u8],
    context: &SessionContext<'_>,
) -> Result<DownlinkStep, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let mut encoder = VisionEncoder::new(user_id).map_err(VisionSessionError::VisionEncode)?;
    // The VLESS response header and the opening Vision frame are assembled once,
    // directly inside the final AEAD plaintext region.
    let preamble = encoder
        .plan(0, VisionCommand::Continue, true)
        .map_err(VisionSessionError::VisionEncode)?;
    let preamble_len = response_header
        .len()
        .checked_add(preamble.wire_len())
        .ok_or(VisionSessionError::AllocationFailed)?;
    client
        .write_assembled(
            preamble_len,
            |destination| {
                let Some((header, frame)) = destination.split_at_mut_checked(response_header.len())
                else {
                    return;
                };
                header.copy_from_slice(response_header);
                encoder.assemble(&preamble, &[], frame);
            },
            timeout,
        )
        .await
        .map_err(VisionSessionError::Tls)?;
    encoder.commit(&preamble);

    let mut detector = NestedTlsDetector::new();
    let mut bytes = 0_u64;
    loop {
        match destination.next(timeout).await? {
            NestedRead::Eof => {
                client
                    .shutdown(timeout)
                    .await
                    .map_err(VisionSessionError::Tls)?;
                settle(handoff, Direction::Downlink, DirectionState::Closed);
                return Ok(DownlinkStep::Framed(DirectionStats::framed(bytes)));
            }
            NestedRead::Unframed(content) => {
                bytes = bytes.saturating_add(length_u64(content.len()));
                write_vision_content(
                    client,
                    &mut encoder,
                    content,
                    VisionCommand::End,
                    false,
                    timeout,
                )
                .await?;
                settle(handoff, Direction::Downlink, DirectionState::Outer);
                bytes =
                    bytes.saturating_add(relay_outer_downlink(destination, client, timeout).await?);
                settle(handoff, Direction::Downlink, DirectionState::Closed);
                return Ok(DownlinkStep::Framed(DirectionStats::framed(bytes)));
            }
            NestedRead::Record(record) => {
                bytes = bytes.saturating_add(length_u64(record.len()));
                let decision = detector.observe(record);
                let command = match decision {
                    PaddingDecision::Continue => VisionCommand::Continue,
                    PaddingDecision::End => VisionCommand::End,
                    PaddingDecision::Direct => VisionCommand::Direct,
                };
                write_vision_content(client, &mut encoder, record, command, true, timeout).await?;

                match decision {
                    PaddingDecision::Continue => {}
                    PaddingDecision::End => {
                        settle(handoff, Direction::Downlink, DirectionState::Outer);
                        bytes = bytes.saturating_add(
                            relay_outer_downlink(destination, client, timeout).await?,
                        );
                        settle(handoff, Direction::Downlink, DirectionState::Closed);
                        return Ok(DownlinkStep::Framed(DirectionStats::framed(bytes)));
                    }
                    PaddingDecision::Direct => {
                        // The caller owns the sockets and performs the
                        // transfer; the guard it holds is disarmed on this
                        // `Ok`, so abort authority passes to the raw relay
                        // with no window in which nobody owns it.
                        return Ok(DownlinkStep::Direct { bytes });
                    }
                }
            }
        }
    }
}

/// Upper bound of Vision frames packed into one outer TLS record.
///
/// Full content chunks are `MAX_VISION_CONTENT_AFTER_FIRST_FRAME` bytes, so at
/// most two full frames ever fit one maximum-sized record; the constant only
/// bounds the on-stack plan storage, never the wire image.
const MAX_FRAMES_PER_OUTER_RECORD: usize = 4;

async fn write_vision_content<W>(
    writer: &mut TlsApplicationWriter<W>,
    encoder: &mut VisionEncoder,
    content: &[u8],
    final_command: VisionCommand,
    long_padding: bool,
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    if content.is_empty() {
        return write_vision_frame(writer, encoder, &[], final_command, long_padding, timeout)
            .await;
    }

    let chunk_count = content.len().div_ceil(MAX_VISION_CONTENT_AFTER_FIRST_FRAME);
    let mut index = 0;
    while index < chunk_count {
        // Pack as many complete frames as fit one maximum-sized outer record.
        // Every frame stays a complete Xray padding block, so the plaintext
        // byte stream a client decoder sees is identical; only the outer
        // record boundaries move, which TLS explicitly does not preserve.
        let mut plans = [None; MAX_FRAMES_PER_OUTER_RECORD];
        let mut ranges = [(0_usize, 0_usize); MAX_FRAMES_PER_OUTER_RECORD];
        let mut wire_len = 0_usize;
        let mut packed = 0_usize;
        while packed < MAX_FRAMES_PER_OUTER_RECORD && index + packed < chunk_count {
            let start = (index + packed) * MAX_VISION_CONTENT_AFTER_FIRST_FRAME;
            let end = content
                .len()
                .min(start + MAX_VISION_CONTENT_AFTER_FIRST_FRAME);
            let command = if index + packed + 1 == chunk_count {
                final_command
            } else {
                VisionCommand::Continue
            };
            let Some(plan) = encoder
                .plan_within(
                    end - start,
                    command,
                    long_padding,
                    MAX_PLAINTEXT_LEN - wire_len,
                )
                .map_err(VisionSessionError::VisionEncode)?
            else {
                break;
            };
            wire_len = wire_len.saturating_add(plan.wire_len());
            plans[packed] = Some(plan);
            ranges[packed] = (start, end);
            packed += 1;
        }
        writer
            .write_assembled(
                wire_len,
                |destination| {
                    let mut cursor = 0;
                    for slot in 0..packed {
                        let Some(plan) = plans[slot] else {
                            continue;
                        };
                        let (start, end) = ranges[slot];
                        let Some(frame) = destination.get_mut(cursor..cursor + plan.wire_len())
                        else {
                            return;
                        };
                        let Some(chunk) = content.get(start..end) else {
                            return;
                        };
                        encoder.assemble(&plan, chunk, frame);
                        cursor += plan.wire_len();
                    }
                },
                timeout,
            )
            .await
            .map_err(VisionSessionError::Tls)?;
        for plan in plans.iter().take(packed).flatten() {
            encoder.commit(plan);
        }
        index += packed;
    }
    Ok(())
}

/// Relays the raw downlink after an authenticated Direct boundary.
///
/// The Direct-carrying Vision frame has already been sealed and written to the
/// client, so this direction is at its exact raw boundary. Starting the raw
/// relay only after that final framed write has fully completed is the ordering
/// Xray commit f926ee4a protects: a splice that raced the frame would
/// interleave raw bytes with framed ciphertext. The buffered nested reader may
/// already hold post-boundary raw bytes the destination pipelined after its
/// boundary record; like the uplink drain (the re-derived equivalent of Xray's
/// input/rawInput handling) those pending bytes are written to the client
/// first, ahead of every byte any raw relay moves.
///
/// The direction then decides exactly once, after the bounded pair window
/// [`decide_raw_relay`]: when the peer is at its own raw boundary or already
/// committed to the pair, this direction deposits its halves for the bilateral
/// relay; otherwise it relays the direction independently. Neither branch ever
/// waits for the peer.
async fn finish_downlink_direct(
    destination: NestedRecordReader,
    client: TlsApplicationWriter<OwnedWriteHalf>,
    bytes: u64,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let handoff_started = Instant::now();
    handoff
        .advance(Direction::Downlink, DirectionState::DirectPending)
        .map_err(VisionSessionError::DirectTransition)?;

    // Drain first, then declare the raw boundary: the pending bytes precede
    // every byte the pair or directional relay will move.
    let (pending, raw_destination) = destination.into_inner_with_pending();
    let mut raw_client = client.into_inner();
    if !pending.is_empty() {
        let mut idle = IdleDeadline::new();
        idle.set_activity(Arc::clone(context.activity));
        idle.reset(timeout).map_err(idle_failure)?;
        idle.write_all(&mut raw_client, &pending)
            .await
            .map_err(idle_failure)?;
    }
    let total = bytes.saturating_add(length_u64(pending.len()));
    handoff
        .advance(Direction::Downlink, DirectionState::RawReady)
        .map_err(VisionSessionError::DirectTransition)?;

    match decide_raw_relay(handoff, Direction::Downlink)
        .await
        .map_err(VisionSessionError::DirectTransition)?
        .into_decision()
    {
        RawDecision::Pair => {
            let recovered = handoff
                .deposit_downlink(raw_destination, raw_client)
                .map_err(VisionSessionError::Handoff)?;
            run_handoff(
                context,
                Direction::Downlink,
                recovered,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
        RawDecision::Directional => {
            run_directional(
                context,
                Direction::Downlink,
                raw_destination,
                raw_client,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
    }
}

/// Runs one independent directional raw relay at a Direct boundary.
///
/// A benign peer-teardown race (`BrokenPipe`, `ConnectionReset`, or the raw
/// stage's idle-policy `TimedOut` on an untouched ledger) closes the
/// direction cleanly with its accumulated stats instead of failing the whole
/// session; a write_stall timeout after bytes moved aborts both sockets and
/// arrives as `ConnectionAborted`, failing the session. Errors from the
/// framed and authentication phases never reach here.
async fn run_directional(
    context: &SessionContext<'_>,
    direction: Direction,
    source: OwnedReadHalf,
    destination: OwnedWriteHalf,
    bytes: BoundaryBytes,
    handoff_started: Instant,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout,
        handoff,
        relay,
        ..
    } = *context;
    let delay_us = micros(handoff_started.elapsed());
    let relay_direction = match direction {
        Direction::Uplink => RelayDirection::Uplink,
        Direction::Downlink => RelayDirection::Downlink,
    };
    match relay
        .relay_direction(
            source,
            destination,
            relay_direction,
            DirectionalRelayContext::owned_direction()
                .with_write_stall(timeout)
                .with_activity(Arc::clone(context.activity)),
        )
        .await
    {
        Ok(outcome) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total.saturating_add(outcome.bytes()),
                None,
                Some(outcome.backend()),
                bytes.direct_at,
                delay_us,
                outcome.pipe_downgrade().is_some(),
            ))
        }
        Err(error) if is_benign_teardown(&error) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total,
                None,
                None,
                bytes.direct_at,
                delay_us,
                false,
            ))
        }
        Err(error) => {
            settle(handoff, direction, DirectionState::Failed);
            Err(VisionSessionError::Relay(error))
        }
    }
}

/// Runs the unified relay when this direction deposited its sockets last.
///
/// A `None` deposit means the peer direction still holds one half pair; that
/// peer becomes the last depositor and runs the relay instead. Exactly one of
/// the two directions therefore ever drives the raw relay. The first depositor
/// deliberately remains in `PairPending` rather than transitioning `Closed`:
/// a peer still inside its pair window must keep observing a pairable state
/// until it deposits — transitioning `Closed` here would strand the deposited
/// halves with no runner. The coordinator is per-session, so the lingering
/// state is dropped with it.
async fn run_handoff(
    context: &SessionContext<'_>,
    direction: Direction,
    recovered: Option<super::direct::RecoveredSockets>,
    bytes: BoundaryBytes,
    handoff_started: Instant,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout,
        handoff,
        relay,
        ..
    } = *context;
    let delay_us = micros(handoff_started.elapsed());
    let Some(sockets) = recovered else {
        return Ok(DirectionStats::direct(
            bytes.total,
            None,
            None,
            bytes.direct_at,
            delay_us,
            false,
        ));
    };
    match relay
        .relay_owned(
            sockets.client,
            sockets.destination,
            RelayContext::owned()
                .with_write_stall(timeout)
                .with_activity(Arc::clone(context.activity)),
        )
        .await
    {
        Ok(outcome) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total,
                Some(outcome),
                Some(outcome.backend()),
                bytes.direct_at,
                delay_us,
                outcome.pipe_downgrade().is_some(),
            ))
        }
        Err(error) if is_benign_teardown(&error) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total,
                None,
                None,
                bytes.direct_at,
                delay_us,
                false,
            ))
        }
        Err(error) => {
            settle(handoff, direction, DirectionState::Failed);
            Err(VisionSessionError::Relay(error))
        }
    }
}

/// Converts a duration to microseconds, saturating at the representable bound.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Records a terminal direction state without masking the original failure.
///
/// A rejected transition here means the direction was already terminal, which is
/// not itself an error worth replacing the real cause with.
fn settle(handoff: &DirectHandoff, direction: Direction, state: DirectionState) {
    let _ignored = handoff.advance(direction, state);
}

/// Gives the peer a bounded chance to reach a pairable state, then commits.
///
/// This is the Runtime Adapter shape: the adapter observes shared state, the
/// Session Engine decides, the adapter performs the OS or executor operation.
/// [`PairRendezvous`] owns the policy — how many cooperative scheduling points
/// may be spent and when to stop observing — and this function owns only the
/// `yield_now` that the policy asks for. Never a sleep, a timer, or a wait on
/// the peer, so no direction depends on its peer for write_stall.
///
/// The commit itself is the mutex-serialized [`DirectHandoff::decide`]: the peer
/// read and the state transition are one critical section, so the two directions
/// can never disagree about the relay form — a peer that observed `RawReady` or
/// `PairPending` pairs, and a peer that observed `Relaying` relays
/// directionally, with no interleaving in between.
async fn decide_raw_relay(
    handoff: &DirectHandoff,
    direction: Direction,
) -> Result<RawRelayGrant, InvalidTransition> {
    let mut rendezvous = PairRendezvous::new();
    while rendezvous.step(handoff.peer_can_pair(direction)) == RendezvousStep::Yield {
        tokio::task::yield_now().await;
    }
    handoff.decide(direction)
}

/// Writes exactly one Vision frame straight into the final TLS AEAD plaintext.
///
/// No intermediate frame buffer exists: the frame is planned, the record layer
/// reserves the plaintext region inside the writer's retained ciphertext buffer,
/// and the encoder assembles UUID, header, content and padding in place.
async fn write_vision_frame<W>(
    writer: &mut TlsApplicationWriter<W>,
    encoder: &mut VisionEncoder,
    content: &[u8],
    command: VisionCommand,
    long_padding: bool,
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    let plan = encoder
        .plan(content.len(), command, long_padding)
        .map_err(VisionSessionError::VisionEncode)?;
    writer
        .write_assembled(
            plan.wire_len(),
            |frame| encoder.assemble(&plan, content, frame),
            timeout,
        )
        .await
        .map_err(VisionSessionError::Tls)?;
    encoder.commit(&plan);
    Ok(())
}

async fn relay_outer_downlink<R, W>(
    reader: &mut R,
    writer: &mut TlsApplicationWriter<W>,
    timeout: Duration,
) -> Result<u64, VisionSessionError>
where
    R: VectoredRead,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    loop {
        // The batched variant (experiment D11) lands one vectored destination
        // read in the plaintext regions of up to four record slots of the
        // connection's grow-only buffer, seals each filled slot in place, and
        // writes the contiguous sealed prefix with one write: no scratch
        // buffer and no per-chunk copy exist on this path, and a full batch
        // costs one read plus one write syscall instead of one per record.
        let read = writer
            .write_application_read_from_batched(reader, timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        if read == 0 {
            writer
                .shutdown(timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(copied);
        }
        copied = copied.saturating_add(length_u64(read));
    }
}

fn length_u64(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// Landward owner for one XUDP association (Direct local UDP or NXR carrier).
enum XudpLandwardAssociation {
    Direct(XudpDirectAssociation),
    Nxr(XudpNxrAssociation),
}

impl XudpLandwardAssociation {
    const fn capability(&self) -> XudpEgressCapability {
        match self {
            Self::Direct(_) => XudpEgressCapability::Direct,
            Self::Nxr(_) => XudpEgressCapability::Nxr,
        }
    }

    async fn handle_uplink_packet(
        &mut self,
        packet: &crate::protocol::vless::XudpPacket,
        authorized_destination: Option<&crate::protocol::vless::Destination>,
        now: std::time::Instant,
    ) -> Result<(), XudpSessionError> {
        match self {
            Self::Direct(assoc) => {
                assoc
                    .handle_uplink_packet(packet, authorized_destination, now)
                    .await
            }
            Self::Nxr(assoc) => {
                assoc
                    .handle_uplink_packet(packet, authorized_destination, now)
                    .await
            }
        }
    }

    async fn recv_downlink_frame(
        &mut self,
        buf: &mut [u8],
        output: &mut Vec<u8>,
        now: std::time::Instant,
    ) -> Result<usize, XudpSessionError> {
        match self {
            Self::Direct(assoc) => assoc.recv_downlink_frame(buf, output, now).await,
            Self::Nxr(assoc) => assoc.recv_downlink_frame(buf, output, now).await,
        }
    }

    async fn close(self, globals: &crate::server::xudp::XudpGlobalMap, now: std::time::Instant) {
        match self {
            Self::Direct(assoc) => assoc.close(globals, now),
            Self::Nxr(assoc) => assoc.close(globals, now).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::runtime::policy::{DirectBarrierPolicy, ResourceGovernorPolicy};
    use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Instant, timeout},
    };

    use super::{
        BoundaryBytes, NestedTlsDetector, PaddingDecision, SessionContext, VisionHandler,
        VisionSessionError, is_benign_teardown, length_u64, run_directional,
    };
    use crate::{
        config::node::{routing::RoutingConfig, user::UserConfig},
        protocol::{
            reality::tls13::{
                CipherSuite, ContentType, EstablishedTls, Tls13RecordLayer, TlsApplicationIo,
                TrafficSecret, read_tls_record,
            },
            vless::{
                Command, UserId, VERSION, VISION_FLOW, VISION_FRAME_SIZE, VisionCommand,
                VisionDecoder, VisionEncoder, VisionMode,
            },
        },
        server::{
            direct::{DirectHandoff, Direction},
            outbound::OutboundRegistry,
            reality::RealityEstablished,
            routing::{EmptyAssetMatcher, RoutingTable},
        },
        transport::{FdBudget, RelayBackend, TcpRelay, TcpRelayConfig},
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);
    const USER: UserId = UserId::new([0x33; 16]);

    #[tokio::test(flavor = "current_thread")]
    async fn successful_handoff_reunite_preserves_graceful_carrier_close() {
        let (client, _client_peer) = tcp_pair().await;
        let (landing, mut landing_peer) = tcp_pair().await;
        let (reader, writer) = client.into_split();
        let _client = super::reunite_handoff_client(reader, writer, &landing)
            .expect("matching client halves must reunite");
        drop(landing);
        let mut byte = [0_u8; 1];
        let read = timeout(TEST_TIMEOUT, landing_peer.read(&mut byte))
            .await
            .expect("carrier close must be observable")
            .expect("successful reunification must not arm an abortive carrier close");
        assert_eq!(read, 0, "healthy carrier teardown must deliver FIN");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_handoff_reunite_still_aborts_carrier() {
        let (first, _first_peer) = tcp_pair().await;
        let (second, _second_peer) = tcp_pair().await;
        let (landing, mut landing_peer) = tcp_pair().await;
        let (reader, _first_writer) = first.into_split();
        let (_second_reader, writer) = second.into_split();
        let error = super::reunite_handoff_client(reader, writer, &landing)
            .expect_err("unrelated client halves must fail closed");
        assert!(matches!(
            error,
            VisionSessionError::HandoffLine(super::HandoffLineError::Reunite)
        ));
        drop(landing);
        let mut byte = [0_u8; 1];
        let error = timeout(TEST_TIMEOUT, landing_peer.read(&mut byte))
            .await
            .expect("carrier abort must be observable")
            .expect_err("failed reunification must reset the carrier");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resumed_framed_session_survives_both_asymmetries_and_sparse_alternation() {
        let (mut client, inbound) = tcp_pair().await;
        let (destination, mut target) = tcp_pair().await;
        let (tls, mut client_write, mut client_read) = tls_states();
        let (reader, writer) = TlsApplicationIo::new(inbound, tls).into_owned_split();
        let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096)).expect("relay");
        let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
        let mut initial = Vec::new();
        encoder
            .encode(b"request", VisionCommand::Continue, false, &mut initial)
            .expect("initial frame");
        let session = super::run_resumed_session(
            reader,
            writer,
            destination,
            USER,
            initial,
            &relay,
            Duration::from_millis(20),
        );
        let traffic = async {
            let mut request = [0; 7];
            target.read_exact(&mut request).await?;
            assert_eq!(&request, b"request");
            let mut decoder = VisionDecoder::new(USER);
            let mut first = true;
            let mut decoded = Vec::new();
            let mut wire = Vec::new();
            for phase in 0..3 {
                for tick in 0..8 {
                    // The successful receive synchronizes each progress event.
                    // One direction is silent for 120ms with a 20ms old window.
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    if phase == 1 || (phase == 2 && tick % 2 == 0) {
                        let mut frame = Vec::new();
                        encoder
                            .encode(b"U", VisionCommand::Continue, false, &mut frame)
                            .map_err(io::Error::other)?;
                        wire.clear();
                        client_write
                            .seal_into(ContentType::ApplicationData, &frame, 0, &mut wire)
                            .map_err(io::Error::other)?;
                        client.write_all(&wire).await?;
                        let mut byte = [0];
                        target.read_exact(&mut byte).await?;
                        assert_eq!(&byte, b"U");
                    } else {
                        // The origin remains open and waits for receipt before
                        // its next write: short replies must not wait for FIN.
                        target.write_all(b"ack").await?;
                        let mut response = Vec::new();
                        while response.len() < 3 {
                            let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                                .await
                                .map_err(io::Error::other)?
                                .into_wire();
                            let opened = client_read
                                .open_in_place(&mut record)
                                .map_err(io::Error::other)?;
                            let payload = if first {
                                first = false;
                                &opened.plaintext()[2..]
                            } else {
                                opened.plaintext()
                            };
                            decoder
                                .decode(payload, &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        assert_eq!(response, b"ack");
                    }
                }
            }
            wire.clear();
            client_write
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
                .map_err(io::Error::other)?;
            client.write_all(&wire).await?;
            assert_eq!(target.read(&mut [0]).await?, 0, "uplink FIN");
            // A framed half-close also permits delayed downlink draining.
            tokio::time::sleep(Duration::from_millis(80)).await;
            target.write_all(b"tail!").await?;
            target.shutdown().await?;
            let mut tail = Vec::new();
            loop {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                if opened.content_type() == ContentType::Alert {
                    assert_eq!(opened.plaintext(), &[1, 0]);
                    break;
                }
                decoder
                    .decode(opened.plaintext(), &mut decoded)
                    .map_err(io::Error::other)?;
                tail.extend_from_slice(&decoded);
            }
            assert_eq!(tail, b"tail!");
            Ok::<_, io::Error>(())
        };
        let (stats, traffic) = timeout(TEST_TIMEOUT, async { tokio::join!(session, traffic) })
            .await
            .expect("bounded regression");
        traffic.expect("both directions remain byte-exact");
        let stats = stats.expect("healthy asymmetric session");
        assert_eq!(stats.uplink_bytes(), 19);
        assert_eq!(stats.downlink_bytes(), 41);
        assert!(!stats.uplink_direct());
        assert!(!stats.downlink_direct());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relays_non_tls_vision_session_inside_reality_records() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request(destination_address.port(), b"ping");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                let mut response_header = true;
                loop {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    match opened.content_type() {
                        ContentType::ApplicationData => {
                            let plaintext = opened.plaintext();
                            let vision = if response_header {
                                response_header = false;
                                if plaintext.get(..2) != Some([VERSION, 0].as_slice()) {
                                    return Err(io::Error::other("invalid VLESS response header"));
                                }
                                &plaintext[2..]
                            } else {
                                plaintext
                            };
                            let _ = decoder
                                .decode(vision, &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        ContentType::Alert if opened.plaintext() == [1, 0] => break,
                        _ => return Err(io::Error::other("unexpected outer TLS content")),
                    }
                }
                Ok::<_, io::Error>((response, decoder.mode()))
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(b"pong").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("Vision exchange must not time out");
        let stats = stats.expect("Vision handler must succeed");
        let (response, mode) = client_result.expect("client I/O must succeed");

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping"
        );
        assert_eq!(response, b"pong");
        assert_eq!(mode, VisionMode::Raw);
        assert_eq!(stats.uplink_bytes(), 4);
        assert_eq!(stats.downlink_bytes(), 4);
        assert!(!stats.uplink_direct());
        assert!(!stats.downlink_direct());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn switches_both_directions_only_after_authenticated_direct_boundaries() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request_with_command(
            destination_address.port(),
            b"up-framed",
            VisionCommand::Direct,
        );
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        let nested_application = record(23, b"encrypted-handshake");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                client.write_all(b"up-raw").await?;
                client.shutdown().await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut framed_response = Vec::new();
                let mut response_header = true;
                while decoder.mode() != VisionMode::Direct {
                    let mut outer_record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut outer_record)
                        .map_err(io::Error::other)?;
                    if opened.content_type() != ContentType::ApplicationData {
                        return Err(io::Error::other("expected outer application record"));
                    }
                    let plaintext = opened.plaintext();
                    let vision = if response_header {
                        response_header = false;
                        if plaintext.get(..2) != Some([VERSION, 0].as_slice()) {
                            return Err(io::Error::other("invalid VLESS response header"));
                        }
                        &plaintext[2..]
                    } else {
                        plaintext
                    };
                    let _ = decoder
                        .decode(vision, &mut decoded)
                        .map_err(io::Error::other)?;
                    framed_response.extend_from_slice(&decoded);
                }
                let mut raw_response = Vec::new();
                client.read_to_end(&mut raw_response).await?;
                Ok::<_, io::Error>((framed_response, raw_response))
            };
            let server_hello = nested_server_hello.clone();
            let application = nested_application.clone();
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(&server_hello).await?;
                destination.write_all(&application).await?;
                destination.write_all(b"down-raw").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("direct Vision exchange must not time out");
        let stats = stats.expect("direct Vision handler must succeed");
        let (framed_response, raw_response) = client_result.expect("client I/O must succeed");
        let mut expected_framed = nested_server_hello;
        expected_framed.extend_from_slice(&nested_application);

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"up-framedup-raw"
        );
        assert_eq!(framed_response, expected_framed);
        assert_eq!(raw_response, b"down-raw");
        assert_eq!(
            stats.uplink_bytes(),
            length_u64(b"up-framed".len() + b"up-raw".len())
        );
        assert_eq!(
            stats.downlink_bytes(),
            length_u64(expected_framed.len() + b"down-raw".len())
        );
        assert!(stats.uplink_direct());
        assert!(stats.downlink_direct());
        // The uplink reaches its Direct boundary while the downlink is still
        // framed, so each direction relays independently rather than waiting
        // to form a pair.
        assert_eq!(stats.relay_backend(), None);
        assert_eq!(stats.uplink_backend(), Some(RelayBackend::Buffered));
        assert_eq!(stats.downlink_backend(), Some(RelayBackend::Buffered));
        assert_eq!(
            stats.uplink_direct_at_bytes(),
            length_u64(b"up-framed".len())
        );
        assert_eq!(
            stats.downlink_direct_at_bytes(),
            length_u64(expected_framed.len())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_way_direct_relays_the_direction_independently() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let mut handler = direct_handler(&governor);
        handler.io_timeout = Duration::from_millis(20);
        let request = vision_request_with_command(
            destination_address.port(),
            b"up-framed",
            VisionCommand::Direct,
        );
        // The destination never speaks TLS, so the downlink can never reach a
        // Direct boundary. The uplink must therefore relay its raw direction
        // independently — reporting a backend — while the downlink continues
        // framed outer TLS undisturbed.
        let uplink_raw = vec![0x5a_u8; 96 * 1024];
        let downlink_part_one = b"plain-http-part-one";
        let downlink_part_two = b"plain-http-part-two";

        let expected_uplink = uplink_raw.clone();
        let exchange = async {
            let handle = handler.handle(established);
            let raw = uplink_raw.clone();
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                tokio::time::sleep(Duration::from_millis(80)).await;
                client.write_all(&raw).await?;
                client.shutdown().await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                let mut response_header = true;
                loop {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    match opened.content_type() {
                        ContentType::ApplicationData => {
                            let plaintext = opened.plaintext();
                            let vision = if response_header {
                                response_header = false;
                                &plaintext[2..]
                            } else {
                                plaintext
                            };
                            let _ = decoder
                                .decode(vision, &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        ContentType::Alert if opened.plaintext() == [1, 0] => break,
                        _ => return Err(io::Error::other("unexpected outer TLS content")),
                    }
                }
                Ok::<_, io::Error>(response)
            };
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                destination.write_all(downlink_part_one).await?;
                // `read_to_end` only completes once the directional uplink
                // relay propagated the client EOF as a write-side shutdown of
                // the destination socket. Writing *after* that EOF proves the
                // half-close left the peer direction fully operational.
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                tokio::time::sleep(Duration::from_millis(80)).await;
                destination.write_all(downlink_part_two).await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("one-way direct exchange must not time out");
        let stats = stats.expect("one-way direct handler must succeed");
        let response = client_result.expect("client I/O must succeed");
        let mut expected = b"up-framed".to_vec();
        expected.extend_from_slice(&expected_uplink);
        let mut expected_downlink = downlink_part_one.to_vec();
        expected_downlink.extend_from_slice(downlink_part_two);

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            expected,
            "every raw uplink byte must reach the destination in order"
        );
        assert_eq!(
            response, expected_downlink,
            "the framed downlink must survive the directional uplink's half-close"
        );
        assert!(
            stats.uplink_direct(),
            "the uplink authenticated a Direct command"
        );
        assert!(
            !stats.downlink_direct(),
            "a non-TLS destination must never reach a Direct boundary"
        );
        assert_eq!(stats.uplink_bytes(), length_u64(expected.len()));
        assert_eq!(stats.downlink_bytes(), length_u64(expected_downlink.len()));
        assert_eq!(
            stats.uplink_backend(),
            Some(RelayBackend::Buffered),
            "the directional uplink relay must report the backend that moved its bytes"
        );
        assert_eq!(stats.downlink_backend(), None);
        assert_eq!(
            stats.relay_backend(),
            None,
            "no bilateral handoff happened for a one-way Direct session"
        );
        assert_eq!(
            stats.uplink_direct_at_bytes(),
            length_u64(b"up-framed".len()),
            "the boundary byte count excludes the raw phase"
        );
        assert_eq!(stats.downlink_direct_at_bytes(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bilateral_direct_handoff_transfers_large_payloads_byte_exactly() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 2_000,
            handshake_timeout_ms: 2_000,
            fallback_timeout_ms: 2_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        // The client's first frame continues; the client follows with its own
        // Direct frame only after the server sent its Direct frame, which is
        // the real Vision flow. The downlink therefore reaches its boundary
        // first and is still at `RawReady` when the uplink arrives, so the
        // uplink commits to the pair and the downlink — resuming while the
        // peer is `PairPending` — deposits last and runs the bilateral relay.
        let mut addons = vec![0x0a, 0x10];
        addons.extend_from_slice(VISION_FLOW.as_bytes());
        let mut request = Vec::new();
        request.push(VERSION);
        request.extend_from_slice(USER.as_bytes());
        request.push(u8::try_from(addons.len()).unwrap_or(u8::MAX));
        request.extend_from_slice(&addons);
        request.push(Command::Tcp.as_byte());
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        request.push(1);
        request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        let mut uplink_encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
        let mut first_frame = Vec::new();
        uplink_encoder
            .encode(
                b"up-framed",
                VisionCommand::Continue,
                false,
                &mut first_frame,
            )
            .expect("Vision payload must encode");
        request.extend_from_slice(&first_frame);
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        let nested_application = record(23, b"encrypted-handshake");
        let uplink_raw: Vec<u8> = (0..512_u32 * 1024).map(|value| value as u8).collect();
        let downlink_raw: Vec<u8> = (0..512_u32 * 1024)
            .map(|value| (value >> 3) as u8)
            .collect();

        let expected_down = downlink_raw.clone();
        let exchange = async {
            let handle = handler.handle(established);
            let raw = uplink_raw.clone();
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut framed = Vec::new();
                let mut response_header = true;
                while decoder.mode() != VisionMode::Direct {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    let plaintext = opened.plaintext();
                    let vision = if response_header {
                        response_header = false;
                        &plaintext[2..]
                    } else {
                        plaintext
                    };
                    let _ = decoder
                        .decode(vision, &mut decoded)
                        .map_err(io::Error::other)?;
                    framed.extend_from_slice(&decoded);
                }

                let mut direct_frame = Vec::new();
                uplink_encoder
                    .encode(b"", VisionCommand::Direct, false, &mut direct_frame)
                    .map_err(io::Error::other)?;
                let mut direct_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &direct_frame,
                        0,
                        &mut direct_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&direct_record).await?;

                let (mut reader, mut writer) = client.into_split();
                let send = async move {
                    writer.write_all(&raw).await?;
                    writer.shutdown().await?;
                    Ok::<_, io::Error>(())
                };
                let receive = async move {
                    let mut received = Vec::new();
                    reader.read_to_end(&mut received).await?;
                    Ok::<_, io::Error>(received)
                };
                let (sent, received) = tokio::join!(send, receive);
                sent?;
                Ok::<_, io::Error>((framed, received?))
            };
            let server_hello_record = nested_server_hello.clone();
            let application_record = nested_application.clone();
            let down = downlink_raw.clone();
            let destination_io = async move {
                let (destination, _) = destination_listener.accept().await?;
                let (mut reader, mut writer) = destination.into_split();
                let send = async move {
                    writer.write_all(&server_hello_record).await?;
                    writer.write_all(&application_record).await?;
                    writer.write_all(&down).await?;
                    writer.shutdown().await?;
                    Ok::<_, io::Error>(())
                };
                let receive = async move {
                    let mut received = Vec::new();
                    reader.read_to_end(&mut received).await?;
                    Ok::<_, io::Error>(received)
                };
                let (sent, received) = tokio::join!(send, receive);
                sent?;
                received
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("bilateral direct exchange must not time out");
        let stats = stats.expect("bilateral direct handler must succeed");
        let (framed, raw_response) = client_result.expect("client I/O must succeed");
        let received_up = destination_result.expect("destination I/O must succeed");
        let mut expected_framed = nested_server_hello;
        expected_framed.extend_from_slice(&nested_application);
        let mut expected_up = b"up-framed".to_vec();
        expected_up.extend_from_slice(&uplink_raw);
        assert_eq!(framed, expected_framed);
        assert_eq!(
            received_up.len(),
            expected_up.len(),
            "the handed-off relay must transfer every uplink byte"
        );
        assert_eq!(received_up, expected_up);
        assert_eq!(
            raw_response.len(),
            expected_down.len(),
            "the handed-off relay must transfer every downlink byte"
        );
        assert_eq!(raw_response, expected_down);
        assert!(stats.uplink_direct());
        assert!(stats.downlink_direct());
        assert_eq!(stats.uplink_bytes(), length_u64(expected_up.len()));
        assert_eq!(
            stats.downlink_bytes(),
            length_u64(expected_framed.len() + expected_down.len())
        );
        assert_eq!(
            stats.relay_backend(),
            Some(RelayBackend::Buffered),
            "both directions paired, so the pair relay moved the raw bytes"
        );
        assert_eq!(stats.uplink_backend(), Some(RelayBackend::Buffered));
        assert_eq!(stats.downlink_backend(), Some(RelayBackend::Buffered));
        assert_eq!(
            stats.uplink_direct_at_bytes(),
            length_u64(b"up-framed".len())
        );
        assert_eq!(
            stats.downlink_direct_at_bytes(),
            length_u64(expected_framed.len())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_way_direct_downlink_relays_independently() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        // The client ends its Vision flow (`End`), so the uplink stays in
        // framed pass-through and never reaches a Direct boundary. The
        // destination speaks TLS 1.3, so the downlink goes Direct alone and
        // must relay its direction independently.
        let request =
            vision_request_with_command(destination_address.port(), b"up-ping", VisionCommand::End);
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        let nested_application = record(23, b"encrypted-handshake");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut more_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        b"up-more",
                        0,
                        &mut more_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&more_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut framed = Vec::new();
                let mut response_header = true;
                while decoder.mode() != VisionMode::Direct {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    let plaintext = opened.plaintext();
                    let vision = if response_header {
                        response_header = false;
                        &plaintext[2..]
                    } else {
                        plaintext
                    };
                    let _ = decoder
                        .decode(vision, &mut decoded)
                        .map_err(io::Error::other)?;
                    framed.extend_from_slice(&decoded);
                }
                let mut raw_response = Vec::new();
                client.read_to_end(&mut raw_response).await?;
                Ok::<_, io::Error>((framed, raw_response))
            };
            let server_hello_record = nested_server_hello.clone();
            let application_record = nested_application.clone();
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                destination.write_all(&server_hello_record).await?;
                destination.write_all(&application_record).await?;
                destination.write_all(b"down-raw").await?;
                destination.shutdown().await?;
                let mut received = Vec::new();
                destination.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("downlink direct exchange must not time out");
        let stats = stats.expect("downlink direct handler must succeed");
        let (framed, raw_response) = client_result.expect("client I/O must succeed");
        let mut expected_framed = nested_server_hello;
        expected_framed.extend_from_slice(&nested_application);

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"up-pingup-more",
            "the framed uplink pass-through must stay undisturbed"
        );
        assert_eq!(framed, expected_framed);
        assert_eq!(raw_response, b"down-raw");
        assert!(
            !stats.uplink_direct(),
            "an End flow never reaches an uplink Direct boundary"
        );
        assert!(stats.downlink_direct());
        assert_eq!(
            stats.uplink_bytes(),
            length_u64(b"up-ping".len() + b"up-more".len())
        );
        assert_eq!(
            stats.downlink_bytes(),
            length_u64(expected_framed.len() + b"down-raw".len())
        );
        assert_eq!(stats.relay_backend(), None);
        assert_eq!(stats.uplink_backend(), None);
        assert_eq!(
            stats.downlink_backend(),
            Some(RelayBackend::Buffered),
            "the directional downlink relay must report its backend"
        );
        assert_eq!(stats.uplink_direct_at_bytes(), 0);
        assert_eq!(
            stats.downlink_direct_at_bytes(),
            length_u64(expected_framed.len())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn packs_multiple_vision_frames_into_one_outer_record() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request(destination_address.port(), b"up-ping");
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        // A maximum-sized nested handshake record is framed as three Vision
        // frames; the two full frames carry no padding and must share one
        // maximum-sized outer record.
        let nested_certificate = record(22, &[0x5a_u8; 16_384]);
        let nested_application = record(23, b"encrypted-handshake");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut framed = Vec::new();
                let mut outer_records = 0_usize;
                let mut saw_packed_record = false;
                let mut response_header = true;
                while decoder.mode() != VisionMode::Direct {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    if opened.content_type() != ContentType::ApplicationData {
                        return Err(io::Error::other("expected outer application record"));
                    }
                    let plaintext = opened.plaintext();
                    outer_records += 1;
                    saw_packed_record |= plaintext.len() > VISION_FRAME_SIZE;
                    let vision = if response_header {
                        response_header = false;
                        &plaintext[2..]
                    } else {
                        plaintext
                    };
                    let _ = decoder
                        .decode(vision, &mut decoded)
                        .map_err(io::Error::other)?;
                    framed.extend_from_slice(&decoded);
                }
                let mut raw_response = Vec::new();
                client.read_to_end(&mut raw_response).await?;
                Ok::<_, io::Error>((framed, raw_response, outer_records, saw_packed_record))
            };
            let server_hello_record = nested_server_hello.clone();
            let certificate_record = nested_certificate.clone();
            let application_record = nested_application.clone();
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                destination.write_all(&server_hello_record).await?;
                destination.write_all(&certificate_record).await?;
                destination.write_all(&application_record).await?;
                destination.write_all(b"down-raw").await?;
                destination.shutdown().await?;
                let mut received = Vec::new();
                destination.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("packed Vision exchange must not time out");
        let stats = stats.expect("packed Vision handler must succeed");
        let (framed, raw_response, outer_records, saw_packed_record) =
            client_result.expect("client I/O must succeed");
        let mut expected_framed = nested_server_hello;
        expected_framed.extend_from_slice(&nested_certificate);
        expected_framed.extend_from_slice(&nested_application);

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"up-ping"
        );
        assert_eq!(
            framed, expected_framed,
            "frames packed into shared outer records must decode byte-exactly"
        );
        assert_eq!(raw_response, b"down-raw");
        // Preamble, ServerHello frame, two records for the three certificate
        // frames, and the Direct frame: five records where unpacked framing
        // needed six.
        assert_eq!(outer_records, 5, "full frames must share outer records");
        assert!(
            saw_packed_record,
            "one outer record must carry more than one Vision frame"
        );
        assert!(stats.downlink_direct());
        assert_eq!(
            stats.downlink_bytes(),
            length_u64(expected_framed.len() + b"down-raw".len())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn uplink_direct_drains_pipelined_raw_bytes_ahead_of_the_raw_relay() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request_with_command(
            destination_address.port(),
            b"up-framed",
            VisionCommand::Direct,
        );

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut burst = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, &request, 0, &mut burst)
                    .map_err(io::Error::other)?;
                // The over-read regression shape: the boundary outer record and
                // the post-boundary raw bytes arrive in ONE socket burst, so the
                // buffered reader must drain them to the destination in order.
                burst.extend_from_slice(b"up-raw-pipelined");
                client.write_all(&burst).await?;
                client.shutdown().await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                let mut response_header = true;
                loop {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    match opened.content_type() {
                        ContentType::ApplicationData => {
                            let plaintext = opened.plaintext();
                            let vision = if response_header {
                                response_header = false;
                                &plaintext[2..]
                            } else {
                                plaintext
                            };
                            let _ = decoder
                                .decode(vision, &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        ContentType::Alert if opened.plaintext() == [1, 0] => break,
                        _ => return Err(io::Error::other("unexpected outer TLS content")),
                    }
                }
                Ok::<_, io::Error>(response)
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(b"pong").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("pipelined direct exchange must not time out");
        let stats = stats.expect("pipelined direct handler must succeed");

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"up-framedup-raw-pipelined",
            "the drained pending bytes must reach the destination in order, after the framed prefix"
        );
        assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
        assert!(stats.uplink_direct());
        assert_eq!(
            stats.uplink_bytes(),
            length_u64(b"up-framed".len() + b"up-raw-pipelined".len()),
            "pending bytes count toward the uplink total exactly once"
        );
        assert_eq!(
            stats.uplink_direct_at_bytes(),
            length_u64(b"up-framed".len()),
            "the boundary byte count excludes the raw phase, drained or relayed"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn downlink_direct_drains_pipelined_raw_bytes_ahead_of_the_raw_relay() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request =
            vision_request_with_command(destination_address.port(), b"up-ping", VisionCommand::End);
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        let nested_application = record(23, b"encrypted-handshake");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut framed = Vec::new();
                let mut response_header = true;
                while decoder.mode() != VisionMode::Direct {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    let plaintext = opened.plaintext();
                    let vision = if response_header {
                        response_header = false;
                        &plaintext[2..]
                    } else {
                        plaintext
                    };
                    let _ = decoder
                        .decode(vision, &mut decoded)
                        .map_err(io::Error::other)?;
                    framed.extend_from_slice(&decoded);
                }
                let mut raw_response = Vec::new();
                client.read_to_end(&mut raw_response).await?;
                Ok::<_, io::Error>((framed, raw_response))
            };
            let server_hello_record = nested_server_hello.clone();
            let application_record = nested_application.clone();
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                // One burst: the classification flight, the boundary record, and
                // the post-boundary raw bytes land in the nested reader's buffer
                // together, so the Direct drain must forward them in order.
                let mut burst = server_hello_record;
                burst.extend_from_slice(&application_record);
                burst.extend_from_slice(b"down-raw-pipelined");
                destination.write_all(&burst).await?;
                destination.shutdown().await?;
                let mut received = Vec::new();
                destination.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("pipelined downlink exchange must not time out");
        let stats = stats.expect("pipelined downlink handler must succeed");
        let (framed, raw_response) = client_result.expect("client I/O must succeed");
        let mut expected_framed = nested_server_hello;
        expected_framed.extend_from_slice(&nested_application);

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"up-ping"
        );
        assert_eq!(framed, expected_framed);
        assert_eq!(
            raw_response, b"down-raw-pipelined",
            "the drained pending bytes must reach the client after the framed records, in order"
        );
        assert!(stats.downlink_direct());
        assert_eq!(
            stats.downlink_bytes(),
            length_u64(expected_framed.len() + b"down-raw-pipelined".len())
        );
        assert_eq!(
            stats.downlink_direct_at_bytes(),
            length_u64(expected_framed.len())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outer_downlink_forwards_bytes_buffered_by_classification() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request(destination_address.port(), b"ping");
        // A non-TLS payload larger than the five classification bytes: the
        // classification read buffers the whole burst, returns the header
        // prefix as unframed, and the outer downlink must forward the rest
        // from the buffer before touching the socket again.
        let payload: Vec<u8> = (0..16 * 1024_u32)
            .map(|value| 0x61 + (value % 26) as u8)
            .collect();

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                let mut response_header = true;
                loop {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    match opened.content_type() {
                        ContentType::ApplicationData => {
                            let plaintext = opened.plaintext();
                            let vision = if response_header {
                                response_header = false;
                                &plaintext[2..]
                            } else {
                                plaintext
                            };
                            let _ = decoder
                                .decode(vision, &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        ContentType::Alert if opened.plaintext() == [1, 0] => break,
                        _ => return Err(io::Error::other("unexpected outer TLS content")),
                    }
                }
                Ok::<_, io::Error>(response)
            };
            let downlink = payload.clone();
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(&downlink).await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("outer downlink exchange must not time out");
        let stats = stats.expect("outer downlink handler must succeed");
        let response = client_result.expect("client I/O must succeed");

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping"
        );
        assert_eq!(
            response, payload,
            "bytes buffered by classification must be forwarded, never lost"
        );
        assert!(!stats.downlink_direct());
        assert_eq!(stats.downlink_bytes(), length_u64(payload.len()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn short_non_tls_response_progresses_without_origin_eof() {
        for response in [
            b"x".as_slice(),
            b"ok",
            b"xxx",
            b"pong",
            &[22, 4],
            &[22, 3, 5],
        ] {
            let (mut origin, server) = tcp_pair().await;
            let (read_half, _write_half) = server.into_split();
            let mut reader = super::NestedRecordReader::new(read_half);
            reader
                .idle
                .set_activity(Arc::new(crate::io_activity::SessionActivity::default()));
            origin.write_all(response).await.expect("origin response");
            let observed = timeout(TEST_TIMEOUT, reader.next(TEST_TIMEOUT))
                .await
                .expect("response must progress while origin stays open")
                .expect("classification succeeds");
            match observed {
                super::NestedRead::Unframed(bytes) => assert_eq!(bytes, response),
                _ => panic!("plain response must be forwarded as unframed"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn short_resumed_response_precedes_origin_fin_with_or_without_uplink_fin() {
        for half_close in [false, true] {
            let (mut client, inbound) = tcp_pair().await;
            let (destination, mut target) = tcp_pair().await;
            let (tls, mut client_write, mut client_read) = tls_states();
            let (reader, writer) = TlsApplicationIo::new(inbound, tls).into_owned_split();
            let relay =
                TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096)).expect("relay");
            let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
            let mut initial = Vec::new();
            encoder
                .encode(b"request", VisionCommand::Continue, false, &mut initial)
                .expect("request");
            let session = super::run_resumed_session(
                reader,
                writer,
                destination,
                USER,
                initial,
                &relay,
                TEST_TIMEOUT,
            );
            let traffic = async {
                let mut request = [0; 7];
                target.read_exact(&mut request).await?;
                assert_eq!(&request, b"request");
                let mut wire = Vec::new();
                if half_close {
                    client_write
                        .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
                        .map_err(io::Error::other)?;
                    client.write_all(&wire).await?;
                    assert_eq!(target.read(&mut [0]).await?, 0);
                }
                target.write_all(b"pong").await?;
                let mut first = true;
                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                // FIN is deliberately withheld until the complete payload is received.
                while response.len() < 4 {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    let payload = if first {
                        first = false;
                        &opened.plaintext()[2..]
                    } else {
                        opened.plaintext()
                    };
                    decoder
                        .decode(payload, &mut decoded)
                        .map_err(io::Error::other)?;
                    response.extend_from_slice(&decoded);
                }
                assert_eq!(response, b"pong");
                target.shutdown().await?;
                if !half_close {
                    wire.clear();
                    client_write
                        .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
                        .map_err(io::Error::other)?;
                    client.write_all(&wire).await?;
                    assert_eq!(target.read(&mut [0]).await?, 0);
                }
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                assert_eq!(opened.content_type(), ContentType::Alert);
                Ok::<_, io::Error>(())
            };
            let (stats, traffic) = timeout(TEST_TIMEOUT, async { tokio::join!(session, traffic) })
                .await
                .expect("bounded response");
            traffic.expect("response precedes FIN");
            let stats = stats.expect("healthy session");
            assert_eq!(stats.downlink_bytes(), 4);
            assert!(!stats.downlink_direct());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn plausible_tls_prefix_survives_a_pending_read() {
        let (mut origin, server) = tcp_pair().await;
        let (read_half, _write_half) = server.into_split();
        let mut reader = super::NestedRecordReader::new(read_half);
        reader
            .idle
            .set_activity(Arc::new(crate::io_activity::SessionActivity::default()));
        let hello = record(22, &server_hello(0x1301, true));
        for byte in &hello[..4] {
            origin.write_all(&[*byte]).await.expect("fragment");
            assert!(
                timeout(Duration::from_millis(10), reader.next(TEST_TIMEOUT))
                    .await
                    .is_err(),
                "a plausible incomplete header must not be downgraded"
            );
        }
        origin
            .write_all(&hello[4..])
            .await
            .expect("remaining record");
        match reader
            .next(TEST_TIMEOUT)
            .await
            .expect("complete TLS record")
        {
            super::NestedRead::Record(bytes) => assert_eq!(bytes, hello),
            _ => panic!("fragmentation must preserve TLS classification"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nested_reader_classifies_fragmented_records_and_clean_eof() {
        let (mut client, server) = tcp_pair().await;
        let (destination, _) = server.into_split();
        let mut reader = super::NestedRecordReader::new(destination);
        let hello = record(22, &server_hello(0x1301, true));

        client
            .write_all(&hello[..3])
            .await
            .expect("fragment must be written");
        client
            .write_all(&hello[3..])
            .await
            .expect("fragment must be written");
        match reader
            .next(TEST_TIMEOUT)
            .await
            .expect("record must classify")
        {
            super::NestedRead::Record(bytes) => assert_eq!(bytes, hello.as_slice()),
            _ => panic!("fragmented record must classify as a record"),
        }

        client.shutdown().await.expect("client must half-close");
        assert!(matches!(
            reader.next(TEST_TIMEOUT).await.expect("EOF must classify"),
            super::NestedRead::Eof
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nested_reader_reports_truncated_records_and_partial_headers() {
        let (mut client, server) = tcp_pair().await;
        let (destination, _) = server.into_split();
        let mut reader = super::NestedRecordReader::new(destination);
        let mut truncated = vec![23, 0x03, 0x03, 0, 100];
        truncated.extend_from_slice(&[0x5a; 10]);
        client
            .write_all(&truncated)
            .await
            .expect("truncated record must be written");
        client.shutdown().await.expect("client must half-close");
        assert!(matches!(
            reader.next(TEST_TIMEOUT).await,
            Err(super::VisionSessionError::DestinationTruncatedTlsRecord)
        ));

        let (mut client, server) = tcp_pair().await;
        let (destination, _) = server.into_split();
        let mut reader = super::NestedRecordReader::new(destination);
        client
            .write_all(&[0x16, 0x03, 0x01])
            .await
            .expect("partial header must be written");
        client.shutdown().await.expect("client must half-close");
        match reader.next(TEST_TIMEOUT).await.expect("partial header") {
            super::NestedRead::Unframed(bytes) => assert_eq!(bytes, &[0x16, 0x03, 0x01]),
            _ => panic!("a partial header at EOF must classify as unframed bytes"),
        }
    }

    #[test]
    fn recognizes_tls13_server_hello_then_direct_application_record() {
        let server_hello = server_hello(0x1301, true);
        assert!(super::nested::is_tls13_server_hello(&server_hello));
        let mut detector = NestedTlsDetector::new();
        let handshake_record = record(22, &server_hello);
        let application_record = record(23, b"encrypted handshake");

        assert_eq!(
            detector.observe(&handshake_record),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&application_record),
            PaddingDecision::Direct
        );
    }

    #[test]
    fn rejects_ccm8_and_tls12_for_direct_transition() {
        let mut ccm8 = NestedTlsDetector::new();
        assert_eq!(
            ccm8.observe(&record(22, &server_hello(0x1305, true))),
            PaddingDecision::End
        );
        let mut tls12 = NestedTlsDetector::new();
        assert_eq!(
            tls12.observe(&record(22, &server_hello(0x1301, false))),
            PaddingDecision::End
        );
    }

    #[test]
    fn assembles_fragmented_server_hello_across_records() {
        let hello = server_hello(0x1301, true);
        let split = 30;
        let mut detector = NestedTlsDetector::new();

        assert_eq!(
            detector.observe(&record(22, &hello[..split])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(22, &hello[split..])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(23, b"ciphertext")),
            PaddingDecision::Direct
        );
    }

    #[test]
    fn assembles_fragmented_handshake_header_across_records() {
        let hello = server_hello(0x1301, true);
        let mut detector = NestedTlsDetector::new();

        assert_eq!(
            detector.observe(&record(22, &hello[..2])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(22, &hello[2..])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(23, b"ciphertext")),
            PaddingDecision::Direct
        );
    }

    fn server_hello(cipher_suite: u16, tls13: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        if tls13 {
            body.extend_from_slice(&[0, 6, 0, 43, 0, 2, 0x03, 0x04]);
        } else {
            body.extend_from_slice(&[0, 0]);
        }
        let mut message = vec![2, 0, 0, u8::try_from(body.len()).unwrap_or(u8::MAX)];
        message.extend_from_slice(&body);
        message
    }

    fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut record = vec![content_type, 0x03, 0x03];
        record.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        record.extend_from_slice(body);
        record
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("outer listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("address must exist"))
            .await
            .expect("outer client must connect");
        let (server, _) = listener.accept().await.expect("outer server must accept");
        (client, server)
    }

    fn vision_request(destination_port: u16, payload: &[u8]) -> Vec<u8> {
        vision_request_with_command(destination_port, payload, VisionCommand::End)
    }

    fn vision_request_with_command(
        destination_port: u16,
        payload: &[u8],
        command: VisionCommand,
    ) -> Vec<u8> {
        let mut addons = vec![0x0a, 0x10];
        addons.extend_from_slice(VISION_FLOW.as_bytes());
        let mut request = Vec::new();
        request.push(VERSION);
        request.extend_from_slice(USER.as_bytes());
        request.push(u8::try_from(addons.len()).unwrap_or(u8::MAX));
        request.extend_from_slice(&addons);
        request.push(Command::Tcp.as_byte());
        request.extend_from_slice(&destination_port.to_be_bytes());
        request.push(1);
        request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
        let mut frame = Vec::new();
        encoder
            .encode(payload, command, false, &mut frame)
            .expect("Vision payload must encode");
        request.extend_from_slice(&frame);
        request
    }

    fn tls_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
        let suite = CipherSuite::Aes128GcmSha256;
        let client_layer = || {
            let secret = TrafficSecret::from_bytes(suite.hash(), &[0x31; 32])
                .expect("client secret must import");
            Tls13RecordLayer::from_traffic_secret(suite, secret)
                .expect("client record layer must initialize")
        };
        let server_layer = || {
            let secret = TrafficSecret::from_bytes(suite.hash(), &[0x32; 32])
                .expect("server secret must import");
            Tls13RecordLayer::from_traffic_secret(suite, secret)
                .expect("server record layer must initialize")
        };
        (
            EstablishedTls::from_test_records(suite, client_layer(), server_layer()),
            client_layer(),
            server_layer(),
        )
    }

    fn direct_handler(governor: &ResourceGovernorPolicy) -> VisionHandler {
        let barrier = DirectBarrierPolicy {
            max_concurrent: 8,
            max_per_second: 8,
        };
        let outbounds = OutboundRegistry::new(
            &std::collections::BTreeMap::new(),
            &barrier,
            Duration::from_millis(governor.connect_timeout_ms),
            crate::transport::FdBudget::new(4_096),
        );
        let routing = RoutingTable::compile(
            &RoutingConfig {
                default: "direct".to_owned(),
                strategy: None,
                rules: None,
                policies: None,
            },
            &[UserConfig {
                id: "33333333-3333-3333-3333-333333333333".to_owned(),
                short_ids: vec!["0123456789abcdef".to_owned()],
                label: None,
                policy: None,
            }],
            Arc::new(EmptyAssetMatcher),
            crate::runtime::ResourceGovernor::new(
                &crate::runtime::policy::ResourceGovernorPolicy::default(),
            ),
        )
        .expect("test routing must compile");
        let relay = crate::transport::TcpRelay::new(
            crate::transport::TcpRelayConfig {
                buffer_bytes: 32 * 1024,
                max_pooled_buffers: 8,
                max_splice_relays: 0,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            crate::transport::FdBudget::new(4_096),
        )
        .expect("test relay policy must compile");
        VisionHandler::new(outbounds, routing, relay, governor)
    }

    fn handler_with_block_cidr(
        governor: &ResourceGovernorPolicy,
        blocked_cidr: &str,
    ) -> VisionHandler {
        let barrier = DirectBarrierPolicy {
            max_concurrent: 8,
            max_per_second: 8,
        };
        let outbounds = OutboundRegistry::new(
            &std::collections::BTreeMap::new(),
            &barrier,
            Duration::from_millis(governor.connect_timeout_ms),
            crate::transport::FdBudget::new(4_096),
        );
        let routing = RoutingTable::compile(
            &RoutingConfig {
                default: "direct".to_owned(),
                strategy: None,
                rules: Some(vec![crate::config::node::routing::RouteRule {
                    name: Some("xudp-keep-block".to_owned()),
                    outbound: "block".to_owned(),
                    ip: Some(vec![blocked_cidr.to_owned()]),
                    ..crate::config::node::routing::RouteRule::default()
                }]),
                policies: None,
            },
            &[UserConfig {
                id: "33333333-3333-3333-3333-333333333333".to_owned(),
                short_ids: vec!["0123456789abcdef".to_owned()],
                label: None,
                policy: None,
            }],
            Arc::new(EmptyAssetMatcher),
            crate::runtime::ResourceGovernor::new(
                &crate::runtime::policy::ResourceGovernorPolicy::default(),
            ),
        )
        .expect("test routing must compile");
        let relay = crate::transport::TcpRelay::new(
            crate::transport::TcpRelayConfig {
                buffer_bytes: 32 * 1024,
                max_pooled_buffers: 8,
                max_splice_relays: 0,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            crate::transport::FdBudget::new(4_096),
        )
        .expect("test relay policy must compile");
        VisionHandler::new(outbounds, routing, relay, governor)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn xudp_keep_rewrite_direct_then_block_fails_closed() {
        use crate::protocol::vless::{Address, Destination};
        use crate::server::xudp::{XudpEgressCapability, XudpOutboundUnsupported};

        let governor = ResourceGovernorPolicy::default();
        // Block 10.0.0.0/8; default remains Direct.
        let handler = handler_with_block_cidr(&governor, "10.0.0.0/8");
        let green = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 9);
        let red = Destination::new(Address::Ipv4(Ipv4Addr::new(10, 1, 2, 3)), 9);

        let (capability, authorized, tag) = handler
            .authorize_xudp_destination(USER, "public-reality", &green)
            .await
            .expect("Direct destination must remain GREEN");
        assert_eq!(capability, XudpEgressCapability::Direct);
        assert_eq!(authorized.port(), 9);
        assert_eq!(tag, "direct");

        let err = handler
            .authorize_xudp_destination(USER, "public-reality", &red)
            .await
            .expect_err("Keep rewrite to Block must fail closed (RED)");
        match err {
            VisionSessionError::Xudp(crate::server::xudp::XudpSessionError::Outbound(
                XudpOutboundUnsupported::Block,
            )) => {}
            other => panic!("expected Block outbound rejection, got {other}"),
        }
    }

    /// Reproduces the abort-authority lifetime question from #195.
    ///
    /// The client sends its whole request and closes the inner TLS stream, so
    /// the uplink direction completes and `try_join!` drops its future — which
    /// owns the client read half and the destination write half. The
    /// destination then aborts, so the downlink direction fails. At that point
    /// the downlink future owns the *last* halves of both sockets, and the
    /// question is whether the abort guard can still reach a live socket.
    ///
    /// The ordering is a happens-before chain, not a sleep:
    ///
    /// 1. `read_to_end` on the destination returns only after the uplink
    ///    shut the destination write half down, which it does immediately
    ///    before returning `Ok`;
    /// 2. the client decodes a downlink record, which the session can only
    ///    have produced after the uplink future became `Ready` and was
    ///    dropped in that same poll;
    /// 3. only then does the client release the destination, which resets.
    ///
    /// The peer-visible contract is what is asserted: a truncated transfer
    /// must reach the client as a reset, never as a clean end of stream that
    /// a client could mistake for a complete response.
    #[tokio::test(flavor = "current_thread")]
    async fn a_downlink_abort_after_the_uplink_finished_resets_the_client() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request(destination_address.port(), b"ping");
        let (downlink_seen, downlink_wait) = tokio::sync::oneshot::channel::<()>();

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                // Closing the inner stream is what ends the uplink direction.
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                // Barrier 2: one decoded downlink record proves the session
                // progressed past the uplink's completion.
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                assert_eq!(opened.content_type(), ContentType::ApplicationData);
                let _ = downlink_seen.send(());

                // How the transport ends is the whole assertion.
                let mut sink = [0_u8; 4_096];
                loop {
                    match client.read(&mut sink).await {
                        Ok(0) => return Ok::<_, io::Error>(None),
                        Ok(_) => {}
                        Err(error) => return Ok(Some(error.kind())),
                    }
                }
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                // Barrier 1: returns only once the uplink shut this half down.
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(b"partial").await?;
                let _ = downlink_wait.await;
                // Truncate the response mid-transfer, the way a dying origin does.
                rr_linux::socket::abort_linger(&destination).expect("arm the reset");
                drop(destination);
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (session, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("the exchange must not time out");
        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping"
        );
        assert!(
            session.is_err(),
            "a truncated downlink must fail the session, not report a clean close"
        );
        let ending = client_result.expect("client I/O must not fail structurally");
        assert_eq!(
            ending,
            Some(io::ErrorKind::ConnectionReset),
            "an aborted transfer must reach the client as a reset; a clean end of \
             stream lets a truncated response look complete"
        );
    }

    /// The counterpart to the two abort regressions: arming a reset on every
    /// failure must not leak into the graceful path.
    ///
    /// A session that completes normally has to close with FIN so the client
    /// can tell a finished response from a truncated one. Over-aborting would
    /// be a worse defect than the one #195 fixed, because it would corrupt
    /// every healthy session rather than a failing one.
    #[tokio::test(flavor = "current_thread")]
    async fn a_completed_session_closes_the_client_cleanly() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, _client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request(destination_address.port(), b"ping");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut sink = [0_u8; 4_096];
                loop {
                    match client.read(&mut sink).await {
                        Ok(0) => return Ok::<_, io::Error>(None),
                        Ok(_) => {}
                        Err(error) => return Ok(Some(error.kind())),
                    }
                }
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(b"pong").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (session, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("the exchange must not time out");
        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping"
        );
        session.expect("a complete session must succeed");
        assert_eq!(
            client_result.expect("client I/O must not fail structurally"),
            None,
            "a graceful session must end with FIN; resetting a healthy session \
             would be a worse defect than the abort it protects against"
        );
    }

    /// The cancellation half of #195.
    ///
    /// Here the client keeps its stream open, so the uplink direction is alive
    /// and parked on a read when the downlink fails. `try_join!` then cancels
    /// the uplink future *while it owns the client read half and the
    /// destination write half*. Both guards must still deliver a reset, and
    /// neither may let a FIN reach the client first.
    ///
    /// The barrier is the destination observing the relayed payload, which
    /// only happens after the session is fully established and both directions
    /// are running.
    #[tokio::test(flavor = "current_thread")]
    async fn a_downlink_abort_resets_the_client_while_the_uplink_is_cancelled() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        );
        let governor = ResourceGovernorPolicy {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorPolicy::default()
        };
        let handler = direct_handler(&governor);
        let request = vision_request(destination_address.port(), b"ping");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                // No close_notify: the uplink direction stays alive and parked
                // on a read for the whole test, so cancelling it is what the
                // downlink failure below has to do.

                // Consume the downlink preamble so the assertion below observes
                // the end of the transport, not the response.
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                assert_eq!(opened.content_type(), ContentType::ApplicationData);

                let mut sink = [0_u8; 4_096];
                loop {
                    match client.read(&mut sink).await {
                        Ok(0) => return Ok::<_, io::Error>(None),
                        Ok(_) => {}
                        Err(error) => return Ok(Some(error.kind())),
                    }
                }
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                // Barrier: the relayed payload proves both directions are live.
                let mut relayed = [0_u8; 4];
                destination.read_exact(&mut relayed).await?;
                rr_linux::socket::abort_linger(&destination).expect("arm the reset");
                drop(destination);
                Ok::<_, io::Error>(relayed)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (session, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("the exchange must not time out");
        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            *b"ping"
        );
        assert!(
            session.is_err(),
            "an aborted destination must fail the session"
        );
        assert_eq!(
            client_result.expect("client I/O must not fail structurally"),
            Some(io::ErrorKind::ConnectionReset),
            "cancelling a live direction must still reset the client, never FIN it"
        );
    }

    #[test]
    fn an_idle_timeout_is_a_benign_teardown() {
        assert!(is_benign_teardown(&io::Error::new(
            io::ErrorKind::TimedOut,
            "raw relay idle timeout"
        )));
        assert!(is_benign_teardown(&io::Error::new(
            io::ErrorKind::ConnectionReset,
            "reset"
        )));
        assert!(!is_benign_teardown(&io::Error::other("boom")));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_quiet_raw_direction_waits_for_fin_with_its_stats() {
        let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
            .expect("relay policy must compile");
        let handoff = DirectHandoff::new();
        let activity = Arc::new(super::SessionActivity::default());
        let (mut sender, source) = tcp_pair().await;
        let (sink, mut receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = source.into_split();
        let (_sink_reader, sink_writer) = sink.into_split();
        let context = SessionContext {
            activity: &activity,
            timeout: Duration::from_millis(10),
            handoff: &handoff,
            relay: &relay,
        };
        let relaying = run_directional(
            &context,
            Direction::Uplink,
            source_reader,
            sink_writer,
            BoundaryBytes {
                total: 3,
                direct_at: 3,
            },
            Instant::now(),
        );
        tokio::pin!(relaying);
        assert!(
            timeout(Duration::from_millis(50), &mut relaying)
                .await
                .is_err(),
            "a quiet raw direction must remain open"
        );
        sender.shutdown().await.expect("FIN");
        let stats = timeout(TEST_TIMEOUT, relaying)
            .await
            .expect("FIN deadline")
            .expect("clean FIN");
        assert_eq!(receiver.read(&mut [0]).await.expect("EOF"), 0);
        assert!(stats.direct);
        assert_eq!(stats.bytes, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_write_stall_after_moved_bytes_fails_the_session() {
        let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
            .expect("relay policy must compile");
        let handoff = DirectHandoff::new();
        let activity = Arc::new(super::SessionActivity::default());
        let (mut sender, source) = tcp_pair().await;
        let (sink, _receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = source.into_split();
        let (_sink_reader, sink_writer) = sink.into_split();
        let context = SessionContext {
            activity: &activity,
            timeout: Duration::from_millis(50),
            handoff: &handoff,
            relay: &relay,
        };
        let result = timeout(TEST_TIMEOUT, async {
            let mut flood = tokio::io::repeat(0x55);
            tokio::select! {
                result = run_directional(
                    &context, Direction::Uplink, source_reader, sink_writer,
                    BoundaryBytes { total: 3, direct_at: 3 }, Instant::now(),
                ) => result,
                result = tokio::io::copy(&mut flood, &mut sender) =>
                    panic!("source must not finish before write stall: {result:?}"),
            }
        })
        .await
        .expect("stalled write must be bounded");
        let error = result.err().expect("write stall must fail closed");
        let VisionSessionError::Relay(source) = &error else {
            panic!("expected relay error: {error}");
        };
        assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
    }

    /// Release-blocking real-time proof. Paused clocks cannot satisfy it.
    ///
    /// SSE is a quiet uplink with continuing downlink. WebSocket is sparse
    /// traffic in both directions. Both last 600 seconds. A delayed response
    /// begins after 190 seconds, and half-close drains after crossing 120
    /// seconds. A blocked pending write must still fail on the production
    /// 120-second stall, not because the opposite direction is quiet.
    ///
    /// Uses `current_thread` like the other non-ignored Vision proofs: the
    /// accumulation is sequential, and multi-thread Tokio I/O registration
    /// trips ThreadSanitizer inside `ScheduledIo` (ADR 0057). Ignored
    /// multi-thread diagnostics and the 600s matrix keep their flavors.
    #[tokio::test(flavor = "current_thread")]
    async fn three_downlink_chunks_accumulate() {
        let mut session = open_framed(b"SSE", 0x11).await;
        let mut request = [0; 3];
        session.target.read_exact(&mut request).await.unwrap();
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        let mut expected = Vec::new();
        for tick in 0..3_u8 {
            let chunk = [b'S', tick];
            session.target.write_all(&chunk).await.unwrap();
            let need = decoded.len() + chunk.len();
            read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need)
                .await
                .unwrap();
            expected.extend_from_slice(&chunk);
        }
        assert_eq!(decoded, expected);
        finish_both(session, expected.len() as u64).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic: three 30s quiet downlink chunks"]
    async fn three_quiet_downlink_chunks_survive() {
        let mut session = open_framed(b"SSE", 0x11).await;
        let mut request = [0; 3];
        session.target.read_exact(&mut request).await.unwrap();
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        let mut expected = Vec::new();
        for tick in 0..3_u8 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let chunk = [b'S', tick];
            session.target.write_all(&chunk).await.unwrap();
            let need = decoded.len() + chunk.len();
            if let Err(error) =
                read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need).await
            {
                session.task.abort();
                panic!("chunk {tick} was not relayed: {error}");
            }
            expected.extend_from_slice(&chunk);
        }
        assert_eq!(decoded, expected);
        finish_both(session, expected.len() as u64).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "diagnostic: 120s pending write beside one quiet downlink"]
    async fn quiet_downlink_survives_a_parallel_pending_write() {
        let stall = tokio::spawn(pending_write_stalls_at_120s());
        let mut session = open_framed(b"SSE", 0x11).await;
        let mut request = [0; 3];
        session.target.read_exact(&mut request).await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        session.target.write_all(b"AB").await.unwrap();
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        let read = tokio::time::timeout(
            Duration::from_secs(60),
            read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 2),
        )
        .await;
        if !matches!(read, Ok(Ok(()))) || decoded != b"AB" {
            session.task.abort();
            panic!("parallel pending write hid the downlink chunk: {read:?} {decoded:?}");
        }
        let stall = stall.await.unwrap();
        assert!(
            stall.is_ok(),
            "parallel stall did not stay bounded: {stall:?}"
        );
        finish_both(session, 2).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic: one downlink chunk after 30s quiet"]
    async fn one_downlink_chunk_survives_a_quiet_30s() {
        let mut session = open_framed(b"SSE", 0x11).await;
        let mut request = [0; 3];
        session.target.read_exact(&mut request).await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        session.target.write_all(b"AB").await.unwrap();
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        let read = tokio::time::timeout(
            Duration::from_secs(5),
            read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 2),
        )
        .await;
        match read {
            Ok(Ok(())) => assert_eq!(decoded, b"AB"),
            other => {
                session.task.abort();
                panic!("downlink chunk was not relayed: {other:?}");
            }
        }
        finish_both(session, 2).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[ignore = "release qualification: real 600s authenticated connection matrix"]
    async fn authenticated_connections_survive_quiet_directions_for_600s() {
        let started = std::time::Instant::now();
        let (sse, websocket, quiet_downlink, delayed, half_close, stall) = tokio::join!(
            sse_downlink_for_600s(),
            websocket_for_600s(),
            quiet_downlink_for_600s(),
            delayed_response_after_180s(),
            half_close_after_crossing_120s(),
            pending_write_stalls_at_120s(),
        );
        sse.expect("SSE quiet uplink must survive 600s");
        websocket.expect("WebSocket session must survive 600s");
        quiet_downlink.expect("quiet downlink must survive 600s");
        delayed.expect("a response after 180s must not be a timeout");
        half_close.expect("half-close must drain the opposite direction");
        stall.expect("a pending write must hit the 120s stall bound");
        assert!(
            started.elapsed() >= Duration::from_secs(600),
            "the matrix must actually cross 600 elapsed seconds"
        );
    }

    struct LiveSession {
        client: TcpStream,
        client_write: Tls13RecordLayer,
        client_read: Tls13RecordLayer,
        encoder: VisionEncoder,
        target: TcpStream,
        task: tokio::task::JoinHandle<Result<super::VisionRelayStats, VisionSessionError>>,
    }

    async fn open_framed(initial: &[u8], seed: u8) -> LiveSession {
        let (client, inbound) = tcp_pair().await;
        let (destination, target) = tcp_pair().await;
        let (tls, client_write, client_read) = tls_states();
        let (reader, writer) = TlsApplicationIo::new(inbound, tls).into_owned_split();
        let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
            .expect("relay policy must compile");
        let mut encoder = VisionEncoder::with_padding_seed(USER, &[seed; 44]);
        let mut request = Vec::new();
        encoder
            .encode(initial, VisionCommand::Continue, false, &mut request)
            .expect("initial frame");
        let task = tokio::spawn(async move {
            super::run_resumed_session(
                reader,
                writer,
                destination,
                USER,
                request,
                &relay,
                crate::io_activity::WRITE_STALL_TIMEOUT,
            )
            .await
        });
        LiveSession {
            client,
            client_write,
            client_read,
            encoder,
            target,
            task,
        }
    }

    async fn read_exact_payload(
        session: &mut LiveSession,
        decoder: &mut VisionDecoder,
        decoded: &mut Vec<u8>,
        first: &mut bool,
        need: usize,
    ) -> io::Result<()> {
        while decoded.len() < need {
            let mut record = read_tls_record(&mut session.client, Duration::from_secs(60))
                .await
                .map_err(|error| io::Error::other(error.to_string()))?
                .into_wire();
            let opened = session
                .client_read
                .open_in_place(&mut record)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if opened.content_type() == ContentType::Alert {
                return Err(io::Error::other("alert before the expected payload"));
            }
            let payload = if *first {
                *first = false;
                opened
                    .plaintext()
                    .get(2..)
                    .ok_or_else(|| io::Error::other("missing VLESS response header"))?
            } else {
                opened.plaintext()
            };
            // `decode` clears the caller's buffer. Accumulated chunks must
            // survive the next record.
            decoder
                .decode_append(payload, decoded)
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(())
    }

    fn seal_uplink(session: &mut LiveSession, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut frame = Vec::new();
        session
            .encoder
            .encode(payload, VisionCommand::Continue, false, &mut frame)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut wire = Vec::new();
        session
            .client_write
            .seal_into(ContentType::ApplicationData, &frame, 0, &mut wire)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(wire)
    }

    async fn finish_both(mut session: LiveSession, downlink: u64) -> io::Result<()> {
        let mut alert = Vec::new();
        session
            .client_write
            .seal_into(ContentType::Alert, &[1, 0], 0, &mut alert)
            .map_err(|error| io::Error::other(error.to_string()))?;
        session.client.write_all(&alert).await?;
        let mut ignored = [0; 64];
        let _ = session.target.read(&mut ignored).await?;
        session.target.shutdown().await?;
        loop {
            let mut record = read_tls_record(&mut session.client, Duration::from_secs(30))
                .await
                .map_err(|error| io::Error::other(error.to_string()))?
                .into_wire();
            let opened = session
                .client_read
                .open_in_place(&mut record)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if opened.content_type() == ContentType::Alert {
                break;
            }
        }
        let stats = session
            .task
            .await
            .map_err(|error| io::Error::other(error.to_string()))?
            .map_err(|error| io::Error::other(error.to_string()))?;
        if stats.downlink_bytes() != downlink || stats.uplink_direct() || stats.downlink_direct() {
            return Err(io::Error::other(format!(
                "unexpected stats uplink={} downlink={} expected_downlink={downlink}",
                stats.uplink_bytes(),
                stats.downlink_bytes()
            )));
        }
        Ok(())
    }

    async fn sse_downlink_for_600s() -> io::Result<()> {
        let mut session = open_framed(b"SSE", 0x11).await;
        let mut request = [0; 3];
        session.target.read_exact(&mut request).await?;
        if &request != b"SSE" {
            session.task.abort();
            return Err(io::Error::other("SSE request was corrupted"));
        }
        let started = std::time::Instant::now();
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        let mut expected = Vec::new();
        let mut tick = 0_u8;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let chunk = [b'S', tick];
            tick = tick.wrapping_add(1);
            session.target.write_all(&chunk).await?;
            let need = decoded.len() + chunk.len();
            read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need).await?;
            expected.extend_from_slice(&chunk);
            if started.elapsed() >= Duration::from_secs(600) {
                break;
            }
        }
        if decoded != expected {
            session.task.abort();
            return Err(io::Error::other("SSE payload or duration failed"));
        }
        finish_both(session, expected.len() as u64).await
    }

    async fn websocket_for_600s() -> io::Result<()> {
        let mut session = open_framed(b"WS", 0x22).await;
        let mut request = [0; 2];
        session.target.read_exact(&mut request).await?;
        if &request != b"WS" {
            session.task.abort();
            return Err(io::Error::other("WebSocket request was corrupted"));
        }
        let started = std::time::Instant::now();
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        let mut expected_down = Vec::new();
        let mut tick = 0_u8;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let up = [b'u', tick];
            let down = [b'd', tick];
            tick = tick.wrapping_add(1);
            let wire = seal_uplink(&mut session, &up)?;
            session.client.write_all(&wire).await?;
            let mut got = [0; 2];
            session.target.read_exact(&mut got).await?;
            if got != up {
                session.task.abort();
                return Err(io::Error::other("WebSocket uplink was corrupted"));
            }
            session.target.write_all(&down).await?;
            let need = decoded.len() + down.len();
            read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need).await?;
            expected_down.extend_from_slice(&down);
            if started.elapsed() >= Duration::from_secs(600) {
                break;
            }
        }
        if decoded != expected_down {
            session.task.abort();
            return Err(io::Error::other("WebSocket payload or duration failed"));
        }
        finish_both(session, expected_down.len() as u64).await
    }

    async fn quiet_downlink_for_600s() -> io::Result<()> {
        let mut session = open_framed(b"UP", 0x33).await;
        let mut request = [0; 2];
        session.target.read_exact(&mut request).await?;
        if &request != b"UP" {
            session.task.abort();
            return Err(io::Error::other("uplink request was corrupted"));
        }
        let started = std::time::Instant::now();
        let mut tick = 0_u8;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let up = [b'q', tick];
            tick = tick.wrapping_add(1);
            let wire = seal_uplink(&mut session, &up)?;
            session.client.write_all(&wire).await?;
            let mut got = [0; 2];
            session.target.read_exact(&mut got).await?;
            if got != up {
                session.task.abort();
                return Err(io::Error::other("quiet-downlink uplink was corrupted"));
            }
            if started.elapsed() >= Duration::from_secs(600) {
                break;
            }
        }
        session.target.write_all(b"DONE").await?;
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 4).await?;
        if decoded != b"DONE" {
            session.task.abort();
            return Err(io::Error::other("delayed opposite payload was corrupted"));
        }
        finish_both(session, 4).await
    }

    async fn delayed_response_after_180s() -> io::Result<()> {
        let mut session = open_framed(b"WAIT", 0x44).await;
        let mut request = [0; 4];
        session.target.read_exact(&mut request).await?;
        if &request != b"WAIT" {
            session.task.abort();
            return Err(io::Error::other("delayed request was corrupted"));
        }
        let started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_secs(190)).await;
        if started.elapsed() < Duration::from_secs(180) {
            session.task.abort();
            return Err(io::Error::other("delay did not cross 180s"));
        }
        session.target.write_all(b"LATE").await?;
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 4).await?;
        if decoded != b"LATE" {
            session.task.abort();
            return Err(io::Error::other("late response was corrupted"));
        }
        finish_both(session, 4).await
    }

    async fn half_close_after_crossing_120s() -> io::Result<()> {
        let mut session = open_framed(b"HALF", 0x55).await;
        let mut request = [0; 4];
        session.target.read_exact(&mut request).await?;
        if &request != b"HALF" {
            session.task.abort();
            return Err(io::Error::other("half-close request was corrupted"));
        }
        session.target.write_all(b"ping").await?;
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 4).await?;
        let started = std::time::Instant::now();
        tokio::time::sleep(Duration::from_secs(130)).await;
        if started.elapsed() < Duration::from_secs(120) || decoded != b"ping" {
            session.task.abort();
            return Err(io::Error::other("half-close did not cross 120s intact"));
        }
        let mut alert = Vec::new();
        session
            .client_write
            .seal_into(ContentType::Alert, &[1, 0], 0, &mut alert)
            .map_err(|error| io::Error::other(error.to_string()))?;
        session.client.write_all(&alert).await?;
        let mut ignored = [0; 8];
        let end = session.target.read(&mut ignored).await?;
        if end != 0 {
            session.task.abort();
            return Err(io::Error::other(
                "uplink half-close did not reach the origin",
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        session.target.write_all(b"TAIL!").await?;
        session.target.shutdown().await?;
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 9).await?;
        if &decoded[4..] != b"TAIL!" {
            session.task.abort();
            return Err(io::Error::other("opposite drain was corrupted"));
        }
        loop {
            let mut record = read_tls_record(&mut session.client, Duration::from_secs(30))
                .await
                .map_err(|error| io::Error::other(error.to_string()))?
                .into_wire();
            let opened = session
                .client_read
                .open_in_place(&mut record)
                .map_err(|error| io::Error::other(error.to_string()))?;
            if opened.content_type() == ContentType::Alert {
                break;
            }
        }
        let stats = session
            .task
            .await
            .map_err(|error| io::Error::other(error.to_string()))?
            .map_err(|error| io::Error::other(error.to_string()))?;
        if stats.downlink_bytes() != 9 {
            return Err(io::Error::other("half-close downlink count mismatch"));
        }
        Ok(())
    }

    async fn pending_write_stalls_at_120s() -> io::Result<()> {
        let mut session = open_framed(b"STALL", 0x66).await;
        let mut request = [0; 5];
        session.target.read_exact(&mut request).await?;
        if &request != b"STALL" {
            session.task.abort();
            return Err(io::Error::other("stall request was corrupted"));
        }
        session.target.write_all(b"X").await?;
        let mut decoder = VisionDecoder::new(USER);
        let mut decoded = Vec::new();
        let mut first = true;
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 1).await?;
        if decoded != b"X" {
            session.task.abort();
            return Err(io::Error::other("stall prefix was corrupted"));
        }
        let started = std::time::Instant::now();
        let mut target = session.target;
        let task = session.task;
        let _flood = tokio::spawn(async move {
            // Larger than this host's 32 MiB TCP receive autotune plus the
            // 4 MiB send buffer, so the pending write actually blocks.
            let payload = vec![0x5a; 64 * 1024 * 1024];
            let _ = target.write_all(&payload).await;
        });
        let result = tokio::time::timeout(Duration::from_secs(170), task)
            .await
            .map_err(|_| io::Error::other("write stall exceeded 170s"))?
            .map_err(|error| io::Error::other(error.to_string()))?;
        let elapsed = started.elapsed();
        if elapsed < Duration::from_secs(115) {
            return Err(io::Error::other(format!(
                "write stall fired too early: {elapsed:?}"
            )));
        }
        match result {
            Err(VisionSessionError::Tls(
                crate::protocol::reality::tls13::TlsApplicationIoError::Timeout,
            )) => Ok(()),
            Err(VisionSessionError::Timeout) => Ok(()),
            other => Err(io::Error::other(format!(
                "pending write did not fail as a stall: {other:?}"
            ))),
        }
    }
}
