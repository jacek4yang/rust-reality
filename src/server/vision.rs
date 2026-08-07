use std::{
    error::Error,
    fmt, io,
    ops::Range,
    os::fd::AsRawFd as _,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::Instant,
};

use crate::{
    config::{Config, DnsStrategy, ResourceGovernorConfig},
    protocol::{
        handoff::ContinuationState,
        reality::tls13::{
            IdleDeadline, IdleError, MAX_PLAINTEXT_LEN, TlsApplicationIoError,
            TlsApplicationReader, TlsApplicationWriter, VectoredRead,
        },
        vless::{
            DecodeError, Destination, RequestHeader, RequestValidationError, UserId, UserRegistry,
            VISION_FRAME_SIZE, VisionCommand, VisionDecodeError, VisionDecoder, VisionEncodeError,
            VisionEncoder, VisionMode, VisionPayload, decode_request, encode_response_header,
        },
    },
};

use super::{
    direct::{DirectHandoff, Direction, DirectionState, InvalidTransition, RawDecision},
    handoff::HandoffLineError,
    outbound::{OutboundConnectError, OutboundConnectOutcome, OutboundRegistry},
    reality::RealityEstablished,
    routing::{AssetMatcher, RouteResolutionError, RoutingCompileError, RoutingTable},
};
use crate::transport::{
    BackendRequest, RelayBackend, RelayContext, RelayDirection, RelayOutcome, TcpRelay,
};

const MAX_REQUEST_HEADER_SIZE: usize = 533;
const MAX_REQUEST_BUFFER_SIZE: usize = MAX_REQUEST_HEADER_SIZE + MAX_PLAINTEXT_LEN;
const VISION_HEADER_SIZE: usize = 5;
const MAX_VISION_CONTENT_AFTER_FIRST_FRAME: usize = VISION_FRAME_SIZE - VISION_HEADER_SIZE;
const NESTED_TLS_HEADER_SIZE: usize = 5;
const MAX_NESTED_TLS_RECORD_SIZE: usize = (1 << 14) + 2_048;
const MAX_NESTED_SERVER_HELLO_SIZE: usize = 8 * 1024;
const MAX_CLASSIFICATION_RECORDS: u8 = 8;
const TLS_HANDSHAKE: u8 = 22;
const TLS_APPLICATION_DATA: u8 = 23;
const TLS_SERVER_HELLO: u8 = 2;
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// Counts and direct-transition results from one Vision relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VisionRelayStats {
    uplink_bytes: u64,
    downlink_bytes: u64,
    uplink_direct: bool,
    downlink_direct: bool,
    relay_backend: Option<RelayBackend>,
    uplink_direct_at_bytes: u64,
    downlink_direct_at_bytes: u64,
    uplink_backend: Option<RelayBackend>,
    downlink_backend: Option<RelayBackend>,
    uplink_handoff_delay_us: u64,
    downlink_handoff_delay_us: u64,
    pipe_capacity_downgraded: bool,
}

impl VisionRelayStats {
    /// Returns unpadded client bytes delivered to the destination.
    #[must_use]
    pub const fn uplink_bytes(self) -> u64 {
        self.uplink_bytes
    }

    /// Returns destination bytes delivered to the client.
    #[must_use]
    pub const fn downlink_bytes(self) -> u64 {
        self.downlink_bytes
    }

    /// Returns whether the client authenticated a Vision Direct command.
    #[must_use]
    pub const fn uplink_direct(self) -> bool {
        self.uplink_direct
    }

    /// Returns whether the server completed a Vision Direct write boundary.
    #[must_use]
    pub const fn downlink_direct(self) -> bool {
        self.downlink_direct
    }

    /// Returns the backend that ran the raw relay after a bilateral handoff.
    #[must_use]
    pub const fn relay_backend(self) -> Option<RelayBackend> {
        self.relay_backend
    }

    /// Returns uplink bytes delivered before the uplink Direct boundary.
    #[must_use]
    pub const fn uplink_direct_at_bytes(self) -> u64 {
        self.uplink_direct_at_bytes
    }

    /// Returns downlink bytes delivered before the downlink Direct boundary.
    #[must_use]
    pub const fn downlink_direct_at_bytes(self) -> u64 {
        self.downlink_direct_at_bytes
    }

    /// Returns the backend that moved the uplink's raw bytes, when direct.
    #[must_use]
    pub const fn uplink_backend(self) -> Option<RelayBackend> {
        self.uplink_backend
    }

    /// Returns the backend that moved the downlink's raw bytes, when direct.
    #[must_use]
    pub const fn downlink_backend(self) -> Option<RelayBackend> {
        self.downlink_backend
    }

    /// Returns microseconds from the uplink boundary to its raw relay start.
    #[must_use]
    pub const fn uplink_handoff_delay_us(self) -> u64 {
        self.uplink_handoff_delay_us
    }

    /// Returns microseconds from the downlink boundary to its raw relay start.
    #[must_use]
    pub const fn downlink_handoff_delay_us(self) -> u64 {
        self.downlink_handoff_delay_us
    }

    /// Returns whether a raw-relay backend was granted less pipe capacity
    /// than requested because kernel pipe-page limits downgraded it.
    #[must_use]
    pub const fn pipe_capacity_downgraded(self) -> bool {
        self.pipe_capacity_downgraded
    }
}

/// Immutable Vision data path with UUID-grouped routing and outbound selection.
#[derive(Clone)]
pub struct VisionHandler {
    outbounds: OutboundRegistry,
    routing: RoutingTable,
    relay: TcpRelay,
    request_timeout: Duration,
    io_timeout: Duration,
    dns_strategy: DnsStrategy,
    dns_timeout: Duration,
}

impl VisionHandler {
    /// Compiles validated config and one immutable asset snapshot.
    ///
    /// # Errors
    ///
    /// Returns a routing matcher or UUID compilation error.
    pub fn from_config(
        config: &Config,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
    ) -> Result<Self, RoutingCompileError> {
        Self::build(config, assets, relay, None)
    }

    /// Compiles the data path with a pressure-aware outbound registry.
    ///
    /// # Errors
    ///
    /// Returns a routing matcher or UUID compilation error.
    pub fn from_config_with_pressure(
        config: &Config,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
        pressure: &crate::runtime::PressureGauge,
        direct_barrier: crate::runtime::DirectBarrier,
        governor: crate::runtime::ResourceGovernor,
    ) -> Result<Self, RoutingCompileError> {
        Self::build(
            config,
            assets,
            relay,
            Some((pressure.clone(), direct_barrier, governor)),
        )
    }

    fn build(
        config: &Config,
        assets: Arc<dyn AssetMatcher>,
        relay: TcpRelay,
        authorities: Option<(
            crate::runtime::PressureGauge,
            crate::runtime::DirectBarrier,
            crate::runtime::ResourceGovernor,
        )>,
    ) -> Result<Self, RoutingCompileError> {
        let governor = &config.policy.resource_governor;
        let connect_timeout = Duration::from_millis(governor.connect_timeout_ms);
        let (outbounds, dns_governor) = match authorities {
            Some((_pressure, direct_barrier, dns_governor)) => (
                OutboundRegistry::with_barrier(
                    &config.outbounds,
                    direct_barrier,
                    connect_timeout,
                    relay.fd_budget().clone(),
                ),
                dns_governor,
            ),
            None => (
                OutboundRegistry::new(
                    &config.outbounds,
                    &config.policy.direct_barrier,
                    connect_timeout,
                    relay.fd_budget().clone(),
                ),
                crate::runtime::ResourceGovernor::new(governor),
            ),
        };
        Ok(Self::new_with_dns(
            outbounds,
            RoutingTable::compile(&config.routing, assets, dns_governor)?,
            relay,
            governor,
            config.routing.domain_strategy,
            Duration::from_millis(config.dns.timeout_ms),
        ))
    }

    /// Binds compiled routing and outbound snapshots to bounded session timeouts.
    #[must_use]
    pub fn new(
        outbounds: OutboundRegistry,
        routing: RoutingTable,
        relay: TcpRelay,
        governor: &ResourceGovernorConfig,
    ) -> Self {
        Self::new_with_dns(
            outbounds,
            routing,
            relay,
            governor,
            DnsStrategy::AsIs,
            Duration::from_secs(5),
        )
    }

    /// Binds routing to an explicit bounded DNS strategy.
    #[must_use]
    pub fn new_with_dns(
        outbounds: OutboundRegistry,
        routing: RoutingTable,
        relay: TcpRelay,
        governor: &ResourceGovernorConfig,
        dns_strategy: DnsStrategy,
        dns_timeout: Duration,
    ) -> Self {
        Self {
            outbounds,
            routing,
            relay,
            request_timeout: Duration::from_millis(governor.handshake_timeout_ms),
            io_timeout: Duration::from_millis(governor.fallback_timeout_ms),
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
        let (application, users, inbound_tag) = established.into_parts();
        let (mut client_reader, mut client_writer) = application.into_owned_split();
        let request = read_vision_request(&mut client_reader, &users, self.request_timeout).await?;
        let route = self
            .routing
            .select_with_dns(
                request.user_id,
                &inbound_tag,
                &request.destination,
                self.dns_strategy,
                self.dns_timeout,
            )
            .await
            .map_err(VisionSessionError::Route)?;
        // The session-handoff boundary: routing has selected the outbound, the
        // downlink TLS direction is still at sequence zero with nothing
        // written, and no Vision encoder or decoder exists yet. A handoff
        // outbound transfers the session to the landing node here and this
        // node never touches its TLS or Vision state again.
        if let Some(line) = self.outbounds.handoff_line(route.decision().outbound()) {
            return self
                .relay_via_handoff(&line, client_reader, client_writer, request, client_random)
                .await;
        }
        let outcome = self
            .outbounds
            .connect_resolved(
                route.decision().outbound(),
                &request.destination,
                route.resolved_ips(),
            )
            .await
            .map_err(VisionSessionError::Outbound)?;
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            client_writer
                .shutdown(self.io_timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(VisionRelayStats {
                uplink_bytes: 0,
                downlink_bytes: 0,
                uplink_direct: false,
                downlink_direct: false,
                relay_backend: None,
                uplink_direct_at_bytes: 0,
                downlink_direct_at_bytes: 0,
                uplink_backend: None,
                downlink_backend: None,
                uplink_handoff_delay_us: 0,
                downlink_handoff_delay_us: 0,
                pipe_capacity_downgraded: false,
            });
        };
        let (destination, outbound_permit) = connection.into_parts();
        let (destination_reader, destination_writer) = destination.into_split();
        let user_id = request.user_id;
        let response_header = encode_response_header(&request.header, &[])
            .map_err(VisionSessionError::ResponseHeader)?;

        // One coordinator per session. It holds two atomics, four socket-half
        // slots, and a version watch; never a queue and never a payload.
        let handoff = DirectHandoff::new();
        let context = SessionContext {
            timeout: self.io_timeout,
            handoff: &handoff,
            relay: &self.relay,
        };
        let uplink = relay_uplink(
            client_reader,
            destination_writer,
            user_id,
            request.buffer,
            request.prefetched,
            &context,
        );
        let downlink = relay_downlink(
            destination_reader,
            client_writer,
            user_id,
            &response_header,
            &context,
        );
        let (uplink, downlink) = tokio::try_join!(uplink, downlink)?;
        drop(outbound_permit);
        Ok(session_stats(uplink, downlink))
    }

    /// Transfers one boundary-session to a Handoff landing node, then relays
    /// the client socket against the handoff socket raw in both directions.
    ///
    /// The continuation carries both record layers, the reader's read-ahead
    /// ciphertext, and the prefetched VLESS payload; afterwards this node
    /// never decrypts or frames the session again. Any failure — dial, seal,
    /// or write — leaves the abort guard armed, so the client socket is reset
    /// rather than half-closed and the session is never served locally with
    /// consumed state. A successful transfer always produces immediate
    /// downlink (the response header and opening Vision frame are LANDING's
    /// first sealed record), while every rejection closes the connection
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
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let client_fd = client_reader.fd();
        let (pending, client_read_half, client_records) = client_reader.into_handoff_parts();
        let (client_write_half, server_records) = client_writer.into_handoff_parts();
        // Until the transfer provably lands, the guard covers only the client
        // socket (twice — the second abort is an idempotent setsockopt); the
        // landing descriptor takes its place once it exists.
        let mut guard = DirectionAbortGuard::new(client_fd, client_fd);
        let (suite, client_traffic, client_sequence) =
            client_records.into_exported_state().into_parts();
        let (_suite, server_traffic, server_sequence) =
            server_records.into_exported_state().into_parts();
        let prefetched = request
            .buffer
            .get(request.prefetched.clone())
            .unwrap_or_default()
            .to_vec();
        let state = ContinuationState::new(
            suite,
            client_traffic,
            client_sequence,
            server_traffic,
            server_sequence,
            *request.user_id.as_bytes(),
            request.destination.clone(),
            true,
            pending,
            prefetched,
        )
        .map_err(HandoffLineError::Transfer)
        .map_err(VisionSessionError::HandoffLine)?;
        let (handoff_stream, _fd_permit) = line
            .transfer(self.relay.fd_budget(), &state, client_random)
            .await
            .map_err(VisionSessionError::HandoffLine)?;
        guard.fds[1] = handoff_stream.as_raw_fd();
        let client_stream = client_read_half
            .reunite(client_write_half)
            .map_err(|_| VisionSessionError::HandoffLine(HandoffLineError::Reunite))?;
        // Classify the silent protocol's only failure signal before any socket
        // moves into the relay: no TLS downlink byte within the deadline means
        // rejection. The guard's descriptors are still open here, so dropping
        // it armed aborts both sockets (SO_LINGER {on,0}); they close as whole
        // streams right after, delivering RST — never FIN — and the session's
        // descriptors, permits, and pipes are not held until the idle timeout.
        if !super::handoff::first_downlink_landed(
            &handoff_stream,
            super::handoff::LANDING_FIRST_BYTE_TIMEOUT,
        )
        .await
        {
            drop(guard);
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        let outcome = self
            .relay
            .relay_owned(
                client_stream,
                handoff_stream,
                RelayContext::owned().with_liveness(self.io_timeout),
            )
            .await
            .map_err(HandoffLineError::Relay)
            .map_err(VisionSessionError::HandoffLine)?;
        // Backstop for the first-byte probe above: a completed relay that
        // moved zero downlink bytes still reads as a rejection.
        if outcome.outbound_to_inbound() == 0 {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        guard.disarm();
        // The counts are raw ciphertext bytes moved by the splice, matching how
        // the Direct transition counts its raw phase.
        Ok(VisionRelayStats {
            uplink_bytes: outcome.inbound_to_outbound(),
            downlink_bytes: outcome.outbound_to_inbound(),
            uplink_direct: false,
            downlink_direct: false,
            relay_backend: Some(outcome.backend()),
            uplink_direct_at_bytes: 0,
            downlink_direct_at_bytes: 0,
            uplink_backend: None,
            downlink_backend: None,
            uplink_handoff_delay_us: 0,
            downlink_handoff_delay_us: 0,
            pipe_capacity_downgraded: outcome.pipe_downgrade().is_some(),
        })
    }
}

struct AcceptedVisionRequest {
    header: RequestHeader,
    user_id: UserId,
    destination: Destination,
    /// The retained request buffer. The prefetched payload is a range inside it,
    /// so no copy is made when the VLESS header and its payload prefix arrive in
    /// the same record.
    buffer: Vec<u8>,
    prefetched: Range<usize>,
}

/// Combines both directions' counters into per-session relay statistics.
fn session_stats(uplink: DirectionStats, downlink: DirectionStats) -> VisionRelayStats {
    let handed_off = uplink.handoff.or(downlink.handoff);
    let (handed_up, handed_down) = handed_off.map_or((0, 0), |outcome| {
        (outcome.inbound_to_outbound(), outcome.outbound_to_inbound())
    });
    let pair_backend = handed_off.map(RelayOutcome::backend);
    VisionRelayStats {
        uplink_bytes: uplink.bytes.saturating_add(handed_up),
        downlink_bytes: downlink.bytes.saturating_add(handed_down),
        uplink_direct: uplink.direct,
        downlink_direct: downlink.direct,
        relay_backend: pair_backend,
        uplink_direct_at_bytes: uplink.direct_at_bytes,
        downlink_direct_at_bytes: downlink.direct_at_bytes,
        // A pair outcome exists only when both directions committed to the
        // bilateral handoff, so a directional backend and the pair backend
        // can never both be present for one direction.
        uplink_backend: uplink.backend.or(pair_backend),
        downlink_backend: downlink.backend.or(pair_backend),
        uplink_handoff_delay_us: uplink.handoff_delay_us,
        downlink_handoff_delay_us: downlink.handoff_delay_us,
        pipe_capacity_downgraded: handed_off.and_then(RelayOutcome::pipe_downgrade).is_some()
            || uplink.pipe_downgrade
            || downlink.pipe_downgrade,
    }
}

/// Runs the standard Vision relay for a session resumed from a Handoff
/// transfer on a landing node.
///
/// The resumed halves carry the transferred record layers, and the reader is
/// preloaded with the read-ahead ciphertext the previous owner had already
/// consumed from the kernel, so the client-visible record stream continues
/// exactly at the boundary. `prefetched_plaintext` enters the fresh Vision
/// decoder before any decrypted record, mirroring the freshly accepted path.
/// The response header and opening Vision frame are the first sealed server
/// record, which the transfer channel guarantees sits at sequence zero.
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
    // Identical to `encode_response_header(&request.header, &[])`: the VLESS
    // version is fixed and this implementation never negotiates addons.
    let response_header = [crate::protocol::vless::VERSION, 0];
    let prefetched = 0..prefetched_plaintext.len();
    let handoff = DirectHandoff::new();
    let context = SessionContext {
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
    let (uplink, downlink) = tokio::try_join!(uplink, downlink)?;
    Ok(session_stats(uplink, downlink))
}

async fn read_vision_request<R>(
    reader: &mut TlsApplicationReader<R>,
    users: &UserRegistry,
    timeout: Duration,
) -> Result<AcceptedVisionRequest, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let deadline = operation_deadline(timeout)?;
    let mut buffer = Vec::with_capacity(MAX_REQUEST_BUFFER_SIZE);

    loop {
        match decode_request(&buffer) {
            Ok(decoded) => {
                let (header, payload) = decoded.into_parts();
                let payload_len = payload.len();
                let destination = users
                    .authorize_vision_tcp(&header)
                    .map_err(VisionSessionError::Validate)?
                    .clone();
                let prefetched_start = buffer.len().saturating_sub(payload_len);
                return Ok(AcceptedVisionRequest {
                    user_id: header.user_id(),
                    header,
                    destination,
                    prefetched: prefetched_start..buffer.len(),
                    buffer,
                });
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

struct DirectionStats {
    bytes: u64,
    direct: bool,
    /// Byte counts produced by the unified raw relay, present only on the
    /// direction that deposited its sockets last and therefore ran the relay.
    handoff: Option<RelayOutcome>,
    /// The backend that moved this direction's raw bytes: the directional
    /// backend for an independent relay, or the pair backend for the direction
    /// that ran the bilateral relay.
    backend: Option<RelayBackend>,
    /// Bytes this direction had delivered when it reached its Direct boundary.
    direct_at_bytes: u64,
    /// Microseconds from the boundary to the deposit or directional relay start.
    handoff_delay_us: u64,
    /// The backend's pipe capacity was downgraded by kernel pipe-page limits.
    pipe_downgrade: bool,
}

impl DirectionStats {
    const fn framed(bytes: u64) -> Self {
        Self {
            bytes,
            direct: false,
            handoff: None,
            backend: None,
            direct_at_bytes: 0,
            handoff_delay_us: 0,
            pipe_downgrade: false,
        }
    }

    const fn direct(
        bytes: u64,
        handoff: Option<RelayOutcome>,
        backend: Option<RelayBackend>,
        direct_at_bytes: u64,
        handoff_delay_us: u64,
        pipe_downgrade: bool,
    ) -> Self {
        Self {
            bytes,
            direct: true,
            handoff,
            backend,
            direct_at_bytes,
            handoff_delay_us,
            pipe_downgrade,
        }
    }
}

/// Immutable per-session state shared by both relay directions.
///
/// Bundling these three keeps the direction entry points inside the repository's
/// argument-count lint without hiding anything: the coordinator and the relay
/// are borrowed, never cloned per connection.
struct SessionContext<'session> {
    timeout: Duration,
    handoff: &'session DirectHandoff,
    relay: &'session TcpRelay,
}

/// Resets both sockets with `SO_LINGER {on,0}` if the direction ends without
/// being disarmed — cancellation via `try_join`, shutdown abort, or any error
/// path. An aborted transfer must be distinguishable from graceful
/// completion: the peer observes a reset, never a clean short EOF. Graceful
/// exits disarm the guard, preserving FIN and independent half-close.
struct DirectionAbortGuard {
    fds: [std::os::fd::RawFd; 2],
    disarmed: bool,
}

impl DirectionAbortGuard {
    const fn new(client_fd: std::os::fd::RawFd, destination_fd: std::os::fd::RawFd) -> Self {
        Self {
            fds: [client_fd, destination_fd],
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for DirectionAbortGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        for fd in self.fds {
            let _ignored = rr_linux::socket::abort_linger(fd);
        }
    }
}

async fn relay_uplink(
    client: TlsApplicationReader<OwnedReadHalf>,
    destination: OwnedWriteHalf,
    user_id: UserId,
    request_buffer: Vec<u8>,
    prefetched: Range<usize>,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let mut guard = DirectionAbortGuard::new(client.fd(), destination.as_ref().as_raw_fd());
    let result = relay_uplink_inner(
        client,
        destination,
        user_id,
        request_buffer,
        prefetched,
        context,
    )
    .await;
    if result.is_ok() {
        guard.disarm();
    }
    result
}

async fn relay_uplink_inner(
    mut client: TlsApplicationReader<OwnedReadHalf>,
    mut destination: OwnedWriteHalf,
    user_id: UserId,
    request_buffer: Vec<u8>,
    prefetched: Range<usize>,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let mut decoder = VisionDecoder::new(user_id);
    let mut plaintext = Vec::new();
    // A raw-mode record can carry a full maximum-sized TLS plaintext; the
    // staged output is reserved for that worst case exactly once.
    plaintext
        .try_reserve_exact(MAX_PLAINTEXT_LEN)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    let mut idle = IdleDeadline::new();
    let mut bytes = 0_u64;

    // The prefetched payload is a borrowed range inside the retained request
    // buffer. It is decoded before the record loop starts so that the loop below
    // never has to reconcile two different input lifetimes, and so that no copy
    // of the payload is ever made.
    if let Some(initial) = request_buffer.get(prefetched.clone())
        && !initial.is_empty()
    {
        let mode = decoder
            .decode(initial, &mut plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        if !plaintext.is_empty() {
            idle.reset(timeout).map_err(idle_failure)?;
            idle.write_all(&mut destination, &plaintext)
                .await
                .map_err(idle_failure)?;
            bytes = bytes.saturating_add(length_u64(plaintext.len()));
        }
        if mode == VisionMode::Direct {
            return finish_uplink_direct(client, destination, bytes, context).await;
        }
    }
    drop(request_buffer);

    loop {
        // Raw-mode records are relayed straight out of the reader's reusable
        // record storage: the decoder borrows the payload from the record, so
        // the steady-state uplink performs no per-record copy at all. The
        // borrow of the record storage ends before the next read or the
        // socket handoff.
        let record = match client.read_application(timeout).await {
            Ok(record) => record,
            Err(TlsApplicationIoError::PeerAlert {
                level: _,
                description: 0,
            }) => {
                idle.reset(timeout).map_err(idle_failure)?;
                idle.shutdown(&mut destination)
                    .await
                    .map_err(idle_failure)?;
                settle(handoff, Direction::Uplink, DirectionState::Closed);
                return Ok(DirectionStats::framed(bytes));
            }
            Err(error) => {
                settle(handoff, Direction::Uplink, DirectionState::Failed);
                return Err(VisionSessionError::Tls(error));
            }
        };
        if record.is_empty() {
            continue;
        }
        let (mode, payload) = decoder
            .decode_borrowed(record.plaintext(), &mut plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        let content = match payload {
            VisionPayload::Borrowed(bytes) => bytes,
            VisionPayload::Staged => plaintext.as_slice(),
        };
        if !content.is_empty() {
            idle.reset(timeout).map_err(idle_failure)?;
            idle.write_all(&mut destination, content)
                .await
                .map_err(idle_failure)?;
            bytes = bytes.saturating_add(length_u64(content.len()));
        }
        if mode == VisionMode::Direct {
            return finish_uplink_direct(client, destination, bytes, context).await;
        }
    }
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

async fn relay_downlink(
    destination: OwnedReadHalf,
    client: TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    response_header: &[u8],
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let nested = NestedRecordReader::new(destination);
    let mut guard = DirectionAbortGuard::new(client.fd(), nested.fd());
    let result = relay_downlink_inner(nested, client, user_id, response_header, context).await;
    if result.is_ok() {
        guard.disarm();
    }
    result
}

async fn relay_downlink_inner(
    mut destination: NestedRecordReader,
    mut client: TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    response_header: &[u8],
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
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
                return Ok(DirectionStats::framed(bytes));
            }
            NestedRead::Unframed(content) => {
                bytes = bytes.saturating_add(length_u64(content.len()));
                write_vision_content(
                    &mut client,
                    &mut encoder,
                    content,
                    VisionCommand::End,
                    false,
                    timeout,
                )
                .await?;
                settle(handoff, Direction::Downlink, DirectionState::Outer);
                bytes = bytes.saturating_add(
                    relay_outer_downlink(&mut destination, &mut client, timeout).await?,
                );
                settle(handoff, Direction::Downlink, DirectionState::Closed);
                return Ok(DirectionStats::framed(bytes));
            }
            NestedRead::Record(record) => {
                bytes = bytes.saturating_add(length_u64(record.len()));
                let decision = detector.observe(record);
                let command = match decision {
                    PaddingDecision::Continue => VisionCommand::Continue,
                    PaddingDecision::End => VisionCommand::End,
                    PaddingDecision::Direct => VisionCommand::Direct,
                };
                write_vision_content(&mut client, &mut encoder, record, command, true, timeout)
                    .await?;

                match decision {
                    PaddingDecision::Continue => {}
                    PaddingDecision::End => {
                        settle(handoff, Direction::Downlink, DirectionState::Outer);
                        bytes = bytes.saturating_add(
                            relay_outer_downlink(&mut destination, &mut client, timeout).await?,
                        );
                        settle(handoff, Direction::Downlink, DirectionState::Closed);
                        return Ok(DirectionStats::framed(bytes));
                    }
                    PaddingDecision::Direct => {
                        return finish_downlink_direct(destination, client, bytes, context).await;
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

/// Byte counters at a raw boundary.
///
/// `total` is every byte the direction delivered, including pending bytes
/// drained out of a socket buffer; `direct_at` is the framed-only count the
/// direction had delivered when it reached its Direct boundary, which excludes
/// the raw phase whether the bytes were drained or relayed.
#[derive(Clone, Copy)]
struct BoundaryBytes {
    total: u64,
    direct_at: u64,
}

/// Runs one independent directional raw relay at a Direct boundary.
///
/// A benign peer-teardown race (`BrokenPipe`, `ConnectionReset`, or the raw
/// stage's idle-policy `TimedOut` on an untouched ledger) closes the
/// direction cleanly with its accumulated stats instead of failing the whole
/// session; a liveness timeout after bytes moved aborts both sockets and
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
            BackendRequest::Automatic,
            Some(timeout),
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
            RelayContext::owned().with_liveness(timeout),
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

/// Returns whether a raw-stage I/O error is a benign peer-teardown race.
///
/// A reset or broken pipe once the raw relay owns the sockets means the peer
/// tore the connection down mid-transfer. An idle `TimedOut` reaching here
/// never moved a byte: the relay reclassifies a liveness timeout that
/// truncated a live transfer as `ConnectionAborted` after resetting both
/// sockets, so a `TimedOut` is always the relay's own liveness policy ending
/// a stalled, untouched direction — a clean teardown from the session's
/// perspective, never a transport failure. In all three cases the session's
/// accumulated counts stay valid and must not be suppressed by a
/// session-level relay error.
fn is_benign_teardown(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
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
/// Two scheduling points — never a sleep, a timer, or a wait on the peer — let
/// a peer whose own boundary flight is already queued observe `RawReady` and
/// become pairable before this direction commits. The commit itself is the
/// mutex-serialized [`DirectHandoff::decide`]: the peer read and the state
/// transition are one critical section, so the two directions can never
/// disagree about the relay form — a peer that observed `RawReady` or
/// `PairPending` pairs, and a peer that observed `Relaying` relays
/// directionally, with no interleaving in between.
async fn decide_raw_relay(
    handoff: &DirectHandoff,
    direction: Direction,
) -> Result<RawDecision, InvalidTransition> {
    for attempt in 0..3 {
        if handoff.peer_can_pair(direction) || attempt == 2 {
            break;
        }
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

/// The outcome of one nested-record read from the buffered connection storage.
///
/// Both non-EOF variants borrow their bytes from the reader's socket buffer
/// rather than copying into an owned `Vec`, which removes the per-record
/// downlink allocation. The borrow ends before the next read.
enum NestedRead<'a> {
    Eof,
    Record(&'a [u8]),
    Unframed(&'a [u8]),
}

/// Capacity of the nested reader's socket buffer.
///
/// Four maximum-sized nested records per refill, so a burst of destination
/// records costs one syscall per refill instead of one header read plus one
/// body read per record.
const NESTED_SOCKET_BUFFER_CAPACITY: usize =
    4 * (NESTED_TLS_HEADER_SIZE + MAX_NESTED_TLS_RECORD_SIZE);

/// Buffered nested-TLS record reader over the destination's read half.
///
/// The same grow-only socket-buffer mechanics as the outer TLS reader: one
/// refill moves available destination bytes into the connection-owned buffer
/// with a single socket read, and nested records are classified out of the
/// buffered range. Bytes buffered beyond an unframed prefix or a Direct
/// boundary stay owned by the reader: the outer downlink relay drains them
/// first through the `AsyncRead` impl, and the Direct transition hands them to
/// the caller via [`NestedRecordReader::into_inner_with_pending`].
struct NestedRecordReader {
    io: OwnedReadHalf,
    socket_buffer: Vec<u8>,
    buffered_start: usize,
    buffered_end: usize,
    idle: IdleDeadline,
}

impl NestedRecordReader {
    /// Returns the raw destination descriptor for abort-path socket options.
    fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self.io.as_ref().as_raw_fd()
    }

    fn new(io: OwnedReadHalf) -> Self {
        Self {
            io,
            socket_buffer: Vec::new(),
            buffered_start: 0,
            buffered_end: 0,
            idle: IdleDeadline::new(),
        }
    }

    /// Classifies the next nested record out of the buffered range.
    ///
    /// The classification semantics are exactly the record-exact reader's: EOF
    /// before any byte is `Eof`; socket EOF with fewer than five buffered bytes
    /// yields the remaining bytes as `Unframed`; a header that fails
    /// [`looks_like_tls_record_header`] or declares a body above
    /// [`MAX_NESTED_TLS_RECORD_SIZE`] yields the five header bytes as
    /// `Unframed` while any remaining buffered bytes stay owned by the reader;
    /// EOF inside an otherwise accepted record is
    /// [`VisionSessionError::DestinationTruncatedTlsRecord`].
    async fn next(&mut self, timeout: Duration) -> Result<NestedRead<'_>, VisionSessionError> {
        while self.buffered_end - self.buffered_start < NESTED_TLS_HEADER_SIZE {
            if !self.refill(timeout).await? {
                let start = self.buffered_start;
                let remaining = self.buffered_end - start;
                if remaining == 0 {
                    return Ok(NestedRead::Eof);
                }
                self.buffered_start = self.buffered_end;
                return Ok(NestedRead::Unframed(
                    self.socket_buffer
                        .get(start..self.buffered_end)
                        .unwrap_or_default(),
                ));
            }
        }
        let header_end = self.buffered_start + NESTED_TLS_HEADER_SIZE;
        let header: [u8; NESTED_TLS_HEADER_SIZE] = self
            .socket_buffer
            .get(self.buffered_start..header_end)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(VisionSessionError::DestinationTruncatedTlsRecord)?;
        let body_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if !looks_like_tls_record_header(&header) || body_length > MAX_NESTED_TLS_RECORD_SIZE {
            let start = self.buffered_start;
            self.buffered_start = header_end;
            return Ok(NestedRead::Unframed(
                self.socket_buffer
                    .get(start..header_end)
                    .unwrap_or_default(),
            ));
        }

        let record_length = NESTED_TLS_HEADER_SIZE + body_length;
        while self.buffered_end - self.buffered_start < record_length {
            if !self.refill(timeout).await? {
                return Err(VisionSessionError::DestinationTruncatedTlsRecord);
            }
        }
        let start = self.buffered_start;
        self.buffered_start = start + record_length;
        Ok(NestedRead::Record(
            self.socket_buffer
                .get(start..start + record_length)
                .unwrap_or_default(),
        ))
    }

    /// Moves available socket bytes into the buffer under one idle window.
    ///
    /// Returns `false` on socket EOF. The buffer is allocated and zero-filled
    /// once, compacted only when the free tail can no longer hold one
    /// maximum-sized nested record, and grown only if a single record ever
    /// needs more than the whole buffer.
    async fn refill(&mut self, timeout: Duration) -> Result<bool, VisionSessionError> {
        if self.socket_buffer.capacity() == 0 {
            let mut buffer = Vec::new();
            buffer
                .try_reserve_exact(NESTED_SOCKET_BUFFER_CAPACITY)
                .map_err(|_| VisionSessionError::AllocationFailed)?;
            buffer.resize(NESTED_SOCKET_BUFFER_CAPACITY, 0);
            self.socket_buffer = buffer;
        }
        if self.buffered_start == self.buffered_end {
            self.buffered_start = 0;
            self.buffered_end = 0;
        } else if self.socket_buffer.len() - self.buffered_end
            < NESTED_TLS_HEADER_SIZE + MAX_NESTED_TLS_RECORD_SIZE
        {
            let buffered = self.buffered_end - self.buffered_start;
            self.socket_buffer
                .copy_within(self.buffered_start..self.buffered_end, 0);
            self.buffered_start = 0;
            self.buffered_end = buffered;
        }
        if self.buffered_end == self.socket_buffer.len() {
            self.socket_buffer
                .try_reserve_exact(NESTED_SOCKET_BUFFER_CAPACITY)
                .map_err(|_| VisionSessionError::AllocationFailed)?;
            self.socket_buffer
                .resize(self.socket_buffer.len() + NESTED_SOCKET_BUFFER_CAPACITY, 0);
        }
        self.idle
            .reset(timeout)
            .map_err(|_| VisionSessionError::Timeout)?;
        let end = self.buffered_end;
        let destination = self
            .socket_buffer
            .get_mut(end..)
            .ok_or(VisionSessionError::AllocationFailed)?;
        let read = self
            .idle
            .read(&mut self.io, destination)
            .await
            .map_err(idle_failure)?;
        if read == 0 {
            return Ok(false);
        }
        self.buffered_end += read;
        Ok(true)
    }

    /// Consumes the reader and returns unparsed buffered bytes plus the transport.
    ///
    /// Every buffered byte is a post-boundary raw byte the destination
    /// pipelined behind its boundary record; the caller must deliver them, in
    /// order, ahead of every byte any raw relay moves.
    fn into_inner_with_pending(self) -> (Vec<u8>, OwnedReadHalf) {
        let pending = self
            .socket_buffer
            .get(self.buffered_start..self.buffered_end)
            .unwrap_or_default()
            .to_vec();
        (pending, self.io)
    }
}

impl AsyncRead for NestedRecordReader {
    /// Drains buffered bytes before touching the socket.
    ///
    /// The outer downlink relay reads through this impl, so bytes buffered by
    /// the classification reads are forwarded ahead of — never lost behind —
    /// the bytes still in the kernel.
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let buffered = self.buffered_end - self.buffered_start;
        if buffered > 0 {
            let start = self.buffered_start;
            let count = buffered.min(buffer.remaining());
            buffer.put_slice(
                self.socket_buffer
                    .get(start..start + count)
                    .unwrap_or_default(),
            );
            self.buffered_start += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(context, buffer)
    }
}

impl VectoredRead for NestedRecordReader {
    /// Drains buffered bytes into the first buffer, otherwise one `readv`.
    ///
    /// Buffered bytes are the rare post-classification leftovers; they fill
    /// only the first non-empty buffer, exactly like the scalar
    /// [`AsyncRead`] impl. Once the buffer is empty the call forwards to one
    /// vectored socket read, which is what lets the batched downlink relay
    /// (experiment D11) fill several record slots per syscall.
    async fn read_vectored<'buf>(
        &'buf mut self,
        buffers: &'buf mut [io::IoSliceMut<'buf>],
    ) -> io::Result<usize> {
        let buffered = self.buffered_end - self.buffered_start;
        if buffered > 0 {
            let Some(first) = buffers.iter_mut().find(|buffer| !buffer.is_empty()) else {
                return Ok(0);
            };
            let count = buffered.min(first.len());
            let start = self.buffered_start;
            first[..count].copy_from_slice(
                self.socket_buffer
                    .get(start..start + count)
                    .unwrap_or_default(),
            );
            self.buffered_start += count;
            return Ok(count);
        }
        loop {
            self.io.readable().await?;
            match self.io.try_read_vectored(buffers) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

const fn looks_like_tls_record_header(header: &[u8; NESTED_TLS_HEADER_SIZE]) -> bool {
    matches!(header[0], 20..=23) && header[1] == 0x03 && header[2] <= 0x04
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaddingDecision {
    Continue,
    End,
    Direct,
}

#[derive(Debug)]
struct NestedTlsDetector {
    records_seen: u8,
    server_hello: Vec<u8>,
    server_hello_length: Option<usize>,
    tls13: Option<bool>,
}

impl NestedTlsDetector {
    const fn new() -> Self {
        Self {
            records_seen: 0,
            server_hello: Vec::new(),
            server_hello_length: None,
            tls13: None,
        }
    }

    fn observe(&mut self, record: &[u8]) -> PaddingDecision {
        self.records_seen = self.records_seen.saturating_add(1);
        let content_type = record.first().copied();
        let body = record.get(NESTED_TLS_HEADER_SIZE..).unwrap_or_default();

        if self.tls13.is_none() && content_type == Some(TLS_HANDSHAKE) {
            self.observe_server_hello(body);
        }
        match self.tls13 {
            Some(true) if content_type == Some(TLS_APPLICATION_DATA) => PaddingDecision::Direct,
            Some(false) => PaddingDecision::End,
            None if self.records_seen >= MAX_CLASSIFICATION_RECORDS => PaddingDecision::End,
            _ => PaddingDecision::Continue,
        }
    }

    fn observe_server_hello(&mut self, body: &[u8]) {
        if self.server_hello_length.is_none() {
            if self.server_hello.is_empty() && body.first() != Some(&TLS_SERVER_HELLO) {
                return;
            }
            let header_remaining = 4_usize.saturating_sub(self.server_hello.len());
            let header_bytes = header_remaining.min(body.len());
            if self.server_hello.try_reserve(header_bytes).is_err() {
                self.tls13 = Some(false);
                return;
            }
            self.server_hello.extend_from_slice(&body[..header_bytes]);
            if self.server_hello.len() < 4 {
                return;
            }
            let length = (usize::from(self.server_hello[1]) << 16)
                | (usize::from(self.server_hello[2]) << 8)
                | usize::from(self.server_hello[3]);
            let Some(total) = length.checked_add(4) else {
                self.tls13 = Some(false);
                return;
            };
            if total > MAX_NESTED_SERVER_HELLO_SIZE {
                self.tls13 = Some(false);
                return;
            }
            self.server_hello_length = Some(total);
            self.extend_server_hello(&body[header_bytes..], total);
        } else if let Some(expected) = self.server_hello_length {
            self.extend_server_hello(body, expected);
        }

        let Some(expected) = self.server_hello_length else {
            return;
        };
        if self.server_hello.len() == expected {
            self.tls13 = Some(is_tls13_server_hello(&self.server_hello));
        }
    }

    fn extend_server_hello(&mut self, body: &[u8], expected: usize) {
        let remaining = expected.saturating_sub(self.server_hello.len());
        let count = remaining.min(body.len());
        if self.server_hello.try_reserve(count).is_err() {
            self.tls13 = Some(false);
            return;
        }
        self.server_hello.extend_from_slice(&body[..count]);
    }
}

fn is_tls13_server_hello(message: &[u8]) -> bool {
    let Some(body) = message.get(4..) else {
        return false;
    };
    let Some(session_id_length) = body.get(34).copied().map(usize::from) else {
        return false;
    };
    let Some(cipher_offset) = 35_usize.checked_add(session_id_length) else {
        return false;
    };
    let Some(cipher_bytes) = body.get(cipher_offset..cipher_offset + 2) else {
        return false;
    };
    let cipher_suite = u16::from_be_bytes([cipher_bytes[0], cipher_bytes[1]]);
    if cipher_suite == TLS_AES_128_CCM_8_SHA256 {
        return false;
    }
    let Some(extensions_length_offset) = cipher_offset.checked_add(3) else {
        return false;
    };
    let Some(length_bytes) = body.get(extensions_length_offset..extensions_length_offset + 2)
    else {
        return false;
    };
    let extensions_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    let extensions_start = extensions_length_offset + 2;
    let Some(extensions_end) = extensions_start.checked_add(extensions_length) else {
        return false;
    };
    let Some(extensions) = body.get(extensions_start..extensions_end) else {
        return false;
    };

    let mut cursor = 0;
    while cursor + 4 <= extensions.len() {
        let extension_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            extensions[cursor + 2],
            extensions[cursor + 3],
        ]));
        cursor += 4;
        let Some(end) = cursor.checked_add(extension_length) else {
            return false;
        };
        let Some(value) = extensions.get(cursor..end) else {
            return false;
        };
        if extension_type == 43 {
            return value == TLS13_VERSION;
        }
        cursor = end;
    }
    false
}

/// A Vision data session failed after REALITY authentication.
#[derive(Debug)]
pub enum VisionSessionError {
    Timeout,
    AllocationFailed,
    RequestTooLarge { limit: usize },
    Decode(DecodeError),
    Validate(RequestValidationError),
    Route(RouteResolutionError),
    Outbound(OutboundConnectError),
    ResponseHeader(crate::protocol::vless::ResponseEncodeError),
    Tls(TlsApplicationIoError),
    VisionDecode(VisionDecodeError),
    VisionEncode(VisionEncodeError),
    DestinationTruncatedTlsRecord,
    DirectTransition(InvalidTransition),
    Handoff(io::Error),
    HandoffLine(HandoffLineError),
    Relay(io::Error),
    Io(io::Error),
}

impl fmt::Display for VisionSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Vision session operation timed out"),
            Self::AllocationFailed => formatter.write_str("bounded Vision allocation failed"),
            Self::RequestTooLarge { limit } => {
                write!(formatter, "VLESS request exceeds {limit}-byte bound")
            }
            Self::Decode(source) => source.fmt(formatter),
            Self::Validate(source) => source.fmt(formatter),
            Self::Route(source) => source.fmt(formatter),
            Self::Outbound(source) => source.fmt(formatter),
            Self::ResponseHeader(source) => source.fmt(formatter),
            Self::Tls(source) => source.fmt(formatter),
            Self::VisionDecode(source) => source.fmt(formatter),
            Self::VisionEncode(source) => source.fmt(formatter),
            Self::DestinationTruncatedTlsRecord => {
                formatter.write_str("destination closed inside a TLS record")
            }
            Self::DirectTransition(source) => source.fmt(formatter),
            Self::Handoff(_) => formatter.write_str("Vision Direct socket recovery failed"),
            Self::HandoffLine(source) => source.fmt(formatter),
            Self::Relay(_) => formatter.write_str("unified raw relay failed"),
            Self::Io(_) => formatter.write_str("Vision relay socket I/O failed"),
        }
    }
}

impl Error for VisionSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            Self::Validate(source) => Some(source),
            Self::Route(source) => Some(source),
            Self::Outbound(source) => Some(source),
            Self::ResponseHeader(source) => Some(source),
            Self::Tls(source) => Some(source),
            Self::VisionDecode(source) => Some(source),
            Self::VisionEncode(source) => Some(source),
            Self::DirectTransition(source) => Some(source),
            Self::Handoff(source) | Self::Relay(source) | Self::Io(source) => Some(source),
            Self::HandoffLine(source) => Some(source),
            Self::Timeout
            | Self::AllocationFailed
            | Self::RequestTooLarge { .. }
            | Self::DestinationTruncatedTlsRecord => None,
        }
    }
}

fn operation_deadline(timeout: Duration) -> Result<Instant, VisionSessionError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(VisionSessionError::Timeout)
}

/// Maps an idle-guarded operation failure to the session error.
fn idle_failure(error: IdleError) -> VisionSessionError {
    match error {
        IdleError::Timeout => VisionSessionError::Timeout,
        IdleError::Io(source) => VisionSessionError::Io(source),
    }
}

fn length_u64(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Instant, timeout},
    };

    use super::{
        BoundaryBytes, NestedTlsDetector, PaddingDecision, SessionContext, VisionHandler,
        VisionSessionError, is_benign_teardown, is_tls13_server_hello, length_u64, run_directional,
    };
    use crate::{
        config::{
            DirectBarrierConfig, DnsStrategy, OutboundConfig, RelayPolicy, ResourceGovernorConfig,
            RoutingConfig, UserPolicy,
        },
        protocol::{
            reality::tls13::{
                CipherSuite, ContentType, EstablishedTls, Tls13KeySchedule, Tls13RecordLayer,
                TlsApplicationIo, read_tls_record,
            },
            vless::{
                Command, UserId, UserRegistry, VERSION, VISION_FLOW, VISION_FRAME_SIZE,
                VisionCommand, VisionDecoder, VisionEncoder, VisionMode,
            },
        },
        runtime::FdBudget,
        server::{
            direct::{DirectHandoff, Direction},
            outbound::OutboundRegistry,
            reality::RealityEstablished,
            routing::{EmptyAssetMatcher, RoutingTable},
        },
        transport::{RelayBackend, TcpRelay},
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);
    const USER: UserId = UserId::new([0x33; 16]);

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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
        };
        let handler = direct_handler(&governor);
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 2_000,
            handshake_timeout_ms: 2_000,
            fallback_timeout_ms: 2_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
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
        assert!(is_tls13_server_hello(&server_hello));
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
        let schedule = Tls13KeySchedule::new(
            suite,
            &[0x11; 32],
            &suite.hash().digest(b"Vision server hello transcript"),
        )
        .expect("test schedule must initialize");
        let secrets = schedule
            .application_traffic_secrets(&suite.hash().digest(b"Vision test transcript"))
            .expect("test application secrets must derive");
        let server_client_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.client())
                .expect("client keys must derive"),
        )
        .expect("server read records must initialize");
        let server_server_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.server())
                .expect("server keys must derive"),
        )
        .expect("server write records must initialize");
        let client_write_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.client())
                .expect("client keys must derive"),
        )
        .expect("client write records must initialize");
        let client_read_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.server())
                .expect("server keys must derive"),
        )
        .expect("client read records must initialize");
        (
            EstablishedTls::from_test_records(suite, server_client_records, server_server_records),
            client_write_records,
            client_read_records,
        )
    }

    fn direct_handler(governor: &ResourceGovernorConfig) -> VisionHandler {
        let barrier = DirectBarrierConfig {
            max_concurrent: 8,
            max_per_second: 8,
        };
        let outbounds = OutboundRegistry::new(
            &[OutboundConfig::Direct {
                tag: "direct".to_owned(),
            }],
            &barrier,
            Duration::from_millis(governor.connect_timeout_ms),
            crate::runtime::FdBudget::new(4_096),
        );
        let routing =
            RoutingTable::compile(
                &RoutingConfig {
                    domain_strategy: DnsStrategy::AsIs,
                    global_rules: Vec::new(),
                    users: vec![UserPolicy {
                        name: "test-user".to_owned(),
                        user_ids: vec!["33333333-3333-3333-3333-333333333333".to_owned()],
                        default_outbound: "direct".to_owned(),
                        rules: Vec::new(),
                    }],
                },
                Arc::new(EmptyAssetMatcher),
                crate::runtime::ResourceGovernor::new(
                    &crate::config::ResourceGovernorConfig::default(),
                ),
            )
            .expect("test routing must compile");
        let relay = crate::transport::TcpRelay::new(
            &crate::config::RelayPolicy {
                buffer_bytes: 32 * 1024,
                max_pooled_buffers: 8,
                max_splice_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            crate::runtime::FdBudget::new(4_096),
        )
        .expect("test relay policy must compile");
        VisionHandler::new(outbounds, routing, relay, governor)
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
    async fn an_idle_raw_direction_closes_cleanly_with_its_stats() {
        // The raw stage's idle policy ends a stalled direction that never
        // moved a byte with TimedOut; the session must treat that like any
        // other benign teardown — clean DirectionStats, never a session error.
        let relay = TcpRelay::new(&RelayPolicy::default(), FdBudget::new(4_096))
            .expect("relay policy must compile");
        let handoff = DirectHandoff::new();
        let (_sender, source) = tcp_pair().await;
        let (sink, _receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = source.into_split();
        let (_sink_reader, sink_writer) = sink.into_split();

        let stats = timeout(
            TEST_TIMEOUT,
            run_directional(
                &SessionContext {
                    timeout: Duration::from_millis(200),
                    handoff: &handoff,
                    relay: &relay,
                },
                Direction::Uplink,
                source_reader,
                sink_writer,
                BoundaryBytes {
                    total: 3,
                    direct_at: 3,
                },
                Instant::now(),
            ),
        )
        .await
        .expect("the idle direction must end within the test timeout")
        .expect("an idle timeout on an untouched ledger must close cleanly");
        assert!(stats.direct);
        assert_eq!(stats.bytes, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_liveness_timeout_after_moved_bytes_fails_the_session() {
        // Once the raw relay moved bytes, a liveness timeout truncates the
        // peer direction's tail: the relay resets both sockets and reports
        // the abort as ConnectionAborted, so the session must fail rather
        // than record a clean teardown.
        let relay = TcpRelay::new(&RelayPolicy::default(), FdBudget::new(4_096))
            .expect("relay policy must compile");
        let handoff = DirectHandoff::new();
        let (mut sender, source) = tcp_pair().await;
        let (sink, _receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = source.into_split();
        let (_sink_reader, sink_writer) = sink.into_split();
        sender
            .write_all(b"stall")
            .await
            .expect("the prefix must land");

        let result = timeout(
            TEST_TIMEOUT,
            run_directional(
                &SessionContext {
                    timeout: Duration::from_millis(200),
                    handoff: &handoff,
                    relay: &relay,
                },
                Direction::Uplink,
                source_reader,
                sink_writer,
                BoundaryBytes {
                    total: 3,
                    direct_at: 3,
                },
                Instant::now(),
            ),
        )
        .await
        .expect("the stalled direction must end within the test timeout");
        drop(sender);
        let error = result
            .err()
            .expect("a timeout that truncated a live transfer must fail the session");
        let VisionSessionError::Relay(source) = &error else {
            panic!("the abort must surface as a relay error: {error}");
        };
        assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
    }
}
