use std::{error::Error, fmt, io, ops::Range, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::{self, Instant},
};

use crate::{
    config::{Config, DnsStrategy, ResourceGovernorConfig},
    protocol::{
        reality::tls13::{
            MAX_PLAINTEXT_LEN, TlsApplicationIoError, TlsApplicationReader, TlsApplicationWriter,
        },
        vless::{
            DecodeError, Destination, RequestHeader, RequestValidationError, UserId, UserRegistry,
            VISION_FRAME_SIZE, VisionCommand, VisionDecodeError, VisionDecoder, VisionEncodeError,
            VisionEncoder, VisionMode, decode_request, encode_response_header,
        },
    },
};

use super::{
    direct::{DirectHandoff, Direction, DirectionState, InvalidTransition},
    outbound::{OutboundConnectError, OutboundConnectOutcome, OutboundRegistry},
    reality::RealityEstablished,
    routing::{AssetMatcher, RouteResolutionError, RoutingCompileError, RoutingTable},
};
use crate::transport::{RelayBackend, RelayContext, RelayOutcome, TcpRelay};

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
        let governor = &config.policy.resource_governor;
        Ok(Self::new_with_dns(
            OutboundRegistry::new(
                &config.outbounds,
                &config.policy.direct_barrier,
                Duration::from_millis(governor.connect_timeout_ms),
            ),
            RoutingTable::compile(&config.routing, assets)?,
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
    /// The direct outbound permit is retained for the entire session. Vision
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

        let handed_off = uplink.handoff.or(downlink.handoff);
        let (handed_up, handed_down) = handed_off.map_or((0, 0), |outcome| {
            (outcome.inbound_to_outbound(), outcome.outbound_to_inbound())
        });
        Ok(VisionRelayStats {
            uplink_bytes: uplink.bytes.saturating_add(handed_up),
            downlink_bytes: downlink.bytes.saturating_add(handed_down),
            uplink_direct: uplink.direct,
            downlink_direct: downlink.direct,
            relay_backend: handed_off.map(RelayOutcome::backend),
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
}

impl DirectionStats {
    const fn framed(bytes: u64) -> Self {
        Self {
            bytes,
            direct: false,
            handoff: None,
        }
    }

    const fn direct(bytes: u64, handoff: Option<RelayOutcome>) -> Self {
        Self {
            bytes,
            direct: true,
            handoff,
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

async fn relay_uplink(
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
    plaintext
        .try_reserve_exact(VISION_FRAME_SIZE)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
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
            write_all_before(&mut destination, &plaintext, timeout).await?;
            bytes = bytes.saturating_add(length_u64(plaintext.len()));
        }
        if mode == VisionMode::Direct {
            return finish_uplink_direct(client, destination, bytes, context).await;
        }
    }
    drop(request_buffer);

    loop {
        // The borrow of the reader's reusable record storage lives only for this
        // block: the decoder copies decoded content into `plaintext`, and the
        // borrow ends before the next read or the socket handoff.
        let mode = {
            let record = match client.read_application(timeout).await {
                Ok(record) => record,
                Err(TlsApplicationIoError::PeerAlert {
                    level: _,
                    description: 0,
                }) => {
                    shutdown_before(&mut destination, timeout).await?;
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
            decoder
                .decode(record.plaintext(), &mut plaintext)
                .map_err(VisionSessionError::VisionDecode)?
        };
        if !plaintext.is_empty() {
            write_all_before(&mut destination, &plaintext, timeout).await?;
            bytes = bytes.saturating_add(length_u64(plaintext.len()));
        }
        if mode == VisionMode::Direct {
            return finish_uplink_direct(client, destination, bytes, context).await;
        }
    }
}

/// Relays the raw uplink after an authenticated Direct boundary.
///
/// Every decoded plaintext byte was already written to the destination in order
/// by the caller, so this direction is at the exact raw boundary. It advances
/// through `DirectPending` to `RawReady` and then either hands both complete
/// sockets to the unified relay — only once the peer direction has also reached
/// `RawReady` — or, when the peer can never become raw, relays this single
/// direction with one bounded userspace buffer.
async fn finish_uplink_direct(
    client: TlsApplicationReader<OwnedReadHalf>,
    mut destination: OwnedWriteHalf,
    bytes: u64,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout,
        handoff,
        relay,
    } = *context;
    handoff
        .advance(Direction::Uplink, DirectionState::DirectPending)
        .map_err(VisionSessionError::DirectTransition)?;
    handoff
        .advance(Direction::Uplink, DirectionState::RawReady)
        .map_err(VisionSessionError::DirectTransition)?;

    let mut raw_client = client.into_inner();
    let mut copied = 0_u64;
    let mut buffer = raw_buffer()?;
    let mut versions = handoff.subscribe();

    loop {
        if handoff.both_raw_ready() {
            let recovered = handoff
                .deposit_uplink(raw_client, destination)
                .map_err(VisionSessionError::Handoff)?;
            return run_handoff(relay, recovered, bytes.saturating_add(copied)).await;
        }
        if handoff.peer_is_settled(Direction::Uplink) {
            let extra = copy_before(&mut raw_client, &mut destination, timeout).await?;
            shutdown_before(&mut destination, timeout).await?;
            settle(handoff, Direction::Uplink, DirectionState::Closed);
            return Ok(DirectionStats::direct(
                bytes.saturating_add(copied).saturating_add(extra),
                None,
            ));
        }

        tokio::select! {
            // `AsyncReadExt::read` is cancellation-safe on a TCP half, so losing
            // this branch to a peer state change cannot consume a raw byte.
            read = read_before(&mut raw_client, &mut buffer, timeout) => {
                let read = read?;
                if read == 0 {
                    if handoff.both_raw_ready() {
                        let recovered = handoff
                            .deposit_uplink(raw_client, destination)
                            .map_err(VisionSessionError::Handoff)?;
                        return run_handoff(relay, recovered, bytes.saturating_add(copied)).await;
                    }
                    shutdown_before(&mut destination, timeout).await?;
                    settle(handoff, Direction::Uplink, DirectionState::Closed);
                    return Ok(DirectionStats::direct(bytes.saturating_add(copied), None));
                }
                let payload = buffer
                    .get(..read)
                    .ok_or(VisionSessionError::DestinationTruncatedTlsRecord)?;
                write_all_before(&mut destination, payload, timeout).await?;
                copied = copied.saturating_add(length_u64(read));
            }
            changed = versions.changed() => {
                changed.map_err(|_| VisionSessionError::Handoff(io::Error::other(
                    "Vision direction coordinator closed",
                )))?;
            }
        }
    }
}

async fn relay_downlink(
    mut destination: OwnedReadHalf,
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

    let mut nested = Vec::new();
    nested
        .try_reserve_exact(NESTED_TLS_HEADER_SIZE + MAX_NESTED_TLS_RECORD_SIZE)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    let mut detector = NestedTlsDetector::new();
    let mut bytes = 0_u64;
    loop {
        match read_nested_record(&mut destination, &mut nested, timeout).await? {
            NestedRead::Eof => {
                client
                    .shutdown(timeout)
                    .await
                    .map_err(VisionSessionError::Tls)?;
                settle(handoff, Direction::Downlink, DirectionState::Closed);
                return Ok(DirectionStats::framed(bytes));
            }
            NestedRead::Unframed(length) => {
                bytes = bytes.saturating_add(length_u64(length));
                write_vision_content(
                    &mut client,
                    &mut encoder,
                    &nested[..length],
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
            NestedRead::Record(length) => {
                bytes = bytes.saturating_add(length_u64(length));
                let decision = detector.observe(&nested[..length]);
                let command = match decision {
                    PaddingDecision::Continue => VisionCommand::Continue,
                    PaddingDecision::End => VisionCommand::End,
                    PaddingDecision::Direct => VisionCommand::Direct,
                };
                write_vision_content(
                    &mut client,
                    &mut encoder,
                    &nested[..length],
                    command,
                    true,
                    timeout,
                )
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
    for (index, chunk) in content
        .chunks(MAX_VISION_CONTENT_AFTER_FIRST_FRAME)
        .enumerate()
    {
        let command = if index + 1 == chunk_count {
            final_command
        } else {
            VisionCommand::Continue
        };
        write_vision_frame(writer, encoder, chunk, command, long_padding, timeout).await?;
    }
    Ok(())
}

/// Relays the raw downlink after an authenticated Direct boundary.
///
/// The Direct-carrying Vision frame has already been sealed and written to the
/// client, so this direction is at its exact raw boundary with nothing pending.
async fn finish_downlink_direct(
    mut destination: OwnedReadHalf,
    client: TlsApplicationWriter<OwnedWriteHalf>,
    bytes: u64,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout,
        handoff,
        relay,
    } = *context;
    handoff
        .advance(Direction::Downlink, DirectionState::DirectPending)
        .map_err(VisionSessionError::DirectTransition)?;
    handoff
        .advance(Direction::Downlink, DirectionState::RawReady)
        .map_err(VisionSessionError::DirectTransition)?;

    let mut raw_client = client.into_inner();
    let mut copied = 0_u64;
    let mut buffer = raw_buffer()?;
    let mut versions = handoff.subscribe();

    loop {
        if handoff.both_raw_ready() {
            let recovered = handoff
                .deposit_downlink(destination, raw_client)
                .map_err(VisionSessionError::Handoff)?;
            return run_handoff(relay, recovered, bytes.saturating_add(copied)).await;
        }
        if handoff.peer_is_settled(Direction::Downlink) {
            let extra = copy_before(&mut destination, &mut raw_client, timeout).await?;
            shutdown_before(&mut raw_client, timeout).await?;
            settle(handoff, Direction::Downlink, DirectionState::Closed);
            return Ok(DirectionStats::direct(
                bytes.saturating_add(copied).saturating_add(extra),
                None,
            ));
        }

        tokio::select! {
            read = read_before(&mut destination, &mut buffer, timeout) => {
                let read = read?;
                if read == 0 {
                    if handoff.both_raw_ready() {
                        let recovered = handoff
                            .deposit_downlink(destination, raw_client)
                            .map_err(VisionSessionError::Handoff)?;
                        return run_handoff(relay, recovered, bytes.saturating_add(copied)).await;
                    }
                    shutdown_before(&mut raw_client, timeout).await?;
                    settle(handoff, Direction::Downlink, DirectionState::Closed);
                    return Ok(DirectionStats::direct(bytes.saturating_add(copied), None));
                }
                let payload = buffer
                    .get(..read)
                    .ok_or(VisionSessionError::DestinationTruncatedTlsRecord)?;
                write_all_before(&mut raw_client, payload, timeout).await?;
                copied = copied.saturating_add(length_u64(read));
            }
            changed = versions.changed() => {
                changed.map_err(|_| VisionSessionError::Handoff(io::Error::other(
                    "Vision direction coordinator closed",
                )))?;
            }
        }
    }
}

/// Runs the unified relay when this direction deposited its sockets last.
///
/// A `None` deposit means the peer direction still holds one half pair; that
/// peer becomes the last depositor and runs the relay instead. Exactly one of
/// the two directions therefore ever drives the raw relay.
async fn run_handoff(
    relay: &TcpRelay,
    recovered: Option<super::direct::RecoveredSockets>,
    bytes: u64,
) -> Result<DirectionStats, VisionSessionError> {
    let Some(sockets) = recovered else {
        return Ok(DirectionStats::direct(bytes, None));
    };
    let outcome = relay
        .relay_owned(sockets.client, sockets.destination, RelayContext::owned())
        .await
        .map_err(VisionSessionError::Relay)?;
    Ok(DirectionStats::direct(bytes, Some(outcome)))
}

/// Records a terminal direction state without masking the original failure.
///
/// A rejected transition here means the direction was already terminal, which is
/// not itself an error worth replacing the real cause with.
fn settle(handoff: &DirectHandoff, direction: Direction, state: DirectionState) {
    let _ignored = handoff.advance(direction, state);
}

/// Allocates one bounded raw-relay buffer for a mixed one-way Direct session.
fn raw_buffer() -> Result<Vec<u8>, VisionSessionError> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(MAX_PLAINTEXT_LEN)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    buffer.resize(MAX_PLAINTEXT_LEN, 0);
    Ok(buffer)
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
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; MAX_PLAINTEXT_LEN];
    let mut copied = 0_u64;
    loop {
        let read = read_before(reader, &mut buffer, timeout).await?;
        if read == 0 {
            writer
                .shutdown(timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(copied);
        }
        writer
            .write_application(&buffer[..read], timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        copied = copied.saturating_add(length_u64(read));
    }
}

/// The outcome of one nested-record read into reusable connection storage.
///
/// Both non-EOF variants carry a length into the caller's retained buffer rather
/// than an owned `Vec`, which removes the per-record downlink allocation.
enum NestedRead {
    Eof,
    Record(usize),
    Unframed(usize),
}

async fn read_nested_record<R>(
    reader: &mut R,
    storage: &mut Vec<u8>,
    timeout: Duration,
) -> Result<NestedRead, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let deadline = operation_deadline(timeout)?;
    let capacity = NESTED_TLS_HEADER_SIZE + MAX_NESTED_TLS_RECORD_SIZE;
    if storage.capacity() < capacity {
        storage
            .try_reserve_exact(capacity - storage.len())
            .map_err(|_| VisionSessionError::AllocationFailed)?;
    }
    storage.clear();
    storage.resize(NESTED_TLS_HEADER_SIZE, 0);
    let header_read = read_exact_or_eof(reader, storage, deadline).await?;
    if header_read == 0 {
        return Ok(NestedRead::Eof);
    }
    storage.truncate(header_read);
    if header_read < NESTED_TLS_HEADER_SIZE {
        return Ok(NestedRead::Unframed(header_read));
    }
    let header: [u8; NESTED_TLS_HEADER_SIZE] = storage
        .get(..NESTED_TLS_HEADER_SIZE)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(VisionSessionError::DestinationTruncatedTlsRecord)?;
    if !looks_like_tls_record_header(&header) {
        return Ok(NestedRead::Unframed(NESTED_TLS_HEADER_SIZE));
    }
    let body_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body_length > MAX_NESTED_TLS_RECORD_SIZE {
        return Ok(NestedRead::Unframed(NESTED_TLS_HEADER_SIZE));
    }

    let record_length = NESTED_TLS_HEADER_SIZE + body_length;
    storage.resize(record_length, 0);
    let body = storage
        .get_mut(NESTED_TLS_HEADER_SIZE..)
        .ok_or(VisionSessionError::DestinationTruncatedTlsRecord)?;
    let read = read_exact_or_eof(reader, body, deadline).await?;
    if read != body_length {
        return Err(VisionSessionError::DestinationTruncatedTlsRecord);
    }
    Ok(NestedRead::Record(record_length))
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

async fn read_exact_or_eof<R>(
    reader: &mut R,
    output: &mut [u8],
    deadline: Instant,
) -> Result<usize, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let mut read = 0;
    while read < output.len() {
        let count = time::timeout_at(deadline, reader.read(&mut output[read..]))
            .await
            .map_err(|_| VisionSessionError::Timeout)?
            .map_err(VisionSessionError::Io)?;
        if count == 0 {
            break;
        }
        read += count;
    }
    Ok(read)
}

async fn read_before<R>(
    reader: &mut R,
    output: &mut [u8],
    timeout: Duration,
) -> Result<usize, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    time::timeout(timeout, reader.read(output))
        .await
        .map_err(|_| VisionSessionError::Timeout)?
        .map_err(VisionSessionError::Io)
}

async fn write_all_before<W>(
    writer: &mut W,
    input: &[u8],
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, writer.write_all(input))
        .await
        .map_err(|_| VisionSessionError::Timeout)?
        .map_err(VisionSessionError::Io)
}

async fn shutdown_before<W>(writer: &mut W, timeout: Duration) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, writer.shutdown())
        .await
        .map_err(|_| VisionSessionError::Timeout)?
        .map_err(VisionSessionError::Io)
}

async fn copy_before<R, W>(
    reader: &mut R,
    writer: &mut W,
    timeout: Duration,
) -> Result<u64, VisionSessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; MAX_PLAINTEXT_LEN];
    let mut copied = 0_u64;
    loop {
        let read = read_before(reader, &mut buffer, timeout).await?;
        if read == 0 {
            return Ok(copied);
        }
        write_all_before(writer, &buffer[..read], timeout).await?;
        copied = copied.saturating_add(length_u64(read));
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
        time::timeout,
    };

    use super::{
        NestedTlsDetector, PaddingDecision, VisionHandler, is_tls13_server_hello, length_u64,
    };
    use crate::{
        config::{
            DirectBarrierConfig, DnsStrategy, OutboundConfig, ResourceGovernorConfig,
            RoutingConfig, UserPolicy,
        },
        protocol::{
            reality::tls13::{
                CipherSuite, ContentType, EstablishedTls, Tls13KeySchedule, Tls13RecordLayer,
                TlsApplicationIo, read_tls_record,
            },
            vless::{
                Command, UserId, UserRegistry, VERSION, VISION_FLOW, VisionCommand, VisionDecoder,
                VisionEncoder, VisionMode,
            },
        },
        server::{
            outbound::OutboundRegistry,
            reality::RealityEstablished,
            routing::{EmptyAssetMatcher, RoutingTable},
        },
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
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_way_direct_keeps_the_pair_in_mixed_userspace_relay() {
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
        // Direct boundary. The uplink is raw and the downlink stays framed:
        // exactly the one-way case that must not hand the pair to a backend.
        let uplink_raw = vec![0x5a_u8; 96 * 1024];
        let downlink_plain = b"plain-http-response";

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
                destination.write_all(downlink_plain).await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
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

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            expected,
            "every raw uplink byte must reach the destination in order"
        );
        assert_eq!(response, downlink_plain);
        assert!(
            stats.uplink_direct(),
            "the uplink authenticated a Direct command"
        );
        assert!(
            !stats.downlink_direct(),
            "a non-TLS destination must never reach a Direct boundary"
        );
        assert_eq!(stats.uplink_bytes(), length_u64(expected.len()));
        assert_eq!(stats.downlink_bytes(), length_u64(downlink_plain.len()));
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
        let request =
            vision_request_with_command(destination_address.port(), b"", VisionCommand::Direct);
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        let nested_application = record(23, b"encrypted-handshake");
        let uplink_raw: Vec<u8> = (0..512_u32 * 1024).map(|value| value as u8).collect();
        let downlink_raw: Vec<u8> = (0..512_u32 * 1024)
            .map(|value| (value >> 3) as u8)
            .collect();

        let expected_up = uplink_raw.clone();
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
        );
        let routing = RoutingTable::compile(
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
        )
        .expect("test routing must compile");
        let relay = crate::transport::TcpRelay::new(
            &crate::config::RelayPolicy {
                buffer_bytes: 32 * 1024,
                max_pooled_buffers: 8,
                max_splice_relays: 0,
                max_io_uring_relays: 0,
                max_sockhash_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                max_pinned_memory_bytes: u64::MAX,
                splice: false,
                io_uring: false,
                sockhash: false,
            },
            crate::runtime::FdBudget::new(4_096),
        )
        .expect("test relay policy must compile");
        VisionHandler::new(outbounds, routing, relay, governor)
    }
}
