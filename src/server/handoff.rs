//! LINE-side transfer and LANDING-side landing for the Handoff prototype.
//!
//! A LINE node transfers one authenticated session at the Vision boundary
//! (after routing, before any steady-state Vision processing) to a LANDING
//! node over the authenticated single-flight channel of
//! [`crate::protocol::handoff`]. After a successful transfer LINE relays the
//! client socket against the handoff socket raw and never touches TLS or
//! Vision state for the session again; LANDING reconstructs the record layers,
//! feeds the transferred pending bytes first, and runs the standard Vision
//! relay against a directly dialed destination.

use std::{
    error::Error,
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{self, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    config::{HandoffInboundConfig, HandoffSettings, RelayPolicy},
    protocol::{
        handoff::{
            ContinuationState, HEADER_LEN, HandoffError, HandoffPsk, HandoffReplayCache,
            message_len_from_header, open_transfer, seal_transfer,
        },
        reality::tls13::{
            EstablishedTls, ExportedRecordState, ExportedTlsState, TrafficKeys,
            resume_application_halves,
        },
        vless::UserId,
    },
    runtime::{FdBudget, FdPermit, UNITS_OUTBOUND_SOCKET},
    transport::{
        relay::RelayStats,
        tcp_relay::{TcpRelay, TcpRelayConfigError},
    },
};

use super::{
    connector::{DestinationConnectError, DestinationConnector},
    vision::{VisionSessionError, run_resumed_session},
};

/// Compiled LINE-side landing endpoint for session transfers.
///
/// Key material is independent of the NXR pre-shared key and of any REALITY
/// private key; `Debug` never reveals it.
#[derive(Clone)]
pub struct HandoffLine {
    address: Arc<str>,
    port: u16,
    psk: HandoffPsk,
    landing_public: PublicKey,
    connect_timeout: Duration,
    first_byte_timeout: Duration,
}

impl HandoffLine {
    /// Compiles validated outbound settings into secret-safe runtime state.
    ///
    /// Returns `None` only when key material does not decode, which validated
    /// configuration has already excluded.
    #[must_use]
    pub fn from_settings(settings: &HandoffSettings) -> Option<Self> {
        let psk = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(settings.pre_shared_key.expose())
                .ok()?,
        );
        let psk: [u8; 32] = psk.as_slice().try_into().ok()?;
        let public = BASE64_URL_SAFE_NO_PAD
            .decode(&settings.landing_public_key)
            .ok()?;
        let public: [u8; 32] = public.as_slice().try_into().ok()?;
        Some(Self {
            address: Arc::from(settings.address.as_str()),
            port: settings.port,
            psk: HandoffPsk::new(psk),
            landing_public: PublicKey::from(public),
            connect_timeout: Duration::from_millis(settings.connect_timeout_ms),
            first_byte_timeout: Duration::from_millis(settings.first_byte_timeout_ms),
        })
    }

    /// Returns the deadline for LANDING's first downlink byte after the
    /// transfer write — the rejection-detection window for the silent
    /// protocol. A successful transfer produces immediate downlink (the
    /// resumed response header and opening Vision frame are LANDING's first
    /// sealed record), while every rejection closes the connection silently.
    /// The validated configuration bounds this above zero; it must exceed
    /// the landing node's authentication and destination-dial budgets, or
    /// viable but slow sessions are reset.
    #[must_use]
    pub(crate) const fn first_byte_timeout(&self) -> Duration {
        self.first_byte_timeout
    }

    /// Dials LANDING and writes the one sealed transfer message.
    ///
    /// The dial and the bounded write share one deadline derived from the
    /// configured connect timeout. The connection stays open in both
    /// directions afterwards: it becomes the raw carrier for the session's
    /// client-side ciphertext, and LANDING never answers the transfer itself —
    /// its first byte on this connection is already session downlink.
    ///
    /// # Errors
    ///
    /// Returns a descriptor-budget, deadline, connection, clock, or transfer
    /// sealing error. Every error leaves the client session to its caller's
    /// abort path; a partially written transfer is never retried.
    pub(crate) async fn transfer(
        &self,
        fd_budget: &FdBudget,
        state: &ContinuationState,
        client_random: [u8; 32],
    ) -> Result<(TcpStream, FdPermit), HandoffLineError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HandoffLineError::Clock)?
            .as_secs();
        let mut message = Vec::new();
        seal_transfer(
            state,
            &self.psk,
            &self.landing_public,
            client_random,
            timestamp,
            &mut message,
        )
        .map_err(HandoffLineError::Transfer)?;
        let fd_permit = fd_budget
            .try_acquire(UNITS_OUTBOUND_SOCKET)
            .ok_or(HandoffLineError::DescriptorBudget)?;
        let deadline = Instant::now()
            .checked_add(self.connect_timeout)
            .ok_or(HandoffLineError::Timeout)?;
        let stream = time::timeout_at(
            deadline,
            super::connector::connect_host(self.address.as_ref(), self.port),
        )
        .await
        .map_err(|_| HandoffLineError::Timeout)?
        .map_err(HandoffLineError::Connect)?;
        crate::transport::TcpAcceptor::configure_stream(&stream)
            .map_err(HandoffLineError::Connect)?;
        let mut stream = stream;
        time::timeout_at(deadline, stream.write_all(&message))
            .await
            .map_err(|_| HandoffLineError::Timeout)?
            .map_err(HandoffLineError::Connect)?;
        Ok((stream, fd_permit))
    }
}

impl fmt::Debug for HandoffLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffLine")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// TLS record content type for application data: the resumed session's first
/// record is always sealed application data.
const TLS_APPLICATION_DATA: u8 = 23;

/// Waits, without consuming, for LANDING's first byte after the transfer and
/// classifies it.
///
/// Returns `true` only when a byte arrived before `deadline` and carries the
/// TLS application-data content type. Anything else — a silent close, a
/// reset, a stall past the deadline, or the handshake/alert bytes a misdialed
/// REALITY cover target would mirror back — is the silent protocol's
/// rejection signal, and the caller must reset the client socket rather than
/// relay on. Peeking leaves the byte in the kernel buffer for the raw relay.
pub(crate) async fn first_downlink_landed(stream: &TcpStream, deadline: Duration) -> bool {
    let mut probe = [0_u8; 1];
    match time::timeout(deadline, stream.peek(&mut probe)).await {
        Ok(Ok(bytes)) => bytes > 0 && probe[0] == TLS_APPLICATION_DATA,
        Ok(Err(_)) | Err(_) => false,
    }
}

/// One LINE-side session transfer failed; the client socket must be reset.
#[derive(Debug)]
pub enum HandoffLineError {
    /// The descriptor budget denied the handoff connection.
    DescriptorBudget,
    /// The shared dial/write deadline elapsed.
    Timeout,
    /// The landing dial, socket configuration, or transfer write failed.
    Connect(io::Error),
    /// The system clock is before the Unix epoch.
    Clock,
    /// Sealing the continuation state failed.
    Transfer(HandoffError),
    /// The handoff socket halves could not be reunited (unreachable in practice).
    Reunite,
    /// LANDING produced no TLS downlink byte within the first-byte deadline:
    /// it closed silently, stalled, or answered with non-session bytes — the
    /// only failure signal the silent protocol carries.
    LandingRejected,
    /// The raw client-to-landing relay failed mid-session.
    Relay(io::Error),
}

impl fmt::Display for HandoffLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DescriptorBudget => {
                formatter.write_str("descriptor budget denied the handoff connection")
            }
            Self::Timeout => formatter.write_str("handoff transfer timed out"),
            Self::Connect(_) => formatter.write_str("failed to reach the handoff landing node"),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Transfer(source) => source.fmt(formatter),
            Self::Reunite => formatter.write_str("handoff socket halves did not reunite"),
            Self::LandingRejected => {
                formatter.write_str("handoff landing node closed without serving the session")
            }
            Self::Relay(_) => formatter.write_str("handoff raw relay failed"),
        }
    }
}

impl Error for HandoffLineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connect(source) | Self::Relay(source) => Some(source),
            Self::Transfer(source) => Some(source),
            Self::DescriptorBudget
            | Self::Timeout
            | Self::Clock
            | Self::Reunite
            | Self::LandingRejected => None,
        }
    }
}

/// One Handoff landing connection: verify and decrypt one transfer, dial the
/// transferred destination directly, then resume the session's Vision relay.
///
/// Every failure before the session relay starts closes the connection with
/// zero response bytes; LINE observes the close as a transfer rejection.
#[derive(Clone)]
pub struct HandoffLandingHandler {
    psk: HandoffPsk,
    landing_secret: StaticSecret,
    replay: HandoffReplayCache,
    maximum_time_difference: u64,
    connector: DestinationConnector,
    authentication_timeout: Duration,
    relay: TcpRelay,
    /// Idle bound handed to the resumed Vision relay, so a stalled peer cannot
    /// park a landing session on its descriptors and permits forever.
    io_timeout: Duration,
}

impl HandoffLandingHandler {
    /// Compiles one validated internal listener with a new replay cache.
    ///
    /// # Errors
    ///
    /// Rejects invalid key material or replay-cache policy.
    pub fn from_inbound(
        inbound: &HandoffInboundConfig,
        relay_policy: &RelayPolicy,
        fd_budget: FdBudget,
        io_timeout: Duration,
    ) -> Result<Self, HandoffLandingConfigError> {
        let replay = HandoffReplayCache::new(
            usize::try_from(inbound.settings.max_nonce_entries)
                .map_err(|_| HandoffLandingConfigError::Capacity)?,
            Duration::from_secs(inbound.settings.nonce_retention_seconds),
        )
        .map_err(HandoffLandingConfigError::Replay)?;
        let relay =
            TcpRelay::new(relay_policy, fd_budget).map_err(HandoffLandingConfigError::Relay)?;
        Self::from_inbound_with_replay(inbound, replay, relay, io_timeout)
    }

    /// Compiles one validated listener while retaining its process-lifetime
    /// replay history across immutable runtime generations.
    ///
    /// # Errors
    ///
    /// Rejects malformed or incorrectly sized key material.
    pub fn from_inbound_with_replay(
        inbound: &HandoffInboundConfig,
        replay: HandoffReplayCache,
        relay: TcpRelay,
        io_timeout: Duration,
    ) -> Result<Self, HandoffLandingConfigError> {
        let psk = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(inbound.settings.pre_shared_key.expose())
                .map_err(|_| HandoffLandingConfigError::Key)?,
        );
        let psk: [u8; 32] = psk
            .as_slice()
            .try_into()
            .map_err(|_| HandoffLandingConfigError::Key)?;
        let secret = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(inbound.settings.private_key.expose())
                .map_err(|_| HandoffLandingConfigError::Key)?,
        );
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| HandoffLandingConfigError::Key)?;
        Ok(Self::new(
            HandoffPsk::new(psk),
            StaticSecret::from(secret),
            replay,
            inbound.settings.max_time_difference_seconds,
            Duration::from_millis(inbound.settings.connect_timeout_ms),
            Duration::from_millis(inbound.settings.authentication_timeout_ms),
            relay,
            io_timeout,
        ))
    }

    /// Creates a landing handler from already compiled policy.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per compiled listener policy input"
    )]
    pub const fn new(
        psk: HandoffPsk,
        landing_secret: StaticSecret,
        replay: HandoffReplayCache,
        maximum_time_difference: u64,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        relay: TcpRelay,
        io_timeout: Duration,
    ) -> Self {
        Self {
            psk,
            landing_secret,
            replay,
            maximum_time_difference,
            connector: DestinationConnector::new(connect_timeout),
            authentication_timeout,
            relay,
            io_timeout,
        }
    }

    /// Processes a single Handoff TCP connection.
    ///
    /// Authentication failures return without writing a response and occur
    /// before destination DNS or connect. On success the transferred pending
    /// ciphertext is fed to the resumed record layer first, the prefetched
    /// payload enters a fresh Vision decoder first, and the response header
    /// plus opening Vision frame is the first sealed server record (sequence
    /// zero) — the exact ordering the session boundary requires.
    ///
    /// # Errors
    ///
    /// Returns bounded transfer-read, clock, authentication, destination, or
    /// relay errors. Callers must silently close on every error.
    pub async fn handle(&self, mut inbound: TcpStream) -> Result<RelayStats, HandoffLandingError> {
        let message = read_transfer(&mut inbound, self.authentication_timeout).await?;
        let now = unix_seconds()?;
        let opened = open_transfer(
            &message,
            &self.psk,
            &self.landing_secret,
            &self.replay,
            now,
            self.maximum_time_difference,
        )
        .map_err(HandoffLandingError::Protocol)?;
        // The wire message's only consumer is `open_transfer`.
        drop(message);
        let state = opened.state();
        // Reconstruct and validate the TLS state before touching the network:
        // a blob that cannot resume must not cost a destination connection.
        let tls = resume_tls(state)?;
        let user_id = UserId::new(*state.user_id());
        let destination = state.destination().clone();
        let pending = state.pending_ciphertext().to_vec();
        let prefetched = state.prefetched_plaintext().to_vec();
        // The transferred key material lives on inside the resumed record
        // layers only; the continuation copies are zeroized here, before the
        // whole-session relay below.
        drop(opened);
        // The descriptor unit is reserved before connect(2) and outlives the
        // relay: the outbound socket closes before its unit is released.
        let _fd_permit = self
            .relay
            .fd_budget()
            .try_acquire(UNITS_OUTBOUND_SOCKET)
            .ok_or(HandoffLandingError::DescriptorBudget)?;
        let destination = self.connector.connect(&destination).await?;
        let (reader_half, writer_half) = inbound.into_split();
        let (client_reader, client_writer) =
            resume_application_halves(reader_half, pending, writer_half, tls);
        let stats = run_resumed_session(
            client_reader,
            client_writer,
            destination,
            user_id,
            prefetched,
            &self.relay,
            self.io_timeout,
        )
        .await
        .map_err(HandoffLandingError::Session)?;
        Ok(RelayStats::new(
            stats.uplink_bytes(),
            stats.downlink_bytes(),
        ))
    }
}

/// Rebuilds the session's TLS application state from a verified transfer.
///
/// The key material is copied once into freshly zeroizing structures; the
/// transferred state is zeroized when the caller drops it.
fn resume_tls(state: &ContinuationState) -> Result<EstablishedTls, HandoffLandingError> {
    let suite = state.suite();
    let client_traffic =
        TrafficKeys::from_raw_parts(state.client_traffic().key(), *state.client_traffic().iv())
            .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))?;
    let server_traffic =
        TrafficKeys::from_raw_parts(state.server_traffic().key(), *state.server_traffic().iv())
            .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))?;
    let client = ExportedRecordState::from_parts(suite, client_traffic, state.client_sequence())
        .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))?;
    let server = ExportedRecordState::from_parts(suite, server_traffic, state.server_sequence())
        .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))?;
    EstablishedTls::from_exported_state(ExportedTlsState::from_directions(client, server))
        .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))
}

async fn read_transfer(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>, HandoffLandingError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(HandoffLandingError::Timeout)?;
    let mut header = [0_u8; HEADER_LEN];
    read_exact_before(stream, &mut header, deadline).await?;
    let total = message_len_from_header(&header).map_err(HandoffLandingError::Protocol)?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(total)
        .map_err(|_| HandoffLandingError::Allocation)?;
    message.extend_from_slice(&header);
    message.resize(total, 0);
    read_exact_before(stream, &mut message[HEADER_LEN..], deadline).await?;
    Ok(message)
}

async fn read_exact_before(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), HandoffLandingError> {
    time::timeout_at(deadline, stream.read_exact(output))
        .await
        .map_err(|_| HandoffLandingError::Timeout)?
        .map(|_| ())
        .map_err(HandoffLandingError::Read)
}

fn unix_seconds() -> Result<u64, HandoffLandingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HandoffLandingError::Clock)
}

/// Validated Handoff listener state could not be compiled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffLandingConfigError {
    /// PSK or static-key decoding or length did not match the protocol contract.
    Key,
    /// Replay capacity could not be represented on this target.
    Capacity,
    /// Replay cache initialization failed.
    Replay(HandoffError),
    /// Bounded plaintext relay state could not be compiled.
    Relay(TcpRelayConfigError),
}

impl fmt::Display for HandoffLandingConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Handoff landing listener configuration")
    }
}

impl Error for HandoffLandingConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Replay(source) => Some(source),
            Self::Relay(source) => Some(source),
            Self::Key | Self::Capacity => None,
        }
    }
}

/// One Handoff landing connection failed and must close silently.
#[derive(Debug)]
pub enum HandoffLandingError {
    Timeout,
    Read(io::Error),
    Protocol(HandoffError),
    Allocation,
    Clock,
    Destination(DestinationConnectError),
    Session(VisionSessionError),
    DescriptorBudget,
}

impl fmt::Display for HandoffLandingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Handoff landing connection closed")
    }
}

impl Error for HandoffLandingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(source) => Some(source),
            Self::Protocol(source) => Some(source),
            Self::Destination(source) => Some(source),
            Self::Session(source) => Some(source),
            Self::Timeout | Self::Allocation | Self::Clock | Self::DescriptorBudget => None,
        }
    }
}

impl From<DestinationConnectError> for HandoffLandingError {
    fn from(source: DestinationConnectError) -> Self {
        Self::Destination(source)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{
        HandoffLandingError, HandoffLandingHandler, HandoffLine, HandoffLineError, unix_seconds,
    };
    use crate::{
        config::{
            DirectBarrierConfig, DnsStrategy, HandoffSettings, OutboundConfig, RelayPolicy,
            ResourceGovernorConfig, RoutingConfig, SecretString, UserPolicy,
        },
        protocol::{
            handoff::{ContinuationState, HandoffPsk, HandoffReplayCache, seal_transfer},
            reality::tls13::{
                CipherSuite, ContentType, EstablishedTls, Tls13KeySchedule, Tls13RecordLayer,
                TlsApplicationIo, TrafficKeys, read_tls_record,
            },
            vless::{
                Address, Command, Destination, UserId, UserRegistry, VERSION, VISION_FLOW,
                VisionCommand, VisionDecoder, VisionEncoder,
            },
        },
        runtime::FdBudget,
        server::{
            outbound::OutboundRegistry,
            reality::RealityEstablished,
            routing::{EmptyAssetMatcher, RoutingTable},
            vision::{VisionHandler, VisionSessionError},
        },
        transport::TcpRelay,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(3);
    const USER: UserId = UserId::new([0x33; 16]);
    const PSK: [u8; 32] = [0x55; 32];
    const LANDING_SECRET: [u8; 32] = [0x77; 32];

    fn test_relay() -> TcpRelay {
        TcpRelay::new(&RelayPolicy::default(), FdBudget::new(4_096))
            .expect("test relay policy must compile")
    }

    fn test_landing_handler() -> HandoffLandingHandler {
        let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120))
            .expect("test replay cache must compile");
        HandoffLandingHandler::new(
            HandoffPsk::new(PSK),
            StaticSecret::from(LANDING_SECRET),
            replay,
            30,
            Duration::from_secs(1),
            Duration::from_secs(1),
            test_relay(),
            Duration::from_secs(1),
        )
    }

    fn handoff_line(address: std::net::SocketAddr) -> HandoffLine {
        let landing_public = PublicKey::from(&StaticSecret::from(LANDING_SECRET));
        HandoffLine::from_settings(&HandoffSettings {
            address: address.ip().to_string(),
            port: address.port(),
            pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
            landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public.as_bytes()),
            connect_timeout_ms: 1_000,
            first_byte_timeout_ms: 1_000,
        })
        .expect("test handoff settings must compile")
    }

    fn test_state(destination: Destination) -> ContinuationState {
        ContinuationState::new(
            CipherSuite::ChaCha20Poly1305Sha256,
            TrafficKeys::from_raw_parts(&[0x11; 32], [0x21; 12]).expect("client keys"),
            1,
            TrafficKeys::from_raw_parts(&[0x12; 32], [0x22; 12]).expect("server keys"),
            0,
            [0x33; 16],
            destination,
            Vec::new(),
            Vec::new(),
        )
        .expect("test state must be valid")
    }

    fn tls_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = Tls13KeySchedule::new(
            suite,
            &[0x11; 32],
            &suite.hash().digest(b"Handoff server hello transcript"),
        )
        .expect("test schedule must initialize");
        let secrets = schedule
            .application_traffic_secrets(&suite.hash().digest(b"Handoff test transcript"))
            .expect("test application secrets must derive");
        let layer = || {
            Tls13RecordLayer::new(
                suite,
                schedule
                    .traffic_keys(secrets.client())
                    .expect("client keys must derive"),
            )
            .expect("client record layer must initialize")
        };
        let server_layer = || {
            Tls13RecordLayer::new(
                suite,
                schedule
                    .traffic_keys(secrets.server())
                    .expect("server keys must derive"),
            )
            .expect("server record layer must initialize")
        };
        (
            EstablishedTls::from_test_records(suite, layer(), server_layer()),
            layer(),
            server_layer(),
        )
    }

    fn vision_request(destination_port: u16, payload: &[u8]) -> Vec<u8> {
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
            .encode(payload, VisionCommand::End, false, &mut frame)
            .expect("Vision payload must encode");
        request.extend_from_slice(&frame);
        request
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("address must exist"))
            .await
            .expect("client must connect");
        let (server, _) = listener.accept().await.expect("server must accept");
        (client, server)
    }

    fn handoff_vision_handler(landing_address: std::net::SocketAddr) -> VisionHandler {
        let barrier = DirectBarrierConfig {
            max_concurrent: 8,
            max_per_second: 8,
        };
        let landing_public = PublicKey::from(&StaticSecret::from(LANDING_SECRET));
        let outbounds = OutboundRegistry::new(
            &[OutboundConfig::Handoff {
                tag: "handoff".to_owned(),
                settings: HandoffSettings {
                    address: landing_address.ip().to_string(),
                    port: landing_address.port(),
                    pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
                    landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public.as_bytes()),
                    connect_timeout_ms: 1_000,
                    first_byte_timeout_ms: 1_000,
                },
            }],
            &barrier,
            Duration::from_secs(1),
            FdBudget::new(4_096),
        );
        let routing = RoutingTable::compile(
            &RoutingConfig {
                domain_strategy: DnsStrategy::AsIs,
                global_rules: Vec::new(),
                users: vec![UserPolicy {
                    name: "test-user".to_owned(),
                    user_ids: vec!["33333333-3333-3333-3333-333333333333".to_owned()],
                    default_outbound: "handoff".to_owned(),
                    rules: Vec::new(),
                }],
            },
            Arc::new(EmptyAssetMatcher),
            crate::runtime::ResourceGovernor::new(&ResourceGovernorConfig::default()),
        )
        .expect("test routing must compile");
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
        };
        VisionHandler::new(outbounds, routing, test_relay(), &governor)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn landing_rejects_an_unauthenticated_datagram_silently() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let address = listener.local_addr().expect("landing address must exist");
        let handler = test_landing_handler();

        let exchange = async {
            let landing = async {
                let (stream, _) = listener.accept().await?;
                handler.handle(stream).await.map_err(io::Error::other)
            };
            let peer = async {
                let mut stream = TcpStream::connect(address).await?;
                stream.write_all(b"not a handoff transfer at all").await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            tokio::join!(landing, peer)
        };
        let (landing, peer) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("rejection must not stall");
        landing.expect_err("garbage must fail closed");
        assert_eq!(
            peer.expect("peer exchange must succeed"),
            b"",
            "a rejected transfer must receive zero response bytes"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn landing_rejects_a_replayed_transfer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let address = listener.local_addr().expect("landing address must exist");
        let handler = test_landing_handler();
        let landing_public = PublicKey::from(&StaticSecret::from(LANDING_SECRET));
        // Port 9 is the discard sink: nothing listens, so an authenticated
        // transfer fails at the destination dial — proving it passed every
        // authentication step.
        let state = test_state(Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9));
        let mut message = Vec::new();
        seal_transfer(
            &state,
            &HandoffPsk::new(PSK),
            &landing_public,
            [0x44; 32],
            unix_seconds().expect("test clock must be valid"),
            &mut message,
        )
        .expect("test state must seal");

        let exchange = async {
            let landing = async {
                let mut outcomes = Vec::new();
                for _ in 0..2 {
                    let (stream, _) = listener.accept().await?;
                    outcomes.push(handler.handle(stream).await);
                }
                Ok::<_, io::Error>(outcomes)
            };
            let peer = async {
                for _ in 0..2 {
                    let mut stream = TcpStream::connect(address).await?;
                    stream.write_all(&message).await?;
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await?;
                    assert_eq!(response, b"", "failures must stay silent");
                }
                Ok::<_, io::Error>(())
            };
            tokio::join!(landing, peer)
        };
        let (landing, peer) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("replay rejection must not stall");
        peer.expect("peer exchange must succeed");
        let outcomes = landing.expect("landing task must succeed");
        assert!(
            matches!(outcomes[0], Err(HandoffLandingError::Destination(_))),
            "the first delivery must authenticate and fail only at the dial"
        );
        assert!(
            matches!(
                outcomes[1],
                Err(HandoffLandingError::Protocol(
                    crate::protocol::handoff::HandoffError::Replay
                ))
            ),
            "the replayed delivery must be rejected by the nonce cache"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn line_to_landing_moves_a_full_vision_session_byte_exactly() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let landing_address = landing_listener
            .local_addr()
            .expect("landing address must exist");
        let landing_handler = test_landing_handler();
        let line_handler = handoff_vision_handler(landing_address);
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            UserRegistry::new([USER]),
        );
        let request = vision_request(destination_address.port(), b"ping");

        let exchange = async {
            let line = line_handler.handle(established);
            let landing = async {
                let (stream, _) = landing_listener.accept().await?;
                landing_handler
                    .handle(stream)
                    .await
                    .map_err(io::Error::other)
            };
            let client_io = async {
                // One burst: the request record and a post-request raw-mode
                // record travel together, so LINE's reader may hold the second
                // record as read-ahead ciphertext at the boundary; the
                // continuation must carry it and LANDING must open it in order.
                let mut burst = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, &request, 0, &mut burst)
                    .map_err(io::Error::other)?;
                let mut more = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, b"-more", 0, &mut more)
                    .map_err(io::Error::other)?;
                burst.extend_from_slice(&more);
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                burst.extend_from_slice(&close_record);
                client.write_all(&burst).await?;

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
                // A real client closes the socket after close_notify; the raw
                // splice on LINE terminates only on TCP-level EOF.
                client.shutdown().await?;
                Ok::<_, io::Error>(response)
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut received = Vec::new();
                destination.read_to_end(&mut received).await?;
                destination.write_all(b"pong").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(line, landing, client_io, destination_io)
        };
        let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("handoff exchange must not time out");
        let line_stats = line.expect("LINE handler must succeed");
        let landing_stats = landing.expect("LANDING handler must succeed");

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping-more",
            "prefetched and post-boundary records must arrive byte-exactly, in order"
        );
        assert_eq!(
            client_result.expect("client I/O must succeed"),
            b"pong",
            "the resumed downlink must decrypt byte-exactly at the client"
        );
        assert_eq!(landing_stats.inbound_to_outbound_bytes(), 9);
        assert_eq!(landing_stats.outbound_to_inbound_bytes(), 4);
        assert!(
            line_stats.downlink_bytes() > 0,
            "LINE must report the raw downlink ciphertext it spliced: up={} down={}",
            line_stats.uplink_bytes(),
            line_stats.downlink_bytes()
        );
        // The whole client burst fit LINE's reader buffer, so it traveled
        // inside the sealed continuation and the uplink splice legitimately
        // moved zero bytes.
    }

    #[tokio::test(flavor = "current_thread")]
    async fn line_splices_post_transfer_uplink_records_to_landing() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let landing_address = landing_listener
            .local_addr()
            .expect("landing address must exist");
        let landing_handler = test_landing_handler();
        let line_handler = handoff_vision_handler(landing_address);
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            UserRegistry::new([USER]),
        );
        let request = vision_request(destination_address.port(), b"ping");

        let exchange = async {
            let line = line_handler.handle(established);
            let landing = async {
                let (stream, _) = landing_listener.accept().await?;
                landing_handler
                    .handle(stream)
                    .await
                    .map_err(io::Error::other)
            };
            let client_io = async {
                let mut record = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                    .map_err(io::Error::other)?;
                client.write_all(&record).await?;

                // The first downlink record (response header + opening frame)
                // proves the transfer landed; everything sent afterwards must
                // travel the raw splice, never LINE's TLS state.
                let mut first = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut first)
                    .map_err(io::Error::other)?;
                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                {
                    let plaintext = opened.plaintext();
                    if opened.content_type() != ContentType::ApplicationData
                        || plaintext.get(..2) != Some([VERSION, 0].as_slice())
                    {
                        return Err(io::Error::other("missing resumed response header"));
                    }
                    let _ = decoder
                        .decode(&plaintext[2..], &mut decoded)
                        .map_err(io::Error::other)?;
                    response.extend_from_slice(&decoded);
                }
                let mut more = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, b"-more", 0, &mut more)
                    .map_err(io::Error::other)?;
                client.write_all(&more).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

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
                            let _ = decoder
                                .decode(opened.plaintext(), &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        ContentType::Alert if opened.plaintext() == [1, 0] => break,
                        _ => return Err(io::Error::other("unexpected outer TLS content")),
                    }
                }
                client.shutdown().await?;
                Ok::<_, io::Error>(response)
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut received = Vec::new();
                destination.read_to_end(&mut received).await?;
                destination.write_all(b"pong").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(line, landing, client_io, destination_io)
        };
        let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("spliced uplink exchange must not time out");
        let line_stats = line.expect("LINE handler must succeed");
        landing.expect("LANDING handler must succeed");

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping-more"
        );
        assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
        assert!(
            line_stats.uplink_bytes() > 0,
            "post-transfer records must move through the raw splice"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn line_aborts_the_client_when_landing_rejects_the_transfer() {
        // A landing node with the WRONG psk: every transfer fails
        // authentication and closes silently.
        let wrong_psk_handler = {
            let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120))
                .expect("test replay cache must compile");
            HandoffLandingHandler::new(
                HandoffPsk::new([0x66; 32]),
                StaticSecret::from(LANDING_SECRET),
                replay,
                30,
                Duration::from_secs(1),
                Duration::from_secs(1),
                test_relay(),
                Duration::from_secs(1),
            )
        };
        let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let landing_address = landing_listener
            .local_addr()
            .expect("landing address must exist");
        let line_handler = handoff_vision_handler(landing_address);
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, _client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            UserRegistry::new([USER]),
        );
        let request = vision_request(9, b"ping");

        let exchange = async {
            let line = line_handler.handle(established);
            let landing = async {
                let (stream, _) = landing_listener.accept().await?;
                wrong_psk_handler
                    .handle(stream)
                    .await
                    .map_err(io::Error::other)
            };
            let client_io = async {
                let mut record = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                    .map_err(io::Error::other)?;
                client.write_all(&record).await?;
                // The client stays open like any patient client: LINE must
                // detect the silent rejection at its own first-byte deadline —
                // far inside TEST_TIMEOUT — and reset this socket. A clean
                // FIN (Ok(0)) or any read byte is a failure of the spec's
                // failure semantics, not a race to tolerate.
                let mut byte = [0_u8; 1];
                let error = client
                    .read(&mut byte)
                    .await
                    .expect_err("a rejected transfer must reset the client, never FIN it");
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset,
                    "the rejection abort must reach the client as RST"
                );
                Ok::<_, io::Error>(())
            };
            tokio::join!(line, landing, client_io)
        };
        let (line, landing, client_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("rejection exchange must not time out");
        assert!(landing.is_err(), "the wrong psk must fail authentication");
        client_result.expect("client I/O must succeed");
        let error = line.expect_err("LINE must fail the session, never serve it locally");
        assert!(
            matches!(
                error,
                VisionSessionError::HandoffLine(HandoffLineError::LandingRejected)
            ),
            "a landing close without downlink must read as a rejection: {error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn line_transfer_failure_on_unreachable_landing_fails_the_session() {
        // Reserve a port and drop the listener so connects are refused fast.
        let refused_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe listener must bind")
            .local_addr()
            .expect("probe address must exist")
            .port();
        let landing_address = std::net::SocketAddr::new(Ipv4Addr::LOCALHOST.into(), refused_port);
        let line_handler = handoff_vision_handler(landing_address);
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, _client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            UserRegistry::new([USER]),
        );
        let request = vision_request(9, b"ping");

        let exchange = async {
            let line = line_handler.handle(established);
            let client_io = async {
                let mut record = Vec::new();
                client_write_records
                    .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                    .map_err(io::Error::other)?;
                client.write_all(&record).await
            };
            tokio::join!(line, client_io)
        };
        let (line, client_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("dial failure must not stall");
        client_result.expect("the request write must succeed");
        let error = line.expect_err("an unreachable landing must fail the session");
        assert!(
            matches!(
                error,
                VisionSessionError::HandoffLine(HandoffLineError::Connect(_))
            ),
            "a refused landing dial must surface as a connect failure: {error}"
        );
    }

    #[test]
    fn handoff_line_rejects_undecodable_settings() {
        assert!(
            HandoffLine::from_settings(&HandoffSettings {
                address: "127.0.0.1".to_owned(),
                port: 443,
                pre_shared_key: SecretString::new("not-base64!"),
                landing_public_key: BASE64_URL_SAFE_NO_PAD.encode([0x77; 32]),
                connect_timeout_ms: 1_000,
                first_byte_timeout_ms: 1_000,
            })
            .is_none()
        );
        assert!(
            HandoffLine::from_settings(&HandoffSettings {
                address: "127.0.0.1".to_owned(),
                port: 443,
                pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
                landing_public_key: BASE64_URL_SAFE_NO_PAD.encode([0x77; 16]),
                connect_timeout_ms: 1_000,
                first_byte_timeout_ms: 1_000,
            })
            .is_none()
        );
    }

    #[test]
    fn debug_output_never_reveals_key_material() {
        let line = handoff_line(std::net::SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443));
        let rendered = format!("{line:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("VVVV"), "the base64 PSK must not appear");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn first_downlink_byte_classification() {
        // Session downlink begins with a sealed application-data record and
        // the probe must not consume it.
        let (mut peer, mut stream) = tcp_pair().await;
        peer.write_all(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xaa])
            .await
            .expect("peer write must succeed");
        assert!(
            super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
            "a TLS application-data first byte must classify as landed"
        );
        drop(peer);
        let mut rest = Vec::new();
        stream
            .read_to_end(&mut rest)
            .await
            .expect("the peeked bytes must remain for the raw relay");
        assert_eq!(rest, [0x17, 0x03, 0x03, 0x00, 0x01, 0xaa]);

        // A silent close and a mid-flight reset both read as rejection.
        let (peer, stream) = tcp_pair().await;
        drop(peer);
        assert!(
            !super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
            "a silent close must classify as rejected"
        );
        let (peer, stream) = tcp_pair().await;
        rr_linux::socket::abort_linger(std::os::fd::AsRawFd::as_raw_fd(&peer))
            .expect("abort linger must apply");
        drop(peer);
        assert!(
            !super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
            "a reset must classify as rejected"
        );

        // A REALITY cover target mirroring the transfer would answer with a
        // handshake or alert record, never session application data.
        let (mut peer, stream) = tcp_pair().await;
        peer.write_all(&[0x16, 0x03, 0x01])
            .await
            .expect("peer write must succeed");
        assert!(
            !super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
            "non-application-data bytes must classify as rejected"
        );
        drop(peer);

        // A landing that holds the connection without answering trips the
        // deadline, not the session idle timeout.
        let (_peer, stream) = tcp_pair().await;
        let started = std::time::Instant::now();
        assert!(
            !super::first_downlink_landed(&stream, Duration::from_millis(50)).await,
            "a stalled landing must classify as rejected at the deadline"
        );
        assert!(
            started.elapsed() < TEST_TIMEOUT,
            "the deadline must bound the wait, not the idle timeout"
        );
    }
}
