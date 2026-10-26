//! LANDING-side Handoff session resume handler.
//!
//! Internal to [`crate::server::handoff`]: opens a sealed transfer, reconstructs
//! TLS application halves, and runs the resumed Vision session. Behavior-
//! preserving modularization only — no wire, crypto, or trust changes.

use std::{
    error::Error,
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::crypto::StaticX25519Key;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    config::{SecretString, node::landing::HandoffLandingConfig},
    network::NetworkEnvironment,
    protocol::{
        handoff::{
            HEADER_LEN, HandoffError, HandoffLandingKeys, HandoffPsk, HandoffReplayCache,
            SessionKind, message_len_from_header, open_transfer,
        },
        reality::tls13::{EstablishedTls, ExportedTlsState, resume_application_halves},
        vless::UserId,
    },
    runtime::{AdmissionDenied, PressureGauge, ResourceGovernor},
    transport::{
        relay::RelayStats,
        tcp_relay::{TcpRelay, TcpRelayConfigError},
    },
};

use super::super::{
    connector::{DestinationConnectError, DestinationConnector},
    outbound::{OutboundConnectError, OutboundConnectOutcome, OutboundRegistry},
    pre_auth::{PreAuthError, PreAuthGeneration, begin_authentication},
    vision::{VisionSessionError, run_resumed_session},
};
use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::ResourceGovernorPolicy;

/// One Handoff landing connection: verify and decrypt one transfer, dial the
/// transferred destination — directly, or through the listener's configured
/// egress outbound — then resume the session's Vision relay.
///
/// Every failure before the session relay starts closes the connection with
/// zero response bytes; LINE observes the close as a transfer rejection.
#[derive(Clone)]

pub struct HandoffLandingHandler {
    pub(crate) keys: HandoffLandingKeys,
    pub(crate) replay: HandoffReplayCache,
    maximum_time_difference: u64,
    connector: DestinationConnector,
    egress: Option<LandingEgress>,
    pre_auth_idle_timeout: Duration,
    authentication_timeout: Duration,
    pub(crate) governor: ResourceGovernor,
    pressure: PressureGauge,
    generation: PreAuthGeneration,
    pub(crate) relay: TcpRelay,
    /// Idle bound handed to the resumed Vision relay, so a stalled peer cannot
    /// park a landing session on its descriptors and permits forever.
    io_timeout: Duration,
}

/// A validated outbound the landing dials transferred destinations through.
#[derive(Clone)]
struct LandingEgress {
    registry: OutboundRegistry,
    tag: Arc<str>,
}

impl HandoffLandingHandler {
    /// Compiles one validated listener while retaining its process-lifetime
    /// replay history across immutable runtime generations.
    ///
    /// When the listener configures `settings.egress`, the landing dials
    /// transferred destinations through that tag of the shared outbound
    /// registry instead of dialing directly; validation has already excluded
    /// unknown tags and handoff-typed outbounds.
    ///
    /// # Errors
    ///
    /// Rejects malformed or incorrectly sized key material.
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per immutable landing policy and process authority"
    )]
    pub(crate) fn from_landing_with_replay(
        settings: &HandoffLandingConfig,
        egress: Option<&str>,
        replay: HandoffReplayCache,
        relay: TcpRelay,
        io_timeout: Duration,
        outbounds: &OutboundRegistry,
        network: &NetworkConfig,
        network_environment: NetworkEnvironment,
        governor: ResourceGovernor,
        pressure: PressureGauge,
        generation: PreAuthGeneration,
    ) -> Result<Self, HandoffLandingConfigError> {
        let timing = settings.timing();
        let psk = decode_key(&settings.psk)?;
        let secret = decode_key(&settings.private_key)?;
        let previous_psks = settings
            .previous_psks()
            .iter()
            .map(|key| decode_key(key).map(HandoffPsk::new))
            .collect::<Result<Vec<_>, _>>()?;
        let previous_secrets = settings
            .previous_private_keys()
            .iter()
            .map(|key| decode_key(key).map(|bytes| StaticX25519Key::new(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        let keys = HandoffLandingKeys::with_previous(
            HandoffPsk::new(psk),
            previous_psks,
            StaticX25519Key::new(&secret),
            previous_secrets,
        )
        .ok_or(HandoffLandingConfigError::Key)?;
        let mut handler = Self::new(
            keys,
            replay,
            timing.max_time_difference_seconds,
            Duration::from_millis(timing.connect_timeout_ms),
            Duration::from_millis(timing.authentication_timeout_ms),
            relay,
            io_timeout,
        );
        handler.pre_auth_idle_timeout = Duration::from_millis(timing.pre_auth_idle_timeout_ms);
        handler.governor = governor;
        handler.pressure = pressure;
        handler.generation = generation;
        handler.connector = DestinationConnector::with_environment(
            Duration::from_millis(timing.connect_timeout_ms),
            *network,
            network_environment,
        );
        Ok(match egress {
            Some(name) => handler.with_egress(outbounds.clone(), name),
            None => handler,
        })
    }

    /// Selects the validated outbound the landing dials transferred
    /// destinations through, replacing the default direct dial.
    #[must_use]
    pub fn with_egress(mut self, outbounds: OutboundRegistry, tag: &str) -> Self {
        self.egress = Some(LandingEgress {
            registry: outbounds,
            tag: Arc::from(tag),
        });
        self
    }

    /// Creates a landing handler from already compiled policy.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per compiled listener policy input"
    )]
    pub fn new(
        keys: HandoffLandingKeys,
        replay: HandoffReplayCache,
        maximum_time_difference: u64,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        relay: TcpRelay,
        io_timeout: Duration,
    ) -> Self {
        let governor = ResourceGovernor::new(&ResourceGovernorPolicy::default());
        Self {
            keys,
            replay,
            maximum_time_difference,
            connector: DestinationConnector::new(connect_timeout),
            egress: None,
            pre_auth_idle_timeout: Duration::from_secs(60),
            authentication_timeout,
            governor,
            pressure: PressureGauge::new(),
            generation: PreAuthGeneration::default(),
            relay,
            io_timeout,
        }
    }

    /// Processes a single Handoff TCP connection.
    ///
    /// Authentication failures return without writing a response and occur
    /// before destination DNS or connect. On success the transferred pending
    /// ciphertext is fed to the resumed record layer first, the prefetched
    /// payload enters a fresh Vision decoder first, and the first downlink is
    /// either an owed KeyUpdate response or the response header plus opening
    /// Vision frame. It is sealed at the exact transferred generation and
    /// sequence zero or one.
    ///
    /// # Errors
    ///
    /// Returns bounded transfer-read, clock, authentication, destination, or
    /// relay errors. Callers must silently close on every error.
    pub async fn handle(&self, mut inbound: TcpStream) -> Result<RelayStats, HandoffLandingError> {
        let authentication = begin_authentication(
            &mut inbound,
            self.pre_auth_idle_timeout,
            self.authentication_timeout,
            &self.governor,
            &self.pressure,
            &self.generation,
        )
        .await
        .map_err(HandoffLandingError::from_pre_auth)?;
        let message = read_transfer_after_first(
            &mut inbound,
            authentication.first_byte,
            authentication.deadline,
        )
        .await?;
        let now = unix_seconds()?;
        let opened = open_transfer(
            &message,
            &self.keys,
            &self.replay,
            now,
            self.maximum_time_difference,
        )
        .map_err(HandoffLandingError::Protocol)?;
        // The wire message's only consumer is `open_transfer`.
        drop(message);
        let state = opened.into_state();
        // Move both generation secrets into TLS state before touching the
        // network: a blob that cannot resume must not cost a destination
        // connection, and no duplicate secret representation survives.
        let (
            exported_tls,
            user_id,
            destination,
            pending,
            prefetched,
            key_update_response_pending,
            session_kind,
            _inbound_tag,
            policy,
        ) = state.into_parts().map_err(HandoffLandingError::Protocol)?;
        let tls = resume_tls(exported_tls)?;
        let user_id = UserId::new(user_id);
        // Authentication state no longer owns session material once the
        // continuation has been consumed into these move-only parts.
        drop(authentication);

        if session_kind == SessionKind::Xudp {
            // XUDP: no TCP dial / destination side effect. TLS ownership is on
            // LANDING; UDP sockets open only after transfer+auth succeeded.
            // Bind UDP to the same local IP the Handoff TCP listener accepted on
            // so peers observe LANDING (not LINE) on multi-address loopback.
            let udp_bind_ip = inbound.local_addr().ok().map(|addr| addr.ip());
            let (reader_half, writer_half) = inbound.into_split();
            let (client_reader, client_writer) = resume_application_halves(
                reader_half,
                pending,
                writer_half,
                tls,
                key_update_response_pending,
            );
            let stats = crate::server::vision::run_resumed_xudp_session(
                client_reader,
                client_writer,
                user_id,
                prefetched,
                policy,
                self.io_timeout,
                udp_bind_ip,
            )
            .await
            .map_err(HandoffLandingError::Session)?;
            return Ok(RelayStats::new(
                stats.uplink_bytes(),
                stats.downlink_bytes(),
            ));
        }

        // TCP Vision resume (existing path).
        // The descriptor unit is reserved before connect(2) and outlives the
        // relay: the outbound socket closes before its unit is released. Both
        // permit slots are declared before the socket so either dial path
        // keeps that drop order. The egress registry and the default connector
        // each acquire and return their own correctly accounted unit.
        let _ = policy;
        let _fd_permit;
        let _egress_permit;
        let destination = match &self.egress {
            Some(egress) => match egress.registry.connect(&egress.tag, &destination).await {
                Ok(OutboundConnectOutcome::Connected(connection)) => {
                    let (stream, permit) = connection.into_parts();
                    _egress_permit = permit;
                    stream
                }
                // A blackhole egress discards the session by configuration:
                // end it without dialing and without an error, leaving the
                // silent close the line node reads as a rejection.
                Ok(OutboundConnectOutcome::Blocked) => return Ok(RelayStats::new(0, 0)),
                Err(source) => return Err(HandoffLandingError::Egress(source)),
            },
            None => {
                let connected = self
                    .connector
                    .connect_resolved_accounted(&destination, &[], self.relay.fd_budget())
                    .await
                    .map_err(|error| match error {
                        DestinationConnectError::DescriptorBudget => {
                            HandoffLandingError::DescriptorBudget
                        }
                        error => HandoffLandingError::Destination(error),
                    })?;
                let (stream, permit) = connected.into_parts();
                _fd_permit = permit;
                stream
            }
        };
        let (reader_half, writer_half) = inbound.into_split();
        let (client_reader, client_writer) = resume_application_halves(
            reader_half,
            pending,
            writer_half,
            tls,
            key_update_response_pending,
        );
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

/// Decodes one validated base64 32-byte secret; validated configuration has
/// already excluded every failure this maps to `Key`.
fn decode_key(key: &SecretString) -> Result<[u8; 32], HandoffLandingConfigError> {
    let decoded = Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD
            .decode(key.expose())
            .map_err(|_| HandoffLandingConfigError::Key)?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| HandoffLandingConfigError::Key)
}

/// Rebuilds the session's TLS application state from a verified transfer.
pub(super) fn resume_tls(state: ExportedTlsState) -> Result<EstablishedTls, HandoffLandingError> {
    EstablishedTls::from_exported_state(state)
        .map_err(|_| HandoffLandingError::Protocol(HandoffError::State))
}

async fn read_transfer_after_first(
    stream: &mut TcpStream,
    first_byte: u8,
    deadline: Instant,
) -> Result<Vec<u8>, HandoffLandingError> {
    let mut header = [0_u8; HEADER_LEN];
    header[0] = first_byte;
    read_exact_before(stream, &mut header[1..], deadline).await?;
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

pub(super) fn unix_seconds() -> Result<u64, HandoffLandingError> {
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
    /// Pre-auth idle or authentication admission was refused.
    Admission(AdmissionDenied),
    /// An unused socket was reclaimed by pressure or generation retirement.
    Reclaimed,
    /// The LINE retired an unused zero-byte warm transport normally.
    PreAuthPeerClosed,
    /// Runtime reload retired this unused pre-auth generation normally.
    PreAuthGenerationRetired,
    Timeout,
    Read(io::Error),
    Protocol(HandoffError),
    Allocation,
    Clock,
    Destination(DestinationConnectError),
    /// The configured egress outbound could not serve the transferred
    /// destination dial.
    Egress(OutboundConnectError),
    Session(VisionSessionError),
    DescriptorBudget,
}

impl HandoffLandingError {
    fn from_pre_auth(error: PreAuthError) -> Self {
        match error {
            PreAuthError::Admission(error) => Self::Admission(error),
            PreAuthError::Timeout => Self::Timeout,
            PreAuthError::PeerClosed => Self::PreAuthPeerClosed,
            PreAuthError::Read(error) => Self::Read(error),
            PreAuthError::PressureReclaimed => Self::Reclaimed,
            PreAuthError::GenerationRetired => Self::PreAuthGenerationRetired,
        }
    }
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
            Self::Egress(source) => Some(source),
            Self::Session(source) => Some(source),
            Self::Admission(source) => Some(source),
            Self::Reclaimed
            | Self::PreAuthPeerClosed
            | Self::PreAuthGenerationRetired
            | Self::Timeout
            | Self::Allocation
            | Self::Clock
            | Self::DescriptorBudget => None,
        }
    }
}

impl From<DestinationConnectError> for HandoffLandingError {
    fn from(source: DestinationConnectError) -> Self {
        Self::Destination(source)
    }
}
