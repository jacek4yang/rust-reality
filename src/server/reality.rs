use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    config::{NetworkConfig, ResourceGovernorConfig, VlessInboundConfig},
    network::NetworkEnvironment,
    protocol::{
        reality::{
            RealityAuthConfigError, RealityAuthenticator, ReplayCache, ReplayError,
            read_client_hello,
            tls13::{
                CertificateIdentity, ClientFinishedReadError, CoverHandshakePlan,
                CoverHandshakeRecordShape, HandshakeMessageError, ServerFlight, TlsApplicationIo,
                build_server_flight_with_shape, read_client_finished,
            },
        },
        vless::UserId,
    },
    runtime::{AdmissionDenied, AdmissionKind, AdmissionPermit, ResourceGovernor},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{self, Instant},
};

use super::fallback::{CoverConnection, FallbackError, FallbackStats, RealityFallback};

/// Validated runtime state could not be built for one REALITY listener.
#[derive(Debug)]
pub enum RealityAcceptorConfigError {
    /// REALITY private-key or identity-set compilation failed.
    Authentication(RealityAuthConfigError),
    /// Process-lifetime certificate identity generation failed.
    Certificate(HandshakeMessageError),
}

impl fmt::Display for RealityAcceptorConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(source) => source.fmt(formatter),
            Self::Certificate(source) => source.fmt(formatter),
        }
    }
}

impl Error for RealityAcceptorConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authentication(source) => Some(source),
            Self::Certificate(source) => Some(source),
        }
    }
}

/// A connection failed after it could no longer safely transition to cover fallback.
#[derive(Debug)]
pub enum RealityAcceptError {
    /// A bounded handshake or cryptographic category rejected work without waiting.
    Admission(AdmissionDenied),
    /// Connecting or transitioning to the cover target failed.
    Fallback(FallbackError),
    /// The authenticated handshake deadline elapsed while writing the server flight.
    HandshakeWriteTimeout,
    /// Writing the generated server flight failed.
    HandshakeWrite(io::Error),
    /// Encrypted ClientFinished was invalid or did not arrive in time.
    ClientFinished(ClientFinishedReadError),
    /// Replay state could not commit after a valid ClientFinished.
    Replay(ReplayError),
    /// Wall-clock time could not be represented for REALITY authentication.
    Clock,
}

impl fmt::Display for RealityAcceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(source) => source.fmt(formatter),
            Self::Fallback(source) => source.fmt(formatter),
            Self::HandshakeWriteTimeout => {
                formatter.write_str("REALITY server flight write timed out")
            }
            Self::HandshakeWrite(_) => formatter.write_str("REALITY server flight write failed"),
            Self::ClientFinished(source) => source.fmt(formatter),
            Self::Replay(source) => source.fmt(formatter),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
        }
    }
}

impl Error for RealityAcceptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Fallback(source) => Some(source),
            Self::HandshakeWrite(source) => Some(source),
            Self::ClientFinished(source) => Some(source),
            Self::Replay(source) => Some(source),
            Self::HandshakeWriteTimeout | Self::Clock => None,
        }
    }
}

/// A connection either authenticated into TLS application state or completed fallback.
#[derive(Debug)]
pub enum RealityAcceptOutcome {
    /// A valid ClientFinished unlocked application traffic and committed replay state.
    ///
    /// The established session is boxed so that the common fallback outcome does
    /// not pay for the much larger established-session state, which now retains
    /// reusable per-direction record storage.
    Established(Box<RealityEstablished>),
    /// The same inbound bytes were relayed to the configured cover target.
    Fallback(FallbackStats),
}

/// Established REALITY transport plus immutable VLESS authorization state.
pub struct RealityEstablished {
    stream: TlsApplicationIo<TcpStream>,
    inbound_tag: Arc<str>,
    client_random: [u8; 32],
    authenticated_user_id: UserId,
    cover_flight: Option<SelectedCoverFlight>,
}

struct SelectedCoverFlight {
    plan: CoverHandshakePlan,
    retained_prefix: Vec<u8>,
}

/// Non-secret cover-flight selection data used only for debug evidence.
pub(crate) struct CoverFlightEvidence {
    pub(crate) emit_ccs: bool,
    pub(crate) layout: &'static str,
    pub(crate) wire_lens: Vec<usize>,
    pub(crate) nst_wire_len: Option<usize>,
    pub(crate) retained_prefix: Vec<u8>,
}

impl RealityEstablished {
    /// Returns the inbound routing tag without exposing any key material.
    #[must_use]
    pub fn inbound_tag(&self) -> &str {
        &self.inbound_tag
    }

    /// Returns the client random of the accepted TLS session.
    ///
    /// A session-handoff transfer binds this value into its authenticated
    /// transcript so a continuation cannot be replayed onto a different
    /// session.
    #[must_use]
    pub const fn client_random(&self) -> &[u8; 32] {
        &self.client_random
    }

    /// Removes non-secret cover evidence for a debug log event.
    pub(crate) fn take_cover_flight_evidence(&mut self) -> Option<CoverFlightEvidence> {
        let selected = self.cover_flight.take()?;
        let (layout, wire_lens, nst_wire_len) = match selected.plan.shape {
            CoverHandshakeRecordShape::Coalesced { wire_len } => {
                ("coalesced", vec![wire_len], None)
            }
            CoverHandshakeRecordShape::PositionalRecords {
                wire_lens,
                nst_wire_len,
            } => ("positional", wire_lens.to_vec(), nst_wire_len),
        };
        Some(CoverFlightEvidence {
            emit_ccs: selected.plan.emit_ccs,
            layout,
            wire_lens,
            nst_wire_len,
            retained_prefix: selected.retained_prefix,
        })
    }

    /// Separates authenticated TLS I/O, authorization, and routing identity.
    #[must_use]
    pub fn into_parts(self) -> (TlsApplicationIo<TcpStream>, Arc<str>, UserId) {
        (self.stream, self.inbound_tag, self.authenticated_user_id)
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        stream: TlsApplicationIo<TcpStream>,
        authenticated_user_id: UserId,
    ) -> Self {
        Self {
            stream,
            inbound_tag: Arc::from("test-reality"),
            client_random: [0; 32],
            authenticated_user_id,
            cover_flight: None,
        }
    }
}

impl fmt::Debug for RealityEstablished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityEstablished")
            .field("stream", &self.stream)
            .field("inbound_tag", &self.inbound_tag)
            .finish_non_exhaustive()
    }
}

/// Immutable state that accepts one public VLESS + REALITY + Vision handshake.
pub struct RealityAcceptor {
    authenticator: RealityAuthenticator,
    replay: ReplayCache,
    identity: Arc<CertificateIdentity>,
    fallback: RealityFallback,
    governor: ResourceGovernor,
    inbound_tag: Arc<str>,
    client_hello_timeout: Duration,
    handshake_timeout: Duration,
    target_hello_timeout: Duration,
}

impl RealityAcceptor {
    /// Compiles an inbound while retaining process-wide replay history across
    /// immutable runtime generations.
    pub(crate) fn from_inbound_with_replay(
        inbound: &VlessInboundConfig,
        governor: ResourceGovernor,
        policy: &ResourceGovernorConfig,
        replay: ReplayCache,
        relay: crate::transport::TcpRelay,
        network: &NetworkConfig,
        network_environment: NetworkEnvironment,
    ) -> Result<Self, RealityAcceptorConfigError> {
        let reality = &inbound.stream_settings.reality_settings;
        let authenticator = RealityAuthenticator::from_inbound(inbound)
            .map_err(RealityAcceptorConfigError::Authentication)?;
        let identity = CertificateIdentity::generate()
            .map(Arc::new)
            .map_err(RealityAcceptorConfigError::Certificate)?;
        Ok(Self {
            authenticator,
            replay,
            identity,
            fallback: RealityFallback::with_environment(
                reality.target.as_str(),
                governor.clone(),
                policy,
                relay,
                network,
                network_environment,
            ),
            governor,
            inbound_tag: Arc::from(inbound.tag.as_str()),
            client_hello_timeout: Duration::from_millis(policy.client_hello_timeout_ms),
            handshake_timeout: Duration::from_millis(policy.handshake_timeout_ms),
            target_hello_timeout: Duration::from_millis(policy.connect_timeout_ms),
        })
    }

    /// Authenticates one accepted TCP stream or relays it byte-exactly to cover.
    ///
    /// Parse, SNI, authentication, replay, target compatibility, and pre-flight
    /// cryptographic failures all share the same fallback behavior. After the
    /// generated server flight is written, failures close instead of attempting an
    /// unsafe mid-handshake fallback. Replay commits only after ClientFinished.
    ///
    /// # Errors
    ///
    /// Returns only resource, cover connection, post-flight I/O, clock, or replay errors.
    pub async fn accept(
        &self,
        mut stream: TcpStream,
        _peer_addr: SocketAddr,
    ) -> Result<RealityAcceptOutcome, RealityAcceptError> {
        let handshake_permit = self
            .governor
            .try_acquire(AdmissionKind::Handshake)
            .map_err(RealityAcceptError::Admission)?;
        let read = match read_client_hello(&mut stream, self.client_hello_timeout).await {
            Ok(read) => read,
            Err(error) => {
                let (_, prefix) = error.into_parts();
                return self
                    .fallback_prefix(stream, &prefix, handshake_permit)
                    .await;
            }
        };
        let (hello, client_prefix, remainder) = read.into_parts();
        let client_random = *hello.random();
        if !remainder.is_empty() {
            return self
                .fallback_prefix(stream, &client_prefix, handshake_permit)
                .await;
        }

        let crypto_permit = match self.governor.try_acquire(AdmissionKind::CryptoOperation) {
            Ok(permit) => permit,
            Err(_) => {
                return self
                    .fallback_prefix(stream, &client_prefix, handshake_permit)
                    .await;
            }
        };
        let now = unix_seconds()?;
        let authenticated = match self.authenticator.authenticate(&hello, now) {
            Ok(authenticated) => authenticated,
            Err(_) => {
                drop(crypto_permit);
                return self
                    .fallback_prefix(stream, &client_prefix, handshake_permit)
                    .await;
            }
        };
        drop(crypto_permit);
        // One instant anchors both the replay reservation TTL and the
        // handshake deadline: they are the same duration, so a ClientFinished
        // accepted anywhere up to the deadline still finds its reservation
        // alive and can commit.
        let handshake_started = Instant::now();
        let replay = match self.replay.reserve_at(&hello, handshake_started.into_std()) {
            Ok(replay) => replay,
            Err(_) => {
                return self
                    .fallback_prefix(stream, &client_prefix, handshake_permit)
                    .await;
            }
        };
        let handshake_deadline = handshake_started
            .checked_add(self.handshake_timeout)
            .ok_or(RealityAcceptError::HandshakeWriteTimeout)?;
        let mut cover = self
            .fallback
            .mirror(&client_prefix)
            .await
            .map_err(RealityAcceptError::Fallback)?;
        let target_flight = match cover
            .read_server_flight(
                &hello,
                self.target_hello_timeout
                    .min(handshake_deadline.saturating_duration_since(Instant::now())),
            )
            .await
        {
            Ok(target_flight) => target_flight,
            Err(error) => {
                let (_, target_prefix) = error.into_parts();
                drop(replay);
                return transition_cover(stream, cover, &target_prefix, handshake_permit).await;
            }
        };
        let (target, record_shape, target_prefix) = target_flight.into_parts();
        let crypto_permit = match self.governor.try_acquire(AdmissionKind::CryptoOperation) {
            Ok(permit) => permit,
            Err(_) => {
                drop(replay);
                return transition_cover(stream, cover, &target_prefix, handshake_permit).await;
            }
        };
        // The client's first protocol is only the preference: the flight
        // builder downgrades it to what the cover's observed EE record slot
        // can hold, emitting no ALPN for a cover that negotiated none.
        let selected_alpn = hello.alpn_protocols().next();
        let flight = match build_server_flight_with_shape(
            &hello,
            authenticated.auth_key(),
            target,
            &self.identity,
            selected_alpn,
            record_shape,
        ) {
            Ok(flight) => flight,
            Err(_) => {
                drop(crypto_permit);
                drop(replay);
                return transition_cover(stream, cover, &target_prefix, handshake_permit).await;
            }
        };
        drop(crypto_permit);
        drop(cover);
        write_server_flight(&mut stream, &flight, handshake_deadline).await?;
        let established = read_client_finished(
            &mut stream,
            flight,
            handshake_deadline.saturating_duration_since(Instant::now()),
        )
        .await
        .map_err(RealityAcceptError::ClientFinished)?;
        replay
            .commit_after_client_finished()
            .map_err(RealityAcceptError::Replay)?;
        drop(handshake_permit);

        Ok(RealityAcceptOutcome::Established(Box::new(
            RealityEstablished {
                stream: TlsApplicationIo::new(stream, established),
                inbound_tag: Arc::clone(&self.inbound_tag),
                client_random,
                authenticated_user_id: authenticated.user_id(),
                cover_flight: Some(SelectedCoverFlight {
                    plan: record_shape,
                    retained_prefix: target_prefix,
                }),
            },
        )))
    }

    async fn fallback_prefix(
        &self,
        stream: TcpStream,
        prefix: &[u8],
        handshake_permit: AdmissionPermit,
    ) -> Result<RealityAcceptOutcome, RealityAcceptError> {
        drop(handshake_permit);
        self.fallback
            .relay(stream, prefix)
            .await
            .map(RealityAcceptOutcome::Fallback)
            .map_err(RealityAcceptError::Fallback)
    }
}

impl fmt::Debug for RealityAcceptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityAcceptor")
            .field("authenticator", &self.authenticator)
            .field("identity", &self.identity)
            .field("fallback", &self.fallback)
            .field("inbound_tag", &self.inbound_tag)
            .field("client_hello_timeout", &self.client_hello_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

async fn transition_cover(
    stream: TcpStream,
    cover: CoverConnection,
    target_prefix: &[u8],
    handshake_permit: AdmissionPermit,
) -> Result<RealityAcceptOutcome, RealityAcceptError> {
    drop(handshake_permit);
    cover
        .relay(stream, target_prefix)
        .await
        .map(RealityAcceptOutcome::Fallback)
        .map_err(RealityAcceptError::Fallback)
}

async fn write_server_flight(
    stream: &mut TcpStream,
    flight: &ServerFlight,
    deadline: Instant,
) -> Result<(), RealityAcceptError> {
    write_before(stream, flight.wire(), deadline).await
}

async fn write_before(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), RealityAcceptError> {
    time::timeout_at(deadline, stream.write_all(bytes))
        .await
        .map_err(|_| RealityAcceptError::HandshakeWriteTimeout)?
        .map_err(RealityAcceptError::HandshakeWrite)
}

fn unix_seconds() -> Result<u64, RealityAcceptError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RealityAcceptError::Clock)
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::{RealityAcceptError, RealityAcceptOutcome, RealityAcceptor};
    use crate::{
        config::{Config, test_config_json},
        protocol::reality::{ReplayCache, SESSION_ID_LEN, client_hello_fixtures},
        runtime::ResourceGovernor,
        server::fallback::FallbackError,
    };

    const COVER_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_failure_relays_exact_client_hello_to_cover() {
        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let mut config: Config =
            serde_json::from_str(test_config_json()).expect("test config must parse");
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .target = cover_listener
            .local_addr()
            .expect("cover address must exist")
            .to_string();
        let policy = config.advanced.limits.resource_governor.clone();
        let governor = ResourceGovernor::new(&policy);
        let replay = ReplayCache::new(governor.clone(), &policy);
        let acceptor = RealityAcceptor::from_inbound_with_replay(
            config.inbounds[0]
                .as_vless()
                .expect("fixture must contain VLESS"),
            governor,
            &policy,
            replay,
            crate::transport::TcpRelay::new(
                &crate::config::RelayPolicy::default(),
                crate::runtime::FdBudget::new(4_096),
            )
            .expect("test relay must build"),
            &config.network,
            crate::network::NetworkEnvironment::detect(),
        )
        .expect("validated inbound must compile");
        let (mut client, server, peer_addr) = tcp_pair().await;
        let message = client_hello_fixtures::client_hello(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
        );
        let client_prefix = client_hello_fixtures::record(&message);

        let exchange = async {
            let accept = acceptor.accept(server, peer_addr);
            let client_io = async {
                client.write_all(&client_prefix).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = cover_listener.accept().await?;
                let mut request = Vec::new();
                cover.read_to_end(&mut request).await?;
                cover.write_all(COVER_RESPONSE).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(accept, client_io, cover_io)
        };
        let (outcome, response, request) = timeout(Duration::from_secs(2), exchange)
            .await
            .expect("fallback exchange must complete");
        let outcome = outcome.expect("fallback must succeed");

        assert!(matches!(outcome, RealityAcceptOutcome::Fallback(_)));
        assert_eq!(response.expect("client I/O must succeed"), COVER_RESPONSE);
        assert_eq!(request.expect("cover I/O must succeed"), client_prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unavailable_cover_fails_closed_with_fallback_error() {
        // Reserve a port and drop the listener so cover connects are refused.
        let refused_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe listener must bind")
            .local_addr()
            .expect("probe address must exist")
            .to_string();
        let mut config: Config =
            serde_json::from_str(test_config_json()).expect("test config must parse");
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .target = refused_target;
        let policy = config.advanced.limits.resource_governor.clone();
        let governor = ResourceGovernor::new(&policy);
        let replay = ReplayCache::new(governor.clone(), &policy);
        let acceptor = RealityAcceptor::from_inbound_with_replay(
            config.inbounds[0]
                .as_vless()
                .expect("fixture must contain VLESS"),
            governor,
            &policy,
            replay,
            crate::transport::TcpRelay::new(
                &crate::config::RelayPolicy::default(),
                crate::runtime::FdBudget::new(4_096),
            )
            .expect("test relay must build"),
            &config.network,
            crate::network::NetworkEnvironment::detect(),
        )
        .expect("validated inbound must compile");
        let (mut client, server, peer_addr) = tcp_pair().await;
        let message = client_hello_fixtures::client_hello(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
        );
        let client_prefix = client_hello_fixtures::record(&message);

        let exchange = async {
            let accept = acceptor.accept(server, peer_addr);
            let client_io = async {
                client.write_all(&client_prefix).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                // Failing closed drops the session without serving cover
                // bytes; a reset satisfies the same observation as an EOF.
                let _ = client.read_to_end(&mut response).await;
                Ok::<_, io::Error>(response)
            };
            tokio::join!(accept, client_io)
        };
        let (outcome, response) = timeout(Duration::from_secs(2), exchange)
            .await
            .expect("a refused cover target must fail fast, not hang");

        let error = outcome.expect_err("an unreachable cover target must fail closed");
        match error {
            RealityAcceptError::Fallback(FallbackError::Io(error)) => assert_eq!(
                error.kind(),
                io::ErrorKind::ConnectionRefused,
                "the cover refusal must surface inside the fallback error"
            ),
            other => panic!("expected a fail-closed Fallback(Io) error, got {other}"),
        }
        assert_eq!(
            response.expect("client I/O must succeed"),
            b"",
            "a failed fallback must not serve any bytes to the client"
        );
    }

    async fn tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("inbound listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("inbound address must exist"))
            .await
            .expect("client must connect");
        let (server, peer_addr) = listener.accept().await.expect("server must accept");
        (client, server, peer_addr)
    }
}
