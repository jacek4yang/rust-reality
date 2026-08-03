use std::{
    error::Error,
    fmt, io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{self, Instant},
};
use uuid::Uuid;

use crate::{
    config::{InboundConfig, ResourceGovernorConfig},
    protocol::{
        reality::{
            RealityAuthConfigError, RealityAuthenticator, ReplayCache, ReplayError,
            read_client_hello,
            tls13::{
                CertificateIdentity, ClientFinishedReadError, HandshakeMessageError, ServerFlight,
                TlsApplicationIo, build_server_flight, read_client_finished,
            },
        },
        vless::{UserId, UserRegistry},
    },
    runtime::{AdmissionDenied, AdmissionKind, AdmissionPermit, ResourceGovernor},
};

use super::fallback::{CoverConnection, FallbackError, FallbackStats, RealityFallback};

/// Validated runtime state could not be built for one REALITY listener.
#[derive(Debug)]
pub enum RealityAcceptorConfigError {
    /// REALITY private-key or identity-set compilation failed.
    Authentication(RealityAuthConfigError),
    /// Process-lifetime certificate identity generation failed.
    Certificate(HandshakeMessageError),
    /// A configured VLESS UUID was not canonical after validation.
    UserId,
}

impl fmt::Display for RealityAcceptorConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(source) => source.fmt(formatter),
            Self::Certificate(source) => source.fmt(formatter),
            Self::UserId => formatter.write_str("invalid VLESS user ID in listener snapshot"),
        }
    }
}

impl Error for RealityAcceptorConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Authentication(source) => Some(source),
            Self::Certificate(source) => Some(source),
            Self::UserId => None,
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
    Established(RealityEstablished),
    /// The same inbound bytes were relayed to the configured cover target.
    Fallback(FallbackStats),
}

/// Established REALITY transport plus immutable VLESS authorization state.
pub struct RealityEstablished {
    stream: TlsApplicationIo<TcpStream>,
    users: Arc<UserRegistry>,
    inbound_tag: Arc<str>,
}

impl RealityEstablished {
    /// Returns the immutable VLESS user registry for the listener snapshot.
    #[must_use]
    pub fn users(&self) -> &UserRegistry {
        &self.users
    }

    /// Returns the inbound routing tag without exposing any key material.
    #[must_use]
    pub fn inbound_tag(&self) -> &str {
        &self.inbound_tag
    }

    /// Separates authenticated TLS I/O, authorization, and routing identity.
    #[must_use]
    pub fn into_parts(self) -> (TlsApplicationIo<TcpStream>, Arc<UserRegistry>, Arc<str>) {
        (self.stream, self.users, self.inbound_tag)
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        stream: TlsApplicationIo<TcpStream>,
        users: UserRegistry,
    ) -> Self {
        Self {
            stream,
            users: Arc::new(users),
            inbound_tag: Arc::from("test-reality"),
        }
    }
}

impl fmt::Debug for RealityEstablished {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityEstablished")
            .field("stream", &self.stream)
            .field("users", &"[COMPILED]")
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
    users: Arc<UserRegistry>,
    inbound_tag: Arc<str>,
    client_hello_timeout: Duration,
    handshake_timeout: Duration,
    target_hello_timeout: Duration,
}

impl RealityAcceptor {
    /// Compiles one validated inbound snapshot into process runtime state.
    ///
    /// # Errors
    ///
    /// Returns an authentication-key, certificate-identity, or UUID error.
    pub fn from_inbound(
        inbound: &InboundConfig,
        governor: ResourceGovernor,
        policy: &ResourceGovernorConfig,
    ) -> Result<Self, RealityAcceptorConfigError> {
        let reality = &inbound.stream_settings.reality_settings;
        let authenticator = RealityAuthenticator::from_config(reality)
            .map_err(RealityAcceptorConfigError::Authentication)?;
        let identity = CertificateIdentity::generate()
            .map(Arc::new)
            .map_err(RealityAcceptorConfigError::Certificate)?;
        let users = inbound
            .settings
            .clients
            .iter()
            .map(|client| {
                Uuid::parse_str(&client.id)
                    .map(|uuid| UserId::new(*uuid.as_bytes()))
                    .map_err(|_| RealityAcceptorConfigError::UserId)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            authenticator,
            replay: ReplayCache::new(governor.clone(), policy),
            identity,
            fallback: RealityFallback::new(reality.target.as_str(), governor.clone(), policy),
            governor,
            users: Arc::new(UserRegistry::new(users)),
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
                    .fallback_prefix(&mut stream, &prefix, handshake_permit)
                    .await;
            }
        };
        let (hello, client_prefix, remainder) = read.into_parts();
        if !remainder.is_empty() {
            return self
                .fallback_prefix(&mut stream, &client_prefix, handshake_permit)
                .await;
        }

        let crypto_permit = match self.governor.try_acquire(AdmissionKind::CryptoOperation) {
            Ok(permit) => permit,
            Err(_) => {
                return self
                    .fallback_prefix(&mut stream, &client_prefix, handshake_permit)
                    .await;
            }
        };
        let now = unix_seconds()?;
        let authenticated = match self.authenticator.authenticate(&hello, now) {
            Ok(authenticated) => authenticated,
            Err(_) => {
                drop(crypto_permit);
                return self
                    .fallback_prefix(&mut stream, &client_prefix, handshake_permit)
                    .await;
            }
        };
        drop(crypto_permit);
        let replay = match self.replay.reserve(&hello) {
            Ok(replay) => replay,
            Err(_) => {
                return self
                    .fallback_prefix(&mut stream, &client_prefix, handshake_permit)
                    .await;
            }
        };
        let handshake_deadline = Instant::now()
            .checked_add(self.handshake_timeout)
            .ok_or(RealityAcceptError::HandshakeWriteTimeout)?;
        let mut cover = self
            .fallback
            .mirror(&client_prefix)
            .await
            .map_err(RealityAcceptError::Fallback)?;
        let target_hello = match cover
            .read_server_hello(
                &hello,
                self.target_hello_timeout
                    .min(handshake_deadline.saturating_duration_since(Instant::now())),
            )
            .await
        {
            Ok(target_hello) => target_hello,
            Err(error) => {
                let (_, target_prefix) = error.into_parts();
                drop(replay);
                return transition_cover(&mut stream, cover, &target_prefix, handshake_permit)
                    .await;
            }
        };
        let (target, target_prefix) = target_hello.into_parts();
        let crypto_permit = match self.governor.try_acquire(AdmissionKind::CryptoOperation) {
            Ok(permit) => permit,
            Err(_) => {
                drop(replay);
                return transition_cover(&mut stream, cover, &target_prefix, handshake_permit)
                    .await;
            }
        };
        let selected_alpn = hello.alpn_protocols().next().map(<[u8]>::to_vec);
        let flight = match build_server_flight(
            &hello,
            authenticated.auth_key(),
            target,
            &self.identity,
            selected_alpn.as_deref(),
        ) {
            Ok(flight) => flight,
            Err(_) => {
                drop(crypto_permit);
                drop(replay);
                return transition_cover(&mut stream, cover, &target_prefix, handshake_permit)
                    .await;
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

        Ok(RealityAcceptOutcome::Established(RealityEstablished {
            stream: TlsApplicationIo::new(stream, established),
            users: Arc::clone(&self.users),
            inbound_tag: Arc::clone(&self.inbound_tag),
        }))
    }

    async fn fallback_prefix(
        &self,
        stream: &mut TcpStream,
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
            .field("users", &"[COMPILED]")
            .field("inbound_tag", &self.inbound_tag)
            .field("client_hello_timeout", &self.client_hello_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

async fn transition_cover(
    stream: &mut TcpStream,
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
    write_before(stream, flight.server_hello_record(), deadline).await?;
    write_before(stream, flight.change_cipher_spec(), deadline).await?;
    for record in flight.encrypted_handshake_records() {
        write_before(stream, record, deadline).await?;
    }
    Ok(())
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

    use super::{RealityAcceptOutcome, RealityAcceptor};
    use crate::{
        config::{Config, test_config_json},
        protocol::reality::{SESSION_ID_LEN, client_hello_fixtures},
        runtime::ResourceGovernor,
    };

    const COVER_RESPONSE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_failure_relays_exact_client_hello_to_cover() {
        let cover_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let mut config: Config =
            serde_json::from_str(test_config_json()).expect("test config must parse");
        config.inbounds[0].stream_settings.reality_settings.target = cover_listener
            .local_addr()
            .expect("cover address must exist")
            .to_string();
        let policy = config.policy.resource_governor.clone();
        let governor = ResourceGovernor::new(&policy);
        let acceptor = RealityAcceptor::from_inbound(&config.inbounds[0], governor, &policy)
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
