use std::{error::Error, fmt, io, sync::Arc, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{self, Instant},
};

use crate::{
    config::ResourceGovernorConfig,
    protocol::reality::{
        ClientHello,
        tls13::{
            TargetServerHelloRead, TargetServerHelloReadError,
            read_target_server_hello as read_server_hello,
        },
    },
    runtime::{AdmissionDenied, AdmissionKind, AdmissionPermit, ResourceGovernor},
    transport::{RelayContext, TcpRelay, relay::RelayStats},
};

/// Completed fallback byte counts, including the already-consumed wire prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackStats {
    forwarded_prefix: u64,
    returned_prefix: u64,
    relay: RelayStats,
}

impl FallbackStats {
    /// Returns the exact number of pre-read bytes forwarded before live relay.
    #[must_use]
    pub const fn forwarded_prefix_bytes(self) -> u64 {
        self.forwarded_prefix
    }

    /// Returns target bytes replayed before live target-to-client relay.
    #[must_use]
    pub const fn returned_prefix_bytes(self) -> u64 {
        self.returned_prefix
    }

    /// Returns the subsequent bidirectional relay counts.
    #[must_use]
    pub const fn relay(self) -> RelayStats {
        self.relay
    }
}

/// A bounded cover-target fallback failure.
#[derive(Debug)]
pub enum FallbackError {
    /// Global fallback admission rejected the session without queuing.
    Admission(AdmissionDenied),
    /// Cover target connection exceeded its configured deadline.
    ConnectTimeout,
    /// The entire fallback session exceeded its configured lifetime.
    SessionTimeout,
    /// Target connection, exact prefix forwarding, or relay failed.
    Io(io::Error),
    /// The descriptor budget denied the cover connection before `connect(2)`.
    DescriptorBudget,
}

impl fmt::Display for FallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(_) => formatter.write_str("REALITY fallback admission denied"),
            Self::ConnectTimeout => formatter.write_str("REALITY cover connection timed out"),
            Self::SessionTimeout => formatter.write_str("REALITY fallback session timed out"),
            Self::Io(_) => formatter.write_str("REALITY fallback I/O failed"),
            Self::DescriptorBudget => {
                formatter.write_str("descriptor budget denied the fallback connection")
            }
        }
    }
}

impl Error for FallbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::ConnectTimeout | Self::SessionTimeout | Self::DescriptorBudget => None,
        }
    }
}

/// Connects failed REALITY handshakes to their cover target under hard bounds.
#[derive(Clone)]
pub struct RealityFallback {
    target: Arc<str>,
    governor: ResourceGovernor,
    relay: TcpRelay,
    connect_timeout: Duration,
    session_timeout: Duration,
}

/// One admitted cover connection whose byte ownership can transition to fallback.
pub struct CoverConnection {
    stream: TcpStream,
    governor: ResourceGovernor,
    relay: TcpRelay,
    permit: Option<AdmissionPermit>,
    fd_permit: Option<crate::runtime::FdPermit>,
    deadline: Instant,
    forwarded_prefix: u64,
}

impl RealityFallback {
    /// Creates immutable fallback state from a validated listener snapshot.
    #[must_use]
    pub fn new(
        target: impl Into<Arc<str>>,
        governor: ResourceGovernor,
        config: &ResourceGovernorConfig,
        relay: TcpRelay,
    ) -> Self {
        Self {
            target: target.into(),
            governor,
            relay,
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            session_timeout: Duration::from_millis(config.fallback_timeout_ms),
        }
    }

    /// Forwards every consumed byte before relaying any new client input.
    ///
    /// The caller must pass the exact owned prefix from `read_client_hello`; this
    /// method never reparses, normalizes, or reconstructs attacker-controlled bytes.
    /// Admission is non-waiting and both connection setup and total lifetime are
    /// bounded. The permit is released on timeout, cancellation, and every error.
    ///
    /// After the exact prefixes are written, the remaining raw pair is relayed by
    /// the unified owned relay, so a fallback session can use kernel backends
    /// under the same descriptor accounting as every other raw boundary.
    ///
    /// # Errors
    ///
    /// Returns an admission, deadline, connection, prefix-write, or relay error.
    pub async fn relay(
        &self,
        inbound: TcpStream,
        consumed_prefix: &[u8],
    ) -> Result<FallbackStats, FallbackError> {
        self.connect(consumed_prefix)
            .await?
            .relay(inbound, &[])
            .await
    }

    /// Opens one admitted target connection and writes the exact client prefix.
    ///
    /// The returned connection may first inspect the target ServerHello. Any bytes
    /// consumed during that inspection remain caller-owned and can be supplied to
    /// [`CoverConnection::relay`] if authentication or compatibility later fails.
    ///
    /// # Errors
    ///
    /// Returns an admission, connection deadline, prefix write, or session error.
    pub async fn connect(&self, consumed_prefix: &[u8]) -> Result<CoverConnection, FallbackError> {
        let permit = self
            .governor
            .try_acquire(AdmissionKind::Fallback)
            .map_err(FallbackError::Admission)?;
        self.connect_with_permit(consumed_prefix, Some(permit))
            .await
    }

    /// Opens a short-lived target mirror without consuming fallback capacity.
    ///
    /// The caller must already hold handshake admission. If the connection later
    /// transitions to byte relay, [`CoverConnection::relay`] acquires fallback
    /// admission immediately before that longer-lived phase.
    ///
    /// # Errors
    ///
    /// Returns a connection deadline, prefix write, or session error.
    pub async fn mirror(&self, consumed_prefix: &[u8]) -> Result<CoverConnection, FallbackError> {
        self.connect_with_permit(consumed_prefix, None).await
    }

    async fn connect_with_permit(
        &self,
        consumed_prefix: &[u8],
        permit: Option<AdmissionPermit>,
    ) -> Result<CoverConnection, FallbackError> {
        let now = Instant::now();
        let deadline = now
            .checked_add(self.session_timeout)
            .ok_or(FallbackError::SessionTimeout)?;
        let connect_deadline = now
            .checked_add(self.connect_timeout)
            .map_or(deadline, |candidate| candidate.min(deadline));
        let fd_permit = self
            .relay
            .fd_budget()
            .try_acquire(crate::runtime::UNITS_OUTBOUND_SOCKET)
            .ok_or(FallbackError::DescriptorBudget)?;
        let connect = TcpStream::connect(self.target.as_ref());
        let mut stream = time::timeout_at(connect_deadline, connect)
            .await
            .map_err(|_| FallbackError::ConnectTimeout)?
            .map_err(FallbackError::Io)?;
        stream.set_nodelay(true).map_err(FallbackError::Io)?;
        time::timeout_at(deadline, stream.write_all(consumed_prefix))
            .await
            .map_err(|_| FallbackError::SessionTimeout)?
            .map_err(FallbackError::Io)?;
        let forwarded_prefix =
            u64::try_from(consumed_prefix.len()).map_or(u64::MAX, |length| length);
        Ok(CoverConnection {
            stream,
            governor: self.governor.clone(),
            relay: self.relay.clone(),
            permit,
            fd_permit: Some(fd_permit),
            deadline,
            forwarded_prefix,
        })
    }
}

impl CoverConnection {
    /// Reads the compatible target ServerHello without consuming its next record.
    ///
    /// The shorter of `timeout` and the remaining fallback lifetime is used.
    ///
    /// # Errors
    ///
    /// Returns a byte-owning target read error suitable for exact fallback.
    pub async fn read_server_hello(
        &mut self,
        client: &ClientHello,
        timeout: Duration,
    ) -> Result<TargetServerHelloRead, TargetServerHelloReadError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        read_server_hello(&mut self.stream, client, timeout.min(remaining)).await
    }

    /// Replays a previously consumed target prefix, then relays the same connection.
    ///
    /// This consumes the transaction so the fallback permit and socket cannot be
    /// accidentally reused after ownership passes to the unified raw relay. The
    /// owned client and cover sockets are handed to [`TcpRelay::relay_owned`], so
    /// the remaining raw pair can run on the best available backend instead of a
    /// borrowed userspace copy.
    ///
    /// # Errors
    ///
    /// Returns an I/O or absolute session-lifetime error.
    pub async fn relay(
        mut self,
        inbound: TcpStream,
        consumed_target_prefix: &[u8],
    ) -> Result<FallbackStats, FallbackError> {
        let _permit = match self.permit.take() {
            Some(permit) => permit,
            None => self
                .governor
                .try_acquire(AdmissionKind::Fallback)
                .map_err(FallbackError::Admission)?,
        };
        // Declared before the relay future so it drops last: the cover
        // descriptor is closed before its budget unit is released.
        let _fd_permit = self.fd_permit.take();
        let operation = async {
            let mut inbound = inbound;
            inbound
                .write_all(consumed_target_prefix)
                .await
                .map_err(FallbackError::Io)?;
            let outcome = self
                .relay
                // No idle liveness here: the absolute session deadline below
                // already bounds the whole relay, subsuming an idle window.
                .relay_owned(inbound, self.stream, RelayContext::owned())
                .await
                .map_err(FallbackError::Io)?;
            let returned_prefix =
                u64::try_from(consumed_target_prefix.len()).map_or(u64::MAX, |length| length);
            Ok(FallbackStats {
                forwarded_prefix: self.forwarded_prefix,
                returned_prefix,
                relay: RelayStats::new(
                    outcome.inbound_to_outbound(),
                    outcome.outbound_to_inbound(),
                ),
            })
        };

        time::timeout_at(self.deadline, operation)
            .await
            .map_err(|_| FallbackError::SessionTimeout)?
    }
}

impl fmt::Debug for CoverConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverConnection")
            .field("deadline", &self.deadline)
            .field("forwarded_prefix", &self.forwarded_prefix)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RealityFallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFallback")
            .field("target", &"[CONFIGURED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("session_timeout", &self.session_timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::{FallbackError, RealityFallback};
    use crate::{
        config::{RelayPolicy, ResourceGovernorConfig},
        protocol::reality::{ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello_fixtures},
        runtime::{FdBudget, ResourceGovernor},
        transport::TcpRelay,
    };

    const PREFIX: &[u8] = b"exact-fragmented-client-hello-prefix";
    const SUFFIX: &[u8] = b"bytes-read-after-fallback-connect";
    const RESPONSE: &[u8] = b"cover-response";

    fn test_fallback(target: String, config: &ResourceGovernorConfig) -> RealityFallback {
        let relay = TcpRelay::new(&RelayPolicy::default(), FdBudget::new(4_096))
            .expect("test relay must build");
        RealityFallback::new(target, ResourceGovernor::new(config), config, relay)
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("pair listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("pair address must exist"))
            .await
            .expect("pair client must connect");
        let (server, _) = listener.accept().await.expect("pair must accept");
        (client, server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forwards_consumed_prefix_byte_exactly_before_live_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(target, &config);
        let (mut client, inbound) = tcp_pair().await;

        let exchange = async {
            let fallback_io = fallback.relay(inbound, PREFIX);
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut request = Vec::new();
                cover.read_to_end(&mut request).await?;
                cover.write_all(RESPONSE).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("fallback exchange must finish");

        let stats = fallback_result.expect("fallback must succeed");
        let response = client_result.expect("client I/O must succeed");
        let request = cover_result.expect("cover I/O must succeed");
        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(SUFFIX);
        assert_eq!(request, expected);
        assert_eq!(response, RESPONSE);
        assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
        assert_eq!(stats.returned_prefix_bytes(), 0);
        assert_eq!(
            stats.relay().inbound_to_outbound_bytes(),
            SUFFIX.len() as u64
        );
        assert_eq!(
            stats.relay().outbound_to_inbound_bytes(),
            RESPONSE.len() as u64
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspected_target_response_can_rejoin_same_fallback_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(target, &config);
        let client_hello = client_hello();
        let target_record = target_server_hello_record();
        let (mut client, inbound) = tcp_pair().await;

        let exchange = async {
            let fallback_io = async {
                let mut connection = fallback
                    .connect(PREFIX)
                    .await
                    .expect("cover connection must open");
                let target_hello = connection
                    .read_server_hello(&client_hello, Duration::from_secs(1))
                    .await
                    .expect("target ServerHello must be compatible");
                connection.relay(inbound, target_hello.wire_record()).await
            };
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut prefix = vec![0_u8; PREFIX.len()];
                cover.read_exact(&mut prefix).await?;
                cover.write_all(&target_record).await?;
                let mut suffix = Vec::new();
                cover.read_to_end(&mut suffix).await?;
                cover.write_all(RESPONSE).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>((prefix, suffix))
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("inspected fallback exchange must finish");

        let stats = fallback_result.expect("same cover connection must relay");
        let response = client_result.expect("client I/O must succeed");
        let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
        let mut expected_response = target_record.clone();
        expected_response.extend_from_slice(RESPONSE);
        assert_eq!(prefix, PREFIX);
        assert_eq!(suffix, SUFFIX);
        assert_eq!(response, expected_response);
        assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
        assert_eq!(stats.returned_prefix_bytes(), target_record.len() as u64);
        assert_eq!(
            stats.relay().inbound_to_outbound_bytes(),
            SUFFIX.len() as u64
        );
        assert_eq!(
            stats.relay().outbound_to_inbound_bytes(),
            RESPONSE.len() as u64
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_releases_fallback_admission_permit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let mut config = ResourceGovernorConfig {
            max_fallbacks: 1,
            fallback_timeout_ms: 10,
            ..ResourceGovernorConfig::default()
        };
        config.connect_timeout_ms = 100;
        let fallback = test_fallback(
            listener
                .local_addr()
                .expect("cover listener address must exist")
                .to_string(),
            &config,
        );

        for _ in 0..2 {
            let (_client, inbound) = tcp_pair().await;
            assert!(matches!(
                fallback.relay(inbound, &[]).await,
                Err(FallbackError::SessionTimeout)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_mirror_acquires_fallback_capacity_only_when_relaying() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let config = ResourceGovernorConfig {
            max_fallbacks: 0,
            ..ResourceGovernorConfig::default()
        };
        let fallback = test_fallback(
            listener
                .local_addr()
                .expect("cover listener address must exist")
                .to_string(),
            &config,
        );

        let connection = fallback
            .mirror(PREFIX)
            .await
            .expect("short target mirror must not consume fallback capacity");
        let (mut cover, _) = listener.accept().await.expect("mirror must connect");
        let mut received = vec![0_u8; PREFIX.len()];
        cover
            .read_exact(&mut received)
            .await
            .expect("mirror prefix must arrive");
        assert_eq!(received, PREFIX);

        let (_client, inbound) = tcp_pair().await;
        assert!(matches!(
            connection.relay(inbound, &[]).await,
            Err(FallbackError::Admission(_))
        ));
    }

    fn client_hello() -> ClientHello {
        ClientHello::parse_message(&client_hello_fixtures::client_hello_with_key_share(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            X25519_GROUP,
            &[0x22; 32],
        ))
        .expect("test ClientHello must parse")
    }

    fn target_server_hello_record() -> Vec<u8> {
        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&X25519_GROUP.to_be_bytes());
        key_share.extend_from_slice(&32_u16.to_be_bytes());
        key_share.extend_from_slice(&[0x55; 32]);
        push_extension(&mut extensions, 0x0033, &key_share);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(SESSION_ID_LEN).expect("test session ID must fit"));
        body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("test extensions must fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut message = vec![2];
        let message_len = u32::try_from(body.len()).expect("test ServerHello body must fit");
        message.extend_from_slice(&message_len.to_be_bytes()[1..]);
        message.extend_from_slice(&body);

        let mut record = vec![22, 3, 3];
        record.extend_from_slice(
            &u16::try_from(message.len())
                .expect("test record must fit")
                .to_be_bytes(),
        );
        record.extend_from_slice(&message);
        record
    }

    fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .expect("test extension must fit")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
}
