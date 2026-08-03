use std::{collections::HashMap, error::Error, fmt, io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    config::{DirectBarrierConfig, OutboundConfig, Socks5Settings},
    protocol::vless::{Address, Destination},
    runtime::{AdmissionDenied, DirectBarrier, DirectPermit},
};

use super::connector::{DestinationConnectError, DestinationConnector};

const SOCKS_VERSION: u8 = 5;
const SOCKS_AUTH_VERSION: u8 = 1;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_NO_AUTH: u8 = 0;
const SOCKS_USERNAME_PASSWORD: u8 = 2;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;

/// Immutable outbound transports indexed by validated routing tags.
#[derive(Clone)]
pub struct OutboundRegistry {
    outbounds: Arc<HashMap<String, CompiledOutbound>>,
    direct_barrier: DirectBarrier,
    connect_timeout: Duration,
}

impl OutboundRegistry {
    /// Compiles validated outbound configuration into secret-safe runtime state.
    #[must_use]
    pub fn new(
        outbounds: &[OutboundConfig],
        direct_barrier: &DirectBarrierConfig,
        connect_timeout: Duration,
    ) -> Self {
        let outbounds = outbounds
            .iter()
            .map(|outbound| (outbound.tag().to_owned(), CompiledOutbound::from(outbound)))
            .collect();
        Self {
            outbounds: Arc::new(outbounds),
            direct_barrier: DirectBarrier::new(direct_barrier),
            connect_timeout,
        }
    }

    /// Connects the selected transport without ever logging credentials or keys.
    ///
    /// # Errors
    ///
    /// Returns an unknown-tag, admission, connection, SOCKS5, or unsupported-NXR error.
    pub async fn connect(
        &self,
        tag: &str,
        destination: &Destination,
    ) -> Result<OutboundConnectOutcome, OutboundConnectError> {
        let outbound = self
            .outbounds
            .get(tag)
            .ok_or_else(|| OutboundConnectError::UnknownTag(tag.to_owned()))?;
        match outbound {
            CompiledOutbound::Direct => {
                let permit = self
                    .direct_barrier
                    .try_acquire()
                    .map_err(OutboundConnectError::Admission)?;
                let stream = DestinationConnector::new(self.connect_timeout)
                    .connect(destination)
                    .await
                    .map_err(OutboundConnectError::Direct)?;
                Ok(OutboundConnectOutcome::Connected(OutboundConnection {
                    stream,
                    _direct_permit: Some(permit),
                }))
            }
            CompiledOutbound::Blackhole { delay } => {
                if !delay.is_zero() {
                    time::sleep(*delay).await;
                }
                Ok(OutboundConnectOutcome::Blackholed)
            }
            CompiledOutbound::Socks5(settings) => {
                let stream = connect_socks5(settings, destination, self.connect_timeout).await?;
                Ok(OutboundConnectOutcome::Connected(OutboundConnection {
                    stream,
                    _direct_permit: None,
                }))
            }
            CompiledOutbound::Nxr => Err(OutboundConnectError::NxrUnavailable),
        }
    }

    /// Returns whether a validated tag is present in this immutable snapshot.
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.outbounds.contains_key(tag)
    }
}

impl fmt::Debug for OutboundRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tags: Vec<_> = self.outbounds.keys().map(String::as_str).collect();
        tags.sort_unstable();
        formatter
            .debug_struct("OutboundRegistry")
            .field("tags", &tags)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

enum CompiledOutbound {
    Direct,
    Blackhole { delay: Duration },
    Socks5(CompiledSocks5),
    Nxr,
}

impl From<&OutboundConfig> for CompiledOutbound {
    fn from(outbound: &OutboundConfig) -> Self {
        match outbound {
            OutboundConfig::Direct { .. } => Self::Direct,
            OutboundConfig::Blackhole { settings, .. } => Self::Blackhole {
                delay: Duration::from_millis(settings.response_delay_ms),
            },
            OutboundConfig::Socks5 { settings, .. } => Self::Socks5(settings.into()),
            OutboundConfig::Nxr { .. } => Self::Nxr,
        }
    }
}

struct CompiledSocks5 {
    address: Arc<str>,
    port: u16,
    credentials: Option<Socks5Credentials>,
}

impl From<&Socks5Settings> for CompiledSocks5 {
    fn from(settings: &Socks5Settings) -> Self {
        let credentials = settings
            .username
            .as_ref()
            .zip(settings.password.as_ref())
            .map(|(username, password)| Socks5Credentials {
                username: Zeroizing::new(username.expose().to_owned()),
                password: Zeroizing::new(password.expose().to_owned()),
            });
        Self {
            address: Arc::from(settings.address.as_str()),
            port: settings.port,
            credentials,
        }
    }
}

struct Socks5Credentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

/// A connected outbound stream retaining any lifetime admission permit.
pub struct OutboundConnection {
    stream: TcpStream,
    _direct_permit: Option<DirectPermit>,
}

impl OutboundConnection {
    /// Separates the stream and its lifetime permit for a session relay.
    #[must_use]
    pub fn into_parts(self) -> (TcpStream, OutboundPermit) {
        (
            self.stream,
            OutboundPermit {
                _direct: self._direct_permit,
            },
        )
    }
}

impl fmt::Debug for OutboundConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundConnection")
            .field("stream", &"[CONNECTED]")
            .field("direct_permit", &self._direct_permit.is_some())
            .finish()
    }
}

/// Permit retained until a connected outbound session ends.
pub struct OutboundPermit {
    _direct: Option<DirectPermit>,
}

/// The selected route either connected or intentionally discarded the session.
#[derive(Debug)]
pub enum OutboundConnectOutcome {
    Connected(OutboundConnection),
    Blackholed,
}

/// Outbound selection or connection failed.
#[derive(Debug)]
pub enum OutboundConnectError {
    UnknownTag(String),
    Admission(AdmissionDenied),
    Direct(DestinationConnectError),
    SocksConnect(io::Error),
    SocksTimeout,
    SocksProtocol(Socks5ProtocolError),
    NxrUnavailable,
}

impl fmt::Display for OutboundConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTag(_) => formatter.write_str("routing selected an unknown outbound tag"),
            Self::Admission(source) => source.fmt(formatter),
            Self::Direct(source) => source.fmt(formatter),
            Self::SocksConnect(_) => formatter.write_str("failed to connect to SOCKS5 outbound"),
            Self::SocksTimeout => formatter.write_str("SOCKS5 outbound handshake timed out"),
            Self::SocksProtocol(source) => source.fmt(formatter),
            Self::NxrUnavailable => {
                formatter.write_str("NXR outbound is not available in this runtime stage")
            }
        }
    }
}

impl Error for OutboundConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Direct(source) => Some(source),
            Self::SocksConnect(source) => Some(source),
            Self::SocksProtocol(source) => Some(source),
            Self::UnknownTag(_) | Self::SocksTimeout | Self::NxrUnavailable => None,
        }
    }
}

/// A SOCKS5 server returned invalid negotiation data or a failure reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Socks5ProtocolError {
    CredentialsTooLong,
    DomainTooLong,
    UnexpectedMethod { expected: u8, received: u8 },
    AuthenticationFailed(u8),
    ConnectFailed(u8),
    InvalidReply,
}

impl fmt::Display for Socks5ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialsTooLong => formatter.write_str("SOCKS5 credentials exceed 255 bytes"),
            Self::DomainTooLong => formatter.write_str("SOCKS5 domain exceeds 255 bytes"),
            Self::UnexpectedMethod { .. } => {
                formatter.write_str("SOCKS5 server selected an unexpected authentication method")
            }
            Self::AuthenticationFailed(_) => {
                formatter.write_str("SOCKS5 username/password authentication failed")
            }
            Self::ConnectFailed(_) => formatter.write_str("SOCKS5 CONNECT request was rejected"),
            Self::InvalidReply => formatter.write_str("SOCKS5 server returned an invalid reply"),
        }
    }
}

impl Error for Socks5ProtocolError {}

async fn connect_socks5(
    settings: &CompiledSocks5,
    destination: &Destination,
    timeout: Duration,
) -> Result<TcpStream, OutboundConnectError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(OutboundConnectError::SocksTimeout)?;
    let mut stream = time::timeout_at(
        deadline,
        TcpStream::connect((settings.address.as_ref(), settings.port)),
    )
    .await
    .map_err(|_| OutboundConnectError::SocksTimeout)?
    .map_err(OutboundConnectError::SocksConnect)?;
    stream
        .set_nodelay(true)
        .map_err(OutboundConnectError::SocksConnect)?;

    negotiate_socks5(&mut stream, settings, destination, deadline).await?;
    Ok(stream)
}

async fn negotiate_socks5(
    stream: &mut TcpStream,
    settings: &CompiledSocks5,
    destination: &Destination,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let method = if settings.credentials.is_some() {
        SOCKS_USERNAME_PASSWORD
    } else {
        SOCKS_NO_AUTH
    };
    write_before(stream, &[SOCKS_VERSION, 1, method], deadline).await?;
    let mut method_reply = [0_u8; 2];
    read_before(stream, &mut method_reply, deadline).await?;
    if method_reply[0] != SOCKS_VERSION || method_reply[1] != method {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::UnexpectedMethod {
                expected: method,
                received: method_reply[1],
            },
        ));
    }
    if method_reply[1] == SOCKS_NO_ACCEPTABLE_METHODS {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::UnexpectedMethod {
                expected: method,
                received: method_reply[1],
            },
        ));
    }

    if let Some(credentials) = &settings.credentials {
        authenticate_socks5(stream, credentials, deadline).await?;
    }
    write_connect_request(stream, destination, deadline).await?;
    read_connect_reply(stream, deadline).await
}

async fn authenticate_socks5(
    stream: &mut TcpStream,
    credentials: &Socks5Credentials,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let username = credentials.username.as_bytes();
    let password = credentials.password.as_bytes();
    let username_length = u8::try_from(username.len()).map_err(|_| {
        OutboundConnectError::SocksProtocol(Socks5ProtocolError::CredentialsTooLong)
    })?;
    let password_length = u8::try_from(password.len()).map_err(|_| {
        OutboundConnectError::SocksProtocol(Socks5ProtocolError::CredentialsTooLong)
    })?;
    let mut request = Zeroizing::new(Vec::new());
    request
        .try_reserve(3 + username.len() + password.len())
        .map_err(|_| {
            OutboundConnectError::SocksProtocol(Socks5ProtocolError::CredentialsTooLong)
        })?;
    request.extend_from_slice(&[SOCKS_AUTH_VERSION, username_length]);
    request.extend_from_slice(username);
    request.push(password_length);
    request.extend_from_slice(password);
    write_before(stream, &request, deadline).await?;

    let mut reply = [0_u8; 2];
    read_before(stream, &mut reply, deadline).await?;
    if reply[0] != SOCKS_AUTH_VERSION || reply[1] != 0 {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::AuthenticationFailed(reply[1]),
        ));
    }
    Ok(())
}

async fn write_connect_request(
    stream: &mut TcpStream,
    destination: &Destination,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let mut request = Vec::with_capacity(4 + 1 + 255 + 2);
    request.extend_from_slice(&[SOCKS_VERSION, SOCKS_CONNECT, 0]);
    match destination.address() {
        Address::Ipv4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Address::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                OutboundConnectError::SocksProtocol(Socks5ProtocolError::DomainTooLong)
            })?;
            request.extend_from_slice(&[3, length]);
            request.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(address) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    write_before(stream, &request, deadline).await
}

async fn read_connect_reply(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let mut header = [0_u8; 4];
    read_before(stream, &mut header, deadline).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::InvalidReply,
        ));
    }
    if header[1] != 0 {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::ConnectFailed(header[1]),
        ));
    }
    match header[3] {
        1 => consume_reply_address(stream, 4, deadline).await?,
        3 => {
            let mut length = [0_u8; 1];
            read_before(stream, &mut length, deadline).await?;
            consume_reply_address(stream, usize::from(length[0]), deadline).await?;
        }
        4 => consume_reply_address(stream, 16, deadline).await?,
        _ => {
            return Err(OutboundConnectError::SocksProtocol(
                Socks5ProtocolError::InvalidReply,
            ));
        }
    }
    let mut port = [0_u8; 2];
    read_before(stream, &mut port, deadline).await
}

async fn consume_reply_address(
    stream: &mut TcpStream,
    length: usize,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let mut address = [0_u8; 255];
    read_before(stream, &mut address[..length], deadline).await
}

async fn write_before(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    time::timeout_at(deadline, stream.write_all(bytes))
        .await
        .map_err(|_| OutboundConnectError::SocksTimeout)?
        .map_err(OutboundConnectError::SocksConnect)
}

async fn read_before(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    time::timeout_at(deadline, stream.read_exact(bytes))
        .await
        .map_err(|_| OutboundConnectError::SocksTimeout)?
        .map(|_| ())
        .map_err(OutboundConnectError::SocksConnect)
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{OutboundConnectOutcome, OutboundRegistry};
    use crate::{
        config::{DirectBarrierConfig, OutboundConfig, SecretString, Socks5Settings},
        protocol::vless::{Address, Destination},
    };

    #[tokio::test(flavor = "current_thread")]
    async fn negotiates_authenticated_socks5_domain_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: Some(SecretString::new("user")),
                    password: Some(SecretString::new("pass")),
                },
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
        );
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await?;
            let mut auth = [0_u8; 11];
            stream.read_exact(&mut auth).await?;
            assert_eq!(
                auth,
                [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
            );
            stream.write_all(&[1, 0]).await?;
            let mut connect = [0_u8; 18];
            stream.read_exact(&mut connect).await?;
            assert_eq!(&connect[..5], &[5, 1, 0, 3, 11]);
            assert_eq!(&connect[5..16], b"example.com");
            assert_eq!(&connect[16..], &443_u16.to_be_bytes());
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert!(matches!(
            connect_result.expect("SOCKS connection must succeed"),
            OutboundConnectOutcome::Connected(_)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blackhole_never_opens_a_destination_stream() {
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Blackhole {
                tag: "blocked".to_owned(),
                settings: crate::config::BlackholeSettings {
                    response_delay_ms: 0,
                },
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);

        assert!(matches!(
            registry
                .connect("blocked", &destination)
                .await
                .expect("blackhole route must complete"),
            OutboundConnectOutcome::Blackholed
        ));
    }
}
