use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{net::TcpStream, time};

use crate::protocol::vless::{Address, Destination};

const MAX_PRE_RESOLVED_IPS: usize = 64;

/// Returns a socket address when `host` is a numeric IP literal, so callers
/// can dial it directly without entering the blocking system resolver.
/// Real hostnames return `None` and keep asynchronous resolution.
pub(crate) fn literal_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    host.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

/// Connects to `host:port`, skipping the blocking resolver when `host` is a
/// numeric IP literal. Real hostnames keep asynchronous system resolution.
pub(crate) async fn connect_host(host: &str, port: u16) -> io::Result<TcpStream> {
    match literal_socket_addr(host, port) {
        Some(address) => TcpStream::connect(address).await,
        None => TcpStream::connect((host, port)).await,
    }
}

/// Connects to a combined `host:port` target, skipping the blocking resolver
/// when the target is a numeric socket address literal.
pub(crate) async fn connect_target(target: &str) -> io::Result<TcpStream> {
    match target.parse::<SocketAddr>() {
        Ok(address) => TcpStream::connect(address).await,
        Err(_) => TcpStream::connect(target).await,
    }
}

/// Establishes outbound TCP connections for authorized VLESS requests.
#[derive(Clone, Copy, Debug)]
pub struct DestinationConnector {
    connect_timeout: Duration,
}

impl DestinationConnector {
    pub const fn new(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub async fn connect(
        &self,
        destination: &Destination,
    ) -> Result<TcpStream, DestinationConnectError> {
        self.connect_resolved(destination, &[]).await
    }

    /// Connects a domain to the exact bounded address snapshot already used by
    /// routing. Empty snapshots retain normal system resolution behavior.
    pub async fn connect_resolved(
        &self,
        destination: &Destination,
        resolved_ips: &[IpAddr],
    ) -> Result<TcpStream, DestinationConnectError> {
        if resolved_ips.len() > MAX_PRE_RESOLVED_IPS {
            return Err(DestinationConnectError::TooManyResolvedAddresses);
        }
        let connect = async {
            match destination.address() {
                Address::Ipv4(address) => {
                    let socket_addr = SocketAddr::new(IpAddr::V4(*address), destination.port());

                    TcpStream::connect(socket_addr).await
                }

                Address::Domain(_) if !resolved_ips.is_empty() => {
                    let mut addresses = Vec::new();
                    addresses
                        .try_reserve_exact(resolved_ips.len())
                        .map_err(|_| io::Error::other("resolved address allocation failed"))?;
                    addresses.extend(
                        resolved_ips
                            .iter()
                            .map(|address| SocketAddr::new(*address, destination.port())),
                    );
                    TcpStream::connect(addresses.as_slice()).await
                }

                Address::Domain(domain) => connect_host(domain.as_str(), destination.port()).await,

                Address::Ipv6(address) => {
                    let socket_addr = SocketAddr::new(IpAddr::V6(*address), destination.port());

                    TcpStream::connect(socket_addr).await
                }
            }
        };

        let stream = match time::timeout(self.connect_timeout, connect).await {
            Ok(result) => result.map_err(DestinationConnectError::Io)?,
            Err(_) => {
                return Err(DestinationConnectError::TimedOut {
                    timeout: self.connect_timeout,
                });
            }
        };

        crate::transport::TcpAcceptor::configure_stream(&stream)
            .map_err(DestinationConnectError::Io)?;

        Ok(stream)
    }
}

/// An error produced while connecting to a VLESS destination.
#[derive(Debug)]
pub enum DestinationConnectError {
    /// The connection attempt exceeded its configured deadline.
    TimedOut { timeout: Duration },

    /// Address resolution or TCP connection establishment failed.
    Io(io::Error),

    /// A caller supplied more addresses than the bounded connector accepts.
    TooManyResolvedAddresses,
}

impl fmt::Display for DestinationConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { timeout } => write!(
                formatter,
                "destination connection timed out after {timeout:?}"
            ),
            Self::Io(error) => write!(formatter, "failed to connect to destination: {error}"),
            Self::TooManyResolvedAddresses => {
                formatter.write_str("pre-resolved destination address count exceeds 64")
            }
        }
    }
}

impl Error for DestinationConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimedOut { .. } => None,
            Self::Io(error) => Some(error),
            Self::TooManyResolvedAddresses => None,
        }
    }
}

impl From<io::Error> for DestinationConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use tokio::net::TcpListener;

    use super::{DestinationConnector, connect_target, literal_socket_addr};
    use crate::protocol::vless::{Address, Destination};

    #[test]
    fn classifies_numeric_literals_without_resolver() {
        assert_eq!(
            literal_socket_addr("127.0.0.1", 443),
            Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443))
        );
        assert_eq!(
            literal_socket_addr("::1", 8443),
            Some(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 8443))
        );
        // Real hostnames (and near-miss strings) must keep resolver behavior.
        assert_eq!(literal_socket_addr("localhost", 443), None);
        assert_eq!(literal_socket_addr("example.com", 443), None);
        assert_eq!(literal_socket_addr("127.0.0.1.", 443), None);
        assert_eq!(literal_socket_addr("256.0.0.1", 443), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connects_to_domain_holding_ipv4_literal_without_resolver() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");

        let listener_addr = listener
            .local_addr()
            .expect("listener should have a local address");

        // A numeric string carried as a VLESS domain must connect directly.
        let destination = Destination::new(
            Address::Domain("127.0.0.1".to_owned()),
            listener_addr.port(),
        );

        let connector = DestinationConnector::new(Duration::from_secs(1));

        let stream = connector
            .connect(&destination)
            .await
            .expect("numeric literal domain should connect without resolution");

        let (_server_stream, peer_addr) = listener
            .accept()
            .await
            .expect("listener should accept connection");

        assert_eq!(
            stream
                .local_addr()
                .expect("client stream should have a local address"),
            peer_addr
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connects_combined_numeric_target_without_resolver() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");

        let listener_addr = listener
            .local_addr()
            .expect("listener should have a local address");

        let stream = connect_target(&listener_addr.to_string())
            .await
            .expect("numeric host:port target should connect without resolution");

        let (_server_stream, peer_addr) = listener
            .accept()
            .await
            .expect("listener should accept connection");

        assert_eq!(
            stream
                .local_addr()
                .expect("client stream should have a local address"),
            peer_addr
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connects_to_ipv4_destination() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");

        let listener_addr = listener
            .local_addr()
            .expect("listener should have a local address");

        let destination =
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), listener_addr.port());

        let connector = DestinationConnector::new(Duration::from_secs(1));

        let stream = connector
            .connect(&destination)
            .await
            .expect("IPv4 destination should connect");

        let (_server_stream, peer_addr) = listener
            .accept()
            .await
            .expect("listener should accept connection");

        assert_eq!(
            stream
                .peer_addr()
                .expect("client stream should have a peer"),
            listener_addr
        );

        assert_eq!(
            stream
                .local_addr()
                .expect("client stream should have a local address"),
            peer_addr
        );

        assert!(
            stream.nodelay().expect("read TCP_NODELAY"),
            "outbound proxy streams must disable Nagle"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolves_and_connects_to_domain_destination() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");

        let listener_addr = listener
            .local_addr()
            .expect("listener should have a local address");

        let destination = Destination::new(
            Address::Domain("localhost".to_owned()),
            listener_addr.port(),
        );

        let connector = DestinationConnector::new(Duration::from_secs(5));

        let stream = connector
            .connect(&destination)
            .await
            .expect("localhost destination should resolve and connect");

        let (_server_stream, peer_addr) = listener
            .accept()
            .await
            .expect("listener should accept connection");

        assert_eq!(
            stream
                .local_addr()
                .expect("client stream should have a local address"),
            peer_addr
        );

        assert!(
            stream.nodelay().expect("read TCP_NODELAY"),
            "outbound proxy streams must disable Nagle"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reuses_pre_resolved_address_without_second_dns_lookup() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");
        let listener_addr = listener
            .local_addr()
            .expect("listener should have a local address");
        let destination = Destination::new(
            Address::Domain("must-not-resolve.invalid".to_owned()),
            listener_addr.port(),
        );
        let connector = DestinationConnector::new(Duration::from_secs(1));

        let stream = connector
            .connect_resolved(&destination, &[Ipv4Addr::LOCALHOST.into()])
            .await
            .expect("pre-resolved loopback must connect");
        let (_server_stream, peer_addr) = listener
            .accept()
            .await
            .expect("listener should accept connection");

        assert_eq!(
            stream
                .local_addr()
                .expect("client stream should have a local address"),
            peer_addr
        );
    }
}
