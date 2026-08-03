use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{net::TcpStream, time};

use crate::protocol::vless::{Address, Destination};

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
        let connect = async {
            match destination.address() {
                Address::Ipv4(address) => {
                    let socket_addr = SocketAddr::new(IpAddr::V4(*address), destination.port());

                    TcpStream::connect(socket_addr).await
                }

                Address::Domain(domain) => {
                    TcpStream::connect((domain.as_str(), destination.port())).await
                }

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

        stream
            .set_nodelay(true)
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
}

impl fmt::Display for DestinationConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { timeout } => write!(
                formatter,
                "destination connection timed out after {timeout:?}"
            ),
            Self::Io(error) => write!(formatter, "failed to connect to destination: {error}"),
        }
    }
}

impl Error for DestinationConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimedOut { .. } => None,
            Self::Io(error) => Some(error),
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
    use std::{net::Ipv4Addr, time::Duration};

    use tokio::net::TcpListener;

    use super::DestinationConnector;
    use crate::protocol::vless::{Address, Destination};

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
}
