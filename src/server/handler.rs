use std::{error::Error, fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{io::AsyncWriteExt, net::TcpStream, time};

use crate::{
    protocol::vless::{
        ReadError, RequestValidationError, ResponseWriteError, UserRegistry, read_request,
        write_response_header,
    },
    transport::relay::relay_bidirectional,
};

use super::{
    config::ServerConfig,
    connector::{DestinationConnectError, DestinationConnector},
};

/// Handles one plain VLESS TCP connection.
#[derive(Clone)]
pub struct ConnectionHandler {
    users: Arc<UserRegistry>,
    handshake_timeout: Duration,
    connector: DestinationConnector,
}

impl ConnectionHandler {
    pub fn new(
        users: UserRegistry,
        handshake_timeout: Duration,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            users: Arc::new(users),
            handshake_timeout,
            connector: DestinationConnector::new(connect_timeout),
        }
    }

    pub fn from_config(config: &ServerConfig) -> Self {
        Self::new(
            config.users().clone(),
            config.handshake_timeout(),
            config.connect_timeout(),
        )
    }

    pub async fn handle(
        &self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(), ConnectionError> {
        let request = time::timeout(self.handshake_timeout, read_request(&mut stream))
            .await
            .map_err(|_| ConnectionError::HandshakeTimeout {
                peer_addr,
                timeout: self.handshake_timeout,
            })?
            .map_err(ConnectionError::ReadRequest)?;

        let (header, prefetched_payload) = request.into_parts();

        let destination = self
            .users
            .authorize_plain_tcp(&header)
            .map_err(ConnectionError::ValidateRequest)?;

        let mut outbound = self
            .connector
            .connect(destination)
            .await
            .map_err(ConnectionError::ConnectDestination)?;

        write_response_header(&mut stream, &header, &[])
            .await
            .map_err(ConnectionError::WriteResponse)?;

        if !prefetched_payload.is_empty() {
            outbound
                .write_all(&prefetched_payload)
                .await
                .map_err(ConnectionError::WritePrefetchedPayload)?;
        }

        relay_bidirectional(&mut stream, &mut outbound)
            .await
            .map_err(ConnectionError::Relay)?;

        Ok(())
    }
}

/// An error produced while handling one VLESS connection.
#[derive(Debug)]
pub enum ConnectionError {
    /// The client did not provide a complete request before the deadline.
    HandshakeTimeout {
        peer_addr: SocketAddr,
        timeout: Duration,
    },

    /// Reading or decoding the request failed.
    ReadRequest(ReadError),

    /// The decoded request was not authorized or supported.
    ValidateRequest(RequestValidationError),

    /// Establishing the outbound TCP connection failed.
    ConnectDestination(DestinationConnectError),

    /// Writing the VLESS response header failed.
    WriteResponse(ResponseWriteError),

    /// Writing payload prefetched with the request header failed.
    WritePrefetchedPayload(io::Error),

    /// Relaying traffic between the client and destination failed.
    Relay(io::Error),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeTimeout { peer_addr, timeout } => write!(
                formatter,
                "VLESS handshake from {peer_addr} timed out after {timeout:?}"
            ),

            Self::ReadRequest(error) => write!(formatter, "VLESS handshake read failed: {error}"),

            Self::ValidateRequest(error) => {
                write!(formatter, "VLESS request validation failed: {error}")
            }

            Self::ConnectDestination(error) => {
                write!(formatter, "VLESS destination connection failed: {error}")
            }

            Self::WriteResponse(error) => write!(formatter, "VLESS response write failed: {error}"),

            Self::WritePrefetchedPayload(error) => write!(
                formatter,
                "failed to write prefetched VLESS payload: {error}"
            ),

            Self::Relay(error) => write!(formatter, "VLESS TCP relay failed: {error}"),
        }
    }
}

impl Error for ConnectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::HandshakeTimeout { .. } => None,
            Self::ReadRequest(error) => Some(error),
            Self::ValidateRequest(error) => Some(error),
            Self::ConnectDestination(error) => Some(error),
            Self::WriteResponse(error) => Some(error),
            Self::WritePrefetchedPayload(error) | Self::Relay(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use super::{ConnectionError, ConnectionHandler};
    use crate::protocol::vless::{Command, RequestValidationError, UserId, UserRegistry, VERSION};

    const UNKNOWN_USER: UserId = UserId::new([0x22; 16]);

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_unauthorized_request_before_connecting() {
        let (mut client, server, peer_addr) = tcp_pair().await;

        client
            .write_all(&unauthorized_request())
            .await
            .expect("request should be written");

        let handler = ConnectionHandler::new(
            UserRegistry::default(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );

        let error = handler
            .handle(server, peer_addr)
            .await
            .expect_err("unknown user should be rejected");

        assert!(matches!(
            error,
            ConnectionError::ValidateRequest(RequestValidationError::UnauthorizedUser)
        ));
    }

    async fn tcp_pair() -> (TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener should bind");

        let listener_addr = listener
            .local_addr()
            .expect("listener should have an address");

        let client = TcpStream::connect(listener_addr)
            .await
            .expect("client should connect");

        let (server, peer_addr) = listener
            .accept()
            .await
            .expect("server should accept client");

        (client, server, peer_addr)
    }

    fn unauthorized_request() -> Vec<u8> {
        let mut request = Vec::new();

        request.push(VERSION);
        request.extend_from_slice(UNKNOWN_USER.as_bytes());
        request.push(0);
        request.push(Command::Tcp.as_byte());
        request.extend_from_slice(&443_u16.to_be_bytes());
        request.push(0x01);
        request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());

        request
    }
}
