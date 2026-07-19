use std::{io, net::SocketAddr};

use tokio::net::{TcpListener, TcpStream};

/// Owns a TCP listening socket and accepts inbound connections.
pub struct TcpAcceptor {
    listener: TcpListener,
}

impl TcpAcceptor {
    /// Creates a TCP listener bound to `address`.
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;

        Ok(Self { listener })
    }

    /// Returns the local address assigned to the listening socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Waits for and accepts one inbound TCP connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept().await
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::TcpAcceptor;

    #[tokio::test(flavor = "current_thread")]
    async fn bind_replaces_zero_port_with_kernel_assigned_port() {
        let requested_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

        let acceptor = TcpAcceptor::bind(requested_addr)
            .await
            .expect("loopback listener should bind");

        let actual_addr = acceptor
            .local_addr()
            .expect("bound listener should have a local address");

        assert_eq!(actual_addr.ip(), requested_addr.ip());
        assert_ne!(actual_addr.port(), 0);
    }
}
