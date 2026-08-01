use std::{net::SocketAddr, time::Duration};

use crate::protocol::vless::UserRegistry;

/// Runtime configuration for the plain VLESS TCP server.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    listen_addr: SocketAddr,
    users: UserRegistry,
    handshake_timeout: Duration,
    connect_timeout: Duration,
}

impl ServerConfig {
    pub fn new(
        listen_addr: SocketAddr,
        users: UserRegistry,
        handshake_timeout: Duration,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            listen_addr,
            users,
            handshake_timeout,
            connect_timeout,
        }
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn users(&self) -> &UserRegistry {
        &self.users
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };

    use super::ServerConfig;
    use crate::protocol::vless::{UserId, UserRegistry};

    const AUTHORIZED_USER: UserId = UserId::new([0x11; 16]);

    #[test]
    fn preserves_explicit_server_settings() {
        let listen_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443));
        let handshake_timeout = Duration::from_secs(5);
        let connect_timeout = Duration::from_secs(10);

        let config = ServerConfig::new(
            listen_addr,
            UserRegistry::new([AUTHORIZED_USER]),
            handshake_timeout,
            connect_timeout,
        );

        assert_eq!(config.listen_addr(), listen_addr);
        assert!(config.users().contains(AUTHORIZED_USER));
        assert_eq!(config.handshake_timeout(), handshake_timeout);
        assert_eq!(config.connect_timeout(), connect_timeout);
    }
}
