use std::{io, net::SocketAddr};

use tokio::net::TcpStream;

use crate::protocol::vless::UserRegistry;

#[derive(Clone)]
pub struct ConnectionHandler {
    #[expect(
        dead_code,
        reason = "used by the VLESS handshake in the next pipeline stage"
    )]
    users: UserRegistry,
}

impl ConnectionHandler {
    pub fn new(users: UserRegistry) -> Self {
        Self { users }
    }

    pub async fn handle(&self, stream: TcpStream, peer_addr: SocketAddr) -> io::Result<()> {
        let _ = stream;
        let _ = peer_addr;

        Ok(())
    }
}
