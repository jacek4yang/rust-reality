use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

use rust_reality::transport::tcp::TcpAcceptor;

const DEFAULT_LISTEN_PORT: u16 = 8443;

#[tokio::main]
async fn main() -> io::Result<()> {
    let requested_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_LISTEN_PORT));

    let acceptor = TcpAcceptor::bind(requested_addr).await?;
    let actual_addr = acceptor.local_addr()?;

    eprintln!("listening on {actual_addr}");

    loop {
        let (stream, peer_addr) = acceptor.accept().await?;

        eprintln!("accepted TCP connection from {peer_addr}");

        drop(stream);
    }
}
