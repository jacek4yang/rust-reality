use std::net::{Ipv4Addr, SocketAddr};

use rust_reality::transport::tcp::TcpAcceptor;
use tokio::net::TcpStream;

#[tokio::test(flavor = "current_thread")]
async fn accepts_loopback_connection() {
    let requested_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    let acceptor = TcpAcceptor::bind(requested_addr)
        .await
        .expect("loopback listener should bind");

    let listen_addr = acceptor
        .local_addr()
        .expect("bound listener should have a local address");

    let connect = TcpStream::connect(listen_addr);
    let accept = acceptor.accept();

    let (client_result, server_result) = tokio::join!(connect, accept);

    let client_stream = client_result.expect("client should connect");
    let (server_stream, peer_addr) = server_result.expect("server should accept connection");

    let client_local_addr = client_stream
        .local_addr()
        .expect("client should have a local address");

    assert_eq!(peer_addr, client_local_addr);
    assert_eq!(
        server_stream
            .local_addr()
            .expect("server stream should have a local address"),
        listen_addr
    );
    assert_eq!(
        server_stream
            .peer_addr()
            .expect("server stream should have a peer address"),
        peer_addr
    );
}
