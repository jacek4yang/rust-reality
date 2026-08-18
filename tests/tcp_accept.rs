use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use rust_reality::transport::tcp::TcpAcceptor;
use tokio::net::TcpStream;

#[tokio::test(flavor = "current_thread")]
async fn accepts_ipv4_loopback_connection() {
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

#[tokio::test(flavor = "current_thread")]
async fn accepts_ipv6_loopback_connection() {
    let acceptor = TcpAcceptor::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)))
        .await
        .expect("IPv6 loopback listener should bind");
    let listen_addr = acceptor.local_addr().expect("read IPv6 listen address");

    let (client, accepted) = tokio::join!(TcpStream::connect(listen_addr), acceptor.accept());
    let client = client.expect("IPv6 client should connect");
    let (server, peer) = accepted.expect("IPv6 listener should accept");

    assert!(listen_addr.is_ipv6());
    assert_eq!(client.local_addr().expect("read client address"), peer);
    assert_eq!(
        server.local_addr().expect("read server address"),
        listen_addr
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn independent_wildcard_sockets_accept_both_families() {
    let ipv6 = TcpAcceptor::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
        .await
        .expect("IPv6 wildcard listener should bind");
    let port = ipv6.local_addr().expect("read IPv6 address").port();
    let ipv4 = TcpAcceptor::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .await
        .expect("independent IPv4 wildcard listener should bind the same port");

    assert!(ipv6.ipv6_only().expect("read IPV6_V6ONLY"));
    assert!(ipv4.local_addr().expect("read IPv4 address").is_ipv4());

    let ipv4_address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let (ipv4_client, ipv4_accepted) =
        tokio::join!(TcpStream::connect(ipv4_address), ipv4.accept());
    ipv4_client.expect("IPv4 client should connect");
    let (_, ipv4_peer) = ipv4_accepted.expect("IPv4 socket should accept");
    assert!(ipv4_peer.is_ipv4());

    let ipv6_address = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let (ipv6_client, ipv6_accepted) =
        tokio::join!(TcpStream::connect(ipv6_address), ipv6.accept());
    ipv6_client.expect("IPv6 client should connect");
    let (_, ipv6_peer) = ipv6_accepted.expect("IPv6 socket should accept");
    assert!(ipv6_peer.is_ipv6());
}
