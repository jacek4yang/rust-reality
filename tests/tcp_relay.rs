use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use rust_reality::transport::{relay::relay_bidirectional, tcp::TcpAcceptor};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const REQUEST_SIZE: usize = 128 * 1024;
const RESPONSE_SIZE: usize = 96 * 1024;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "current_thread")]
async fn preserves_tcp_response_after_client_half_close() {
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    let acceptor = TcpAcceptor::bind(loopback)
        .await
        .expect("relay listener should bind");

    let relay_addr = acceptor
        .local_addr()
        .expect("relay listener should have an address");

    let upstream_listener = TcpListener::bind(loopback)
        .await
        .expect("upstream listener should bind");

    let upstream_addr = upstream_listener
        .local_addr()
        .expect("upstream listener should have an address");

    let request = vec![0x5a; REQUEST_SIZE];
    let response = vec![0xa5; RESPONSE_SIZE];

    let exchange = async {
        let client_io = async {
            let mut stream = TcpStream::connect(relay_addr).await?;

            stream.write_all(&request).await?;
            stream.shutdown().await?;

            let mut received_response = Vec::new();
            stream.read_to_end(&mut received_response).await?;

            Ok::<_, io::Error>(received_response)
        };

        let relay_io = async {
            let (mut inbound, _) = acceptor.accept().await?;
            let mut outbound = TcpStream::connect(upstream_addr).await?;

            relay_bidirectional(&mut inbound, &mut outbound).await
        };

        let upstream_io = async {
            let (mut stream, _) = upstream_listener.accept().await?;

            let mut received_request = Vec::new();
            stream.read_to_end(&mut received_request).await?;

            stream.write_all(&response).await?;
            stream.shutdown().await?;

            Ok::<_, io::Error>(received_request)
        };

        tokio::join!(client_io, relay_io, upstream_io)
    };

    let (client_result, relay_result, upstream_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("TCP relay exchange should not time out");

    let received_response = client_result.expect("client I/O should succeed");

    let stats = relay_result.expect("relay should succeed");

    let received_request = upstream_result.expect("upstream I/O should succeed");

    assert_eq!(received_request, request);
    assert_eq!(received_response, response);

    assert_eq!(stats.inbound_to_outbound_bytes(), REQUEST_SIZE as u64,);
    assert_eq!(stats.outbound_to_inbound_bytes(), RESPONSE_SIZE as u64,);
}
