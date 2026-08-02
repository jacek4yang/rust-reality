use std::{io, net::Ipv4Addr, time::Duration};

use rust_reality::{
    protocol::vless::{Command, UserId, UserRegistry, VERSION},
    server::{config::ServerConfig, handler::ConnectionHandler},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

const AUTHORIZED_USER: UserId = UserId::new([0x11; 16]);

const PREFETCHED_PAYLOAD: &[u8] = b"payload sent with VLESS header; ";

const STREAMED_PAYLOAD: &[u8] = b"payload sent after handler starts";

const UPSTREAM_RESPONSE: &[u8] = b"response after request half-close";

#[tokio::test(flavor = "current_thread")]
async fn relays_authorized_vless_tcp_connection() {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream listener should bind");

    let upstream_addr = upstream_listener
        .local_addr()
        .expect("upstream listener should have an address");

    let inbound_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("VLESS listener should bind");

    let inbound_addr = inbound_listener
        .local_addr()
        .expect("VLESS listener should have an address");

    let mut client = TcpStream::connect(inbound_addr)
        .await
        .expect("VLESS client should connect");

    let (server_stream, peer_addr) = inbound_listener
        .accept()
        .await
        .expect("VLESS listener should accept client");

    let config = ServerConfig::new(
        inbound_addr,
        UserRegistry::new([AUTHORIZED_USER]),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );

    let handler = ConnectionHandler::from_config(&config);

    let initial_packet = request_packet(upstream_addr.port(), PREFETCHED_PAYLOAD);

    client
        .write_all(&initial_packet)
        .await
        .expect("initial VLESS packet should be written");

    let exchange = async {
        let client_io = async {
            client.write_all(STREAMED_PAYLOAD).await?;

            client.shutdown().await?;

            let mut response_header = [0_u8; 2];

            client.read_exact(&mut response_header).await?;

            let mut response_payload = Vec::new();

            client.read_to_end(&mut response_payload).await?;

            Ok::<_, io::Error>((response_header, response_payload))
        };

        let handler_io = handler.handle(server_stream, peer_addr);

        let upstream_io = async {
            let (mut stream, _) = upstream_listener.accept().await?;

            let mut request_payload = Vec::new();

            stream.read_to_end(&mut request_payload).await?;

            stream.write_all(UPSTREAM_RESPONSE).await?;

            stream.shutdown().await?;

            Ok::<_, io::Error>(request_payload)
        };

        tokio::join!(client_io, handler_io, upstream_io,)
    };

    let (client_result, handler_result, upstream_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("VLESS exchange should not time out");

    let (response_header, response_payload) = client_result.expect("client I/O should succeed");

    handler_result.expect("connection handler should succeed");

    let request_payload = upstream_result.expect("upstream I/O should succeed");

    let mut expected_request = Vec::new();
    expected_request.extend_from_slice(PREFETCHED_PAYLOAD);
    expected_request.extend_from_slice(STREAMED_PAYLOAD);

    assert_eq!(response_header, [VERSION, 0]);
    assert_eq!(request_payload, expected_request);
    assert_eq!(response_payload.as_slice(), UPSTREAM_RESPONSE);
}

fn request_packet(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.push(VERSION);
    packet.extend_from_slice(AUTHORIZED_USER.as_bytes());
    packet.push(0);
    packet.push(Command::Tcp.as_byte());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.push(0x01);
    packet.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    packet.extend_from_slice(payload);

    packet
}
