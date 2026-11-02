use std::{net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time,
};

use super::{NxrAuthenticator, NxrLandingHandler, NxrReplayCache};
use crate::{
    protocol::{
        nxr::NxrKey,
        nxr_udp::{
            DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_TYPE_DATAGRAM, NxrUdpSeq,
            NxrUdpSessionKey, drain_frames, encode_frame, encode_udp_open,
            open_authenticated_prefix,
        },
        vless::{Address, Destination},
    },
    transport::{TcpRelay, TcpRelayConfig},
};

fn landing_handler(key: [u8; 32]) -> NxrLandingHandler {
    let relay = TcpRelay::new(
        TcpRelayConfig::for_test(),
        crate::transport::FdBudget::new(4_096),
    )
    .expect("relay");
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    NxrLandingHandler::new(
        NxrAuthenticator::new(NxrKey::new(key), cache, 30),
        Duration::from_secs(2),
        Duration::from_secs(2),
        relay,
        Duration::from_secs(5),
    )
}

#[tokio::test]
async fn nxr_udp_landing_echo_round_trip() {
    let key_bytes = [0x42_u8; 32];
    let key = NxrKey::new(key_bytes);
    let echo = UdpSocket::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), echo_addr.port());

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let land_addr = listener.local_addr().unwrap();
    let handler = landing_handler(key_bytes);
    let land_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler.handle(stream).await
    });

    let mut client = TcpStream::connect(land_addr).await.unwrap();
    let mut open = Vec::new();
    encode_udp_open(
        &dest,
        [0x11; 16],
        super::request::unix_seconds().unwrap(),
        [0x99; 16],
        &key,
        &mut open,
    )
    .unwrap();
    client.write_all(&open).await.unwrap();
    let session = NxrUdpSessionKey::derive(&key, open_authenticated_prefix(&open).unwrap());

    let mut seq_out = NxrUdpSeq::new();
    let mut frame = Vec::new();
    encode_frame(
        &session,
        DIR_LINE_TO_LANDING,
        FRAME_TYPE_DATAGRAM,
        seq_out.next_out().unwrap(),
        Some(&dest),
        b"hello-nxr-udp",
        &mut frame,
    )
    .unwrap();
    client.write_all(&frame).await.unwrap();

    let mut buf = [0_u8; 64];
    let (n, from) = time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo recv")
        .unwrap();
    assert_eq!(&buf[..n], b"hello-nxr-udp");
    echo.send_to(b"echo-ok", from).await.unwrap();

    let mut reply_buf = vec![0_u8; 0];
    // Read until one complete frame arrives.
    let mut scratch = [0_u8; 4096];
    let deadline = time::Instant::now() + Duration::from_secs(2);
    let mut seq_in = NxrUdpSeq::new();
    let reply = loop {
        let n = time::timeout_at(deadline, client.read(&mut scratch))
            .await
            .expect("reply read timeout")
            .unwrap();
        assert!(n > 0);
        reply_buf.extend_from_slice(&scratch[..n]);
        let frames = drain_frames(&mut reply_buf, &session, DIR_LANDING_TO_LINE).unwrap();
        if let Some(frame) = frames.into_iter().next() {
            seq_in.accept_in(frame.seq).unwrap();
            break frame;
        }
    };
    assert_eq!(reply.payload, b"echo-ok");
    assert_eq!(reply.destination, Some(dest));

    // An oversized UDP reply must not become a valid truncated datagram.
    echo.send_to(
        &vec![0x5a; crate::protocol::nxr_udp::NXR_UDP_MAX_PAYLOAD + 1],
        from,
    )
    .await
    .unwrap();
    assert_eq!(
        time::timeout(Duration::from_secs(2), client.read(&mut scratch))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(matches!(
        time::timeout(Duration::from_secs(2), land_task)
            .await
            .unwrap()
            .unwrap(),
        Err(super::NxrLandingError::UdpProtocol(
            crate::protocol::nxr_udp::NxrUdpError::Payload
        ))
    ));
}

#[tokio::test]
async fn tcp_open_still_relays_bytes() {
    // Non-regression: TCP NXR path unchanged.
    let key_bytes = [0x33_u8; 32];
    let key = NxrKey::new(key_bytes);
    let dest_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let dest_addr = dest_listener.local_addr().unwrap();
    let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), dest_addr.port());
    let dest_task = tokio::spawn(async move {
        let (mut stream, _) = dest_listener.accept().await.unwrap();
        let mut buf = [0_u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let land_addr = listener.local_addr().unwrap();
    let handler = landing_handler(key_bytes);
    let land_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler.handle(stream).await
    });

    let mut client = TcpStream::connect(land_addr).await.unwrap();
    let mut open = Vec::new();
    crate::protocol::nxr::encode_request(
        &dest,
        super::request::unix_seconds().unwrap(),
        [0x22; 16],
        &key,
        &mut open,
    )
    .unwrap();
    client.write_all(&open).await.unwrap();
    client.write_all(b"tcp-payload").await.unwrap();
    let mut buf = [0_u8; 16];
    let n = time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"tcp-payload");
    dest_task.await.unwrap();
    land_task.abort();
}
