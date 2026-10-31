//! One association with two destinations and deliberately delayed replies.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

pub(super) fn delayed_replies_preserve_sources(socks_port: u16, expected_egress: Ipv4Addr) {
    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, socks_port)).unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    control
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    control.write_all(&[5, 1, 0]).unwrap();
    let mut method = [0; 2];
    control.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let local = bind();
    let a = bind();
    let b = bind();
    send(&local, relay, a.local_addr().unwrap(), b"open-a");
    let peer_a = receive(&a, b"open-a");
    send(&local, relay, b.local_addr().unwrap(), b"rewrite-b");
    let peer_b = receive(&b, b"rewrite-b");
    assert_eq!(peer_a, peer_b, "both packets must use the same association");
    assert_eq!(peer_a.ip(), expected_egress);

    // B is now the uplink target. A's delayed response must still name A.
    a.send_to(b"late-a", peer_a).unwrap();
    receive_reply(&local, relay, a.local_addr().unwrap(), b"late-a");
    // Receiving A must not suppress the required B -> A uplink rewrite.
    send(
        &local,
        relay,
        a.local_addr().unwrap(),
        b"return-after-late-a",
    );
    assert_eq!(receive(&a, b"return-after-late-a"), peer_a);
    b.send_to(b"reply-b", peer_b).unwrap();
    receive_reply(&local, relay, b.local_addr().unwrap(), b"reply-b");
    // Continue on the same TCP control and UDP association after both replies.
    send(&local, relay, b.local_addr().unwrap(), b"keep-b");
    assert_eq!(receive(&b, b"keep-b"), peer_b);
    send(&local, relay, a.local_addr().unwrap(), b"return-a");
    assert_eq!(receive(&a, b"return-a"), peer_a);
    drop(control);
}

fn bind() -> UdpSocket {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
}

fn send(local: &UdpSocket, relay: SocketAddr, destination: SocketAddr, payload: &[u8]) {
    let SocketAddr::V4(destination) = destination else {
        panic!("IPv4 fixture")
    };
    let mut datagram = vec![0, 0, 0, 1];
    datagram.extend_from_slice(&destination.ip().octets());
    datagram.extend_from_slice(&destination.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    assert_eq!(local.send_to(&datagram, relay).unwrap(), datagram.len());
}

fn receive(socket: &UdpSocket, expected: &[u8]) -> SocketAddr {
    let mut bytes = [0; 256];
    let (len, peer) = socket.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..len], expected);
    peer
}

fn receive_reply(local: &UdpSocket, relay: SocketAddr, source: SocketAddr, payload: &[u8]) {
    let mut bytes = [0; 256];
    let (len, from) = local.recv_from(&mut bytes).unwrap();
    assert_eq!(from, relay);
    assert!(len >= 10);
    assert_eq!(&bytes[..4], &[0, 0, 0, 1]);
    assert_eq!(&bytes[10..len], payload);
    let received_source = SocketAddr::from((
        [bytes[4], bytes[5], bytes[6], bytes[7]],
        u16::from_be_bytes([bytes[8], bytes[9]]),
    ));
    assert_eq!(
        received_source, source,
        "delayed reply source must not follow the latest uplink"
    );
}
