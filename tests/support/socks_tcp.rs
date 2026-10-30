//! Shared process-test assertion for framed TCP and a write half-close.
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

pub(super) fn assert_echo(socks_port: u16) {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = origin.local_addr().unwrap().port();
    origin.set_nonblocking(true).unwrap();
    let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match origin.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("echo accept: {error}"),
            }
            assert!(Instant::now() < deadline, "echo admission deadline");
            thread::sleep(Duration::from_millis(5));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        let mut end = [0];
        assert_eq!(
            stream.read(&mut end).unwrap(),
            0,
            "write half-close reaches origin"
        );
        stream.write_all(&received).unwrap();
    });
    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    client.write_all(&payload).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut received = vec![0; payload.len()];
    client.read_exact(&mut received).unwrap();
    assert_eq!(received, payload);
    peer.join().unwrap();
}

/// The destination may finish sending before the client finishes uploading.
pub(super) fn assert_reverse_half_close(socks_port: u16) {
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = origin.local_addr().unwrap().port();
    origin.set_nonblocking(true).unwrap();
    let payload = vec![0x5a; 128 * 1024];
    let expected = payload.clone();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match origin.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("reverse echo accept: {error}"),
            }
            assert!(Instant::now() < deadline, "reverse echo admission deadline");
            thread::sleep(Duration::from_millis(5));
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(b"reply before upload").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        let mut end = [0];
        assert_eq!(stream.read(&mut end).unwrap(), 0);
    });
    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"reply before upload");
    client.write_all(&payload).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    peer.join().unwrap();
}
