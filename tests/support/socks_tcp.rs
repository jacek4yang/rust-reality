//! Shared process-test assertion for framed TCP and a write half-close.
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    process::Command,
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

/// Length-framed 128 KiB echo through the SOCKS client, plus a hard proof that
/// LANDING (not LINE) owns the TCP connection to the origin.
///
/// This does not use a client write half-close. Stock Xray `xtls-rprx-vision`
/// through a rust-reality LINE delivers the origin's reply after a client FIN
/// to the origin, but the Xray SOCKS client then sees EOF instead of the
/// reply. Bidirectional length-framed bytes still prove the TCP Vision path.
///
/// Peer IP is not used as the proof: `DestinationConnector` dials with an
/// unbound `TcpStream::connect`, so the source on loopback is typically
/// 127.0.0.1 rather than the LANDING listen address. The `/proc` census is
/// taken while the connection is still established.
pub(super) fn assert_length_echo_landing_is_tcp_sender(
    socks_port: u16,
    landing_pid: u32,
    entry_pid: u32,
) {
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
        // Census after the payload arrives and before the reply, so the
        // LANDING socket is still established.
        assert_landing_owns_origin_tcp(port, landing_pid, entry_pid);
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
    let mut received = vec![0; payload.len()];
    client.read_exact(&mut received).unwrap();
    assert_eq!(received, payload);
    peer.join().unwrap();
}

fn parse_proc_ipv4_port(field: &str) -> Option<u16> {
    let (_, port) = field.split_once(':')?;
    u16::from_str_radix(port, 16).ok()
}

fn established_tcp_inodes_touching_port(origin_port: u16) -> Vec<u64> {
    let text = fs::read_to_string("/proc/net/tcp").expect("/proc/net/tcp");
    let mut inodes = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 || cols[3] != "01" {
            continue;
        }
        let touches = [cols[1], cols[2]]
            .into_iter()
            .any(|field| parse_proc_ipv4_port(field) == Some(origin_port));
        if touches && let Ok(inode) = cols[9].parse::<u64>() {
            inodes.push(inode);
        }
    }
    inodes
}

fn pid_owns_socket_inode(pid: u32, inode: u64) -> bool {
    let dir = format!("/proc/{pid}/fd");
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    let needle = format!("socket:[{inode}]");
    entries
        .flatten()
        .any(|entry| fs::read_link(entry.path()).is_ok_and(|link| link.to_string_lossy() == needle))
}

fn assert_landing_owns_origin_tcp(origin_port: u16, landing_pid: u32, entry_pid: u32) {
    let inodes = established_tcp_inodes_touching_port(origin_port);
    let landing_owns = inodes
        .iter()
        .any(|inode| pid_owns_socket_inode(landing_pid, *inode));
    let entry_owns = inodes
        .iter()
        .any(|inode| pid_owns_socket_inode(entry_pid, *inode));
    let ss = Command::new("ss")
        .args(["-tnpH"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    assert!(
        landing_owns,
        "LANDING pid={landing_pid} must own TCP to origin :{origin_port} (inodes={inodes:?});
ss:
{ss}"
    );
    assert!(
        !entry_owns,
        "LINE pid={entry_pid} must not own TCP to origin :{origin_port} (inodes={inodes:?});
ss:
{ss}"
    );
    eprintln!(
        "landing_tcp_sender_proof origin_port={origin_port} inodes={inodes:?} landing_pid={landing_pid} entry_pid={entry_pid}"
    );
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
