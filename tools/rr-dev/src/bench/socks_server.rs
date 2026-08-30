//! Process-isolated no-auth SOCKS5 mechanism for outbound-pool gates.
//!
//! The soak keeps a conventional TCP-only SOCKS5 upstream alive so the measured
//! LINE can exercise negotiation, CONNECT and warm-pool checkout against a real
//! process boundary. This module implements only that mechanism: no policy,
//! authentication database, UDP transport or shell wrapper.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
};

/// Serves no-auth TCP CONNECT sessions until the process is terminated.
///
/// # Errors
///
/// Returns an I/O error when the listener can no longer accept connections.
pub fn serve(listener: &TcpListener) -> std::io::Result<()> {
    serve_with_target(listener, None)
}

/// Serves TCP CONNECT sessions, optionally rewriting every destination.
///
/// A fixed target is a routing-proof mechanism: content from that target proves
/// the measured server selected this SOCKS outbound, regardless of the address
/// its client requested.
///
/// # Errors
///
/// Returns an I/O error when the listener can no longer accept connections.
pub fn serve_with_target(
    listener: &TcpListener,
    fixed_target: Option<SocketAddr>,
) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::Builder::new()
            .name("rr-socks5-session".to_owned())
            .spawn(move || {
                let _ = session(stream, fixed_target);
            })?;
    }
    Ok(())
}

fn session(mut client: TcpStream, fixed_target: Option<SocketAddr>) -> std::io::Result<()> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return Ok(());
    }
    client.write_all(&[5, 0])?;

    let mut request = [0_u8; 4];
    client.read_exact(&mut request)?;
    if request[0] != 5 || request[1] != 1 {
        reply(&mut client, 7)?;
        return Ok(());
    }
    let host = match request[3] {
        1 => {
            let mut bytes = [0_u8; 4];
            client.read_exact(&mut bytes)?;
            IpAddr::V4(Ipv4Addr::from(bytes)).to_string()
        }
        3 => {
            let mut length = [0_u8];
            client.read_exact(&mut length)?;
            let mut bytes = vec![0_u8; usize::from(length[0])];
            client.read_exact(&mut bytes)?;
            String::from_utf8(bytes).map_err(std::io::Error::other)?
        }
        4 => {
            let mut bytes = [0_u8; 16];
            client.read_exact(&mut bytes)?;
            IpAddr::V6(Ipv6Addr::from(bytes)).to_string()
        }
        _ => {
            reply(&mut client, 8)?;
            return Ok(());
        }
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port)?;
    let requested_port = u16::from_be_bytes(port);
    let upstream = match fixed_target.map_or_else(
        || TcpStream::connect((host.as_str(), requested_port)),
        TcpStream::connect,
    ) {
        Ok(stream) => stream,
        Err(error) => {
            let _ = reply(&mut client, 5);
            return Err(error);
        }
    };
    reply(&mut client, 0)?;
    relay(client, upstream)
}

fn reply(client: &mut TcpStream, status: u8) -> std::io::Result<()> {
    client.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
}

fn relay(mut client: TcpStream, mut upstream: TcpStream) -> std::io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let upload = std::thread::spawn(move || {
        let result = std::io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
        result
    });
    let download = std::io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let upload = upload
        .join()
        .map_err(|_| std::io::Error::other("SOCKS5 upload relay panicked"))?;
    upload?;
    download?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_connect_relays_bytes_in_both_directions() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination_port = destination.local_addr().unwrap().port();
        let echo = std::thread::spawn(move || {
            let (mut stream, _) = destination.accept().unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).unwrap();
            stream.write_all(&bytes).unwrap();
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            session(stream, None).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut greeting = [0_u8; 2];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 0]);
        let port = destination_port.to_be_bytes();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0);
        client.write_all(b"ping").unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);
        server.join().unwrap();
        echo.join().unwrap();
    }

    #[test]
    fn a_fixed_target_rewrites_the_requested_destination() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixed = destination.local_addr().unwrap();
        let echo = std::thread::spawn(move || {
            let (mut stream, _) = destination.accept().unwrap();
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).unwrap();
            stream.write_all(&bytes).unwrap();
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            session(stream, Some(fixed)).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let mut greeting = [0_u8; 2];
        client.read_exact(&mut greeting).unwrap();
        client
            .write_all(&[5, 1, 0, 1, 203, 0, 113, 9, 0, 80])
            .unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0);
        client.write_all(b"ping").unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        drop(client);
        server.join().unwrap();
        echo.join().unwrap();
    }
}
