//! Process-isolated loopback echo mechanism for socket-lifecycle gates.
//!
//! The descriptor-pressure gate must keep many real end-to-end streams open.
//! A separate process is intentional: it gives every REALITY outbound a real
//! socket and lets the harness tear the listener down without coupling it to the
//! control-plane process.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

/// Serves full-duplex echo connections until the process is terminated.
///
/// # Errors
///
/// Returns an I/O error when accepting a connection fails permanently.
pub fn serve(listener: &TcpListener) -> std::io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::Builder::new()
            .name("rr-echo-connection".to_owned())
            .spawn(move || {
                let _ = echo(stream);
            })?;
    }
    Ok(())
}

fn echo(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        stream.write_all(&buffer[..read])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn one_connection_echoes_multiple_payloads() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            echo(stream).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        for payload in [b"first".as_slice(), b"second payload".as_slice()] {
            client.write_all(payload).unwrap();
            let mut received = vec![0; payload.len()];
            client.read_exact(&mut received).unwrap();
            assert_eq!(received, payload);
        }
        drop(client);
        server.join().unwrap();
    }
}
