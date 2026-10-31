//! Loopback SOCKS5 no-auth CONNECT and UDP ASSOCIATE acceptor.

use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::protocol::{
    socks5::{
        DecodeError, EncodeError, MethodResponse, decode_connect_request, decode_method_request,
        decode_udp_associate_request, encode_command_reply, encode_method_response,
    },
    vless::Destination,
};

use super::{line::LineError, selection::LineGroup};

/// SOCKS5 refusal / protocol failure.
#[derive(Debug)]
pub(super) enum Socks5Error {
    /// Protocol decode failed.
    Protocol(DecodeError),
    /// Protocol encode failed.
    Encode(EncodeError),
    /// LINE establishment failed.
    Line(LineError),
    /// Socket I/O failed.
    Io(std::io::Error),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SOCKS5 inbound failed")
    }
}

impl std::error::Error for Socks5Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Encode(e) => Some(e),
            Self::Line(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

enum SocksRequest {
    Connect(Destination),
    UdpAssociate,
}

/// Handles one SOCKS5 client connection through `group`.
pub(super) async fn handle_connection(
    mut local: TcpStream,
    bound: SocketAddr,
    group: &LineGroup,
) -> Result<(), Socks5Error> {
    let request = tokio::time::timeout(
        super::REQUEST_BUDGET,
        negotiate_and_read_request(&mut local),
    )
    .await
    .map_err(|_| {
        Socks5Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SOCKS5 request timed out",
        ))
    })??;
    match request {
        SocksRequest::Connect(destination) => {
            handle_connect(&mut local, bound, group, destination).await
        }
        SocksRequest::UdpAssociate => handle_udp_associate(&mut local, bound, group).await,
    }
}

async fn handle_connect(
    local: &mut TcpStream,
    bound: SocketAddr,
    group: &LineGroup,
    destination: Destination,
) -> Result<(), Socks5Error> {
    match group.establish(&destination).await {
        Ok(mut tunnel) => {
            write_reply(local, 0x00, bound)
                .await
                .map_err(Socks5Error::Io)?;
            let _ = tunnel.relay(local).await;
            Ok(())
        }
        Err(error) => {
            let _ = write_reply(local, map_line_rep(&error), bound).await;
            Err(Socks5Error::Line(error))
        }
    }
}

async fn handle_udp_associate(
    local: &mut TcpStream,
    bound: SocketAddr,
    group: &LineGroup,
) -> Result<(), Socks5Error> {
    // Bind UDP relay on the same loopback family as the TCP listener.
    let udp = bind_udp_relay(bound).await.map_err(Socks5Error::Io)?;
    let relay_addr = udp.local_addr().map_err(Socks5Error::Io)?;

    // Commit one LINE for the whole association before answering success.
    let mut tunnel = match group.establish_xudp().await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            let _ = write_reply(local, map_line_rep(&error), bound).await;
            return Err(Socks5Error::Line(error));
        }
    };

    write_reply(local, 0x00, relay_addr)
        .await
        .map_err(Socks5Error::Io)?;

    // LINE ownership is fixed for this association; control EOF ends it.
    let _ = tunnel.relay_socks5_udp(&udp, local).await;
    Ok(())
}

async fn bind_udp_relay(tcp_bound: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind = match tcp_bound {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
    };
    UdpSocket::bind(bind).await
}

async fn negotiate_and_read_request(stream: &mut TcpStream) -> Result<SocksRequest, Socks5Error> {
    let mut buf = vec![0_u8; 512];
    let mut filled = 0_usize;
    loop {
        if filled >= buf.len() {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 method offer too large",
            )));
        }
        let n = stream
            .read(&mut buf[filled..])
            .await
            .map_err(Socks5Error::Io)?;
        if n == 0 {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SOCKS5 peer closed",
            )));
        }
        filled += n;
        match decode_method_request(&buf[..filled]) {
            Ok(method) => {
                let mut reply = [0_u8; 2];
                encode_method_response(MethodResponse::NoAuthentication, &mut reply)
                    .map_err(Socks5Error::Encode)?;
                stream.write_all(&reply).await.map_err(Socks5Error::Io)?;
                let trailing = method.trailing().to_vec();
                return read_command(stream, trailing).await;
            }
            Err(DecodeError::IncompleteInput { .. }) => continue,
            Err(error) => return Err(Socks5Error::Protocol(error)),
        }
    }
}

async fn read_command(
    stream: &mut TcpStream,
    mut pending: Vec<u8>,
) -> Result<SocksRequest, Socks5Error> {
    let mut buf = vec![0_u8; 512];
    loop {
        if pending.len() >= 2 {
            match pending[1] {
                0x01 => match decode_connect_request(&pending) {
                    Ok(request) => return Ok(SocksRequest::Connect(request.destination().clone())),
                    Err(DecodeError::IncompleteInput { .. }) => {}
                    Err(error) => return Err(Socks5Error::Protocol(error)),
                },
                0x03 => match decode_udp_associate_request(&pending) {
                    Ok(_) => return Ok(SocksRequest::UdpAssociate),
                    Err(DecodeError::IncompleteInput { .. }) => {}
                    Err(error) => return Err(Socks5Error::Protocol(error)),
                },
                other => {
                    return Err(Socks5Error::Protocol(DecodeError::UnsupportedCommand(
                        other,
                    )));
                }
            }
        }
        let n = stream.read(&mut buf).await.map_err(Socks5Error::Io)?;
        if n == 0 {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SOCKS5 request truncated",
            )));
        }
        pending.extend_from_slice(&buf[..n]);
        if pending.len() > 1024 {
            return Err(Socks5Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 request too large",
            )));
        }
    }
}

async fn write_reply(stream: &mut TcpStream, rep: u8, bound: SocketAddr) -> std::io::Result<()> {
    let mut reply = [0_u8; 22];
    let n = encode_command_reply(rep, &bound, &mut reply)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    stream.write_all(&reply[..n]).await?;
    stream.flush().await
}

fn map_line_rep(error: &LineError) -> u8 {
    match error {
        LineError::Dial(_) => 0x05,
        LineError::Handshake(_) | LineError::Session(_) | LineError::Selection(_) => 0x05,
        LineError::Config(_) => 0x01,
    }
}
