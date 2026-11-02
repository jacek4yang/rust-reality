//! LANDING side of an authenticated NXR UDP association: framed datagrams
//! on the NXR TCP stream, one UDP socket owned for the association life.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::{
    protocol::{
        nxr_udp::{
            DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM,
            NXR_UDP_MAX_PAYLOAD, NxrUdpError, NxrUdpSeq, NxrUdpSessionKey, drain_frames,
            encode_frame,
        },
        vless::{Address, Destination},
    },
    transport::relay::RelayStats,
};

use super::{NxrLandingError, NxrLandingHandler};

impl NxrLandingHandler {
    /// Authenticated NXR UDP association: framed datagrams on `inbound`, UDP
    /// sockets owned here. Destination changes are accepted only when covered
    /// by the session MAC (LINE is routing authority).
    pub(super) async fn handle_udp_association(
        &self,
        mut inbound: TcpStream,
        initial_destination: Destination,
        session: NxrUdpSessionKey,
    ) -> Result<RelayStats, NxrLandingError> {
        let mut current = socket_addr_for_udp(&initial_destination)?;
        // Bind the UDP socket to the same local IP the NXR TCP listener accepted
        // on so echo peers observe LANDING's address (not LINE's) on loopback
        // multi-address topologies (e.g. LANDING on 127.0.0.2).
        let bind = inbound
            .local_addr()
            .map(|addr| std::net::SocketAddr::new(addr.ip(), 0))
            .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        let udp = UdpSocket::bind(bind)
            .await
            .map_err(NxrLandingError::UdpIo)?;
        // Charge one outbound FD unit for the UDP socket for the association life.
        let _udp_permit = self
            .relay
            .fd_budget()
            .try_acquire(crate::transport::UNITS_OUTBOUND_SOCKET)
            .ok_or(NxrLandingError::DescriptorBudget)?;

        let mut inbound_buf = Vec::new();
        let mut udp_buf = vec![0_u8; 64 * 1024];
        let mut frame_out = Vec::new();
        let mut seq_in = NxrUdpSeq::new();
        let mut seq_out = NxrUdpSeq::new();
        let mut uplink = 0_u64;
        let mut downlink = 0_u64;
        let idle = Duration::from_secs(60);

        loop {
            tokio::select! {
                biased;
                read = inbound.read_buf(&mut inbound_buf) => {
                    let n = read.map_err(NxrLandingError::Read)?;
                    if n == 0 {
                        break;
                    }
                    if inbound_buf.len() > MAX_FRAME_BUFFER {
                        return Err(NxrLandingError::UdpProtocol(NxrUdpError::Length));
                    }
                    let frames = drain_frames(
                        &mut inbound_buf,
                        &session,
                        DIR_LINE_TO_LANDING,
                    )
                    .map_err(NxrLandingError::UdpProtocol)?;
                    for frame in frames {
                        seq_in.accept_in(frame.seq).map_err(NxrLandingError::UdpProtocol)?;
                        if frame.frame_type == FRAME_TYPE_CLOSE {
                            return Ok(RelayStats::new(uplink, downlink));
                        }
                        if frame.frame_type != FRAME_TYPE_DATAGRAM {
                            return Err(NxrLandingError::UdpProtocol(NxrUdpError::FrameType));
                        }
                        if let Some(dest) = frame.destination.as_ref() {
                            current = socket_addr_for_udp(dest)?;
                        }
                        if frame.payload.len() > NXR_UDP_MAX_PAYLOAD {
                            return Err(NxrLandingError::UdpProtocol(NxrUdpError::Payload));
                        }
                        if !frame.payload.is_empty() {
                            udp.send_to(&frame.payload, current)
                                .await
                                .map_err(NxrLandingError::UdpIo)?;
                            uplink = uplink.saturating_add(frame.payload.len() as u64);
                        }
                    }
                }
                recv = udp.recv_from(&mut udp_buf) => {
                    let (n, from) = recv.map_err(NxrLandingError::UdpIo)?;
                    let source = Destination::from(from);
                    if n > NXR_UDP_MAX_PAYLOAD {
                        return Err(NxrLandingError::UdpProtocol(NxrUdpError::Payload));
                    }
                    let payload = &udp_buf[..n];
                    let seq = seq_out.next_out().map_err(NxrLandingError::UdpProtocol)?;
                    encode_frame(
                        &session,
                        DIR_LANDING_TO_LINE,
                        FRAME_TYPE_DATAGRAM,
                        seq,
                        Some(&source),
                        payload,
                        &mut frame_out,
                    )
                    .map_err(NxrLandingError::UdpProtocol)?;
                    inbound
                        .write_all(&frame_out)
                        .await
                        .map_err(NxrLandingError::UdpIo)?;
                    downlink = downlink.saturating_add(payload.len() as u64);
                }
                () = tokio::time::sleep(idle) => {
                    break;
                }
            }
        }
        Ok(RelayStats::new(uplink, downlink))
    }
}

/// Bound on unreassembled TCP buffer bytes for NXR UDP framing.
const MAX_FRAME_BUFFER: usize = 256 * 1024;

fn socket_addr_for_udp(destination: &Destination) -> Result<std::net::SocketAddr, NxrLandingError> {
    match destination.address() {
        Address::Ipv4(addr) => Ok(std::net::SocketAddr::from((*addr, destination.port()))),
        Address::Ipv6(addr) => Ok(std::net::SocketAddr::from((*addr, destination.port()))),
        Address::Domain(_) => Err(NxrLandingError::UdpProtocol(NxrUdpError::Address)),
    }
}
