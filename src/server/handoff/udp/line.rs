//! LINE end of the native Handoff UDP channel: one XUDP association.
//!
//! LINE keeps the client's REALITY/Vision/XUDP session, authorizes every
//! New/Keep destination with its own routing (DNS, GeoIP/GeoSite, policy),
//! and sends only the resolved, authorized datagrams to LANDING. A Block
//! decision or a capability change fails the association before anything
//! is sent; nothing ever falls back to Direct.

use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{net::UdpSocket, time};

use super::endpoint::{
    ChannelEndpoint, MAX_TIMER_SLEEP, Received, Target, bind_dont_fragment, prober_for,
    production_timers,
};
use crate::protocol::handoff::udp::{PacketType, UdpPacketError, seal_open};
use crate::protocol::vless::{
    Destination, XudpGlobalId, XudpPacket, XudpSessionStatus, encode_xudp_packet,
};
use crate::server::handoff::HandoffLine;
use crate::server::xudp::{
    XudpGlobalLease, XudpGlobalMap, XudpSessionError, destination_to_socket_addr,
};

/// First OPEN retransmission delay; doubles up to [`MAX_OPEN_BACKOFF`].
const OPEN_RETRANSMIT: Duration = Duration::from_millis(250);
const MAX_OPEN_BACKOFF: Duration = Duration::from_secs(2);

/// One XUDP association whose UDP egress lives on a Handoff LANDING and is
/// carried over the native UDP channel.
pub struct XudpHandoffUdpAssociation<'a> {
    socket: UdpSocket,
    endpoint: ChannelEndpoint,
    open_packet: Vec<u8>,
    confirmed: bool,
    open_deadline: Instant,
    next_open: Instant,
    open_backoff: Duration,
    destination: SocketAddr,
    global_lease: Option<XudpGlobalLease<'a>>,
    last_activity: Instant,
    uplink_datagrams: u64,
    downlink_datagrams: u64,
    recv_buf: Vec<u8>,
}

async fn resolve_landing(host: &str, port: u16) -> Result<SocketAddr, XudpSessionError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(XudpSessionError::Io)?;
    addresses.next().ok_or(XudpSessionError::ResolveFailed)
}

impl<'a> XudpHandoffUdpAssociation<'a> {
    /// Opens a native UDP session toward LANDING for the authorized first
    /// destination and registers GlobalID affinity.
    pub async fn open(
        line: &HandoffLine,
        destination: &Destination,
        user_id: [u8; 16],
        global_id: Option<XudpGlobalId>,
        globals: &'a XudpGlobalMap,
        now: Instant,
    ) -> Result<Self, XudpSessionError> {
        let destination = destination_to_socket_addr(destination)?;
        let global_lease = global_id
            .map(|id| globals.acquire(id, user_id, now))
            .transpose()?;
        let (host, port) = line.udp_endpoint();
        let landing = resolve_landing(host, port).await?;
        let bind = if landing.is_ipv6() {
            SocketAddr::from(([0_u16; 8], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let socket = bind_dont_fragment(bind).map_err(XudpSessionError::Io)?;
        socket
            .connect(landing)
            .await
            .map_err(XudpSessionError::Io)?;
        let kernel_mtu = rr_linux::socket::udp_path_mtu(&socket, landing.is_ipv6()).ok();
        let (psk, landing_public) = line.udp_keys();
        let mut open_packet = Vec::new();
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| XudpSessionError::HandoffUdp(UdpPacketError::TimeWindow))?
            .as_secs();
        let channel = seal_open(psk, landing_public, user_id, unix, &mut open_packet)
            .map_err(XudpSessionError::HandoffUdp)?;
        let prober = prober_for(
            line.udp_mtu(),
            kernel_mtu,
            landing.is_ipv6(),
            production_timers(),
            now,
        );
        socket
            .send(&open_packet)
            .await
            .map_err(XudpSessionError::Io)?;
        Ok(Self {
            socket,
            endpoint: ChannelEndpoint::new(channel, prober, landing.is_ipv6()),
            open_packet,
            confirmed: false,
            open_deadline: now + line.connect_timeout(),
            next_open: now + OPEN_RETRANSMIT,
            open_backoff: OPEN_RETRANSMIT,
            destination,
            global_lease,
            last_activity: now,
            uplink_datagrams: 0,
            downlink_datagrams: 0,
            recv_buf: vec![0_u8; 65_536],
        })
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn uplink_datagrams(&self) -> u64 {
        self.uplink_datagrams
    }

    pub fn downlink_datagrams(&self) -> u64 {
        self.downlink_datagrams
    }

    /// Current packetization limit toward LANDING (tests and telemetry).
    pub fn plpmtu(&self) -> usize {
        self.endpoint.plpmtu()
    }

    /// Fragmentation, reassembly, and kernel-feedback counters.
    #[cfg(test)]
    pub(crate) fn channel_stats(&self) -> super::endpoint::EndpointStats {
        self.endpoint.stats()
    }

    /// Whether LANDING acknowledged the open.
    pub fn confirmed(&self) -> bool {
        self.confirmed
    }

    async fn retransmit_open(&mut self, now: Instant) -> Result<(), XudpSessionError> {
        if self.confirmed {
            return Ok(());
        }
        if now >= self.open_deadline {
            return Err(XudpSessionError::HandoffUdpOpenTimeout);
        }
        if now >= self.next_open {
            self.socket
                .send(&self.open_packet)
                .await
                .map_err(XudpSessionError::Io)?;
            self.open_backoff = (self.open_backoff * 2).min(MAX_OPEN_BACKOFF);
            self.next_open = now + self.open_backoff;
        }
        Ok(())
    }

    /// Applies one uplink XUDP packet: every destination field must carry an
    /// authorized, resolved destination from LINE routing.
    pub async fn handle_uplink_packet(
        &mut self,
        packet: &XudpPacket,
        authorized_destination: Option<&Destination>,
        now: Instant,
    ) -> Result<(), XudpSessionError> {
        match packet.status {
            XudpSessionStatus::End | XudpSessionStatus::KeepAlive => {
                self.last_activity = now;
                return Ok(());
            }
            XudpSessionStatus::New | XudpSessionStatus::Keep => {}
        }
        if packet.destination.is_some() {
            let destination =
                authorized_destination.ok_or(XudpSessionError::UnauthorizedRewrite)?;
            self.destination = destination_to_socket_addr(destination)?;
        } else if packet.status == XudpSessionStatus::New {
            return Err(XudpSessionError::MissingNewDestination);
        }
        self.retransmit_open(now).await?;
        if !packet.payload.is_empty() {
            self.endpoint
                .send_datagram(
                    &self.socket,
                    Target::Connected,
                    self.destination,
                    &packet.payload,
                )
                .await
                .map_err(XudpSessionError::Io)?;
            self.uplink_datagrams = self.uplink_datagrams.saturating_add(1);
        }
        self.last_activity = now;
        Ok(())
    }

    fn next_timer(&self, now: Instant) -> Instant {
        let mut deadline = now + MAX_TIMER_SLEEP;
        if !self.confirmed {
            deadline = deadline.min(self.next_open).min(self.open_deadline);
        } else if let Some(probe) = self.endpoint.next_deadline(now) {
            deadline = deadline.min(probe);
        }
        deadline
    }

    /// Receives LANDING packets until one whole downlink datagram is ready,
    /// then encodes it as an XUDP Keep frame naming its real source. Drives
    /// OPEN retransmission and PMTU probing while waiting.
    pub async fn recv_downlink_frame(
        &mut self,
        _buf: &mut [u8],
        output: &mut Vec<u8>,
        _now: Instant,
    ) -> Result<usize, XudpSessionError> {
        loop {
            let deadline = self.next_timer(Instant::now());
            let received = tokio::select! {
                received = self.socket.recv(&mut self.recv_buf) => Some(received),
                () = time::sleep_until(deadline.into()) => None,
            };
            let now = Instant::now();
            let Some(received) = received else {
                self.retransmit_open(now).await?;
                if self.confirmed {
                    self.endpoint
                        .poll_probe(&self.socket, Target::Connected, now)
                        .await
                        .map_err(XudpSessionError::Io)?;
                }
                self.endpoint.expire(now);
                continue;
            };
            let length = match received {
                Ok(length) => length,
                // ICMP port unreachable surfaces as ECONNREFUSED on a
                // connected socket; keep waiting until the open deadline.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(error) => return Err(XudpSessionError::Io(error)),
            };
            let packet = self.recv_buf[..length].to_vec();
            match self
                .endpoint
                .receive(&self.socket, Target::Connected, &packet, now)
                .await
            {
                Ok(Received::Data(source, payload)) => {
                    // Any authenticated packet proves the open landed.
                    self.confirmed = true;
                    output.clear();
                    encode_xudp_packet(
                        &Destination::from(source),
                        &payload,
                        false,
                        None,
                        true,
                        output,
                    )?;
                    self.downlink_datagrams = self.downlink_datagrams.saturating_add(1);
                    self.last_activity = now;
                    return Ok(output.len());
                }
                Ok(Received::OpenAck | Received::Handled) => {
                    self.confirmed = true;
                }
                Ok(Received::Close) => return Err(XudpSessionError::HandoffUdpClosed),
                Err(_) => self.endpoint.note_rejected(),
            }
        }
    }

    /// Best-effort CLOSE so LANDING frees the session before its idle bound.
    pub async fn close(mut self, now: Instant) {
        let _ = self
            .endpoint
            .send_control(&self.socket, Target::Connected, PacketType::Close)
            .await;
        if let Some(lease) = self.global_lease.take() {
            lease.release(now);
        }
    }
}
