//! One authenticated end of a native Handoff UDP session: sealing,
//! packetization (DATA or FRAG under the discovered path MTU), PMTU probes,
//! and receive-side reassembly. Shared by LINE and LANDING.

use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::protocol::handoff::udp::{
    FRAG_HEADER_LEN, HEADER_LEN, PacketType, PmtuProber, PmtuTimers, Reassembler, ReassemblyLimits,
    TAG_LEN, UdpChannel, UdpPacketError, decode_data, encode_data_plaintext, plpmtu_from_ip_mtu,
    split_fragments,
};

/// Attempts to re-packetize one datagram after local `EMSGSIZE` feedback.
const MAX_SEND_ATTEMPTS: usize = 4;

/// Where a sealed packet goes: the connected peer (LINE) or an explicit
/// address on a shared listener socket (LANDING).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Target {
    Connected,
    To(SocketAddr),
}

/// One received, authenticated packet's meaning for the owner.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Received {
    /// A whole datagram with its destination (uplink) or source (downlink).
    Data(SocketAddr, Vec<u8>),
    OpenAck,
    Close,
    /// Control traffic fully handled here, or an incomplete fragment group.
    Handled,
}

/// Builds the prober for one direction from the configured fixed MTU or
/// from the interface/route bound of `socket`.
pub(crate) fn prober_for(
    fixed_mtu: Option<u16>,
    kernel_mtu: Option<u32>,
    ipv6: bool,
    timers: PmtuTimers,
    now: Instant,
) -> PmtuProber {
    match fixed_mtu {
        Some(mtu) => PmtuProber::fixed(plpmtu_from_ip_mtu(usize::from(mtu), ipv6), now),
        None => {
            let ip_mtu = kernel_mtu.map_or(1500, |mtu| mtu as usize);
            PmtuProber::discover(plpmtu_from_ip_mtu(ip_mtu, ipv6), timers, now)
        }
    }
}

/// Binds a UDP socket with DF set (`IP_PMTUDISC_DO`): the channel never
/// relies on IP fragmentation.
pub(crate) fn bind_dont_fragment(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(address)?;
    socket.set_nonblocking(true)?;
    rr_linux::socket::set_udp_dont_fragment(&socket, address.is_ipv6()).map_err(io::Error::from)?;
    UdpSocket::from_std(socket)
}

fn kernel_limit(socket: &UdpSocket, target: Target, ipv6: bool) -> Option<usize> {
    match target {
        Target::Connected => rr_linux::socket::udp_path_mtu(socket, ipv6)
            .ok()
            .map(|mtu| plpmtu_from_ip_mtu(mtu as usize, ipv6)),
        Target::To(_) => None,
    }
}

fn is_too_big(error: &io::Error) -> bool {
    error.raw_os_error() == Some(rr_linux::Errno::MSGSIZE.raw_os_error())
}

async fn send(socket: &UdpSocket, target: Target, bytes: &[u8]) -> io::Result<()> {
    let written = match target {
        Target::Connected => socket.send(bytes).await?,
        Target::To(address) => socket.send_to(bytes, address).await?,
    };
    if written == bytes.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short UDP datagram write",
        ))
    }
}

/// Counters exposed for telemetry and tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EndpointStats {
    pub(crate) fragmented_datagrams: u64,
    pub(crate) fragments_sent: u64,
    pub(crate) reassembled_datagrams: u64,
    pub(crate) too_big_feedback: u64,
    pub(crate) rejected_packets: u64,
}

/// One sealed channel end with its path MTU and reassembly state.
pub(crate) struct ChannelEndpoint {
    channel: UdpChannel,
    pmtu: PmtuProber,
    reassembler: Reassembler,
    ipv6: bool,
    next_fragment_id: u32,
    plain: Vec<u8>,
    wire: Vec<u8>,
    stats: EndpointStats,
}

impl ChannelEndpoint {
    pub(crate) fn new(channel: UdpChannel, pmtu: PmtuProber, ipv6: bool) -> Self {
        Self {
            channel,
            pmtu,
            reassembler: Reassembler::new(ReassemblyLimits::default()),
            ipv6,
            next_fragment_id: 1,
            plain: Vec::new(),
            wire: Vec::new(),
            stats: EndpointStats::default(),
        }
    }

    pub(crate) const fn plpmtu(&self) -> usize {
        self.pmtu.plpmtu()
    }

    pub(crate) const fn stats(&self) -> EndpointStats {
        self.stats
    }

    pub(crate) fn note_rejected(&mut self) {
        self.stats.rejected_packets = self.stats.rejected_packets.saturating_add(1);
    }

    /// Seals and sends one datagram, fragmenting under the current limit and
    /// re-packetizing after local `EMSGSIZE` feedback. Never silently drops.
    pub(crate) async fn send_datagram(
        &mut self,
        socket: &UdpSocket,
        target: Target,
        address: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut plain = std::mem::take(&mut self.plain);
        let result = self
            .send_datagram_inner(socket, target, address, payload, &mut plain)
            .await;
        self.plain = plain;
        result
    }

    async fn send_datagram_inner(
        &mut self,
        socket: &UdpSocket,
        target: Target,
        address: SocketAddr,
        payload: &[u8],
        plain: &mut Vec<u8>,
    ) -> io::Result<()> {
        encode_data_plaintext(address, payload, plain).map_err(invalid)?;
        for _ in 0..MAX_SEND_ATTEMPTS {
            let limit = self.pmtu.plpmtu();
            let outcome = if HEADER_LEN + plain.len() + TAG_LEN <= limit {
                self.channel
                    .seal(PacketType::Data, plain, &mut self.wire)
                    .map_err(invalid)?;
                send(socket, target, &self.wire)
                    .await
                    .map_err(|error| (error, self.wire.len()))
            } else {
                self.send_fragments(socket, target, plain, limit).await
            };
            match outcome {
                Ok(()) => return Ok(()),
                Err((error, attempted)) if is_too_big(&error) => {
                    self.stats.too_big_feedback = self.stats.too_big_feedback.saturating_add(1);
                    let kernel = kernel_limit(socket, target, self.ipv6);
                    self.pmtu.on_send_too_big(attempted, kernel);
                }
                Err((error, _)) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native UDP datagram could not be packetized under the path MTU",
        ))
    }

    async fn send_fragments(
        &mut self,
        socket: &UdpSocket,
        target: Target,
        plain: &[u8],
        limit: usize,
    ) -> Result<(), (io::Error, usize)> {
        let chunk = limit.saturating_sub(HEADER_LEN + TAG_LEN + FRAG_HEADER_LEN);
        let id = self.next_fragment_id;
        self.next_fragment_id = self.next_fragment_id.wrapping_add(1);
        let fragments = split_fragments(id, plain, chunk).map_err(|error| (invalid(error), 0))?;
        self.stats.fragmented_datagrams = self.stats.fragmented_datagrams.saturating_add(1);
        for fragment in &fragments {
            self.channel
                .seal(PacketType::Frag, fragment, &mut self.wire)
                .map_err(|error| (invalid(error), 0))?;
            send(socket, target, &self.wire)
                .await
                .map_err(|error| (error, self.wire.len()))?;
            self.stats.fragments_sent = self.stats.fragments_sent.saturating_add(1);
        }
        Ok(())
    }

    /// Seals and sends one small control packet (OPEN_ACK, CLOSE).
    pub(crate) async fn send_control(
        &mut self,
        socket: &UdpSocket,
        target: Target,
        packet_type: PacketType,
    ) -> io::Result<()> {
        self.channel
            .seal(packet_type, &[], &mut self.wire)
            .map_err(invalid)?;
        send(socket, target, &self.wire).await
    }

    /// Sends the PMTU probe that is due now, if any.
    pub(crate) async fn poll_probe(
        &mut self,
        socket: &UdpSocket,
        target: Target,
        now: Instant,
    ) -> io::Result<()> {
        let Some(probe) = self.pmtu.poll(now) else {
            return Ok(());
        };
        self.channel
            .seal_padded(
                PacketType::Probe,
                &probe.id.to_be_bytes(),
                probe.size,
                &mut self.wire,
            )
            .map_err(invalid)?;
        match send(socket, target, &self.wire).await {
            Err(error) if is_too_big(&error) => {
                self.stats.too_big_feedback = self.stats.too_big_feedback.saturating_add(1);
                self.pmtu.on_probe_too_big(probe.size);
                Ok(())
            }
            other => other,
        }
    }

    /// Earliest instant a timer-driven probe may be due.
    pub(crate) fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.pmtu.next_deadline(now)
    }

    /// Authenticates one received packet and acts on control traffic.
    ///
    /// # Errors
    ///
    /// Returns the closed packet error; the caller drops silently.
    pub(crate) async fn receive(
        &mut self,
        socket: &UdpSocket,
        target: Target,
        packet: &[u8],
        now: Instant,
    ) -> Result<Received, UdpPacketError> {
        let packet_type = self.channel.open(packet, &mut self.plain)?;
        match packet_type {
            PacketType::Data => {
                let (address, payload) = decode_data(&self.plain)?;
                Ok(Received::Data(address, payload.to_vec()))
            }
            PacketType::Frag => match self.reassembler.insert(&self.plain, now)? {
                Some(whole) => {
                    self.stats.reassembled_datagrams =
                        self.stats.reassembled_datagrams.saturating_add(1);
                    let (address, payload) = decode_data(&whole)?;
                    Ok(Received::Data(address, payload.to_vec()))
                }
                None => Ok(Received::Handled),
            },
            PacketType::Probe => {
                let id: [u8; 4] = self
                    .plain
                    .get(..4)
                    .ok_or(UdpPacketError::Length)?
                    .try_into()
                    .map_err(|_| UdpPacketError::Length)?;
                let size = u16::try_from(packet.len()).map_err(|_| UdpPacketError::Length)?;
                let mut ack = [0_u8; 6];
                ack[..4].copy_from_slice(&id);
                ack[4..].copy_from_slice(&size.to_be_bytes());
                self.channel
                    .seal(PacketType::ProbeAck, &ack, &mut self.wire)?;
                // A lost acknowledgement is the probe's loss; nothing to do.
                let _ = send(socket, target, &self.wire).await;
                Ok(Received::Handled)
            }
            PacketType::ProbeAck => {
                if self.plain.len() < 6 {
                    return Err(UdpPacketError::Length);
                }
                let id = u32::from_be_bytes([
                    self.plain[0],
                    self.plain[1],
                    self.plain[2],
                    self.plain[3],
                ]);
                let size = usize::from(u16::from_be_bytes([self.plain[4], self.plain[5]]));
                self.pmtu.on_probe_ack(id, size, now);
                Ok(Received::Handled)
            }
            PacketType::OpenAck => Ok(Received::OpenAck),
            PacketType::Close => Ok(Received::Close),
            PacketType::Open => Err(UdpPacketError::Type),
        }
    }

    /// Discards expired reassembly groups.
    pub(crate) fn expire(&mut self, now: Instant) {
        self.reassembler.expire(now);
    }
}

fn invalid(error: UdpPacketError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Default discovery timers for production sessions.
pub(crate) fn production_timers() -> PmtuTimers {
    #[cfg(test)]
    if let Some(timers) = TEST_TIMERS.with(std::cell::Cell::get) {
        return timers;
    }
    PmtuTimers::default()
}

#[cfg(test)]
thread_local! {
    /// Per-test timer override (tokio current-thread tests run LINE and
    /// LANDING on one thread), so black-hole tests run in seconds.
    pub(crate) static TEST_TIMERS: std::cell::Cell<Option<PmtuTimers>> =
        const { std::cell::Cell::new(None) };
}

/// Upper bound on how long a timer-driven wait may sleep.
pub(crate) const MAX_TIMER_SLEEP: Duration = Duration::from_secs(5);
