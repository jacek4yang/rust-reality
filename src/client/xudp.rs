//! Client XUDP tunnel over one committed REALITY + Vision LINE.
//!
//! Opens VLESS Mux (`0x03`) with wire flow `xtls-rprx-vision`, then carries
//! SOCKS5 UDP ASSOCIATE traffic as XUDP frames. The LINE is fixed for the
//! association lifetime (no mid-session migration).

use std::net::SocketAddr;

use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
};

use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{
            MAX_PLAINTEXT_LEN, TlsApplicationReader, TlsApplicationWriter, application_halves,
        },
    },
    socks5::{decode_udp_datagram, encode_udp_datagram},
    vless::{
        Destination, ResponseDecodeError, UserId, VisionCommand, VisionDecoder, VisionEncoder,
        VisionMode, XudpPacket, decode_response, decode_xudp_packet, encode_vision_xudp_request,
        encode_xudp_packet, vision_udp_command_allows_port,
    },
};

use super::session::VisionTunnelError;

/// Client-side XUDP association bound to one authenticated LINE.
pub struct XudpTunnel {
    reader: TlsApplicationReader<tokio::net::tcp::OwnedReadHalf>,
    writer: TlsApplicationWriter<tokio::net::tcp::OwnedWriteHalf>,
    encoder: VisionEncoder,
    decoder: VisionDecoder,
    downlink: VisionMode,
    readable: Vec<u8>,
    readable_at: usize,
    encoder_done: bool,
    activity: std::sync::Arc<crate::io_activity::SessionActivity>,
    /// Destination of the most recent uplink New/Keep frame (for Keep without rewrite).
    last_destination: Option<Destination>,
    association_opened: bool,
    allow_udp_443: bool,
    /// Stock Xray VLESS inbound buffers the response until the first downlink
    /// write (`SetFlushNext`). XUDP New → UDP echo → mux write flushes it, so
    /// we defer `await_response` until after the first uplink XUDP frame.
    response_pending: bool,
}

impl XudpTunnel {
    /// Sends the Vision Mux/XUDP preamble.
    ///
    /// The VLESS response is read on the first uplink XUDP frame inside
    /// [`Self::relay_socks5_udp`]. Stock Xray inbound only flushes the buffered
    /// response on the first downlink write (`SetFlushNext`); sending XUDP New
    /// first matches stock Xray client parallelism and avoids ASSOCIATE deadlock.
    pub async fn connect(
        stream: TcpStream,
        session: ClientSession,
        user_id: UserId,
        allow_udp_443: bool,
    ) -> Result<Self, VisionTunnelError> {
        let mut request = [0_u8; 128];
        let request_len = encode_vision_xudp_request(user_id, &mut request)
            .map_err(|_| VisionTunnelError::Request)?;
        let mut encoder = VisionEncoder::new(user_id).map_err(|_| VisionTunnelError::Vision)?;
        let preamble = encoder
            .plan(0, VisionCommand::Continue, true)
            .map_err(|_| VisionTunnelError::Vision)?;
        let total = request_len
            .checked_add(preamble.wire_len())
            .filter(|n| *n <= MAX_PLAINTEXT_LEN)
            .ok_or(VisionTunnelError::Request)?;
        let mut frame = vec![0_u8; total];
        frame[..request_len].copy_from_slice(&request[..request_len]);
        encoder.assemble(&preamble, &[], &mut frame[request_len..]);
        encoder.commit(&preamble);

        let (_, write_records, read_records) = session.into_record_layers();
        let (reader, writer) = stream.into_split();
        let (mut reader, mut writer) = application_halves(
            reader,
            Vec::new(),
            writer,
            read_records,
            write_records,
            false,
        );
        let activity = std::sync::Arc::new(crate::io_activity::SessionActivity::default());
        reader.set_activity(activity.clone());
        writer.set_activity(activity.clone());
        writer
            .write_application(&frame, crate::io_activity::WRITE_STALL_TIMEOUT)
            .await
            .map_err(VisionTunnelError::Tls)?;

        Ok(Self {
            reader,
            writer,
            encoder,
            decoder: VisionDecoder::new(user_id),
            downlink: VisionMode::Framed,
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            encoder_done: false,
            activity,
            last_destination: None,
            association_opened: false,
            allow_udp_443,
            response_pending: true,
        })
    }

    /// Relays SOCKS5 UDP datagrams on `udp` while `control` stays open.
    ///
    /// The first peer that sends a datagram becomes the only accepted peer
    /// address (typical SOCKS5 UDP ASSOCIATE cone). The TCP control connection
    /// ending tears the association down.
    pub async fn relay_socks5_udp(
        &mut self,
        udp: &UdpSocket,
        control: &mut TcpStream,
    ) -> Result<(), VisionTunnelError> {
        let mut peer: Option<SocketAddr> = None;
        let mut udp_buf = vec![0_u8; 64 * 1024];
        let mut control_buf = [0_u8; 64];
        let mut socks_out = Vec::new();
        let mut xudp_out = Vec::new();

        let activity = self.activity.clone();
        let expired = activity.expired(crate::io_activity::SESSION_IDLE_WINDOW);
        tokio::pin!(expired);
        loop {
            tokio::select! {
                () = &mut expired => return Err(VisionTunnelError::Tls(
                    crate::protocol::reality::tls13::TlsApplicationIoError::Timeout)),
                result = udp.recv_from(&mut udp_buf) => {
                    let (n, from) = result.map_err(VisionTunnelError::Io)?;
                    match peer {
                        None => peer = Some(from),
                        Some(expected) if expected != from => continue,
                        Some(_) => {}
                    }
                    let datagram = decode_udp_datagram(&udp_buf[..n])
                        .map_err(|_| VisionTunnelError::Request)?;
                    let destination = datagram.destination().clone();
                    if !vision_udp_command_allows_port(self.allow_udp_443, destination.port()) {
                        return Err(VisionTunnelError::Request);
                    }
                    self.send_xudp(&destination, datagram.payload(), &mut xudp_out)
                        .await?;
                    if self.response_pending {
                        // First uplink XUDP lets stock Xray flush the buffered
                        // VLESS response (inbound SetFlushNext). Match stock
                        // Xray client parallelism: send before waiting.
                        self.await_response().await?;
                        self.response_pending = false;
                    }
                }
                ready = self.poll_fill_readable(), if !self.response_pending => {
                    ready?;
                    while let Some(packet) = self.take_xudp_packet()? {
                        let Some(destination) = packet.destination.clone().or_else(|| {
                            self.last_destination.clone()
                        }) else {
                            continue;
                        };
                        encode_udp_datagram(&destination, &packet.payload, &mut socks_out)
                            .map_err(|_| VisionTunnelError::Request)?;
                        if let Some(peer_addr) = peer {
                            udp.send_to(&socks_out, peer_addr)
                                .await
                                .map_err(VisionTunnelError::Io)?;
                        }
                    }
                }
                read = control.read(&mut control_buf) => {
                    let n = read.map_err(VisionTunnelError::Io)?;
                    if n == 0 {
                        return Ok(());
                    }
                    // Discard unexpected TCP bytes on the control channel.
                }
            }
        }
    }

    async fn send_xudp(
        &mut self,
        destination: &Destination,
        payload: &[u8],
        scratch: &mut Vec<u8>,
    ) -> Result<(), VisionTunnelError> {
        let new_association = !self.association_opened;
        let rewrite = self
            .last_destination
            .as_ref()
            .is_some_and(|last| last != destination);
        scratch.clear();
        encode_xudp_packet(
            destination,
            payload,
            new_association,
            None,
            rewrite && !new_association,
            scratch,
        )
        .map_err(|_| VisionTunnelError::Request)?;
        self.write_application(scratch).await?;
        self.association_opened = true;
        self.last_destination = Some(destination.clone());
        Ok(())
    }

    fn take_xudp_packet(&mut self) -> Result<Option<XudpPacket>, VisionTunnelError> {
        if self.readable_at >= self.readable.len() {
            return Ok(None);
        }
        let available = &self.readable[self.readable_at..];
        match decode_xudp_packet(available) {
            Ok((packet, consumed)) => {
                self.readable_at += consumed;
                if let Some(dest) = packet.destination.clone() {
                    self.last_destination = Some(dest);
                }
                if self.readable_at > 64 * 1024 {
                    self.readable.drain(..self.readable_at);
                    self.readable_at = 0;
                }
                Ok(Some(packet))
            }
            Err(crate::protocol::vless::XudpCodecError::Truncated { .. }) => Ok(None),
            Err(_) => Err(VisionTunnelError::Request),
        }
    }

    async fn await_response(&mut self) -> Result<(), VisionTunnelError> {
        let mut response_buf = Vec::new();
        loop {
            let plaintext = self.read_raw_application().await?;
            if plaintext.is_empty() {
                continue;
            }
            response_buf.extend_from_slice(&plaintext);
            match decode_response(&response_buf) {
                Ok(decoded) => {
                    let payload = decoded.payload().to_vec();
                    self.readable.clear();
                    self.readable_at = 0;
                    if !payload.is_empty() {
                        self.ingest_plaintext(&payload)?;
                    }
                    return Ok(());
                }
                Err(ResponseDecodeError::Incomplete { .. }) => continue,
                Err(_) => return Err(VisionTunnelError::Request),
            }
        }
    }

    async fn read_and_open_record(&mut self) -> Result<(), VisionTunnelError> {
        let plaintext = self.read_raw_application().await?;
        if plaintext.is_empty() {
            return Ok(());
        }
        self.ingest_plaintext(&plaintext)
    }

    async fn read_raw_application(&mut self) -> Result<Vec<u8>, VisionTunnelError> {
        let record = self
            .reader
            .read_application(crate::io_activity::SESSION_IDLE_WINDOW)
            .await
            .map_err(VisionTunnelError::Tls)?;
        Ok(record.plaintext().to_vec())
    }

    fn ingest_plaintext(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        match self.downlink {
            VisionMode::Direct | VisionMode::Raw => {
                self.readable.extend_from_slice(plaintext);
                Ok(())
            }
            VisionMode::Framed => {
                let mut staged = Vec::new();
                let mode = self
                    .decoder
                    .decode_append(plaintext, &mut staged)
                    .map_err(|_| VisionTunnelError::Vision)?;
                self.readable.extend_from_slice(&staged);
                self.downlink = mode;
                if matches!(mode, VisionMode::Direct) {
                    self.encoder_done = true;
                }
                Ok(())
            }
        }
    }

    /// True when `readable` holds at least one complete XUDP frame to drain.
    ///
    /// Incomplete leftovers (frame spanning TLS records) must NOT count as
    /// ready — otherwise `select!` re-arms immediately and busy-loops.
    fn has_complete_xudp_frame(&self) -> bool {
        xudp_buffer_has_complete_frame(&self.readable[self.readable_at..])
    }

    async fn poll_fill_readable(&mut self) -> Result<(), VisionTunnelError> {
        if self.has_complete_xudp_frame() {
            return Ok(());
        }
        // Empty or truncated: await another TLS application record.
        self.read_and_open_record().await
    }

    async fn write_application(&mut self, payload: &[u8]) -> Result<(), VisionTunnelError> {
        if payload.is_empty() {
            return Ok(());
        }
        if self.encoder_done {
            return self.seal_and_send(payload).await;
        }
        let mut offset = 0;
        while offset < payload.len() {
            // The preamble already consumed the UUID; reserve the five-byte frame header.
            let want = (payload.len() - offset).min(crate::protocol::vless::VISION_FRAME_SIZE - 5);
            let plan = self
                .encoder
                .plan(want, VisionCommand::Continue, false)
                .map_err(|_| VisionTunnelError::Vision)?;
            let content = &payload[offset..offset + want];
            self.writer
                .write_assembled(
                    plan.wire_len(),
                    |frame| {
                        self.encoder.assemble(&plan, content, frame);
                    },
                    crate::io_activity::WRITE_STALL_TIMEOUT,
                )
                .await
                .map_err(VisionTunnelError::Tls)?;
            self.encoder.commit(&plan);
            offset += want;
        }
        Ok(())
    }

    async fn seal_and_send(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        self.writer
            .write_application(plaintext, crate::io_activity::WRITE_STALL_TIMEOUT)
            .await
            .map(|_| ())
            .map_err(VisionTunnelError::Tls)
    }
}

/// Returns whether `buffer` begins with a complete, decodable XUDP frame.
///
/// Used by the client tunnel to distinguish "ready to drain" from "need more
/// TLS records" when a frame is fragmented across records.
pub(crate) fn xudp_buffer_has_complete_frame(buffer: &[u8]) -> bool {
    decode_xudp_packet(buffer).is_ok()
}

#[cfg(test)]
mod tests {
    use super::xudp_buffer_has_complete_frame;
    use crate::protocol::vless::{Address, Destination, encode_xudp_packet};
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    fn sample_frame() -> Vec<u8> {
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 9);
        let mut wire = Vec::new();
        encode_xudp_packet(&dest, b"frag-test-payload", true, None, false, &mut wire)
            .expect("encode");
        wire
    }

    #[test]
    fn complete_frame_is_ready() {
        let frame = sample_frame();
        assert!(xudp_buffer_has_complete_frame(&frame));
    }

    #[test]
    fn empty_buffer_is_not_ready() {
        assert!(!xudp_buffer_has_complete_frame(&[]));
    }

    #[test]
    fn fragmented_frame_across_chunks_is_not_ready_until_complete() {
        let frame = sample_frame();
        assert!(frame.len() > 4, "fixture must be splittable");
        let split = frame.len() / 2;
        let first = &frame[..split];
        let second = &frame[split..];
        assert!(
            !xudp_buffer_has_complete_frame(first),
            "first TLS-record-sized fragment must not look complete"
        );
        let mut reassembled = first.to_vec();
        reassembled.extend_from_slice(second);
        assert!(xudp_buffer_has_complete_frame(&reassembled));
    }

    #[test]
    fn truncated_meta_len_only_is_not_ready() {
        assert!(!xudp_buffer_has_complete_frame(&[0x00]));
        assert!(!xudp_buffer_has_complete_frame(&[0x00, 0x0c]));
    }

    /// Regression: treating truncated leftovers as "ready" would spin the
    /// `select!` branch without reading. Simulate the poll decision and require
    /// that incomplete buffers demand a read (CPU progress via I/O wait).
    #[test]
    fn incomplete_buffer_requires_read_not_busy_spin() {
        let frame = sample_frame();
        let cut = frame.len().saturating_sub(3).max(1);
        let incomplete = &frame[..cut];
        assert!(!incomplete.is_empty());
        assert!(!xudp_buffer_has_complete_frame(incomplete));

        let mut reads_needed = 0_u32;
        let mut buffer = incomplete.to_vec();
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut iterations = 0_u32;
        while !xudp_buffer_has_complete_frame(&buffer) {
            iterations += 1;
            assert!(
                iterations < 10_000,
                "decision loop must not busy-spin on truncated XUDP"
            );
            if Instant::now() >= deadline {
                panic!("expected simulated read to complete the frame");
            }
            reads_needed += 1;
            buffer.extend_from_slice(&frame[incomplete.len()..]);
        }
        assert_eq!(reads_needed, 1);
        assert_eq!(iterations, 1);
        assert!(xudp_buffer_has_complete_frame(&buffer));
    }

    /// Old bug pattern: leftover bytes ⇒ immediately "ready" even when truncated.
    #[test]
    fn leftover_incomplete_bytes_are_not_ready() {
        let frame = sample_frame();
        let leftover = &frame[..5];
        assert!(!leftover.is_empty());
        assert!(
            !xudp_buffer_has_complete_frame(leftover),
            "non-empty truncated leftover must still require another record"
        );
    }
}
