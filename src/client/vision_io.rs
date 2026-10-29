//! Shared VLESS response and Vision framing over the canonical TLS record I/O.

use std::io;
use tokio::io::AsyncReadExt;

use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{
            MAX_PLAINTEXT_LEN, TlsApplicationReader, TlsApplicationWriter, application_halves,
        },
    },
    vless::{
        ResponseDecodeError, UserId, VisionCommand, VisionDecoder, VisionEncoder, VisionMode,
        decode_response,
    },
};

/// Vision / VLESS session failure.
#[derive(Debug)]
pub enum VisionTunnelError {
    /// VLESS request could not be encoded.
    Request,
    /// Vision framing failed.
    Vision,
    /// Record protection failed.
    Record,
    /// The authenticated downlink reached its raw transport EOF.
    Closed,
    /// Socket I/O failed.
    Io(io::Error),
    /// Authenticated TLS application transport failed.
    Tls(crate::protocol::reality::tls13::TlsApplicationIoError),
}

impl std::fmt::Display for VisionTunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vision tunnel failed")
    }
}

impl std::error::Error for VisionTunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tls(e) => Some(e),
            _ => None,
        }
    }
}

enum ReadDirection {
    Tls(TlsApplicationReader<tokio::net::tcp::OwnedReadHalf>),
    Raw(tokio::net::tcp::OwnedReadHalf),
    Closed,
}

/// Bidirectional Vision tunnel to a destination through an entry.
pub(super) struct VisionIo {
    reader: ReadDirection,
    writer: TlsApplicationWriter<tokio::net::tcp::OwnedWriteHalf>,
    response: Option<Vec<u8>>,
    encoder: VisionEncoder,
    decoder: VisionDecoder,
    pub(super) readable: Vec<u8>,
    pub(super) readable_at: usize,
    pub(super) activity: std::sync::Arc<crate::io_activity::SessionActivity>,
}

impl VisionIo {
    /// Sends the caller's VLESS request and the initial Vision padding frame.
    pub(super) async fn connect(
        stream: tokio::net::TcpStream,
        session: ClientSession,
        user_id: UserId,
        request: &[u8],
    ) -> Result<Self, VisionTunnelError> {
        let request_len = request.len();
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
            reader: ReadDirection::Tls(reader),
            writer,
            response: Some(Vec::new()),
            encoder,
            decoder: VisionDecoder::new(user_id),
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            activity,
        })
    }

    pub(super) async fn await_response(&mut self) -> Result<(), VisionTunnelError> {
        tokio::time::timeout(crate::io_activity::SESSION_IDLE_WINDOW, async {
            while self.response.is_some() {
                self.read_and_open_record().await?;
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            VisionTunnelError::Tls(crate::protocol::reality::tls13::TlsApplicationIoError::Timeout)
        })?
    }

    pub(super) async fn read_and_open_record(&mut self) -> Result<(), VisionTunnelError> {
        // Only the unconsumed tail survives a refill. One bounded TLS record
        // and the Direct boundary's read-ahead are the largest append units.
        if self.readable_at != 0 {
            self.readable.drain(..self.readable_at);
            self.readable_at = 0;
        }
        if self.readable.len() > MAX_PLAINTEXT_LEN {
            return Err(VisionTunnelError::Request);
        }
        match &mut self.reader {
            ReadDirection::Tls(reader) => {
                let record = reader
                    .read_application(crate::io_activity::SESSION_IDLE_WINDOW)
                    .await
                    .map_err(VisionTunnelError::Tls)?;
                decode_downlink(
                    &mut self.response,
                    &mut self.decoder,
                    &mut self.readable,
                    record.plaintext(),
                )?;
                self.finish_read_transition()?;
            }
            ReadDirection::Raw(reader) => {
                let mut buffer = [0_u8; MAX_PLAINTEXT_LEN];
                let count = reader
                    .read(&mut buffer)
                    .await
                    .map_err(VisionTunnelError::Io)?;
                if count == 0 {
                    self.reader = ReadDirection::Closed;
                    return Err(VisionTunnelError::Closed);
                }
                self.activity.progress();
                self.readable.extend_from_slice(&buffer[..count]);
            }
            ReadDirection::Closed => return Err(VisionTunnelError::Closed),
        }
        Ok(())
    }

    fn finish_read_transition(&mut self) -> Result<(), VisionTunnelError> {
        if self.decoder.mode() != VisionMode::Direct {
            return Ok(());
        }
        let ReadDirection::Tls(reader) = std::mem::replace(&mut self.reader, ReadDirection::Closed)
        else {
            return Err(VisionTunnelError::Vision);
        };
        let (pending, reader) = reader.into_inner_with_pending();
        self.readable.extend_from_slice(&pending);
        self.reader = ReadDirection::Raw(reader);
        // Directions transition independently. An authenticated downlink Direct
        // does not authorize removing the uplink's Vision or TLS framing.
        self.activity.enter_raw();
        Ok(())
    }

    pub(super) async fn poll_fill_readable(&mut self) -> Result<(), VisionTunnelError> {
        if self.readable_at < self.readable.len() {
            return Ok(());
        }
        self.read_and_open_record().await
    }

    pub(super) async fn write_application(
        &mut self,
        payload: &[u8],
    ) -> Result<(), VisionTunnelError> {
        if payload.is_empty() {
            return Ok(());
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

    pub(super) async fn shutdown(&mut self) -> Result<(), VisionTunnelError> {
        self.writer
            .shutdown(crate::io_activity::WRITE_STALL_TIMEOUT)
            .await
            .map_err(VisionTunnelError::Tls)
    }
}

// The VLESS response header is at most version + one-byte addon length + addons.
// Its partial bytes belong to the connection, not to a cancellable read future.
fn decode_downlink(
    response: &mut Option<Vec<u8>>,
    decoder: &mut VisionDecoder,
    readable: &mut Vec<u8>,
    plaintext: &[u8],
) -> Result<(), VisionTunnelError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(VisionTunnelError::Record);
    }
    if let Some(header) = response {
        if header.len() > 257 {
            return Err(VisionTunnelError::Request);
        }
        header.extend_from_slice(plaintext);
        match decode_response(header) {
            Ok(decoded) => {
                decoder
                    .decode_append(decoded.payload(), readable)
                    .map_err(|_| VisionTunnelError::Vision)?;
                *response = None;
            }
            Err(ResponseDecodeError::Incomplete { .. }) if header.len() <= 257 => {}
            Err(_) => return Err(VisionTunnelError::Request),
        }
    } else {
        decoder
            .decode_append(plaintext, readable)
            .map_err(|_| VisionTunnelError::Vision)?;
    }
    Ok(())
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_vision_response(input: &[u8]) {
    let mut response = Some(Vec::new());
    let mut decoder = VisionDecoder::new(UserId::new([0x11; 16]));
    let mut readable = Vec::new();
    let chunk_size = input.first().map_or(1, |byte| usize::from(*byte) + 1);
    for chunk in input.chunks(chunk_size) {
        readable.clear();
        if decode_downlink(&mut response, &mut decoder, &mut readable, chunk).is_err() {
            break;
        }
        assert!(response.as_ref().is_none_or(|header| header.len() <= 257));
        assert!(readable.len() <= MAX_PLAINTEXT_LEN + 257);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::reality::tls13::{
        CipherSuite, ContentType, Tls13KeySchedule, Tls13RecordLayer, read_tls_record,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    fn record_pair() -> (Tls13RecordLayer, Tls13RecordLayer) {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = Tls13KeySchedule::new(
            suite,
            &[0x31; 32],
            &suite.hash().digest(b"client record ownership test"),
        )
        .unwrap();
        let transcript = suite.hash().digest(b"server finished");
        let (write, _) = schedule
            .application_traffic_secrets(&transcript)
            .unwrap()
            .into_parts();
        let (read, _) = schedule
            .application_traffic_secrets(&transcript)
            .unwrap()
            .into_parts();
        (
            Tls13RecordLayer::from_traffic_secret(suite, write).unwrap(),
            Tls13RecordLayer::from_traffic_secret(suite, read).unwrap(),
        )
    }

    #[test]
    fn response_addons_and_vision_prefix_survive_every_fragment_boundary() {
        let user = UserId::new([0x11; 16]);
        let mut encoder = VisionEncoder::new(user).unwrap();
        let mut frame = Vec::new();
        encoder
            .encode(b"payload", VisionCommand::End, false, &mut frame)
            .unwrap();
        let mut wire = vec![0, 255];
        wire.extend_from_slice(&[0x55; 255]);
        wire.extend_from_slice(&frame);
        for split in 0..=wire.len() {
            let mut response = Some(Vec::new());
            let mut decoder = VisionDecoder::new(user);
            let mut output = Vec::new();
            decode_downlink(&mut response, &mut decoder, &mut output, &wire[..split]).unwrap();
            decode_downlink(&mut response, &mut decoder, &mut output, &wire[split..]).unwrap();
            assert!(response.is_none());
            assert_eq!(output, b"payload");
            assert_eq!(decoder.mode(), VisionMode::Raw);
        }
    }

    #[tokio::test]
    async fn cancelled_partial_record_and_direct_read_ahead_preserve_direction_ownership() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connect = TcpStream::connect(listener.local_addr().unwrap());
        let (client, accepted) = tokio::join!(connect, listener.accept());
        let (mut peer, _) = accepted.unwrap();
        let (reader, writer) = client.unwrap().into_split();
        let (mut downlink, read) = record_pair();
        let (write, mut uplink) = record_pair();
        let (reader, writer) = application_halves(reader, Vec::new(), writer, read, write, false);
        let user = UserId::new([0x11; 16]);
        let mut io = VisionIo {
            reader: ReadDirection::Tls(reader),
            writer,
            response: None,
            encoder: VisionEncoder::new(user).unwrap(),
            decoder: VisionDecoder::new(user),
            readable: Vec::new(),
            readable_at: 0,
            activity: Arc::new(crate::io_activity::SessionActivity::default()),
        };
        let mut encoder = VisionEncoder::new(user).unwrap();
        let mut plaintext = Vec::new();
        encoder
            .encode(b"boundary", VisionCommand::Direct, false, &mut plaintext)
            .unwrap();
        let mut wire = Vec::new();
        downlink
            .seal_into(ContentType::ApplicationData, &plaintext, 0, &mut wire)
            .unwrap();
        peer.write_all(&wire[..7]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), io.read_and_open_record())
                .await
                .is_err()
        );
        wire.extend_from_slice(b"pipelined raw bytes");
        peer.write_all(&wire[7..]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), io.read_and_open_record())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(io.reader, ReadDirection::Raw(_)));
        let mut received = io.readable.clone();
        io.readable_at = io.readable.len();
        if received.len() < b"boundarypipelined raw bytes".len() {
            io.read_and_open_record().await.unwrap();
            received.extend_from_slice(&io.readable);
            io.readable_at = io.readable.len();
        }
        assert_eq!(received, b"boundarypipelined raw bytes");
        io.write_application(b"uplink remains framed")
            .await
            .unwrap();
        let mut wire = read_tls_record(&mut peer, Duration::from_secs(1))
            .await
            .unwrap()
            .into_wire();
        let opened = uplink.open_in_place(&mut wire).unwrap();
        let mut decoded = Vec::new();
        assert_eq!(
            VisionDecoder::new(user)
                .decode_append(opened.plaintext(), &mut decoded)
                .unwrap(),
            VisionMode::Framed
        );
        assert_eq!(decoded, b"uplink remains framed");
        peer.shutdown().await.unwrap();
        assert!(matches!(
            io.read_and_open_record().await,
            Err(VisionTunnelError::Closed)
        ));
    }
}
