//! Shared VLESS response and Vision framing over the canonical TLS record I/O.

use std::io;
use tokio::io::AsyncReadExt;

use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{
            MAX_PLAINTEXT_LEN, RECORD_SLOT_WIRE_CAPACITY, TLS_RECORD_HEADER_LEN,
            TlsApplicationReader, TlsApplicationWriter, application_halves,
        },
    },
    vless::{
        ResponseDecodeError, UserId, VisionCommand, VisionDecoder, VisionEncoder, VisionFramePlan,
        VisionMode, decode_response,
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
    Raw {
        reader: tokio::net::tcp::OwnedReadHalf,
    },
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
            crate::protocol::vless::VISION_FRAME_SIZE,
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
            // Keep idle delivery storage to one full plaintext record.
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
            ReadDirection::Raw { reader } => {
                // Reuse the drained delivery buffer directly. Its retained
                // capacity bounds the read; no scratch allocation or payload
                // copy is needed after the authenticated Direct transition.
                let count = reader
                    .read_buf(&mut self.readable)
                    .await
                    .map_err(VisionTunnelError::Io)?;
                if count == 0 {
                    self.reader = ReadDirection::Closed;
                    return Err(VisionTunnelError::Closed);
                }
                self.activity.progress();
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
        // Match the two-record delivery window used by buffered TLS reads.
        // Reserve once at the authenticated transition, not on each raw read.
        self.readable
            .try_reserve_exact((2 * MAX_PLAINTEXT_LEN).saturating_sub(self.readable.len()))
            .map_err(|_| VisionTunnelError::Io(io::ErrorKind::OutOfMemory.into()))?;
        self.reader = ReadDirection::Raw { reader };
        // Directions transition independently. An authenticated downlink Direct
        // does not authorize removing the uplink's Vision or TLS framing.
        self.activity.enter_raw();
        Ok(())
    }

    pub(super) async fn poll_fill_readable(&mut self) -> Result<(), VisionTunnelError> {
        if self.readable_at < self.readable.len() {
            return Ok(());
        }
        self.read_and_open_record().await?;
        // Flush before a socket refill. Complete buffered records can share
        // one local write, without delaying a sparse flow or growing a batch
        // beyond two maximum plaintext records.
        while self.readable.len() <= MAX_PLAINTEXT_LEN
            && matches!(&self.reader, ReadDirection::Tls(reader) if reader.has_buffered_record())
        {
            match self.read_and_open_record().await {
                Err(VisionTunnelError::Tls(
                    crate::protocol::reality::tls13::TlsApplicationIoError::PeerAlert {
                        description: 0,
                        ..
                    },
                )) => {
                    // Deliver the authenticated prefix before the caller
                    // observes EOF and shuts down its local write direction.
                    self.reader = ReadDirection::Closed;
                    break;
                }
                result => result?,
            }
        }
        Ok(())
    }

    pub(super) fn take_upload_storage(&mut self) -> Vec<u8> {
        self.writer.take_write_storage()
    }

    /// Moves at most two records of local payload into final AEAD slots in the
    /// same retained allocation. Work backwards so headers cannot overwrite
    /// bytes belonging to a later frame. Each body moves exactly once.
    pub(super) async fn write_upload(
        &mut self,
        storage: &mut Vec<u8>,
        length: usize,
    ) -> Result<(), VisionTunnelError> {
        if length == 0
            || length > 4 * (crate::protocol::vless::VISION_FRAME_SIZE - 5)
            || length > storage.len()
        {
            return Err(VisionTunnelError::Vision);
        }
        let first = UploadRecord::plan(&mut self.encoder, length)?;
        let second = if first.payload_len() < length {
            Some(UploadRecord::plan(
                &mut self.encoder,
                length - first.payload_len(),
            )?)
        } else {
            None
        };
        let slots = 1 + usize::from(second.is_some());
        let required = slots * RECORD_SLOT_WIRE_CAPACITY;
        if storage.len() < required {
            storage
                .try_reserve_exact(required - storage.len())
                .map_err(|_| VisionTunnelError::Io(io::ErrorKind::OutOfMemory.into()))?;
            storage.resize(required, 0);
        }
        if let Some(second) = &second {
            second.assemble_in_place(
                &self.encoder,
                storage,
                first.payload_len(),
                RECORD_SLOT_WIRE_CAPACITY + TLS_RECORD_HEADER_LEN,
            );
        }
        first.assemble_in_place(&self.encoder, storage, 0, TLS_RECORD_HEADER_LEN);
        self.writer
            .write_filled_storage(
                storage,
                first.wire_len() + second.as_ref().map_or(0, UploadRecord::wire_len),
                crate::io_activity::WRITE_STALL_TIMEOUT,
            )
            .await
            .map_err(VisionTunnelError::Tls)?;
        first.commit(&mut self.encoder);
        if let Some(second) = second {
            second.commit(&mut self.encoder);
        }
        Ok(())
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
            let first = UploadRecord::plan(&mut self.encoder, payload.len() - offset)?;
            let next = offset + first.payload_len();
            self.writer
                .write_assembled(
                    first.wire_len(),
                    |record| first.assemble(&self.encoder, &payload[offset..next], record),
                    crate::io_activity::WRITE_STALL_TIMEOUT,
                )
                .await
                .map_err(VisionTunnelError::Tls)?;
            first.commit(&mut self.encoder);
            offset = next;
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

// A complete bounded pair of Vision frames occupying at most one TLS record.
// The preamble has already consumed the UUID before upload planning begins.
struct UploadRecord {
    first: VisionFramePlan,
    second: Option<VisionFramePlan>,
    first_len: usize,
    second_len: usize,
}

impl UploadRecord {
    fn plan(encoder: &mut VisionEncoder, remaining: usize) -> Result<Self, VisionTunnelError> {
        let first_len = remaining.min(crate::protocol::vless::VISION_FRAME_SIZE - 5);
        let first = encoder
            .plan(first_len, VisionCommand::Continue, false)
            .map_err(|_| VisionTunnelError::Vision)?;
        let second_len = (remaining - first_len).min(crate::protocol::vless::VISION_FRAME_SIZE - 5);
        let second = if second_len == 0 {
            None
        } else {
            encoder
                .plan_within(
                    second_len,
                    VisionCommand::Continue,
                    false,
                    MAX_PLAINTEXT_LEN - first.wire_len(),
                )
                .map_err(|_| VisionTunnelError::Vision)?
        };
        let second_len = if second.is_some() { second_len } else { 0 };
        Ok(Self {
            first,
            second,
            first_len,
            second_len,
        })
    }

    fn wire_len(&self) -> usize {
        self.first.wire_len() + self.second.as_ref().map_or(0, VisionFramePlan::wire_len)
    }

    fn payload_len(&self) -> usize {
        self.first_len + self.second_len
    }

    fn assemble(&self, encoder: &VisionEncoder, payload: &[u8], record: &mut [u8]) {
        let (first, second) = record.split_at_mut(self.first.wire_len());
        encoder.assemble(&self.first, &payload[..self.first_len], first);
        if let Some(plan) = &self.second {
            encoder.assemble(plan, &payload[self.first_len..], second);
        }
    }

    fn assemble_in_place(
        &self,
        encoder: &VisionEncoder,
        storage: &mut [u8],
        source: usize,
        target: usize,
    ) {
        if let Some(second) = &self.second {
            let start = target + self.first.wire_len();
            storage.copy_within(
                source + self.first_len..source + self.payload_len(),
                start + 5,
            );
            encoder.assemble_layout(second, &mut storage[start..start + second.wire_len()]);
        }
        storage.copy_within(source..source + self.first_len, target + 5);
        encoder.assemble_layout(
            &self.first,
            &mut storage[target..target + self.first.wire_len()],
        );
    }

    fn commit(&self, encoder: &mut VisionEncoder) {
        encoder.commit(&self.first);
        if let Some(second) = &self.second {
            encoder.commit(second);
        }
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
    fuzz_upload_assembly(input);
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

#[cfg(any(test, feature = "fuzzing"))]
fn fuzz_upload_assembly(input: &[u8]) {
    if input.is_empty() {
        return;
    }
    let input = &input[..input.len().min(32748)];
    let mut seed = [0_u8; 44];
    for (a, b) in seed.iter_mut().zip(input.iter().cycle()) {
        *a = *b;
    }
    let mut encoder = VisionEncoder::with_padding_seed(UserId::new([0x11; 16]), &seed);
    let first = encoder.plan(0, VisionCommand::Continue, false).unwrap();
    encoder.commit(&first);
    let first = UploadRecord::plan(&mut encoder, input.len()).unwrap();
    let second = (first.payload_len() < input.len())
        .then(|| UploadRecord::plan(&mut encoder, input.len() - first.payload_len()).unwrap());
    let mut reference = vec![0_u8; 2 * RECORD_SLOT_WIRE_CAPACITY];
    let mut actual = reference.clone();
    actual[..input.len()].copy_from_slice(input);
    if let Some(second) = &second {
        let start = RECORD_SLOT_WIRE_CAPACITY + TLS_RECORD_HEADER_LEN;
        second.assemble(
            &encoder,
            &input[first.payload_len()..],
            &mut reference[start..start + second.wire_len()],
        );
        second.assemble_in_place(&encoder, &mut actual, first.payload_len(), start);
        assert_eq!(
            &actual[start..start + second.wire_len()],
            &reference[start..start + second.wire_len()]
        );
    }
    let start = TLS_RECORD_HEADER_LEN;
    first.assemble(
        &encoder,
        &input[..first.payload_len()],
        &mut reference[start..start + first.wire_len()],
    );
    first.assemble_in_place(&encoder, &mut actual, 0, start);
    assert_eq!(
        &actual[start..start + first.wire_len()],
        &reference[start..start + first.wire_len()]
    );
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

    #[test]
    fn in_place_upload_matches_assembly_at_every_frame_boundary() {
        for length in [
            1, 2, 8186, 8187, 8188, 16373, 16374, 16375, 24560, 24561, 32747, 32748,
        ] {
            for seed in 0..16_u8 {
                let payload: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_add(seed)).collect();
                fuzz_upload_assembly(&payload);
            }
        }
    }

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
    async fn two_full_buffered_plaintext_records_share_one_delivery() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let (_peer, _) = accepted.unwrap();
        let (reader, writer) = client.unwrap().into_split();
        let (mut downlink, read) = record_pair();
        let (write, _) = record_pair();
        let user = UserId::new([0x11; 16]);
        let mut encoder = VisionEncoder::new(user).unwrap();
        let mut decoder = VisionDecoder::new(user);
        let mut frame = Vec::new();
        encoder
            .encode(&[], VisionCommand::End, false, &mut frame)
            .unwrap();
        decoder.decode_append(&frame, &mut Vec::new()).unwrap();
        let payload = vec![0x42; MAX_PLAINTEXT_LEN];
        let mut pending = Vec::new();
        for _ in 0..2 {
            downlink
                .seal_into(ContentType::ApplicationData, &payload, 0, &mut frame)
                .unwrap();
            pending.extend_from_slice(&frame);
        }
        let (reader, writer) = application_halves(
            reader,
            pending,
            writer,
            read,
            write,
            false,
            crate::protocol::vless::VISION_FRAME_SIZE,
        );
        let mut io = VisionIo {
            reader: ReadDirection::Tls(reader),
            writer,
            response: None,
            encoder: VisionEncoder::new(user).unwrap(),
            decoder,
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            activity: Arc::new(crate::io_activity::SessionActivity::default()),
        };
        tokio::time::timeout(Duration::from_secs(1), io.poll_fill_readable())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(io.readable.len(), 2 * MAX_PLAINTEXT_LEN);
        assert!(io.readable.iter().all(|byte| *byte == 0x42));
        assert_eq!(io.readable.capacity(), 2 * MAX_PLAINTEXT_LEN);
    }

    #[tokio::test]
    async fn buffered_downlink_delivers_authenticated_prefix_before_close_notify() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let (_peer, _) = accepted.unwrap();
        let (reader, writer) = client.unwrap().into_split();
        let (mut downlink, read) = record_pair();
        let (write, _) = record_pair();
        let user = UserId::new([0x11; 16]);
        let mut encoder = VisionEncoder::new(user).unwrap();
        let mut pending = Vec::new();
        let mut frame = Vec::new();
        let mut wire = Vec::new();
        for content in [b"first".as_slice(), b"second"] {
            encoder
                .encode(content, VisionCommand::Continue, false, &mut frame)
                .unwrap();
            downlink
                .seal_into(ContentType::ApplicationData, &frame, 0, &mut wire)
                .unwrap();
            pending.extend_from_slice(&wire);
        }
        downlink
            .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
            .unwrap();
        pending.extend_from_slice(&wire);
        let (reader, writer) = application_halves(
            reader,
            pending,
            writer,
            read,
            write,
            false,
            crate::protocol::vless::VISION_FRAME_SIZE,
        );
        let mut io = VisionIo {
            reader: ReadDirection::Tls(reader),
            writer,
            response: None,
            encoder: VisionEncoder::new(user).unwrap(),
            decoder: VisionDecoder::new(user),
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            activity: Arc::new(crate::io_activity::SessionActivity::default()),
        };
        // The peer sends nothing: buffered records must not trigger a refill
        // or allocate another delivery buffer.
        {
            use std::{
                future::Future,
                task::{Context, Poll, Waker},
            };
            let next = io.poll_fill_readable();
            tokio::pin!(next);
            let allocations = allocation_counter::measure(|| {
                assert!(matches!(
                    next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Ok(()))
                ));
            });
            assert_eq!(allocations.count_total, 0);
        }
        assert_eq!(io.readable, b"firstsecond");
        assert!(matches!(io.reader, ReadDirection::Closed));
        io.readable_at = io.readable.len();
        assert!(matches!(
            io.poll_fill_readable().await,
            Err(VisionTunnelError::Closed)
        ));
    }

    #[tokio::test]
    async fn bulk_upload_packs_two_bounded_frames_in_one_authenticated_record() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let (mut peer, _) = accepted.unwrap();
        let (reader, writer) = client.unwrap().into_split();
        let (_, read) = record_pair();
        let (write, mut uplink) = record_pair();
        let (reader, writer) = application_halves(
            reader,
            Vec::new(),
            writer,
            read,
            write,
            false,
            crate::protocol::vless::VISION_FRAME_SIZE,
        );
        let user = UserId::new([0x11; 16]);
        let mut encoder = VisionEncoder::new(user).unwrap();
        let mut decoder = VisionDecoder::new(user);
        let mut preamble = Vec::new();
        encoder
            .encode(&[], VisionCommand::Continue, true, &mut preamble)
            .unwrap();
        decoder.decode_append(&preamble, &mut Vec::new()).unwrap();
        let mut io = VisionIo {
            reader: ReadDirection::Tls(reader),
            writer,
            response: None,
            encoder,
            decoder,
            readable: Vec::new(),
            readable_at: 0,
            activity: Arc::new(crate::io_activity::SessionActivity::default()),
        };
        let mut received = Vec::new();
        // Exercise full one- and two-record reads, a partial second frame,
        // and the next record's sequence number without splitting a frame.
        for length in [16374, 8190, 1, 32748, 32749, 16374] {
            let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            if length <= 32748 {
                let mut storage = io.take_upload_storage();
                storage.resize(length, 0);
                storage[..length].copy_from_slice(&payload);
                io.write_upload(&mut storage, length).await.unwrap();
                assert!(!storage.is_empty());
            } else {
                io.write_application(&payload).await.unwrap();
            }
            received.clear();
            let mut records = 0;
            while received.len() < payload.len() {
                let mut wire = read_tls_record(&mut peer, Duration::from_secs(1))
                    .await
                    .unwrap()
                    .into_wire();
                let opened = uplink.open_in_place(&mut wire).unwrap();
                assert!(opened.plaintext().len() <= MAX_PLAINTEXT_LEN);
                io.decoder
                    .decode_append(opened.plaintext(), &mut received)
                    .unwrap();
                records += 1;
            }
            assert_eq!(records, payload.len().div_ceil(16374));
            assert_eq!(received, payload);
            assert_eq!(io.decoder.mode(), VisionMode::Framed);
        }
    }

    #[tokio::test]
    async fn small_read_window_promotes_for_large_records_without_steady_allocations() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let (mut peer, read) = record_pair();
        let (write, _) = record_pair();
        let payload = vec![0x42; MAX_PLAINTEXT_LEN];
        let mut wire = Vec::new();
        let mut record = Vec::new();
        for _ in 0..2 {
            peer.seal_into(ContentType::ApplicationData, &payload, 0, &mut record)
                .unwrap();
            wire.extend_from_slice(&record);
        }
        let (mut reader, _) = application_halves(
            wire.as_slice(),
            Vec::new(),
            tokio::io::sink(),
            read,
            write,
            false,
            crate::protocol::vless::VISION_FRAME_SIZE,
        );
        assert_eq!(
            reader
                .read_application(Duration::from_secs(1))
                .await
                .unwrap()
                .plaintext(),
            payload
        );
        let next = reader.read_application(Duration::from_secs(1));
        tokio::pin!(next);
        let measured = allocation_counter::measure(|| {
            let Poll::Ready(Ok(record)) =
                next.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("second complete record must already be buffered");
            };
            assert_eq!(record.plaintext(), payload);
        });
        assert_eq!(measured.count_total, 0);
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
        let (reader, writer) = application_halves(
            reader,
            Vec::new(),
            writer,
            read,
            write,
            false,
            crate::protocol::vless::VISION_FRAME_SIZE,
        );
        let user = UserId::new([0x11; 16]);
        let mut io = VisionIo {
            reader: ReadDirection::Tls(reader),
            writer,
            response: None,
            encoder: VisionEncoder::new(user).unwrap(),
            decoder: VisionDecoder::new(user),
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            activity: Arc::new(crate::io_activity::SessionActivity::default()),
        };
        let mut encoder = VisionEncoder::new(user).unwrap();
        let future_bytes = std::mem::size_of_val(&io.read_and_open_record());
        eprintln!("client record-read future bytes: {future_bytes}");
        assert!(
            future_bytes < MAX_PLAINTEXT_LEN,
            "raw scratch must not live in every framed read future"
        );
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
        assert!(matches!(io.reader, ReadDirection::Raw { .. }));
        assert!(
            io.readable.capacity() >= 2 * MAX_PLAINTEXT_LEN,
            "Direct must retain the bounded two-record delivery window"
        );
        let mut received = io.readable.clone();
        io.readable_at = io.readable.len();
        if received.len() < b"boundarypipelined raw bytes".len() {
            io.read_and_open_record().await.unwrap();
            received.extend_from_slice(&io.readable);
            io.readable_at = io.readable.len();
        }
        assert_eq!(received, b"boundarypipelined raw bytes");
        let bulk = vec![0x5a; 2 * MAX_PLAINTEXT_LEN];
        for _ in 0..2 {
            peer.write_all(&bulk).await.unwrap();
            let mut received = Vec::with_capacity(bulk.len());
            while received.len() < bulk.len() {
                let ReadDirection::Raw { reader } = &io.reader else {
                    panic!("Direct must keep its authenticated read owner");
                };
                reader.as_ref().readable().await.unwrap();
                let allocations = {
                    use std::{
                        future::Future,
                        task::{Context, Poll, Waker},
                    };
                    let next = io.read_and_open_record();
                    tokio::pin!(next);
                    allocation_counter::measure(|| {
                        assert!(matches!(
                            next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                            Poll::Ready(Ok(()))
                        ));
                    })
                };
                assert_eq!(allocations.count_total, 0);
                received.extend_from_slice(&io.readable);
                io.readable_at = io.readable.len();
            }
            assert_eq!(received, bulk);
        }
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
