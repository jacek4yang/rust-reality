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

const UPLOAD_FRAME_PAYLOAD: usize = crate::protocol::vless::VISION_FRAME_SIZE - 5;
pub(super) const UPLOAD_RECORD_PAYLOAD: usize = 2 * UPLOAD_FRAME_PAYLOAD;

/// Reads only available bytes into final frame bodies. A pending readiness wait
/// owns no input; after a successful read there is no await before returning it.
pub(super) async fn read_upload(
    local: &tokio::net::TcpStream,
    storage: &mut [u8],
) -> io::Result<usize> {
    let regions_used = 2 * (storage.len() / RECORD_SLOT_WIRE_CAPACITY);
    let mut regions = upload_payload_regions(storage)?;
    std::future::poll_fn(|cx| {
        loop {
            std::task::ready!(local.poll_read_ready(cx))?;
            match local.try_read_vectored(&mut regions[..regions_used]) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return std::task::Poll::Ready(result),
            }
        }
    })
    .await
}

fn upload_payload_regions(storage: &mut [u8]) -> io::Result<[io::IoSliceMut<'_>; 4]> {
    // The committed preamble consumed the UUID. Every full frame has zero
    // padding, so only the final partial frame needs space after its payload.
    if storage.len() != RECORD_SLOT_WIRE_CAPACITY && storage.len() != 2 * RECORD_SLOT_WIRE_CAPACITY
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (first, second) = storage.split_at_mut(RECORD_SLOT_WIRE_CAPACITY);
    let (a, b) =
        first.split_at_mut(TLS_RECORD_HEADER_LEN + crate::protocol::vless::VISION_FRAME_SIZE);
    let mut regions = [
        io::IoSliceMut::new(&mut a[TLS_RECORD_HEADER_LEN + 5..]),
        io::IoSliceMut::new(&mut b[5..5 + UPLOAD_FRAME_PAYLOAD]),
        io::IoSliceMut::new(&mut []),
        io::IoSliceMut::new(&mut []),
    ];
    if !second.is_empty() {
        let (a, b) =
            second.split_at_mut(TLS_RECORD_HEADER_LEN + crate::protocol::vless::VISION_FRAME_SIZE);
        regions[2] = io::IoSliceMut::new(&mut a[TLS_RECORD_HEADER_LEN + 5..]);
        regions[3] = io::IoSliceMut::new(&mut b[5..5 + UPLOAD_FRAME_PAYLOAD]);
    }
    Ok(regions)
}

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

    /// Completes headers and padding around at most two records of payload read
    /// directly into their final AEAD slots. No payload is moved or copied.
    pub(super) async fn write_upload(
        &mut self,
        storage: &mut Vec<u8>,
        length: usize,
    ) -> Result<(), VisionTunnelError> {
        if length == 0
            || length > 2 * UPLOAD_RECORD_PAYLOAD
            || length > (storage.len() / RECORD_SLOT_WIRE_CAPACITY) * UPLOAD_RECORD_PAYLOAD
            || (storage.len() != RECORD_SLOT_WIRE_CAPACITY
                && storage.len() != 2 * RECORD_SLOT_WIRE_CAPACITY)
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
        if let Some(second) = &second {
            second.complete_in_place(
                &self.encoder,
                storage,
                RECORD_SLOT_WIRE_CAPACITY + TLS_RECORD_HEADER_LEN,
            );
        }
        first.complete_in_place(&self.encoder, storage, TLS_RECORD_HEADER_LEN);
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

    fn complete_in_place(&self, encoder: &VisionEncoder, storage: &mut [u8], target: usize) {
        if let Some(second) = &self.second {
            let start = target + self.first.wire_len();
            encoder.assemble_layout(second, &mut storage[start..start + second.wire_len()]);
        }
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
fn stage_upload_payload(storage: &mut [u8], mut payload: &[u8]) {
    for mut region in upload_payload_regions(storage).unwrap() {
        let count = region.len().min(payload.len());
        region[..count].copy_from_slice(&payload[..count]);
        payload = &payload[count..];
    }
    assert!(payload.is_empty());
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
    let mut actual =
        vec![0_u8; input.len().div_ceil(UPLOAD_RECORD_PAYLOAD) * RECORD_SLOT_WIRE_CAPACITY];
    stage_upload_payload(&mut actual, input);
    if let Some(second) = &second {
        let start = RECORD_SLOT_WIRE_CAPACITY + TLS_RECORD_HEADER_LEN;
        second.assemble(
            &encoder,
            &input[first.payload_len()..],
            &mut reference[start..start + second.wire_len()],
        );
        second.complete_in_place(&encoder, &mut actual, start);
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
    first.complete_in_place(&encoder, &mut actual, start);
    assert_eq!(
        &actual[start..start + first.wire_len()],
        &reference[start..start + first.wire_len()]
    );
}

#[cfg(test)]
mod tests;
