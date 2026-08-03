use std::{error::Error, fmt, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{self, Instant},
};

use crate::{
    config::{DirectBarrierConfig, ResourceGovernorConfig},
    protocol::{
        reality::tls13::{
            MAX_PLAINTEXT_LEN, TlsApplicationIoError, TlsApplicationReader, TlsApplicationWriter,
        },
        vless::{
            DecodeError, Destination, RequestHeader, RequestValidationError, UserId, UserRegistry,
            VISION_FRAME_SIZE, VisionCommand, VisionDecodeError, VisionDecoder, VisionEncodeError,
            VisionEncoder, VisionMode, decode_request, encode_response_header,
        },
    },
    runtime::{AdmissionDenied, DirectBarrier},
};

use super::{
    connector::{DestinationConnectError, DestinationConnector},
    reality::RealityEstablished,
};

const MAX_REQUEST_HEADER_SIZE: usize = 533;
const MAX_REQUEST_BUFFER_SIZE: usize = MAX_REQUEST_HEADER_SIZE + MAX_PLAINTEXT_LEN;
const VISION_HEADER_SIZE: usize = 5;
const MAX_VISION_CONTENT_AFTER_FIRST_FRAME: usize = VISION_FRAME_SIZE - VISION_HEADER_SIZE;
const NESTED_TLS_HEADER_SIZE: usize = 5;
const MAX_NESTED_TLS_RECORD_SIZE: usize = (1 << 14) + 2_048;
const MAX_NESTED_SERVER_HELLO_SIZE: usize = 8 * 1024;
const MAX_CLASSIFICATION_RECORDS: u8 = 8;
const TLS_HANDSHAKE: u8 = 22;
const TLS_APPLICATION_DATA: u8 = 23;
const TLS_SERVER_HELLO: u8 = 2;
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// Counts and direct-transition results from one Vision relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VisionRelayStats {
    uplink_bytes: u64,
    downlink_bytes: u64,
    uplink_direct: bool,
    downlink_direct: bool,
}

impl VisionRelayStats {
    /// Returns unpadded client bytes delivered to the destination.
    #[must_use]
    pub const fn uplink_bytes(self) -> u64 {
        self.uplink_bytes
    }

    /// Returns destination bytes delivered to the client.
    #[must_use]
    pub const fn downlink_bytes(self) -> u64 {
        self.downlink_bytes
    }

    /// Returns whether the client authenticated a Vision Direct command.
    #[must_use]
    pub const fn uplink_direct(self) -> bool {
        self.uplink_direct
    }

    /// Returns whether the server completed a Vision Direct write boundary.
    #[must_use]
    pub const fn downlink_direct(self) -> bool {
        self.downlink_direct
    }
}

/// Direct-only Vision runtime used before routing outbounds are connected.
#[derive(Clone)]
pub struct DirectVisionHandler {
    connector: DestinationConnector,
    direct_barrier: DirectBarrier,
    request_timeout: Duration,
    io_timeout: Duration,
}

impl DirectVisionHandler {
    /// Compiles bounded direct-session state shared by all accepted connections.
    #[must_use]
    pub fn new(governor: &ResourceGovernorConfig, direct_barrier: &DirectBarrierConfig) -> Self {
        Self {
            connector: DestinationConnector::new(Duration::from_millis(
                governor.connect_timeout_ms,
            )),
            direct_barrier: DirectBarrier::new(direct_barrier),
            request_timeout: Duration::from_millis(governor.handshake_timeout_ms),
            io_timeout: Duration::from_millis(governor.fallback_timeout_ms),
        }
    }

    /// Reads, authorizes, connects, and relays one established REALITY session.
    ///
    /// The direct outbound permit is retained for the entire session. Vision
    /// Direct unwraps outer TLS only after the authenticated command record has
    /// completed, and destination TLS is switched only on an exact record boundary.
    ///
    /// # Errors
    ///
    /// Returns bounded request, admission, destination, framing, TLS, or socket errors.
    pub async fn handle(
        &self,
        established: RealityEstablished,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let (application, users, _) = established.into_parts();
        let (mut client_reader, client_writer) = application.into_split();
        let request = read_vision_request(&mut client_reader, &users, self.request_timeout).await?;
        let direct_permit = self
            .direct_barrier
            .try_acquire()
            .map_err(VisionSessionError::Admission)?;
        let destination = self
            .connector
            .connect(&request.destination)
            .await
            .map_err(VisionSessionError::Connect)?;
        let (destination_reader, destination_writer) = tokio::io::split(destination);
        let user_id = request.user_id;
        let response_header = encode_response_header(&request.header, &[])
            .map_err(VisionSessionError::ResponseHeader)?;

        let uplink = relay_uplink(
            client_reader,
            destination_writer,
            user_id,
            request.prefetched,
            self.io_timeout,
        );
        let downlink = relay_downlink(
            destination_reader,
            client_writer,
            user_id,
            &response_header,
            self.io_timeout,
        );
        let (uplink, downlink) = tokio::try_join!(uplink, downlink)?;
        drop(direct_permit);

        Ok(VisionRelayStats {
            uplink_bytes: uplink.bytes,
            downlink_bytes: downlink.bytes,
            uplink_direct: uplink.direct,
            downlink_direct: downlink.direct,
        })
    }
}

struct AcceptedVisionRequest {
    header: RequestHeader,
    user_id: UserId,
    destination: Destination,
    prefetched: Vec<u8>,
}

async fn read_vision_request<R>(
    reader: &mut TlsApplicationReader<R>,
    users: &UserRegistry,
    timeout: Duration,
) -> Result<AcceptedVisionRequest, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let deadline = operation_deadline(timeout)?;
    let mut buffer = Vec::with_capacity(MAX_REQUEST_BUFFER_SIZE);

    loop {
        match decode_request(&buffer) {
            Ok(decoded) => {
                let (header, payload) = decoded.into_parts();
                let destination = users
                    .authorize_vision_tcp(&header)
                    .map_err(VisionSessionError::Validate)?
                    .clone();
                return Ok(AcceptedVisionRequest {
                    user_id: header.user_id(),
                    header,
                    destination,
                    prefetched: payload.to_vec(),
                });
            }
            Err(DecodeError::UnexpectedEnd { .. }) if buffer.len() < MAX_REQUEST_HEADER_SIZE => {}
            Err(DecodeError::UnexpectedEnd { .. }) => {
                return Err(VisionSessionError::RequestTooLarge {
                    limit: MAX_REQUEST_HEADER_SIZE,
                });
            }
            Err(error) => return Err(VisionSessionError::Decode(error)),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VisionSessionError::Timeout);
        }
        let record = reader
            .read_application(remaining)
            .await
            .map_err(VisionSessionError::Tls)?;
        let next_length =
            buffer
                .len()
                .checked_add(record.len())
                .ok_or(VisionSessionError::RequestTooLarge {
                    limit: MAX_REQUEST_BUFFER_SIZE,
                })?;
        if next_length > MAX_REQUEST_BUFFER_SIZE {
            return Err(VisionSessionError::RequestTooLarge {
                limit: MAX_REQUEST_BUFFER_SIZE,
            });
        }
        buffer
            .try_reserve(record.len())
            .map_err(|_| VisionSessionError::AllocationFailed)?;
        buffer.extend_from_slice(record.plaintext());
    }
}

struct DirectionStats {
    bytes: u64,
    direct: bool,
}

async fn relay_uplink<R, W>(
    mut client: TlsApplicationReader<R>,
    mut destination: W,
    user_id: UserId,
    prefetched: Vec<u8>,
    timeout: Duration,
) -> Result<DirectionStats, VisionSessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = VisionDecoder::new(user_id);
    let mut plaintext = Vec::with_capacity(VISION_FRAME_SIZE);
    let mut bytes = 0_u64;
    let mut pending = Some(prefetched);

    loop {
        let input = if let Some(initial) = pending.take() {
            initial
        } else {
            match client.read_application(timeout).await {
                Ok(record) => record.plaintext().to_vec(),
                Err(TlsApplicationIoError::PeerAlert {
                    level: _,
                    description: 0,
                }) => {
                    shutdown_before(&mut destination, timeout).await?;
                    return Ok(DirectionStats {
                        bytes,
                        direct: false,
                    });
                }
                Err(error) => return Err(VisionSessionError::Tls(error)),
            }
        };
        if input.is_empty() {
            continue;
        }

        let mode = decoder
            .decode(&input, &mut plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        if !plaintext.is_empty() {
            write_all_before(&mut destination, &plaintext, timeout).await?;
            bytes = bytes.saturating_add(length_u64(plaintext.len()));
        }
        if mode == VisionMode::Direct {
            let mut raw_client = client.into_inner();
            let copied = copy_before(&mut raw_client, &mut destination, timeout).await?;
            shutdown_before(&mut destination, timeout).await?;
            return Ok(DirectionStats {
                bytes: bytes.saturating_add(copied),
                direct: true,
            });
        }
    }
}

async fn relay_downlink<R, W>(
    mut destination: R,
    mut client: TlsApplicationWriter<W>,
    user_id: UserId,
    response_header: &[u8],
    timeout: Duration,
) -> Result<DirectionStats, VisionSessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut encoder = VisionEncoder::new(user_id);
    let mut frame = Vec::with_capacity(VISION_FRAME_SIZE);
    encoder
        .encode(&[], VisionCommand::Continue, true, &mut frame)
        .map_err(VisionSessionError::VisionEncode)?;
    let mut response = Vec::new();
    response
        .try_reserve(response_header.len() + frame.len())
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    response.extend_from_slice(response_header);
    response.extend_from_slice(&frame);
    client
        .write_application(&response, timeout)
        .await
        .map_err(VisionSessionError::Tls)?;

    let mut detector = NestedTlsDetector::new();
    let mut bytes = 0_u64;
    loop {
        match read_nested_record(&mut destination, timeout).await? {
            NestedRead::Eof => {
                client
                    .shutdown(timeout)
                    .await
                    .map_err(VisionSessionError::Tls)?;
                return Ok(DirectionStats {
                    bytes,
                    direct: false,
                });
            }
            NestedRead::Unframed(prefix) => {
                bytes = bytes.saturating_add(length_u64(prefix.len()));
                write_vision_content(
                    &mut client,
                    &mut encoder,
                    &prefix,
                    VisionCommand::End,
                    false,
                    timeout,
                )
                .await?;
                bytes = bytes.saturating_add(
                    relay_outer_downlink(&mut destination, &mut client, timeout).await?,
                );
                return Ok(DirectionStats {
                    bytes,
                    direct: false,
                });
            }
            NestedRead::Record(record) => {
                bytes = bytes.saturating_add(length_u64(record.len()));
                let decision = detector.observe(&record);
                let command = match decision {
                    PaddingDecision::Continue => VisionCommand::Continue,
                    PaddingDecision::End => VisionCommand::End,
                    PaddingDecision::Direct => VisionCommand::Direct,
                };
                write_vision_content(&mut client, &mut encoder, &record, command, true, timeout)
                    .await?;

                match decision {
                    PaddingDecision::Continue => {}
                    PaddingDecision::End => {
                        bytes = bytes.saturating_add(
                            relay_outer_downlink(&mut destination, &mut client, timeout).await?,
                        );
                        return Ok(DirectionStats {
                            bytes,
                            direct: false,
                        });
                    }
                    PaddingDecision::Direct => {
                        let mut raw_client = client.into_inner();
                        let copied =
                            copy_before(&mut destination, &mut raw_client, timeout).await?;
                        shutdown_before(&mut raw_client, timeout).await?;
                        return Ok(DirectionStats {
                            bytes: bytes.saturating_add(copied),
                            direct: true,
                        });
                    }
                }
            }
        }
    }
}

async fn write_vision_content<W>(
    writer: &mut TlsApplicationWriter<W>,
    encoder: &mut VisionEncoder,
    content: &[u8],
    final_command: VisionCommand,
    long_padding: bool,
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    if content.is_empty() {
        let mut frame = Vec::with_capacity(VISION_FRAME_SIZE);
        encoder
            .encode(&[], final_command, long_padding, &mut frame)
            .map_err(VisionSessionError::VisionEncode)?;
        writer
            .write_application(&frame, timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        return Ok(());
    }

    let chunk_count = content.len().div_ceil(MAX_VISION_CONTENT_AFTER_FIRST_FRAME);
    let mut frame = Vec::with_capacity(VISION_FRAME_SIZE);
    for (index, chunk) in content
        .chunks(MAX_VISION_CONTENT_AFTER_FIRST_FRAME)
        .enumerate()
    {
        let command = if index + 1 == chunk_count {
            final_command
        } else {
            VisionCommand::Continue
        };
        encoder
            .encode(chunk, command, long_padding, &mut frame)
            .map_err(VisionSessionError::VisionEncode)?;
        writer
            .write_application(&frame, timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
    }
    Ok(())
}

async fn relay_outer_downlink<R, W>(
    reader: &mut R,
    writer: &mut TlsApplicationWriter<W>,
    timeout: Duration,
) -> Result<u64, VisionSessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; MAX_PLAINTEXT_LEN];
    let mut copied = 0_u64;
    loop {
        let read = read_before(reader, &mut buffer, timeout).await?;
        if read == 0 {
            writer
                .shutdown(timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(copied);
        }
        writer
            .write_application(&buffer[..read], timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        copied = copied.saturating_add(length_u64(read));
    }
}

enum NestedRead {
    Eof,
    Record(Vec<u8>),
    Unframed(Vec<u8>),
}

async fn read_nested_record<R>(
    reader: &mut R,
    timeout: Duration,
) -> Result<NestedRead, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let deadline = operation_deadline(timeout)?;
    let mut header = [0_u8; NESTED_TLS_HEADER_SIZE];
    let header_read = read_exact_or_eof(reader, &mut header, deadline).await?;
    if header_read == 0 {
        return Ok(NestedRead::Eof);
    }
    if header_read < header.len() || !looks_like_tls_record_header(&header) {
        return Ok(NestedRead::Unframed(header[..header_read].to_vec()));
    }
    let body_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body_length > MAX_NESTED_TLS_RECORD_SIZE {
        return Ok(NestedRead::Unframed(header.to_vec()));
    }

    let record_length = NESTED_TLS_HEADER_SIZE + body_length;
    let mut record = Vec::new();
    record
        .try_reserve_exact(record_length)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    record.extend_from_slice(&header);
    record.resize(record_length, 0);
    read_exact_or_eof(reader, &mut record[NESTED_TLS_HEADER_SIZE..], deadline)
        .await
        .and_then(|read| {
            if read == body_length {
                Ok(())
            } else {
                Err(VisionSessionError::DestinationTruncatedTlsRecord)
            }
        })?;
    Ok(NestedRead::Record(record))
}

const fn looks_like_tls_record_header(header: &[u8; NESTED_TLS_HEADER_SIZE]) -> bool {
    matches!(header[0], 20..=23) && header[1] == 0x03 && header[2] <= 0x04
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaddingDecision {
    Continue,
    End,
    Direct,
}

#[derive(Debug)]
struct NestedTlsDetector {
    records_seen: u8,
    server_hello: Vec<u8>,
    server_hello_length: Option<usize>,
    tls13: Option<bool>,
}

impl NestedTlsDetector {
    const fn new() -> Self {
        Self {
            records_seen: 0,
            server_hello: Vec::new(),
            server_hello_length: None,
            tls13: None,
        }
    }

    fn observe(&mut self, record: &[u8]) -> PaddingDecision {
        self.records_seen = self.records_seen.saturating_add(1);
        let content_type = record.first().copied();
        let body = record.get(NESTED_TLS_HEADER_SIZE..).unwrap_or_default();

        if self.tls13.is_none() && content_type == Some(TLS_HANDSHAKE) {
            self.observe_server_hello(body);
        }
        match self.tls13 {
            Some(true) if content_type == Some(TLS_APPLICATION_DATA) => PaddingDecision::Direct,
            Some(false) => PaddingDecision::End,
            None if self.records_seen >= MAX_CLASSIFICATION_RECORDS => PaddingDecision::End,
            _ => PaddingDecision::Continue,
        }
    }

    fn observe_server_hello(&mut self, body: &[u8]) {
        if self.server_hello_length.is_none() {
            if self.server_hello.is_empty() && body.first() != Some(&TLS_SERVER_HELLO) {
                return;
            }
            let header_remaining = 4_usize.saturating_sub(self.server_hello.len());
            let header_bytes = header_remaining.min(body.len());
            if self.server_hello.try_reserve(header_bytes).is_err() {
                self.tls13 = Some(false);
                return;
            }
            self.server_hello.extend_from_slice(&body[..header_bytes]);
            if self.server_hello.len() < 4 {
                return;
            }
            let length = (usize::from(self.server_hello[1]) << 16)
                | (usize::from(self.server_hello[2]) << 8)
                | usize::from(self.server_hello[3]);
            let Some(total) = length.checked_add(4) else {
                self.tls13 = Some(false);
                return;
            };
            if total > MAX_NESTED_SERVER_HELLO_SIZE {
                self.tls13 = Some(false);
                return;
            }
            self.server_hello_length = Some(total);
            self.extend_server_hello(&body[header_bytes..], total);
        } else if let Some(expected) = self.server_hello_length {
            self.extend_server_hello(body, expected);
        }

        let Some(expected) = self.server_hello_length else {
            return;
        };
        if self.server_hello.len() == expected {
            self.tls13 = Some(is_tls13_server_hello(&self.server_hello));
        }
    }

    fn extend_server_hello(&mut self, body: &[u8], expected: usize) {
        let remaining = expected.saturating_sub(self.server_hello.len());
        let count = remaining.min(body.len());
        if self.server_hello.try_reserve(count).is_err() {
            self.tls13 = Some(false);
            return;
        }
        self.server_hello.extend_from_slice(&body[..count]);
    }
}

fn is_tls13_server_hello(message: &[u8]) -> bool {
    let Some(body) = message.get(4..) else {
        return false;
    };
    let Some(session_id_length) = body.get(34).copied().map(usize::from) else {
        return false;
    };
    let Some(cipher_offset) = 35_usize.checked_add(session_id_length) else {
        return false;
    };
    let Some(cipher_bytes) = body.get(cipher_offset..cipher_offset + 2) else {
        return false;
    };
    let cipher_suite = u16::from_be_bytes([cipher_bytes[0], cipher_bytes[1]]);
    if cipher_suite == TLS_AES_128_CCM_8_SHA256 {
        return false;
    }
    let Some(extensions_length_offset) = cipher_offset.checked_add(3) else {
        return false;
    };
    let Some(length_bytes) = body.get(extensions_length_offset..extensions_length_offset + 2)
    else {
        return false;
    };
    let extensions_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    let extensions_start = extensions_length_offset + 2;
    let Some(extensions_end) = extensions_start.checked_add(extensions_length) else {
        return false;
    };
    let Some(extensions) = body.get(extensions_start..extensions_end) else {
        return false;
    };

    let mut cursor = 0;
    while cursor + 4 <= extensions.len() {
        let extension_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            extensions[cursor + 2],
            extensions[cursor + 3],
        ]));
        cursor += 4;
        let Some(end) = cursor.checked_add(extension_length) else {
            return false;
        };
        let Some(value) = extensions.get(cursor..end) else {
            return false;
        };
        if extension_type == 43 {
            return value == TLS13_VERSION;
        }
        cursor = end;
    }
    false
}

/// A Vision data session failed after REALITY authentication.
#[derive(Debug)]
pub enum VisionSessionError {
    Timeout,
    AllocationFailed,
    RequestTooLarge { limit: usize },
    Decode(DecodeError),
    Validate(RequestValidationError),
    Admission(AdmissionDenied),
    Connect(DestinationConnectError),
    ResponseHeader(crate::protocol::vless::ResponseEncodeError),
    Tls(TlsApplicationIoError),
    VisionDecode(VisionDecodeError),
    VisionEncode(VisionEncodeError),
    DestinationTruncatedTlsRecord,
    Io(io::Error),
}

impl fmt::Display for VisionSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Vision session operation timed out"),
            Self::AllocationFailed => formatter.write_str("bounded Vision allocation failed"),
            Self::RequestTooLarge { limit } => {
                write!(formatter, "VLESS request exceeds {limit}-byte bound")
            }
            Self::Decode(source) => source.fmt(formatter),
            Self::Validate(source) => source.fmt(formatter),
            Self::Admission(source) => source.fmt(formatter),
            Self::Connect(source) => source.fmt(formatter),
            Self::ResponseHeader(source) => source.fmt(formatter),
            Self::Tls(source) => source.fmt(formatter),
            Self::VisionDecode(source) => source.fmt(formatter),
            Self::VisionEncode(source) => source.fmt(formatter),
            Self::DestinationTruncatedTlsRecord => {
                formatter.write_str("destination closed inside a TLS record")
            }
            Self::Io(_) => formatter.write_str("Vision relay socket I/O failed"),
        }
    }
}

impl Error for VisionSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            Self::Validate(source) => Some(source),
            Self::Admission(source) => Some(source),
            Self::Connect(source) => Some(source),
            Self::ResponseHeader(source) => Some(source),
            Self::Tls(source) => Some(source),
            Self::VisionDecode(source) => Some(source),
            Self::VisionEncode(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::Timeout
            | Self::AllocationFailed
            | Self::RequestTooLarge { .. }
            | Self::DestinationTruncatedTlsRecord => None,
        }
    }
}

fn operation_deadline(timeout: Duration) -> Result<Instant, VisionSessionError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(VisionSessionError::Timeout)
}

async fn read_exact_or_eof<R>(
    reader: &mut R,
    output: &mut [u8],
    deadline: Instant,
) -> Result<usize, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let mut read = 0;
    while read < output.len() {
        let count = time::timeout_at(deadline, reader.read(&mut output[read..]))
            .await
            .map_err(|_| VisionSessionError::Timeout)?
            .map_err(VisionSessionError::Io)?;
        if count == 0 {
            break;
        }
        read += count;
    }
    Ok(read)
}

async fn read_before<R>(
    reader: &mut R,
    output: &mut [u8],
    timeout: Duration,
) -> Result<usize, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    time::timeout(timeout, reader.read(output))
        .await
        .map_err(|_| VisionSessionError::Timeout)?
        .map_err(VisionSessionError::Io)
}

async fn write_all_before<W>(
    writer: &mut W,
    input: &[u8],
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, writer.write_all(input))
        .await
        .map_err(|_| VisionSessionError::Timeout)?
        .map_err(VisionSessionError::Io)
}

async fn shutdown_before<W>(writer: &mut W, timeout: Duration) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, writer.shutdown())
        .await
        .map_err(|_| VisionSessionError::Timeout)?
        .map_err(VisionSessionError::Io)
}

async fn copy_before<R, W>(
    reader: &mut R,
    writer: &mut W,
    timeout: Duration,
) -> Result<u64, VisionSessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; MAX_PLAINTEXT_LEN];
    let mut copied = 0_u64;
    loop {
        let read = read_before(reader, &mut buffer, timeout).await?;
        if read == 0 {
            return Ok(copied);
        }
        write_all_before(writer, &buffer[..read], timeout).await?;
        copied = copied.saturating_add(length_u64(read));
    }
}

fn length_u64(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::{
        DirectVisionHandler, NestedTlsDetector, PaddingDecision, is_tls13_server_hello, length_u64,
    };
    use crate::{
        config::{DirectBarrierConfig, ResourceGovernorConfig},
        protocol::{
            reality::tls13::{
                CipherSuite, ContentType, EstablishedTls, Tls13KeySchedule, Tls13RecordLayer,
                TlsApplicationIo, read_tls_record,
            },
            vless::{
                Command, UserId, UserRegistry, VERSION, VISION_FLOW, VisionCommand, VisionDecoder,
                VisionEncoder, VisionMode,
            },
        },
        server::reality::RealityEstablished,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);
    const USER: UserId = UserId::new([0x33; 16]);

    #[tokio::test(flavor = "current_thread")]
    async fn relays_non_tls_vision_session_inside_reality_records() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
        };
        let handler = DirectVisionHandler::new(
            &governor,
            &DirectBarrierConfig {
                max_concurrent: 8,
                max_per_second: 8,
            },
        );
        let request = vision_request(destination_address.port(), b"ping");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                let mut close_record = Vec::new();
                client_write_records
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                    .map_err(io::Error::other)?;
                client.write_all(&close_record).await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut response = Vec::new();
                let mut response_header = true;
                loop {
                    let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut record)
                        .map_err(io::Error::other)?;
                    match opened.content_type() {
                        ContentType::ApplicationData => {
                            let plaintext = opened.plaintext();
                            let vision = if response_header {
                                response_header = false;
                                if plaintext.get(..2) != Some([VERSION, 0].as_slice()) {
                                    return Err(io::Error::other("invalid VLESS response header"));
                                }
                                &plaintext[2..]
                            } else {
                                plaintext
                            };
                            let _ = decoder
                                .decode(vision, &mut decoded)
                                .map_err(io::Error::other)?;
                            response.extend_from_slice(&decoded);
                        }
                        ContentType::Alert if opened.plaintext() == [1, 0] => break,
                        _ => return Err(io::Error::other("unexpected outer TLS content")),
                    }
                }
                Ok::<_, io::Error>((response, decoder.mode()))
            };
            let destination_io = async {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(b"pong").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("Vision exchange must not time out");
        let stats = stats.expect("Vision handler must succeed");
        let (response, mode) = client_result.expect("client I/O must succeed");

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"ping"
        );
        assert_eq!(response, b"pong");
        assert_eq!(mode, VisionMode::Raw);
        assert_eq!(stats.uplink_bytes(), 4);
        assert_eq!(stats.downlink_bytes(), 4);
        assert!(!stats.uplink_direct());
        assert!(!stats.downlink_direct());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn switches_both_directions_only_after_authenticated_direct_boundaries() {
        let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination must bind");
        let destination_address = destination_listener
            .local_addr()
            .expect("destination address must exist");
        let (mut client, server) = tcp_pair().await;
        let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
        let established = RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            UserRegistry::new([USER]),
        );
        let governor = ResourceGovernorConfig {
            connect_timeout_ms: 1_000,
            handshake_timeout_ms: 1_000,
            fallback_timeout_ms: 1_000,
            ..ResourceGovernorConfig::default()
        };
        let handler = DirectVisionHandler::new(
            &governor,
            &DirectBarrierConfig {
                max_concurrent: 8,
                max_per_second: 8,
            },
        );
        let request = vision_request_with_command(
            destination_address.port(),
            b"up-framed",
            VisionCommand::Direct,
        );
        let nested_server_hello = record(22, &server_hello(0x1301, true));
        let nested_application = record(23, b"encrypted-handshake");

        let exchange = async {
            let handle = handler.handle(established);
            let client_io = async {
                let mut request_record = Vec::new();
                client_write_records
                    .seal_into(
                        ContentType::ApplicationData,
                        &request,
                        0,
                        &mut request_record,
                    )
                    .map_err(io::Error::other)?;
                client.write_all(&request_record).await?;
                client.write_all(b"up-raw").await?;
                client.shutdown().await?;

                let mut decoder = VisionDecoder::new(USER);
                let mut decoded = Vec::new();
                let mut framed_response = Vec::new();
                let mut response_header = true;
                while decoder.mode() != VisionMode::Direct {
                    let mut outer_record = read_tls_record(&mut client, TEST_TIMEOUT)
                        .await
                        .map_err(io::Error::other)?
                        .into_wire();
                    let opened = client_read_records
                        .open_in_place(&mut outer_record)
                        .map_err(io::Error::other)?;
                    if opened.content_type() != ContentType::ApplicationData {
                        return Err(io::Error::other("expected outer application record"));
                    }
                    let plaintext = opened.plaintext();
                    let vision = if response_header {
                        response_header = false;
                        if plaintext.get(..2) != Some([VERSION, 0].as_slice()) {
                            return Err(io::Error::other("invalid VLESS response header"));
                        }
                        &plaintext[2..]
                    } else {
                        plaintext
                    };
                    let _ = decoder
                        .decode(vision, &mut decoded)
                        .map_err(io::Error::other)?;
                    framed_response.extend_from_slice(&decoded);
                }
                let mut raw_response = Vec::new();
                client.read_to_end(&mut raw_response).await?;
                Ok::<_, io::Error>((framed_response, raw_response))
            };
            let server_hello = nested_server_hello.clone();
            let application = nested_application.clone();
            let destination_io = async move {
                let (mut destination, _) = destination_listener.accept().await?;
                let mut request = Vec::new();
                destination.read_to_end(&mut request).await?;
                destination.write_all(&server_hello).await?;
                destination.write_all(&application).await?;
                destination.write_all(b"down-raw").await?;
                destination.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(handle, client_io, destination_io)
        };
        let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
            .await
            .expect("direct Vision exchange must not time out");
        let stats = stats.expect("direct Vision handler must succeed");
        let (framed_response, raw_response) = client_result.expect("client I/O must succeed");
        let mut expected_framed = nested_server_hello;
        expected_framed.extend_from_slice(&nested_application);

        assert_eq!(
            destination_result.expect("destination I/O must succeed"),
            b"up-framedup-raw"
        );
        assert_eq!(framed_response, expected_framed);
        assert_eq!(raw_response, b"down-raw");
        assert_eq!(
            stats.uplink_bytes(),
            length_u64(b"up-framed".len() + b"up-raw".len())
        );
        assert_eq!(
            stats.downlink_bytes(),
            length_u64(expected_framed.len() + b"down-raw".len())
        );
        assert!(stats.uplink_direct());
        assert!(stats.downlink_direct());
    }

    #[test]
    fn recognizes_tls13_server_hello_then_direct_application_record() {
        let server_hello = server_hello(0x1301, true);
        assert!(is_tls13_server_hello(&server_hello));
        let mut detector = NestedTlsDetector::new();
        let handshake_record = record(22, &server_hello);
        let application_record = record(23, b"encrypted handshake");

        assert_eq!(
            detector.observe(&handshake_record),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&application_record),
            PaddingDecision::Direct
        );
    }

    #[test]
    fn rejects_ccm8_and_tls12_for_direct_transition() {
        let mut ccm8 = NestedTlsDetector::new();
        assert_eq!(
            ccm8.observe(&record(22, &server_hello(0x1305, true))),
            PaddingDecision::End
        );
        let mut tls12 = NestedTlsDetector::new();
        assert_eq!(
            tls12.observe(&record(22, &server_hello(0x1301, false))),
            PaddingDecision::End
        );
    }

    #[test]
    fn assembles_fragmented_server_hello_across_records() {
        let hello = server_hello(0x1301, true);
        let split = 30;
        let mut detector = NestedTlsDetector::new();

        assert_eq!(
            detector.observe(&record(22, &hello[..split])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(22, &hello[split..])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(23, b"ciphertext")),
            PaddingDecision::Direct
        );
    }

    #[test]
    fn assembles_fragmented_handshake_header_across_records() {
        let hello = server_hello(0x1301, true);
        let mut detector = NestedTlsDetector::new();

        assert_eq!(
            detector.observe(&record(22, &hello[..2])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(22, &hello[2..])),
            PaddingDecision::Continue
        );
        assert_eq!(
            detector.observe(&record(23, b"ciphertext")),
            PaddingDecision::Direct
        );
    }

    fn server_hello(cipher_suite: u16, tls13: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        if tls13 {
            body.extend_from_slice(&[0, 6, 0, 43, 0, 2, 0x03, 0x04]);
        } else {
            body.extend_from_slice(&[0, 0]);
        }
        let mut message = vec![2, 0, 0, u8::try_from(body.len()).unwrap_or(u8::MAX)];
        message.extend_from_slice(&body);
        message
    }

    fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut record = vec![content_type, 0x03, 0x03];
        record.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        record.extend_from_slice(body);
        record
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("outer listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("address must exist"))
            .await
            .expect("outer client must connect");
        let (server, _) = listener.accept().await.expect("outer server must accept");
        (client, server)
    }

    fn vision_request(destination_port: u16, payload: &[u8]) -> Vec<u8> {
        vision_request_with_command(destination_port, payload, VisionCommand::End)
    }

    fn vision_request_with_command(
        destination_port: u16,
        payload: &[u8],
        command: VisionCommand,
    ) -> Vec<u8> {
        let mut addons = vec![0x0a, 0x10];
        addons.extend_from_slice(VISION_FLOW.as_bytes());
        let mut request = Vec::new();
        request.push(VERSION);
        request.extend_from_slice(USER.as_bytes());
        request.push(u8::try_from(addons.len()).unwrap_or(u8::MAX));
        request.extend_from_slice(&addons);
        request.push(Command::Tcp.as_byte());
        request.extend_from_slice(&destination_port.to_be_bytes());
        request.push(1);
        request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        let mut encoder = VisionEncoder::new(USER);
        let mut frame = Vec::new();
        encoder
            .encode(payload, command, false, &mut frame)
            .expect("Vision payload must encode");
        request.extend_from_slice(&frame);
        request
    }

    fn tls_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = Tls13KeySchedule::new(
            suite,
            &[0x11; 32],
            &suite.hash().digest(b"Vision server hello transcript"),
        )
        .expect("test schedule must initialize");
        let secrets = schedule
            .application_traffic_secrets(&suite.hash().digest(b"Vision test transcript"))
            .expect("test application secrets must derive");
        let server_client_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.client())
                .expect("client keys must derive"),
        )
        .expect("server read records must initialize");
        let server_server_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.server())
                .expect("server keys must derive"),
        )
        .expect("server write records must initialize");
        let client_write_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.client())
                .expect("client keys must derive"),
        )
        .expect("client write records must initialize");
        let client_read_records = Tls13RecordLayer::new(
            suite,
            schedule
                .traffic_keys(secrets.server())
                .expect("server keys must derive"),
        )
        .expect("client read records must initialize");
        (
            EstablishedTls::from_test_records(suite, server_client_records, server_server_records),
            client_write_records,
            client_read_records,
        )
    }
}
