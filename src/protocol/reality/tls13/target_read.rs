use std::{error::Error, fmt, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{self, Instant},
};

use crate::protocol::reality::ClientHello;

use super::{MAX_TLS13_CIPHERTEXT_LEN, ServerHelloError, ServerHelloTemplate};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [3, 3];
const MAX_TLS_PLAINTEXT_BYTES: usize = 16 * 1024;
const READ_SCRATCH_BYTES: usize = 4 * 1024;
const COALESCED_COVER_RECORD_THRESHOLD: usize = 512;

/// Bounded cover-derived policy for the encrypted server handshake records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoverHandshakeRecordShape {
    /// The four generated messages share one record padded to the cover's wire length.
    Coalesced { wire_len: usize },
    /// The four generated messages use the cover's four positional outer lengths.
    ///
    /// Cover ciphertext does not reveal its inner message boundaries; the
    /// positional association is an intentionally bounded policy inference.
    PositionalRecords { wire_lens: [usize; 4] },
}

/// A validated target ServerHello and its exact plaintext TLS record.
#[derive(Debug)]
pub struct TargetServerHelloRead {
    template: ServerHelloTemplate,
    wire_record: Vec<u8>,
}

impl TargetServerHelloRead {
    /// Returns the validated target presentation template.
    #[must_use]
    pub const fn template(&self) -> &ServerHelloTemplate {
        &self.template
    }

    /// Returns the exact target bytes consumed from the cover connection.
    #[must_use]
    pub fn wire_record(&self) -> &[u8] {
        &self.wire_record
    }

    /// Separates validated target state from the exact consumed record.
    #[must_use]
    pub fn into_parts(self) -> (ServerHelloTemplate, Vec<u8>) {
        (self.template, self.wire_record)
    }
}

/// Validated target presentation plus its bounded post-ServerHello record shape.
#[derive(Debug)]
pub(crate) struct TargetServerFlightRead {
    template: ServerHelloTemplate,
    shape: CoverHandshakeRecordShape,
    wire_prefix: Vec<u8>,
}

impl TargetServerFlightRead {
    /// Separates the template, cover-derived shape, and exact consumed bytes.
    pub(crate) fn into_parts(self) -> (ServerHelloTemplate, CoverHandshakeRecordShape, Vec<u8>) {
        (self.template, self.shape, self.wire_prefix)
    }
}

/// Category of a bounded target TLS server-flight read failure.
#[derive(Debug)]
pub enum TargetServerHelloReadErrorKind {
    /// The absolute read deadline elapsed.
    Timeout,
    /// The target closed before a complete record arrived.
    UnexpectedEof,
    /// Socket input failed.
    Io(io::Error),
    /// A declared record exceeded the applicable TLS limit or was empty.
    RecordTooLarge,
    /// The first target record was not a TLS 1.3 ServerHello record.
    UnexpectedRecord,
    /// The complete ServerHello was not compatible with the client offer.
    Invalid(ServerHelloError),
}

impl fmt::Display for TargetServerHelloReadErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("target TLS server-flight read timed out"),
            Self::UnexpectedEof => formatter.write_str("target closed during TLS server flight"),
            Self::Io(_) => formatter.write_str("target TLS server-flight socket read failed"),
            Self::RecordTooLarge => {
                formatter.write_str("target TLS server-flight record length is invalid")
            }
            Self::UnexpectedRecord => {
                formatter.write_str("target TLS server-flight record sequence is invalid")
            }
            Self::Invalid(source) => source.fmt(formatter),
        }
    }
}

impl Error for TargetServerHelloReadErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Invalid(source) => Some(source),
            Self::Timeout | Self::UnexpectedEof | Self::RecordTooLarge | Self::UnexpectedRecord => {
                None
            }
        }
    }
}

/// A target read failure retaining every byte required for exact fallback.
#[derive(Debug)]
pub struct TargetServerHelloReadError {
    kind: TargetServerHelloReadErrorKind,
    wire_prefix: Vec<u8>,
}

impl TargetServerHelloReadError {
    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> &TargetServerHelloReadErrorKind {
        &self.kind
    }

    /// Returns exactly the bytes already consumed from the target.
    #[must_use]
    pub fn fallback_prefix(&self) -> &[u8] {
        &self.wire_prefix
    }

    /// Separates the failure category and its exact consumed target prefix.
    #[must_use]
    pub fn into_parts(self) -> (TargetServerHelloReadErrorKind, Vec<u8>) {
        (self.kind, self.wire_prefix)
    }
}

impl fmt::Display for TargetServerHelloReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for TargetServerHelloReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

/// Reads exactly one target ServerHello record under an absolute deadline.
///
/// The reader stops at the first record boundary. Both success and failure retain
/// the exact bytes consumed so an incompatible target can continue as byte-exact
/// fallback without reconnecting or discarding its response.
///
/// # Errors
///
/// Returns a byte-owning error for timeout, EOF, I/O, record framing, or strict
/// ServerHello compatibility failures.
pub async fn read_target_server_hello<R>(
    reader: &mut R,
    client: &ClientHello,
    timeout: Duration,
) -> Result<TargetServerHelloRead, TargetServerHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(failure(TargetServerHelloReadErrorKind::Timeout, Vec::new()));
    };
    read_target_server_hello_until(reader, client, deadline).await
}

async fn read_target_server_hello_until<R>(
    reader: &mut R,
    client: &ClientHello,
    deadline: Instant,
) -> Result<TargetServerHelloRead, TargetServerHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let mut wire_record = Vec::with_capacity(512);
    if let Err(kind) =
        read_exact_to(reader, &mut wire_record, TLS_RECORD_HEADER_LEN, deadline).await
    {
        return Err(failure(kind, wire_record));
    }

    let Some(header) = wire_record.get(..TLS_RECORD_HEADER_LEN) else {
        return Err(failure(
            TargetServerHelloReadErrorKind::UnexpectedEof,
            wire_record,
        ));
    };
    if header[0] != TLS_CONTENT_TYPE_HANDSHAKE || header[1..3] != TLS_LEGACY_RECORD_VERSION {
        return Err(failure(
            TargetServerHelloReadErrorKind::UnexpectedRecord,
            wire_record,
        ));
    }
    let record_body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_body_len == 0 || record_body_len > MAX_TLS_PLAINTEXT_BYTES {
        return Err(failure(
            TargetServerHelloReadErrorKind::RecordTooLarge,
            wire_record,
        ));
    }
    let Some(record_end) = TLS_RECORD_HEADER_LEN.checked_add(record_body_len) else {
        return Err(failure(
            TargetServerHelloReadErrorKind::RecordTooLarge,
            wire_record,
        ));
    };
    if let Err(kind) = read_exact_to(reader, &mut wire_record, record_end, deadline).await {
        return Err(failure(kind, wire_record));
    }
    let Some(message) = wire_record.get(TLS_RECORD_HEADER_LEN..record_end) else {
        return Err(failure(
            TargetServerHelloReadErrorKind::UnexpectedEof,
            wire_record,
        ));
    };
    let template = match ServerHelloTemplate::parse(message, client) {
        Ok(template) => template,
        Err(source) => {
            return Err(failure(
                TargetServerHelloReadErrorKind::Invalid(source),
                wire_record,
            ));
        }
    };

    Ok(TargetServerHelloRead {
        template,
        wire_record,
    })
}

/// Reads the cover-derived encrypted-handshake record plan under one deadline.
///
/// This follows stock Xray's measured 512-wire-byte adaptive branch policy. A
/// larger first encrypted record selects one coalesced generated record; its
/// header and first body byte are consumed before accepting the shape. Otherwise
/// exactly four positional encrypted records are consumed. Rust's existing TLS
/// 1.3 record limit remains authoritative rather than copying Xray's internal
/// observation-buffer size. Every consumed byte is retained for byte-exact
/// fallback.
pub(crate) async fn read_target_server_flight<R>(
    reader: &mut R,
    client: &ClientHello,
    timeout: Duration,
) -> Result<TargetServerFlightRead, TargetServerHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(failure(TargetServerHelloReadErrorKind::Timeout, Vec::new()));
    };
    let hello = read_target_server_hello_until(reader, client, deadline).await?;
    let (template, mut wire_prefix) = hello.into_parts();

    if let Err(kind) = read_change_cipher_spec(reader, &mut wire_prefix, deadline).await {
        return Err(failure(kind, wire_prefix));
    }

    let first_start = wire_prefix.len();
    let first_wire_len = match read_encrypted_header(reader, &mut wire_prefix, deadline).await {
        Ok(wire_len) => wire_len,
        Err(kind) => return Err(failure(kind, wire_prefix)),
    };
    if first_wire_len > COALESCED_COVER_RECORD_THRESHOLD {
        // Xray does not classify a header-only response as a usable cover
        // flight: at least one declared ciphertext byte must have arrived.
        // Stop immediately after that byte so fallback can replay this exact
        // prefix and relay the unread body without buffering the large record.
        let Some(first_body_byte_end) = first_start.checked_add(TLS_RECORD_HEADER_LEN + 1) else {
            return Err(failure(
                TargetServerHelloReadErrorKind::RecordTooLarge,
                wire_prefix,
            ));
        };
        if let Err(kind) =
            read_exact_to(reader, &mut wire_prefix, first_body_byte_end, deadline).await
        {
            return Err(failure(kind, wire_prefix));
        }
        return Ok(TargetServerFlightRead {
            template,
            shape: CoverHandshakeRecordShape::Coalesced {
                wire_len: first_wire_len,
            },
            wire_prefix,
        });
    }

    if let Err(kind) = read_record_body(
        reader,
        &mut wire_prefix,
        first_start,
        first_wire_len,
        deadline,
    )
    .await
    {
        return Err(failure(kind, wire_prefix));
    }
    let mut wire_lens = [0_usize; 4];
    wire_lens[0] = first_wire_len;
    for wire_len in wire_lens.iter_mut().skip(1) {
        let record_start = wire_prefix.len();
        *wire_len = match read_encrypted_header(reader, &mut wire_prefix, deadline).await {
            Ok(wire_len) => wire_len,
            Err(kind) => return Err(failure(kind, wire_prefix)),
        };
        if let Err(kind) =
            read_record_body(reader, &mut wire_prefix, record_start, *wire_len, deadline).await
        {
            return Err(failure(kind, wire_prefix));
        }
    }

    Ok(TargetServerFlightRead {
        template,
        shape: CoverHandshakeRecordShape::PositionalRecords { wire_lens },
        wire_prefix,
    })
}

async fn read_change_cipher_spec<R>(
    reader: &mut R,
    wire_prefix: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(), TargetServerHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let record_start = wire_prefix.len();
    let (outer_type, wire_len) = read_record_header(reader, wire_prefix, deadline).await?;
    if outer_type != TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC || wire_len != TLS_RECORD_HEADER_LEN + 1 {
        return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
    }
    read_record_body(reader, wire_prefix, record_start, wire_len, deadline).await?;
    if wire_prefix.get(record_start + TLS_RECORD_HEADER_LEN) != Some(&1) {
        return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
    }
    Ok(())
}

async fn read_encrypted_header<R>(
    reader: &mut R,
    wire_prefix: &mut Vec<u8>,
    deadline: Instant,
) -> Result<usize, TargetServerHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let (outer_type, wire_len) = read_record_header(reader, wire_prefix, deadline).await?;
    if outer_type != TLS_CONTENT_TYPE_APPLICATION_DATA {
        return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
    }
    Ok(wire_len)
}

async fn read_record_header<R>(
    reader: &mut R,
    wire_prefix: &mut Vec<u8>,
    deadline: Instant,
) -> Result<(u8, usize), TargetServerHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let record_start = wire_prefix.len();
    let header_end = record_start
        .checked_add(TLS_RECORD_HEADER_LEN)
        .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
    read_exact_to(reader, wire_prefix, header_end, deadline).await?;
    let header = wire_prefix
        .get(record_start..header_end)
        .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
    if header[1..3] != TLS_LEGACY_RECORD_VERSION {
        return Err(TargetServerHelloReadErrorKind::UnexpectedRecord);
    }
    let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body_len == 0 || body_len > MAX_TLS13_CIPHERTEXT_LEN {
        return Err(TargetServerHelloReadErrorKind::RecordTooLarge);
    }
    let wire_len = TLS_RECORD_HEADER_LEN
        .checked_add(body_len)
        .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
    Ok((header[0], wire_len))
}

async fn read_record_body<R>(
    reader: &mut R,
    wire_prefix: &mut Vec<u8>,
    record_start: usize,
    wire_len: usize,
    deadline: Instant,
) -> Result<(), TargetServerHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let record_end = record_start
        .checked_add(wire_len)
        .ok_or(TargetServerHelloReadErrorKind::RecordTooLarge)?;
    read_exact_to(reader, wire_prefix, record_end, deadline).await
}

async fn read_exact_to<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    target_len: usize,
    deadline: Instant,
) -> Result<(), TargetServerHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0_u8; READ_SCRATCH_BYTES];
    if output.capacity() < target_len {
        output
            .try_reserve_exact(target_len.saturating_sub(output.len()))
            .map_err(|_| TargetServerHelloReadErrorKind::RecordTooLarge)?;
    }
    while output.len() < target_len {
        let remaining = target_len.saturating_sub(output.len());
        let read_len = remaining.min(scratch.len());
        let buffer = scratch
            .get_mut(..read_len)
            .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
        let read = match time::timeout_at(deadline, reader.read(buffer)).await {
            Ok(Ok(0)) => return Err(TargetServerHelloReadErrorKind::UnexpectedEof),
            Ok(Ok(read)) => read,
            Ok(Err(source)) => return Err(TargetServerHelloReadErrorKind::Io(source)),
            Err(_) => return Err(TargetServerHelloReadErrorKind::Timeout),
        };
        let bytes = buffer
            .get(..read)
            .ok_or(TargetServerHelloReadErrorKind::UnexpectedEof)?;
        output.extend_from_slice(bytes);
    }
    Ok(())
}

const fn failure(
    kind: TargetServerHelloReadErrorKind,
    wire_prefix: Vec<u8>,
) -> TargetServerHelloReadError {
    TargetServerHelloReadError { kind, wire_prefix }
}

#[cfg(test)]
mod tests {
    use std::{io, pin::Pin, task::Poll, time::Duration};

    use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

    use super::{
        CoverHandshakeRecordShape, TargetServerHelloReadErrorKind, read_target_server_flight,
        read_target_server_hello,
    };
    use crate::protocol::reality::{
        ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello::fixtures,
    };

    struct OneByteReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for OneByteReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(byte) = self.bytes.get(self.position).copied() else {
                return Poll::Ready(Ok(()));
            };
            output.put_slice(&[byte]);
            self.position += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reads_fragmented_target_record_without_consuming_next_record() {
        let client = client();
        let record = target_record(&[0x55; 32]);
        let mut input = record.clone();
        input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        let mut reader = OneByteReader {
            bytes: input,
            position: 0,
        };

        let read = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("compatible target ServerHello must be read");

        assert_eq!(read.wire_record(), record);
        assert_eq!(read.template().key_share_group(), X25519_GROUP);
        assert_eq!(reader.position, record.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_target_returns_complete_byte_exact_record() {
        let client = client();
        let mut record = target_record(&[0x55; 32]);
        record[5] = 1;
        let mut reader = OneByteReader {
            bytes: record.clone(),
            position: 0,
        };

        let error = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("non-ServerHello handshake must fail");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Invalid(_)
        ));
        assert_eq!(error.fallback_prefix(), record);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_returns_partial_target_prefix() {
        let client = client();
        let (mut local, mut remote) = tokio::io::duplex(16);
        let prefix = [22, 3, 3, 0, 128, 2, 0];
        remote
            .write_all(&prefix)
            .await
            .expect("partial target response must be written");

        let error = read_target_server_hello(&mut local, &client, Duration::from_millis(20))
            .await
            .expect_err("incomplete target response must time out");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_non_handshake_header_without_reading_declared_body() {
        let client = client();
        let header = [21, 3, 3, 0, 64];
        let mut reader = OneByteReader {
            bytes: header.to_vec(),
            position: 0,
        };

        let error = read_target_server_hello(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("alert record must not be accepted as ServerHello");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::UnexpectedRecord
        ));
        assert_eq!(error.fallback_prefix(), header);
        assert_eq!(reader.position, header.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coalesced_shape_consumes_the_header_and_first_body_byte() {
        let client = client();
        let server_hello = target_record(&[0x55; 32]);
        let ccs = [20, 3, 3, 0, 1, 1];
        let encrypted = opaque_record(23, 600, 0xa5);
        let expected_prefix_len = server_hello.len() + ccs.len() + 6;
        let mut input = server_hello.clone();
        input.extend_from_slice(&ccs);
        input.extend_from_slice(&encrypted);
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("large first encrypted record must select coalescing");
        let (_, shape, prefix) = read.into_parts();

        assert_eq!(
            shape,
            CoverHandshakeRecordShape::Coalesced { wire_len: 605 }
        );
        assert_eq!(prefix, input[..expected_prefix_len]);
        assert_eq!(reader.position, expected_prefix_len);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coalesced_header_without_a_body_byte_times_out_with_exact_prefix() {
        let client = client();
        let mut prefix = target_record(&[0x55; 32]);
        prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        prefix.extend_from_slice(&[23, 3, 3, 2, 88]);
        let (mut local, mut remote) = tokio::io::duplex(2_048);
        remote
            .write_all(&prefix)
            .await
            .expect("header-only target flight must be written");

        let error = read_target_server_flight(&mut local, &client, Duration::from_millis(20))
            .await
            .expect_err("a declared coalesced record must contain ciphertext");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_change_cipher_spec_retains_the_exact_consumed_prefix() {
        let client = client();
        let mut input = target_record(&[0x55; 32]);
        input.extend_from_slice(&[20, 3, 3, 0, 1, 2]);
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let error = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect_err("invalid CCS content must be rejected");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::UnexpectedRecord
        ));
        assert_eq!(error.fallback_prefix(), input);
        assert_eq!(reader.position, input.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn positional_shape_consumes_exactly_four_encrypted_records() {
        let client = client();
        let mut input = target_record(&[0x55; 32]);
        input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        let body_lens = [32_usize, 208, 89, 53];
        for (index, body_len) in body_lens.into_iter().enumerate() {
            input.extend_from_slice(&opaque_record(23, body_len, index as u8));
        }
        let expected_prefix_len = input.len();
        input.extend_from_slice(&opaque_record(23, 24, 0xff));
        let mut reader = OneByteReader {
            bytes: input.clone(),
            position: 0,
        };

        let read = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
            .await
            .expect("four small encrypted records must be read positionally");
        let (_, shape, prefix) = read.into_parts();

        assert_eq!(
            shape,
            CoverHandshakeRecordShape::PositionalRecords {
                wire_lens: [37, 213, 94, 58],
            }
        );
        assert_eq!(prefix, input[..expected_prefix_len]);
        assert_eq!(reader.position, expected_prefix_len);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn positional_timeout_retains_the_exact_partial_record() {
        let client = client();
        let mut prefix = target_record(&[0x55; 32]);
        prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        prefix.extend_from_slice(&opaque_record(23, 32, 0x01));
        prefix.extend_from_slice(&[23, 3, 3, 0, 64, 0xaa, 0xbb, 0xcc]);
        let (mut local, mut remote) = tokio::io::duplex(2_048);
        remote
            .write_all(&prefix)
            .await
            .expect("partial target flight must be written");

        let error = read_target_server_flight(&mut local, &client, Duration::from_millis(20))
            .await
            .expect_err("partial positional record must time out");

        assert!(matches!(
            error.kind(),
            TargetServerHelloReadErrorKind::Timeout
        ));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_positional_flight_truncation_retains_the_exact_prefix() {
        let client = client();
        let mut complete = target_record(&[0x55; 32]);
        complete.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        for (index, body_len) in [32_usize, 48, 64, 40].into_iter().enumerate() {
            complete.extend_from_slice(&opaque_record(23, body_len, index as u8));
        }

        for cutoff in 0..complete.len() {
            let expected = complete[..cutoff].to_vec();
            let mut reader = OneByteReader {
                bytes: expected.clone(),
                position: 0,
            };
            let error = read_target_server_flight(&mut reader, &client, Duration::from_secs(1))
                .await
                .expect_err("every truncated flight must fail closed");

            assert!(matches!(
                error.kind(),
                TargetServerHelloReadErrorKind::UnexpectedEof
            ));
            assert_eq!(error.fallback_prefix(), expected);
            assert_eq!(reader.position, cutoff);
        }
    }

    fn client() -> ClientHello {
        ClientHello::parse_message(&fixtures::client_hello_with_key_share(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            X25519_GROUP,
            &[0x22; 32],
        ))
        .expect("test ClientHello must parse")
    }

    fn target_record(key_exchange: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(SESSION_ID_LEN).expect("test session ID must fit"));
        body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);

        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
        let mut share = Vec::new();
        share.extend_from_slice(&X25519_GROUP.to_be_bytes());
        share.extend_from_slice(
            &u16::try_from(key_exchange.len())
                .expect("test key share must fit")
                .to_be_bytes(),
        );
        share.extend_from_slice(key_exchange);
        push_extension(&mut extensions, 0x0033, &share);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("test extensions must fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut message = vec![2];
        let message_len = u32::try_from(body.len()).expect("test ServerHello body must fit");
        message.extend_from_slice(&message_len.to_be_bytes()[1..]);
        message.extend_from_slice(&body);

        let mut record = vec![22, 3, 3];
        record.extend_from_slice(
            &u16::try_from(message.len())
                .expect("test record must fit")
                .to_be_bytes(),
        );
        record.extend_from_slice(&message);
        record
    }

    fn opaque_record(content_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
        let mut record = vec![content_type, 3, 3];
        record.extend_from_slice(
            &u16::try_from(body_len)
                .expect("test record body must fit")
                .to_be_bytes(),
        );
        record.resize(5 + body_len, fill);
        record
    }

    fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .expect("test extension must fit")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
}
