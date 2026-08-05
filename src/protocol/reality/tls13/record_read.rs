use std::{collections::TryReserveError, error::Error, fmt, io, time::Duration};

use tokio::io::AsyncRead;

use super::{IdleDeadline, IdleError, MAX_PLAINTEXT_LEN};

pub(crate) const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS13_INNER_CONTENT_TYPE_LEN: usize = 1;
const AEAD_TAG_LEN: usize = 16;
pub(crate) const MAX_TLS13_CIPHERTEXT_LEN: usize =
    MAX_PLAINTEXT_LEN + TLS13_INNER_CONTENT_TYPE_LEN + AEAD_TAG_LEN;

/// Bytes required to hold the largest accepted TLS 1.3 record header plus body.
///
/// One buffer of this size per connection direction removes every steady-state
/// record allocation: the header and body are read directly into final storage
/// and the AEAD is opened in place.
pub const MAX_TLS_RECORD_WIRE_LEN: usize = TLS_RECORD_HEADER_LEN + MAX_TLS13_CIPHERTEXT_LEN;

/// Allocates one reusable maximum-sized record buffer for a connection direction.
///
/// The returned buffer never reallocates while it is used by
/// [`read_tls_record_into`], which lets the successful record loop run without
/// touching the allocator.
///
/// # Errors
///
/// Returns the allocator's reservation failure without panicking.
pub fn record_storage() -> Result<Vec<u8>, TryReserveError> {
    let mut wire = Vec::new();
    wire.try_reserve_exact(MAX_TLS_RECORD_WIRE_LEN)?;
    Ok(wire)
}

/// One exact, bounded TLS record read from an asynchronous stream.
#[derive(Debug, Eq, PartialEq)]
pub struct TlsRecordRead {
    wire: Vec<u8>,
}

impl TlsRecordRead {
    /// Returns the complete record header and body.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the outer TLS content type without interpreting it.
    #[must_use]
    pub fn outer_content_type(&self) -> u8 {
        self.wire.first().copied().unwrap_or_default()
    }

    /// Returns the record body following the five-byte header.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.wire.get(TLS_RECORD_HEADER_LEN..).unwrap_or_default()
    }

    /// Consumes the record and returns its exact owned bytes.
    #[must_use]
    pub fn into_wire(self) -> Vec<u8> {
        self.wire
    }
}

/// Category of a bounded asynchronous TLS record read failure.
#[derive(Debug)]
pub enum TlsRecordReadErrorKind {
    /// The absolute record deadline elapsed.
    Timeout,
    /// The peer closed before the declared record boundary.
    UnexpectedEof,
    /// Socket input failed.
    Io(io::Error),
    /// The declared record body was empty or exceeded the TLS 1.3 ciphertext limit.
    RecordTooLarge,
}

impl fmt::Display for TlsRecordReadErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("TLS record read timed out"),
            Self::UnexpectedEof => formatter.write_str("peer closed during TLS record"),
            Self::Io(_) => formatter.write_str("TLS record socket read failed"),
            Self::RecordTooLarge => {
                formatter.write_str("TLS record length is outside fixed bounds")
            }
        }
    }
}

impl Error for TlsRecordReadErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Timeout | Self::UnexpectedEof | Self::RecordTooLarge => None,
        }
    }
}

/// A TLS record read failure that retains every byte already consumed.
#[derive(Debug)]
pub struct TlsRecordReadError {
    kind: TlsRecordReadErrorKind,
    wire_prefix: Vec<u8>,
}

impl TlsRecordReadError {
    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> &TlsRecordReadErrorKind {
        &self.kind
    }

    /// Returns exactly the incomplete or rejected bytes consumed from the peer.
    #[must_use]
    pub fn wire_prefix(&self) -> &[u8] {
        &self.wire_prefix
    }

    /// Separates the failure category from the exact consumed bytes.
    #[must_use]
    pub fn into_parts(self) -> (TlsRecordReadErrorKind, Vec<u8>) {
        (self.kind, self.wire_prefix)
    }
}

impl fmt::Display for TlsRecordReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for TlsRecordReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

/// Reads exactly one TLS record under one idle timeout.
///
/// The function never reads beyond the declared record body, allowing callers to
/// preserve handshake/application state and apply AEAD sequence numbers exactly
/// once. It permits the one-byte compatibility CCS body and bounded TLS 1.3
/// ciphertext records, while rejecting zero and oversized lengths before body I/O.
///
/// # Errors
///
/// Returns a byte-owning error on timeout, EOF, socket failure, or invalid length.
pub async fn read_tls_record<R>(
    reader: &mut R,
    timeout: Duration,
) -> Result<TlsRecordRead, TlsRecordReadError>
where
    R: AsyncRead + Unpin,
{
    let mut wire = match record_storage() {
        Ok(storage) => storage,
        Err(_) => return Err(failure(TlsRecordReadErrorKind::RecordTooLarge, Vec::new())),
    };
    let mut idle = IdleDeadline::new();
    if idle.reset(timeout).is_err() {
        return Err(failure(TlsRecordReadErrorKind::Timeout, Vec::new()));
    }
    let length = read_tls_record_into(reader, &mut wire, &mut idle).await?;
    wire.truncate(length);
    Ok(TlsRecordRead { wire })
}

/// Reads exactly one TLS record into reusable connection-owned storage.
///
/// `wire` must have been produced by [`record_storage`] or otherwise reserve
/// [`MAX_TLS_RECORD_WIRE_LEN`] bytes. `idle` must have been reset for this
/// record, giving the whole record — header and body — one idle window, which
/// is exactly the previous per-record deadline semantics with a single timer
/// registration. The header is read directly into final storage, the declared
/// body length is validated before any body input, and the body is read
/// directly into the same allocation. No scratch array and no intermediate
/// copy are used, so a successful read performs no allocation.
///
/// The storage is grow-only: it is zero-initialized at most once per size
/// class and then reused as already-initialized memory, so the steady-state
/// record loop never re-zeroes the record region. On success the record is
/// exactly the returned prefix of `wire`; the buffer keeps its high-water
/// length, and bytes beyond the prefix are stale and must not be read. On
/// failure `wire` is truncated to exactly the bytes consumed from the peer,
/// and the same prefix is copied into the bounded error value for fallback
/// reconstruction.
///
/// # Errors
///
/// Returns a byte-owning error on timeout, EOF, socket failure, or invalid length.
pub async fn read_tls_record_into<R>(
    reader: &mut R,
    wire: &mut Vec<u8>,
    idle: &mut IdleDeadline,
) -> Result<usize, TlsRecordReadError>
where
    R: AsyncRead + Unpin,
{
    if let Err(kind) = read_exact_into(reader, wire, 0, TLS_RECORD_HEADER_LEN, idle).await {
        return Err(consumed_failure(kind, wire));
    }
    let Some(header) = wire.get(..TLS_RECORD_HEADER_LEN) else {
        return Err(consumed_failure(
            TlsRecordReadErrorKind::UnexpectedEof,
            wire,
        ));
    };
    let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body_len == 0 || body_len > MAX_TLS13_CIPHERTEXT_LEN {
        wire.truncate(TLS_RECORD_HEADER_LEN);
        return Err(consumed_failure(
            TlsRecordReadErrorKind::RecordTooLarge,
            wire,
        ));
    }
    let Some(record_end) = TLS_RECORD_HEADER_LEN.checked_add(body_len) else {
        wire.truncate(TLS_RECORD_HEADER_LEN);
        return Err(consumed_failure(
            TlsRecordReadErrorKind::RecordTooLarge,
            wire,
        ));
    };
    if let Err(kind) = read_exact_into(reader, wire, TLS_RECORD_HEADER_LEN, record_end, idle).await
    {
        return Err(consumed_failure(kind, wire));
    }
    Ok(record_end)
}

/// Reads until `output` holds peer input through `target_len` bytes.
///
/// Growth is the only operation that touches the allocator or zero-fills: a
/// reused buffer already covers `target_len` as initialized memory, so the
/// steady-state path neither allocates nor re-zeroes. Bytes already present
/// are stale contents of an earlier record and are simply overwritten by the
/// socket read. On failure the buffer is truncated to the exact consumed
/// prefix.
async fn read_exact_into<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    start: usize,
    target_len: usize,
    idle: &mut IdleDeadline,
) -> Result<(), TlsRecordReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    if output.len() < target_len {
        if target_len > output.capacity() {
            output
                .try_reserve_exact(target_len - output.len())
                .map_err(|_| TlsRecordReadErrorKind::RecordTooLarge)?;
        }
        output.resize(target_len, 0);
    }
    let mut filled = start;
    while filled < target_len {
        let destination = output
            .get_mut(filled..target_len)
            .ok_or(TlsRecordReadErrorKind::UnexpectedEof)?;
        let read = match idle.read(reader, destination).await {
            Ok(0) => {
                output.truncate(filled);
                return Err(TlsRecordReadErrorKind::UnexpectedEof);
            }
            Ok(read) => read,
            Err(IdleError::Io(source)) => {
                output.truncate(filled);
                return Err(TlsRecordReadErrorKind::Io(source));
            }
            Err(IdleError::Timeout) => {
                output.truncate(filled);
                return Err(TlsRecordReadErrorKind::Timeout);
            }
        };
        filled = filled.saturating_add(read.min(target_len.saturating_sub(filled)));
    }
    Ok(())
}

/// Copies the exact consumed prefix into a bounded error value.
///
/// Only the failure path allocates; the successful record loop never reaches it.
fn consumed_failure(kind: TlsRecordReadErrorKind, wire: &[u8]) -> TlsRecordReadError {
    let mut wire_prefix = Vec::new();
    if wire_prefix.try_reserve_exact(wire.len()).is_ok() {
        wire_prefix.extend_from_slice(wire);
    }
    TlsRecordReadError { kind, wire_prefix }
}

/// Builds a byte-owning error for the buffered record reader.
///
/// The buffered reader in `application_io` keeps unconsumed socket bytes in its
/// connection-owned buffer rather than a per-record prefix; on a failed refill
/// those buffered bytes are exactly the partial record a record-exact read
/// would have consumed, so the error shape is identical.
pub(crate) fn buffered_failure(
    kind: TlsRecordReadErrorKind,
    buffered: &[u8],
) -> TlsRecordReadError {
    consumed_failure(kind, buffered)
}

const fn failure(kind: TlsRecordReadErrorKind, wire_prefix: Vec<u8>) -> TlsRecordReadError {
    TlsRecordReadError { kind, wire_prefix }
}

#[cfg(test)]
mod tests {
    use std::{io, pin::Pin, task::Poll, time::Duration};

    use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

    use super::{
        IdleDeadline, MAX_TLS_RECORD_WIRE_LEN, MAX_TLS13_CIPHERTEXT_LEN, TlsRecordReadErrorKind,
        read_tls_record, read_tls_record_into, record_storage,
    };

    fn armed_idle(timeout: Duration) -> IdleDeadline {
        let mut idle = IdleDeadline::new();
        idle.reset(timeout).expect("test idle window must arm");
        idle
    }

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
    async fn reads_one_fragmented_record_without_consuming_the_next() {
        let record = [23, 3, 3, 0, 4, 1, 2, 3, 4];
        let mut input = record.to_vec();
        input.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        let mut reader = OneByteReader {
            bytes: input,
            position: 0,
        };

        let read = read_tls_record(&mut reader, Duration::from_secs(1))
            .await
            .expect("bounded record must be read");

        assert_eq!(read.wire(), record);
        assert_eq!(read.outer_content_type(), 23);
        assert_eq!(read.body(), [1, 2, 3, 4]);
        assert_eq!(reader.position, record.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepts_exact_change_cipher_spec_record() {
        let record = [20, 3, 3, 0, 1, 1];
        let mut reader = OneByteReader {
            bytes: record.to_vec(),
            position: 0,
        };

        let read = read_tls_record(&mut reader, Duration::from_secs(1))
            .await
            .expect("one-byte compatibility record must be read");

        assert_eq!(read.into_wire(), record);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_preserves_incomplete_record_prefix() {
        let (mut local, mut remote) = tokio::io::duplex(16);
        let prefix = [23, 3, 3, 0, 32, 0xaa, 0xbb];
        remote
            .write_all(&prefix)
            .await
            .expect("partial record must be written");

        let error = read_tls_record(&mut local, Duration::from_millis(20))
            .await
            .expect_err("partial record must time out");

        assert!(matches!(error.kind(), TlsRecordReadErrorKind::Timeout));
        assert_eq!(error.wire_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_oversized_header_before_reading_body() {
        let oversized =
            u16::try_from(MAX_TLS13_CIPHERTEXT_LEN + 1).expect("test record length must fit u16");
        let header = [
            23,
            3,
            3,
            oversized.to_be_bytes()[0],
            oversized.to_be_bytes()[1],
        ];
        let mut reader = OneByteReader {
            bytes: header.to_vec(),
            position: 0,
        };

        let error = read_tls_record(&mut reader, Duration::from_secs(1))
            .await
            .expect_err("oversized record must fail at its header");

        assert!(matches!(
            error.kind(),
            TlsRecordReadErrorKind::RecordTooLarge
        ));
        assert_eq!(error.wire_prefix(), header);
        assert_eq!(reader.position, header.len());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reused_storage_address_is_stable_across_successful_records() {
        let mut input = Vec::new();
        for value in 0..4_u8 {
            input.extend_from_slice(&[23, 3, 3, 0, 4, value, value, value, value]);
        }
        let mut reader = OneByteReader {
            bytes: input,
            position: 0,
        };
        let mut wire = record_storage().expect("record storage must reserve");
        let capacity = wire.capacity();
        let address = wire.as_ptr() as usize;

        for value in 0..4_u8 {
            let length = read_tls_record_into(
                &mut reader,
                &mut wire,
                &mut armed_idle(Duration::from_secs(1)),
            )
            .await
            .expect("record must be read into reused storage");
            assert_eq!(length, 9);
            assert_eq!(
                wire.as_slice(),
                [23, 3, 3, 0, 4, value, value, value, value]
            );
            assert_eq!(
                wire.as_ptr() as usize,
                address,
                "reused record storage must not be reallocated"
            );
            assert_eq!(wire.capacity(), capacity);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reads_maximum_record_into_reserved_storage() {
        let body_len = MAX_TLS13_CIPHERTEXT_LEN;
        let length = u16::try_from(body_len).expect("maximum body length must fit u16");
        let mut input = vec![23, 3, 3, length.to_be_bytes()[0], length.to_be_bytes()[1]];
        input.resize(5 + body_len, 0x5a);
        let (mut local, mut remote) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            remote
                .write_all(&input)
                .await
                .expect("maximum record must be written");
        });
        let mut wire = record_storage().expect("record storage must reserve");
        assert_eq!(wire.capacity(), MAX_TLS_RECORD_WIRE_LEN);
        let address = wire.as_ptr() as usize;

        let read = read_tls_record_into(
            &mut local,
            &mut wire,
            &mut armed_idle(Duration::from_secs(5)),
        )
        .await
        .expect("maximum record must be read");

        writer.await.expect("writer task must finish");
        assert_eq!(read, MAX_TLS_RECORD_WIRE_LEN);
        assert_eq!(wire.len(), MAX_TLS_RECORD_WIRE_LEN);
        assert_eq!(wire.as_ptr() as usize, address);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reused_storage_retains_exact_prefix_after_timeout() {
        let (mut local, mut remote) = tokio::io::duplex(16);
        let prefix = [23, 3, 3, 0, 32, 0xaa, 0xbb];
        remote
            .write_all(&prefix)
            .await
            .expect("partial record must be written");
        let mut wire = record_storage().expect("record storage must reserve");

        let error = read_tls_record_into(
            &mut local,
            &mut wire,
            &mut armed_idle(Duration::from_millis(20)),
        )
        .await
        .expect_err("partial record must time out");

        assert!(matches!(error.kind(), TlsRecordReadErrorKind::Timeout));
        assert_eq!(error.wire_prefix(), prefix);
        assert_eq!(wire.as_slice(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shrinking_records_reuse_high_water_storage_with_exact_prefix() {
        let mut input = Vec::new();
        input.extend_from_slice(&[23, 3, 3, 0, 8, 1, 1, 1, 1, 1, 1, 1, 1]);
        input.extend_from_slice(&[23, 3, 3, 0, 2, 2, 2]);
        input.extend_from_slice(&[23, 3, 3, 0, 4, 3, 3, 3, 3]);
        let mut reader = OneByteReader {
            bytes: input,
            position: 0,
        };
        let mut wire = record_storage().expect("record storage must reserve");
        let address = wire.as_ptr() as usize;

        let first = read_tls_record_into(
            &mut reader,
            &mut wire,
            &mut armed_idle(Duration::from_secs(1)),
        )
        .await
        .expect("larger record must be read");
        assert_eq!(first, 13);
        let high_water = wire.len();
        let second = read_tls_record_into(
            &mut reader,
            &mut wire,
            &mut armed_idle(Duration::from_secs(1)),
        )
        .await
        .expect("smaller record must be read into high-water storage");
        assert_eq!(second, 7);
        assert_eq!(wire.len(), high_water, "storage must stay grow-only");
        assert_eq!(
            wire.get(..second),
            Some([23, 3, 3, 0, 2, 2, 2].as_slice()),
            "the returned prefix must be exactly the smaller record"
        );
        assert_eq!(wire.as_ptr() as usize, address);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_zero_length_body_before_reading_more() {
        let header = [23, 3, 3, 0, 0];
        let mut reader = OneByteReader {
            bytes: header.to_vec(),
            position: 0,
        };
        let mut wire = record_storage().expect("record storage must reserve");

        let error = read_tls_record_into(
            &mut reader,
            &mut wire,
            &mut armed_idle(Duration::from_secs(1)),
        )
        .await
        .expect_err("empty record body must be rejected");

        assert!(matches!(
            error.kind(),
            TlsRecordReadErrorKind::RecordTooLarge
        ));
        assert_eq!(reader.position, header.len());
    }
}
