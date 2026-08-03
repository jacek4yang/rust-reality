use std::{error::Error, fmt, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{self, Instant},
};

use super::MAX_PLAINTEXT_LEN;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS13_INNER_CONTENT_TYPE_LEN: usize = 1;
const AEAD_TAG_LEN: usize = 16;
const MAX_TLS13_CIPHERTEXT_LEN: usize =
    MAX_PLAINTEXT_LEN + TLS13_INNER_CONTENT_TYPE_LEN + AEAD_TAG_LEN;
const READ_SCRATCH_BYTES: usize = 4 * 1024;

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

/// Reads exactly one TLS record under one absolute deadline.
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
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(failure(TlsRecordReadErrorKind::Timeout, Vec::new()));
    };
    let mut wire = Vec::with_capacity(512);
    if let Err(kind) = read_exact_to(reader, &mut wire, TLS_RECORD_HEADER_LEN, deadline).await {
        return Err(failure(kind, wire));
    }
    let Some(header) = wire.get(..TLS_RECORD_HEADER_LEN) else {
        return Err(failure(TlsRecordReadErrorKind::UnexpectedEof, wire));
    };
    let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if body_len == 0 || body_len > MAX_TLS13_CIPHERTEXT_LEN {
        return Err(failure(TlsRecordReadErrorKind::RecordTooLarge, wire));
    }
    let Some(record_end) = TLS_RECORD_HEADER_LEN.checked_add(body_len) else {
        return Err(failure(TlsRecordReadErrorKind::RecordTooLarge, wire));
    };
    if let Err(kind) = read_exact_to(reader, &mut wire, record_end, deadline).await {
        return Err(failure(kind, wire));
    }
    Ok(TlsRecordRead { wire })
}

async fn read_exact_to<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    target_len: usize,
    deadline: Instant,
) -> Result<(), TlsRecordReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0_u8; READ_SCRATCH_BYTES];
    while output.len() < target_len {
        let remaining = target_len.saturating_sub(output.len());
        let read_len = remaining.min(scratch.len());
        let buffer = scratch
            .get_mut(..read_len)
            .ok_or(TlsRecordReadErrorKind::UnexpectedEof)?;
        let read = match time::timeout_at(deadline, reader.read(buffer)).await {
            Ok(Ok(0)) => return Err(TlsRecordReadErrorKind::UnexpectedEof),
            Ok(Ok(read)) => read,
            Ok(Err(source)) => return Err(TlsRecordReadErrorKind::Io(source)),
            Err(_) => return Err(TlsRecordReadErrorKind::Timeout),
        };
        let bytes = buffer
            .get(..read)
            .ok_or(TlsRecordReadErrorKind::UnexpectedEof)?;
        output.extend_from_slice(bytes);
    }
    Ok(())
}

const fn failure(kind: TlsRecordReadErrorKind, wire_prefix: Vec<u8>) -> TlsRecordReadError {
    TlsRecordReadError { kind, wire_prefix }
}

#[cfg(test)]
mod tests {
    use std::{io, pin::Pin, task::Poll, time::Duration};

    use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

    use super::{MAX_TLS13_CIPHERTEXT_LEN, TlsRecordReadErrorKind, read_tls_record};

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
}
