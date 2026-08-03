use std::{error::Error, fmt, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{self, Instant},
};

use super::{ClientHello, ClientHelloError, MAX_CLIENT_HELLO_BYTES};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const MAX_TLS_PLAINTEXT_BYTES: usize = 16 * 1024;
const MAX_CLIENT_HELLO_RECORDS: usize = 16;
const READ_SCRATCH_BYTES: usize = 4 * 1024;

/// A successfully assembled ClientHello and the exact bytes consumed from the socket.
#[derive(Debug)]
pub struct ClientHelloRead {
    hello: ClientHello,
    wire_prefix: Vec<u8>,
    handshake_remainder: Vec<u8>,
}

impl ClientHelloRead {
    /// Returns the parsed ClientHello.
    #[must_use]
    pub const fn hello(&self) -> &ClientHello {
        &self.hello
    }

    /// Returns every TLS record byte consumed while assembling the ClientHello.
    ///
    /// An authentication failure must forward this exact prefix to the cover target
    /// before relaying any subsequent client bytes.
    #[must_use]
    pub fn fallback_prefix(&self) -> &[u8] {
        &self.wire_prefix
    }

    /// Returns handshake bytes following ClientHello in its final TLS record.
    #[must_use]
    pub fn handshake_remainder(&self) -> &[u8] {
        &self.handshake_remainder
    }

    /// Separates parsed state, exact wire ownership, and same-record remainder.
    #[must_use]
    pub fn into_parts(self) -> (ClientHello, Vec<u8>, Vec<u8>) {
        (self.hello, self.wire_prefix, self.handshake_remainder)
    }
}

/// Category of an incremental ClientHello read failure.
#[derive(Debug)]
pub enum ClientHelloReadErrorKind {
    /// The absolute read deadline elapsed.
    Timeout,
    /// The peer closed before a complete ClientHello arrived.
    UnexpectedEof,
    /// Socket input failed.
    Io(io::Error),
    /// A record declared more than the TLS plaintext limit.
    RecordTooLarge,
    /// More than the bounded number of fragments was required.
    TooManyRecords,
    /// A non-handshake record appeared before ClientHello completed.
    UnexpectedRecordType,
    /// The assembled ClientHello failed strict parsing.
    Invalid(ClientHelloError),
}

impl fmt::Display for ClientHelloReadErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("TLS ClientHello read timed out"),
            Self::UnexpectedEof => formatter.write_str("peer closed during TLS ClientHello"),
            Self::Io(_) => formatter.write_str("TLS ClientHello socket read failed"),
            Self::RecordTooLarge => formatter.write_str("TLS handshake record is too large"),
            Self::TooManyRecords => formatter.write_str("TLS ClientHello uses too many records"),
            Self::UnexpectedRecordType => {
                formatter.write_str("non-handshake record interrupted TLS ClientHello")
            }
            Self::Invalid(source) => source.fmt(formatter),
        }
    }
}

impl Error for ClientHelloReadErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Invalid(source) => Some(source),
            Self::Timeout
            | Self::UnexpectedEof
            | Self::RecordTooLarge
            | Self::TooManyRecords
            | Self::UnexpectedRecordType => None,
        }
    }
}

/// A read failure that retains byte-for-byte ownership for bounded fallback.
#[derive(Debug)]
pub struct ClientHelloReadError {
    kind: ClientHelloReadErrorKind,
    wire_prefix: Vec<u8>,
}

impl ClientHelloReadError {
    /// Returns the failure category.
    #[must_use]
    pub const fn kind(&self) -> &ClientHelloReadErrorKind {
        &self.kind
    }

    /// Returns exactly the bytes consumed before failure.
    #[must_use]
    pub fn fallback_prefix(&self) -> &[u8] {
        &self.wire_prefix
    }

    /// Separates the failure category and its exact consumed prefix.
    #[must_use]
    pub fn into_parts(self) -> (ClientHelloReadErrorKind, Vec<u8>) {
        (self.kind, self.wire_prefix)
    }
}

impl fmt::Display for ClientHelloReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for ClientHelloReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

/// Reads and assembles a fragmented ClientHello under one absolute deadline.
///
/// Reads are exact to record boundaries, so the function never consumes the next
/// TLS record. It accepts ClientHello fragmentation across bounded plaintext
/// handshake records and preserves every consumed wire byte for cover fallback.
///
/// # Errors
///
/// Returns a byte-owning error on timeout, EOF, I/O failure, record-limit failure,
/// unexpected record type, or strict ClientHello parse failure.
pub async fn read_client_hello<R>(
    reader: &mut R,
    timeout: Duration,
) -> Result<ClientHelloRead, ClientHelloReadError>
where
    R: AsyncRead + Unpin,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(failure(ClientHelloReadErrorKind::Timeout, Vec::new()));
    };
    let mut wire_prefix = Vec::with_capacity(4 * 1024);
    let mut handshake = Vec::with_capacity(4 * 1024);
    let mut expected_handshake_len = None;

    for _ in 0..MAX_CLIENT_HELLO_RECORDS {
        let header_start = wire_prefix.len();
        let header_end = match header_start.checked_add(TLS_RECORD_HEADER_LEN) {
            Some(end) => end,
            None => {
                return Err(failure(
                    ClientHelloReadErrorKind::RecordTooLarge,
                    wire_prefix,
                ));
            }
        };
        if let Err(kind) = read_exact_to(reader, &mut wire_prefix, header_end, deadline).await {
            return Err(failure(kind, wire_prefix));
        }
        let header: [u8; TLS_RECORD_HEADER_LEN] = match wire_prefix
            .get(header_start..header_end)
            .and_then(|bytes| bytes.try_into().ok())
        {
            Some(header) => header,
            None => {
                return Err(failure(
                    ClientHelloReadErrorKind::UnexpectedEof,
                    wire_prefix,
                ));
            }
        };
        if header[0] != TLS_CONTENT_TYPE_HANDSHAKE {
            return Err(failure(
                ClientHelloReadErrorKind::UnexpectedRecordType,
                wire_prefix,
            ));
        }
        let record_body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if record_body_len == 0 || record_body_len > MAX_TLS_PLAINTEXT_BYTES {
            return Err(failure(
                ClientHelloReadErrorKind::RecordTooLarge,
                wire_prefix,
            ));
        }
        let body_end = match header_end.checked_add(record_body_len) {
            Some(end) => end,
            None => {
                return Err(failure(
                    ClientHelloReadErrorKind::RecordTooLarge,
                    wire_prefix,
                ));
            }
        };
        if let Err(kind) = read_exact_to(reader, &mut wire_prefix, body_end, deadline).await {
            return Err(failure(kind, wire_prefix));
        }
        let Some(record_body) = wire_prefix.get(header_end..body_end) else {
            return Err(failure(
                ClientHelloReadErrorKind::UnexpectedEof,
                wire_prefix,
            ));
        };
        handshake.extend_from_slice(record_body);

        if handshake.first().is_some_and(|kind| *kind != 0x01) {
            return Err(failure(
                ClientHelloReadErrorKind::Invalid(ClientHelloError::NotClientHello),
                wire_prefix,
            ));
        }
        if expected_handshake_len.is_none() && handshake.len() >= 4 {
            let Some(length_bytes) = handshake
                .get(1..4)
                .and_then(|bytes| <[u8; 3]>::try_from(bytes).ok())
            else {
                return Err(failure(
                    ClientHelloReadErrorKind::UnexpectedEof,
                    wire_prefix,
                ));
            };
            let declared = match usize::try_from(u32::from_be_bytes([
                0,
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
            ])) {
                Ok(declared) => declared,
                Err(_) => {
                    return Err(failure(
                        ClientHelloReadErrorKind::RecordTooLarge,
                        wire_prefix,
                    ));
                }
            };
            let total = match 4_usize.checked_add(declared) {
                Some(total) if total <= MAX_CLIENT_HELLO_BYTES => total,
                _ => {
                    return Err(failure(
                        ClientHelloReadErrorKind::Invalid(ClientHelloError::TooLarge),
                        wire_prefix,
                    ));
                }
            };
            expected_handshake_len = Some(total);
        }

        if let Some(expected) = expected_handshake_len
            && handshake.len() >= expected
        {
            let Some(message) = handshake.get(..expected) else {
                return Err(failure(
                    ClientHelloReadErrorKind::UnexpectedEof,
                    wire_prefix,
                ));
            };
            let hello = ClientHello::parse_message(message).map_err(|source| {
                failure(
                    ClientHelloReadErrorKind::Invalid(source),
                    wire_prefix.clone(),
                )
            })?;
            let remainder = handshake
                .get(expected..)
                .map_or_else(Vec::new, <[u8]>::to_vec);
            return Ok(ClientHelloRead {
                hello,
                wire_prefix,
                handshake_remainder: remainder,
            });
        }

        if handshake.len() > MAX_CLIENT_HELLO_BYTES {
            return Err(failure(
                ClientHelloReadErrorKind::Invalid(ClientHelloError::TooLarge),
                wire_prefix,
            ));
        }
    }

    Err(failure(
        ClientHelloReadErrorKind::TooManyRecords,
        wire_prefix,
    ))
}

async fn read_exact_to<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    target_len: usize,
    deadline: Instant,
) -> Result<(), ClientHelloReadErrorKind>
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0_u8; READ_SCRATCH_BYTES];
    while output.len() < target_len {
        let remaining = target_len.saturating_sub(output.len());
        let read_len = remaining.min(scratch.len());
        let buffer = scratch
            .get_mut(..read_len)
            .ok_or(ClientHelloReadErrorKind::UnexpectedEof)?;
        let read = match time::timeout_at(deadline, reader.read(buffer)).await {
            Ok(Ok(0)) => return Err(ClientHelloReadErrorKind::UnexpectedEof),
            Ok(Ok(read)) => read,
            Ok(Err(source)) => return Err(ClientHelloReadErrorKind::Io(source)),
            Err(_) => return Err(ClientHelloReadErrorKind::Timeout),
        };
        let bytes = buffer
            .get(..read)
            .ok_or(ClientHelloReadErrorKind::UnexpectedEof)?;
        output.extend_from_slice(bytes);
    }
    Ok(())
}

const fn failure(kind: ClientHelloReadErrorKind, wire_prefix: Vec<u8>) -> ClientHelloReadError {
    ClientHelloReadError { kind, wire_prefix }
}

#[cfg(test)]
mod tests {
    use std::{io, pin::Pin, task::Poll, time::Duration};

    use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

    use super::{ClientHelloReadErrorKind, MAX_TLS_PLAINTEXT_BYTES, read_client_hello};
    use crate::protocol::reality::client_hello::fixtures::{client_hello, record};

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
    async fn reads_network_fragmentation_one_byte_at_a_time() {
        let message = client_hello([7; 32], &[0xcd; 32], "www.example.com", &[b"h2"]);
        let wire = record(&message);
        let mut reader = OneByteReader {
            bytes: wire.clone(),
            position: 0,
        };

        let read = read_client_hello(&mut reader, Duration::from_secs(1))
            .await
            .expect("fragmented ClientHello must be read");

        assert_eq!(read.fallback_prefix(), wire);
        assert_eq!(read.hello().raw_message(), message);
        assert!(read.handshake_remainder().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn assembles_client_hello_across_tls_records() {
        let message = client_hello([1; 32], &[2; 32], "a.example", &[]);
        let first_end = 17;
        let second_end = 83;
        let mut wire = record(message.get(..first_end).expect("first fragment must exist"));
        wire.extend_from_slice(&record(
            message
                .get(first_end..second_end)
                .expect("second fragment must exist"),
        ));
        wire.extend_from_slice(&record(
            message
                .get(second_end..)
                .expect("third fragment must exist"),
        ));
        let mut reader = OneByteReader {
            bytes: wire.clone(),
            position: 0,
        };

        let read = read_client_hello(&mut reader, Duration::from_secs(1))
            .await
            .expect("record-fragmented ClientHello must be read");

        assert_eq!(read.fallback_prefix(), wire);
        assert_eq!(read.hello().raw_message(), message);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preserves_same_record_handshake_remainder() {
        let message = client_hello([1; 32], &[2; 32], "a.example", &[]);
        let remainder = [0x02, 0, 0, 0];
        let mut body = message.clone();
        body.extend_from_slice(&remainder);
        let wire = record(&body);
        let mut reader = OneByteReader {
            bytes: wire.clone(),
            position: 0,
        };

        let read = read_client_hello(&mut reader, Duration::from_secs(1))
            .await
            .expect("ClientHello with remainder must be read");

        assert_eq!(read.fallback_prefix(), wire);
        assert_eq!(read.handshake_remainder(), remainder);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parse_failure_returns_byte_exact_prefix() {
        let mut message = client_hello([1; 32], &[2; 32], "a.example", &[]);
        message[0] = 0x02;
        let wire = record(&message);
        let mut reader = OneByteReader {
            bytes: wire.clone(),
            position: 0,
        };

        let error = read_client_hello(&mut reader, Duration::from_secs(1))
            .await
            .expect_err("non-ClientHello must fail");

        assert!(matches!(error.kind(), ClientHelloReadErrorKind::Invalid(_)));
        assert_eq!(error.fallback_prefix(), wire);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_returns_every_received_byte() {
        let (mut client, mut server) = tokio::io::duplex(16);
        let prefix = [0x16, 0x03, 0x01];
        server
            .write_all(&prefix)
            .await
            .expect("partial header must be written");

        let error = read_client_hello(&mut client, Duration::from_millis(20))
            .await
            .expect_err("incomplete header must time out");

        assert!(matches!(error.kind(), ClientHelloReadErrorKind::Timeout));
        assert_eq!(error.fallback_prefix(), prefix);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_oversized_record_before_reading_body() {
        let oversized =
            u16::try_from(MAX_TLS_PLAINTEXT_BYTES + 1).expect("test record length must fit u16");
        let header = [
            0x16,
            0x03,
            0x01,
            oversized.to_be_bytes()[0],
            oversized.to_be_bytes()[1],
        ];
        let mut reader = OneByteReader {
            bytes: header.to_vec(),
            position: 0,
        };

        let error = read_client_hello(&mut reader, Duration::from_secs(1))
            .await
            .expect_err("oversized record must fail");

        assert!(matches!(
            error.kind(),
            ClientHelloReadErrorKind::RecordTooLarge
        ));
        assert_eq!(error.fallback_prefix(), header);
    }
}
