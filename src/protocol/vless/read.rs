use std::{error::Error, fmt, io};

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{DecodeError, RequestHeader, decode_request};

/// Maximum version-zero VLESS request header size.
///
/// This includes a 255-byte Addons field and a 255-byte domain.
const MAX_REQUEST_HEADER_SIZE: usize = 533;

/// An owned VLESS request read from an asynchronous byte stream.
#[derive(Debug, Eq, PartialEq)]
pub struct ReadRequest {
    header: RequestHeader,
    payload: Vec<u8>,
}

impl ReadRequest {
    /// Returns the decoded request header.
    pub fn header(&self) -> &RequestHeader {
        &self.header
    }

    /// Returns payload bytes that were read together with the header.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Splits the request into its header and prefetched payload.
    pub fn into_parts(self) -> (RequestHeader, Vec<u8>) {
        (self.header, self.payload)
    }
}

/// An error produced while reading a VLESS request from a stream.
#[derive(Debug)]
pub enum ReadError {
    /// The underlying stream returned an I/O error.
    Io(io::Error),

    /// The stream contained a complete but invalid protocol field.
    Decode(DecodeError),

    /// The stream reached EOF before the request header was complete.
    UnexpectedEof(DecodeError),

    /// The request remained incomplete at the maximum header size.
    HeaderToolLarge { limit: usize },
}

impl fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read VLESS request: {error}"),
            Self::Decode(error) => write!(formatter, "invalid VLESS request: {error}"),
            Self::UnexpectedEof(error) => write!(
                formatter,
                "connection closed before the VLESS request was complete: {error}"
            ),
            Self::HeaderToolLarge { limit } => write!(
                formatter,
                "VLESS request header exceeds the {limit}-byte limit"
            ),
        }
    }
}

impl Error for ReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Decode(error) | Self::UnexpectedEof(error) => Some(error),
            Self::HeaderToolLarge { .. } => None,
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads and decodes one VLESS request header from an asynchronous stream.
///
/// Payload bytes read in the same operation as the end of the header are
/// preserved in the returned value.
pub async fn read_request<R>(reader: &mut R) -> Result<ReadRequest, ReadError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(MAX_REQUEST_HEADER_SIZE);
    let mut chunk = [0_u8; MAX_REQUEST_HEADER_SIZE];

    loop {
        match decode_request(&buffer) {
            Ok(decoded) => {
                let (header, payload) = decoded.into_parts();

                return Ok(ReadRequest {
                    header,
                    payload: payload.to_vec(),
                });
            }

            Err(error @ DecodeError::UnexpectedEnd { .. }) => {
                if buffer.len() >= MAX_REQUEST_HEADER_SIZE {
                    return Err(ReadError::HeaderToolLarge {
                        limit: MAX_REQUEST_HEADER_SIZE,
                    });
                }

                let remaining_capacity = MAX_REQUEST_HEADER_SIZE - buffer.len();

                let read = reader.read(&mut chunk[..remaining_capacity]).await?;

                if read == 0 {
                    return Err(ReadError::UnexpectedEof(error));
                }

                buffer.extend_from_slice(&chunk[..read]);
            }

            Err(error) => {
                return Err(ReadError::Decode(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncWriteExt, duplex},
        task::yield_now,
    };

    use super::{ReadError, read_request};
    use crate::protocol::vless::{Address, Command, DecodeError, VERSION};

    const USER_ID: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    const PAYLOAD: &[u8] = b"prefetched payload";

    #[tokio::test(flavor = "current_thread")]
    async fn reads_header_fragmented_one_byte_at_a_time() {
        let packet = domain_request(&[]);
        let (mut writer, mut reader) = duplex(64);

        let write = async move {
            for byte in packet {
                writer.write_all(&[byte]).await?;
                yield_now().await;
            }

            writer.shutdown().await
        };

        let read = read_request(&mut reader);

        let (write_result, read_result) = tokio::join!(write, read);

        write_result.expect("fragmented request should be written");

        let request = read_result.expect("fragmented request should decode");

        assert!(request.payload().is_empty());
        assert_eq!(request.header().command(), Command::Tcp);

        let destination = request
            .header()
            .destination()
            .expect("TCP request should contain a destination");

        assert_eq!(destination.port(), 443);
        assert_eq!(
            destination.address(),
            &Address::Domain("example.com".to_owned())
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preserves_payload_read_with_header() {
        let packet = domain_request(PAYLOAD);
        let (mut writer, mut reader) = duplex(1024);

        writer
            .write_all(&packet)
            .await
            .expect("complete request should fit in duplex buffer");

        let request = read_request(&mut reader)
            .await
            .expect("complete request should decode");

        assert_eq!(request.payload(), PAYLOAD);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reports_eof_before_complete_header() {
        let (mut writer, mut reader) = duplex(64);

        writer
            .write_all(&[VERSION])
            .await
            .expect("version byte should be written");

        writer.shutdown().await.expect("writer should half-close");

        let error = read_request(&mut reader)
            .await
            .expect_err("truncated request should fail");

        match error {
            ReadError::UnexpectedEof(DecodeError::UnexpectedEnd {
                field,
                needed,
                remaining,
            }) => {
                assert_eq!(field, "user ID");
                assert_eq!(needed, 16);
                assert_eq!(remaining, 0);
            }
            other => {
                panic!("unexpected read error: {other}");
            }
        }
    }

    fn domain_request(payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.push(VERSION);
        packet.extend_from_slice(&USER_ID);
        packet.push(0);
        packet.push(Command::Tcp.as_bytes());
        packet.extend_from_slice(&443_u16.to_be_bytes());
        packet.push(0x02);
        packet.push(11);
        packet.extend_from_slice(b"example.com");
        packet.extend_from_slice(payload);

        packet
    }
}
