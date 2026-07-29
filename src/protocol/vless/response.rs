use std::{error::Error, fmt, io};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::RequestHeader;

const MAX_ADDONS_LENGTH: usize = u8::MAX as usize;

/// An error produced while encoding a VLESS response header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseEncodeError {
    /// The Addons field cannot fit in its one-byte length prefix.
    AddonsTooLong { length: usize, maximum: usize },
}

impl fmt::Display for ResponseEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddonsTooLong { length, maximum } => write!(
                formatter,
                "VLESS response Addons length {length} exceeds \
                the {maximum}-byte limit"
            ),
        }
    }
}

impl Error for ResponseEncodeError {}

/// An error produced while writing a VLESS response header.
#[derive(Debug)]
pub enum ResponseWriteError {
    /// The response header could not be encoded.
    Encode(ResponseEncodeError),

    /// The encoded response header could not be written.
    Io(io::Error),
}

impl fmt::Display for ResponseWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => {
                write!(formatter, "failed to encode VLESS response header: {error}")
            }
            Self::Io(error) => write!(formatter, "failed to write VLESS response header: {error}"),
        }
    }
}

impl Error for ResponseWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<ResponseEncodeError> for ResponseWriteError {
    fn from(error: ResponseEncodeError) -> Self {
        Self::Encode(error)
    }
}

impl From<io::Error> for ResponseWriteError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encodes a VLESS response header.
///
/// The response version is copied from the corresponding request header.
pub fn encode_response_header(
    request: &RequestHeader,
    addons: &[u8],
) -> Result<Vec<u8>, ResponseEncodeError> {
    let addons_length =
        u8::try_from(addons.len()).map_err(|_| ResponseEncodeError::AddonsTooLong {
            length: addons.len(),
            maximum: MAX_ADDONS_LENGTH,
        })?;

    let mut encoded = Vec::with_capacity(2 + addons.len());

    encoded.push(request.version());
    encoded.push(addons_length);
    encoded.extend_from_slice(addons);

    Ok(encoded)
}

/// Encodes and writes a VLESS response header to an asynchronous stream.
pub async fn write_response_header<W>(
    writer: &mut W,
    request: &RequestHeader,
    addons: &[u8],
) -> Result<(), ResponseWriteError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let encoded = encode_response_header(request, addons)?;

    writer.write_all(&encoded).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, duplex};

    use super::{ResponseEncodeError, encode_response_header, write_response_header};
    use crate::protocol::vless::{Command, RequestHeader, UserId, VERSION};

    #[test]
    fn encodes_empty_response_header() {
        let request = request_header();

        let encoded = encode_response_header(&request, &[]).expect("empty response should encode");

        assert_eq!(encoded, [VERSION, 0]);
    }

    #[test]
    fn encodes_response_addons() {
        let request = request_header();
        let addons = [0xaa, 0xbb, 0xcc];

        let encoded =
            encode_response_header(&request, &addons).expect("response Addons should encode");

        assert_eq!(encoded, [VERSION, 3, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn rejects_addons_larger_than_wire_length() {
        let request = request_header();
        let addons = vec![0_u8; 256];

        assert_eq!(
            encode_response_header(&request, &addons),
            Err(ResponseEncodeError::AddonsTooLong {
                length: 256,
                maximum: 255,
            })
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writes_response_header_to_async_stream() {
        let request = request_header();
        let addons = [0xaa, 0xbb];

        let (mut client, mut server) = duplex(64);

        write_response_header(&mut server, &request, &addons)
            .await
            .expect("response header should be written");

        let mut encoded = [0_u8; 4];

        client
            .read_exact(&mut encoded)
            .await
            .expect("client should read response header");

        assert_eq!(encoded, [VERSION, 2, 0xaa, 0xbb]);
    }

    fn request_header() -> RequestHeader {
        RequestHeader::new(
            VERSION,
            UserId::new([0_u8; 16]),
            Vec::new(),
            Command::Mux,
            None,
        )
    }
}
