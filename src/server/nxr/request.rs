//! Bounded read of the NXR open request that follows the pre-auth first byte.

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{self, Instant},
};

use crate::protocol::{
    nxr::{
        FLAG_UDP, NxrProtocolError, REQUEST_HEADER_LEN, peek_open_flags, request_len_from_header,
    },
    nxr_udp::udp_open_len_from_header,
};

use super::NxrLandingError;

pub(super) async fn read_request_after_first(
    stream: &mut TcpStream,
    first_byte: u8,
    deadline: Instant,
) -> Result<Vec<u8>, NxrLandingError> {
    let mut header = [0_u8; REQUEST_HEADER_LEN];
    header[0] = first_byte;
    read_exact_before(stream, &mut header[1..], deadline).await?;
    let total = match peek_open_flags(&header) {
        Some(FLAG_UDP) => udp_open_len_from_header(&header)
            .map_err(|error| NxrLandingError::Protocol(NxrProtocolError::from(error)))?,
        _ => request_len_from_header(&header).map_err(NxrLandingError::Protocol)?,
    };
    let mut request = Vec::new();
    request
        .try_reserve_exact(total)
        .map_err(|_| NxrLandingError::Allocation)?;
    request.extend_from_slice(&header);
    request.resize(total, 0);
    read_exact_before(stream, &mut request[REQUEST_HEADER_LEN..], deadline).await?;
    Ok(request)
}

async fn read_exact_before(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), NxrLandingError> {
    time::timeout_at(deadline, stream.read_exact(output))
        .await
        .map_err(|_| NxrLandingError::Timeout)?
        .map(|_| ())
        .map_err(NxrLandingError::Read)
}

pub(super) fn unix_seconds() -> Result<u64, NxrLandingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NxrLandingError::Clock)
}
