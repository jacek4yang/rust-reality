use std::{error::Error, fmt, time::Duration};

use tokio::{io::AsyncRead, time::Instant};

use super::{
    EstablishedTls, RealityHandshakeError, ServerFlight, TlsRecordReadError,
    change_cipher_spec_record, read_tls_record,
};

const OUTER_APPLICATION_DATA: u8 = 23;
const OUTER_CHANGE_CIPHER_SPEC: u8 = 20;

/// A ClientFinished could not be read and authenticated under the handshake keys.
#[derive(Debug)]
pub enum ClientFinishedReadError {
    /// The requested absolute handshake deadline could not be represented.
    Timeout,
    /// Reading an exact bounded TLS record failed.
    Record(TlsRecordReadError),
    /// A ChangeCipherSpec record differed from the fixed compatibility value.
    InvalidChangeCipherSpec,
    /// A plaintext or otherwise unexpected record preceded ClientFinished.
    UnexpectedRecord,
    /// The encrypted Finished record failed AEAD, framing, or verify-data checks.
    Verify(RealityHandshakeError),
}

impl fmt::Display for ClientFinishedReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("TLS ClientFinished read timed out"),
            Self::Record(source) => source.fmt(formatter),
            Self::InvalidChangeCipherSpec => {
                formatter.write_str("invalid TLS ChangeCipherSpec compatibility record")
            }
            Self::UnexpectedRecord => formatter.write_str("expected encrypted TLS ClientFinished"),
            Self::Verify(source) => source.fmt(formatter),
        }
    }
}

impl Error for ClientFinishedReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Record(source) => Some(source),
            Self::Verify(source) => Some(source),
            Self::Timeout | Self::InvalidChangeCipherSpec | Self::UnexpectedRecord => None,
        }
    }
}

/// Reads an optional exact CCS followed by one encrypted ClientFinished record.
///
/// The deadline covers both records. Successful return is the only transition to
/// application traffic state; the `ServerFlight` is consumed on every verify path
/// so failed handshake sequence state cannot be retried or reused.
///
/// # Errors
///
/// Returns a framing, deadline, compatibility-record, AEAD, or Finished error.
pub async fn read_client_finished<R>(
    reader: &mut R,
    flight: ServerFlight,
    timeout: Duration,
) -> Result<EstablishedTls, ClientFinishedReadError>
where
    R: AsyncRead + Unpin,
{
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(ClientFinishedReadError::Timeout);
    };
    let first = read_tls_record(reader, deadline.saturating_duration_since(Instant::now()))
        .await
        .map_err(ClientFinishedReadError::Record)?;
    let encrypted = if first.outer_content_type() == OUTER_CHANGE_CIPHER_SPEC {
        if first.wire() != change_cipher_spec_record() {
            return Err(ClientFinishedReadError::InvalidChangeCipherSpec);
        }
        read_tls_record(reader, deadline.saturating_duration_since(Instant::now()))
            .await
            .map_err(ClientFinishedReadError::Record)?
    } else {
        first
    };
    if encrypted.outer_content_type() != OUTER_APPLICATION_DATA {
        return Err(ClientFinishedReadError::UnexpectedRecord);
    }
    let mut wire = encrypted.into_wire();
    flight
        .verify_client_finished(&mut wire)
        .map_err(ClientFinishedReadError::Verify)
}
