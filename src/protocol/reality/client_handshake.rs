//! TLS 1.3 client completion of a REALITY-authenticated server flight.
//!
//! After [`super::build_client_hello`] the peer must answer with a target-shaped
//! ServerHello plus encrypted `EncryptedExtensions` through Finished. This
//! module opens that flight under the shared authenticator key, verifies the
//! forged certificate binding, returns ClientFinished, and hands back
//! application traffic state.

use std::{error::Error, fmt, io, time::Duration};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    AuthKey, ClientHello, ClientKeyAgreement, HelloRecord,
    client_verify::{
        CertificateError, parse_encrypted_extensions, verify_certificate_signature,
        verify_finished, verify_server_certificate,
    },
    tls13::{
        CipherSuite, ContentType, EstablishedTls, RealityHandshakeError, ServerFlight,
        ServerHelloError, ServerHelloTemplate, Tls13KeySchedule, Tls13RecordError,
        Tls13RecordLayer, TlsRecordReadError, TlsRecordReadErrorKind, TranscriptHasher,
        change_cipher_spec_record, finished_message, read_tls_record,
    },
};

const OUTER_HANDSHAKE: u8 = 22;
const OUTER_CHANGE_CIPHER_SPEC: u8 = 20;
const OUTER_APPLICATION_DATA: u8 = 23;
const OUTER_ALERT: u8 = 21;
const RECORD_HEADER_LEN: usize = 5;
const MAX_HANDSHAKE_BUFFER: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// A REALITY client handshake could not finish.
#[derive(Debug)]
pub enum ClientHandshakeError {
    /// The peer's ServerHello was not REALITY-compatible.
    ServerHello(ServerHelloError),
    /// Key agreement failed or was non-contributory.
    KeyAgreement,
    /// Certificate binding, signature, ALPN, or Finished failed.
    Certificate(CertificateError),
    /// TLS 1.3 key derivation failed.
    KeySchedule,
    /// Record protection failed.
    Record(Tls13RecordError),
    /// A handshake message could not be framed.
    Message,
    /// A fixed protocol invariant was violated.
    Protocol(&'static str),
    /// The peer closed mid-handshake.
    UnexpectedEof,
    /// The absolute handshake deadline elapsed.
    Timeout,
    /// Socket I/O failed.
    Io(io::Error),
    /// A bounded buffer could not grow.
    BufferAllocation,
}

impl fmt::Display for ClientHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("REALITY client TLS 1.3 handshake failed")
    }
}

impl Error for ClientHandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ServerHello(error) => Some(error),
            Self::Certificate(error) => Some(error),
            Self::Record(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ServerHelloError> for ClientHandshakeError {
    fn from(error: ServerHelloError) -> Self {
        Self::ServerHello(error)
    }
}

impl From<CertificateError> for ClientHandshakeError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

impl From<Tls13RecordError> for ClientHandshakeError {
    fn from(error: Tls13RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<TlsRecordReadError> for ClientHandshakeError {
    fn from(error: TlsRecordReadError) -> Self {
        match error.into_parts().0 {
            TlsRecordReadErrorKind::Timeout => Self::Timeout,
            TlsRecordReadErrorKind::UnexpectedEof => Self::UnexpectedEof,
            TlsRecordReadErrorKind::Io(error) => Self::Io(error),
            TlsRecordReadErrorKind::RecordTooLarge => Self::Protocol("record length"),
        }
    }
}

/// Negotiated parameters retained after ClientFinished.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    /// Selected TLS 1.3 cipher suite.
    pub suite: CipherSuite,
    /// Selected ALPN protocol, when the server claimed one.
    pub alpn: Option<Vec<u8>>,
    /// Selected key-share group.
    pub key_share_group: u16,
}

/// Application traffic state owned by the client after a successful handshake.
pub struct ClientSession {
    negotiated: Negotiated,
    /// Client→server application records.
    write: Tls13RecordLayer,
    /// Server→client application records.
    read: Tls13RecordLayer,
}

impl ClientSession {
    /// Returns the negotiated parameters.
    #[must_use]
    pub const fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// Returns the record layer used to seal client→server application data.
    pub const fn write_mut(&mut self) -> &mut Tls13RecordLayer {
        &mut self.write
    }

    /// Returns the record layer used to open server→client application data.
    pub const fn read_mut(&mut self) -> &mut Tls13RecordLayer {
        &mut self.read
    }

    /// Performs a directional KeyUpdate on the write traffic secret.
    ///
    /// # Errors
    ///
    /// Rejects KeyUpdate before application traffic is active.
    pub fn update_write_secret(&mut self) -> Result<(), Tls13RecordError> {
        self.write.update_traffic_secret()
    }

    /// Performs a directional KeyUpdate on the read traffic secret.
    ///
    /// # Errors
    ///
    /// Rejects KeyUpdate before application traffic is active.
    pub fn update_read_secret(&mut self) -> Result<(), Tls13RecordError> {
        self.read.update_traffic_secret()
    }

    /// Separates the directional record layers while preserving ownership.
    #[must_use]
    pub fn into_record_layers(self) -> (Negotiated, Tls13RecordLayer, Tls13RecordLayer) {
        (self.negotiated, self.write, self.read)
    }
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSession")
            .field("negotiated", &self.negotiated)
            .field("write", &"[REDACTED]")
            .field("read", &"[REDACTED]")
            .finish()
    }
}

/// Completes the TLS 1.3 client handshake against a REALITY peer.
///
/// # Errors
///
/// Rejects an incompatible ServerHello, a certificate that is not bound to
/// `auth_key`, a bad Finished, record-protection failure, and I/O errors.
pub async fn complete<S>(
    stream: &mut S,
    hello: &HelloRecord,
    keys: ClientKeyAgreement,
    auth_key: &AuthKey,
    offered_alpn: &[&[u8]],
) -> Result<ClientSession, ClientHandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client = ClientHello::parse_message(hello.message())
        .map_err(|_| ClientHandshakeError::Protocol("client hello parse"))?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(RECORD_HEADER_LEN + 16 * 1024)
        .map_err(|_| ClientHandshakeError::BufferAllocation)?;

    let server_hello = read_server_hello(stream, &client, &mut scratch).await?;
    let shared = keys
        .tls_shared_secret(
            server_hello.key_share_group(),
            server_hello
                .observed_key_exchange()
                .ok_or(ClientHandshakeError::KeyAgreement)?,
        )
        .ok_or(ClientHandshakeError::KeyAgreement)?;

    let suite = server_hello.suite();
    let mut hasher = TranscriptHasher::new(suite.hash());
    hasher.update(hello.message());
    hasher.update(server_hello.raw_message());
    let schedule = Tls13KeySchedule::new(suite, shared.as_bytes(), &hasher.snapshot())
        .map_err(|_| ClientHandshakeError::KeySchedule)?;
    let server_handshake_keys = schedule
        .traffic_keys(schedule.server_handshake_secret())
        .map_err(|_| ClientHandshakeError::KeySchedule)?;
    let mut server_records = Tls13RecordLayer::new(suite, server_handshake_keys)?;

    let mut flight = MessageBuffer::new();
    let encrypted_extensions =
        next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    let alpn = parse_encrypted_extensions(&encrypted_extensions, offered_alpn)?;
    hasher.update(&encrypted_extensions);

    let certificate = next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    let certificate_key = verify_server_certificate(&certificate, auth_key)?;
    hasher.update(&certificate);

    let certificate_verify =
        next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    verify_certificate_signature(
        &certificate_verify,
        &certificate_key,
        hasher.snapshot().as_bytes(),
    )?;
    hasher.update(&certificate_verify);

    let server_finished =
        next_message(stream, &mut scratch, &mut server_records, &mut flight).await?;
    let expected = schedule
        .finished_verify_data(schedule.server_handshake_secret(), &hasher.snapshot())
        .map_err(|_| ClientHandshakeError::KeySchedule)?;
    verify_finished(&server_finished, expected.as_bytes())?;
    hasher.update(&server_finished);
    let through_server_finished = hasher.snapshot();

    let client_handshake_keys = schedule
        .traffic_keys(schedule.client_handshake_secret())
        .map_err(|_| ClientHandshakeError::KeySchedule)?;
    let mut client_records = Tls13RecordLayer::new(suite, client_handshake_keys)?;
    let client_finished = schedule
        .finished_verify_data(schedule.client_handshake_secret(), &through_server_finished)
        .map_err(|_| ClientHandshakeError::KeySchedule)?;
    let finished =
        finished_message(client_finished.as_bytes()).map_err(|_| ClientHandshakeError::Message)?;

    let mut response = Vec::new();
    response
        .try_reserve_exact(
            change_cipher_spec_record().len() + RECORD_HEADER_LEN + finished.len() + 64,
        )
        .map_err(|_| ClientHandshakeError::BufferAllocation)?;
    response.extend_from_slice(&change_cipher_spec_record());
    let mut sealed = Vec::new();
    client_records.seal_into(ContentType::Handshake, &finished, 0, &mut sealed)?;
    response.extend_from_slice(&sealed);
    stream.write_all(&response).await.map_err(socket_failure)?;
    stream.flush().await.map_err(socket_failure)?;

    let application = schedule
        .application_traffic_secrets(&through_server_finished)
        .map_err(|_| ClientHandshakeError::KeySchedule)?;
    let key_share_group = server_hello.key_share_group();
    let (client_secret, server_secret) = application.into_parts();
    let write = Tls13RecordLayer::from_traffic_secret(suite, client_secret)?;
    let read = Tls13RecordLayer::from_traffic_secret(suite, server_secret)?;

    Ok(ClientSession {
        negotiated: Negotiated {
            suite,
            alpn,
            key_share_group,
        },
        write,
        read,
    })
}

/// Drives a client handshake against an in-memory [`ServerFlight`] and returns
/// both peers' application traffic state after ClientFinished.
///
/// # Errors
///
/// Same rejection classes as [`complete`], plus a ClientFinished mismatch.
pub async fn establish_with_server_flight(
    hello: &HelloRecord,
    keys: ClientKeyAgreement,
    auth_key: &AuthKey,
    offered_alpn: &[&[u8]],
    flight: ServerFlight,
) -> Result<(ClientSession, EstablishedTls), ClientHandshakeError> {
    let wire = flight.wire().to_vec();
    let capacity = wire
        .len()
        .saturating_add(change_cipher_spec_record().len())
        .saturating_add(1024)
        .max(64 * 1024);
    let (mut client_end, mut server_end) = tokio::io::duplex(capacity);
    server_end.write_all(&wire).await.map_err(socket_failure)?;

    let client_task = complete(&mut client_end, hello, keys, auth_key, offered_alpn);
    let server_task = async {
        let mut buffer = vec![0_u8; 2048];
        let mut offset = 0_usize;
        let flight = flight;
        loop {
            if offset + RECORD_HEADER_LEN > buffer.len() {
                buffer.resize(offset + RECORD_HEADER_LEN + 16 * 1024, 0);
            }
            server_end
                .read_exact(&mut buffer[offset..offset + RECORD_HEADER_LEN])
                .await
                .map_err(socket_failure)?;
            let body_len =
                usize::from(u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]));
            let record_end = offset
                .checked_add(RECORD_HEADER_LEN)
                .and_then(|start| start.checked_add(body_len))
                .ok_or(ClientHandshakeError::BufferAllocation)?;
            if record_end > buffer.len() {
                buffer.resize(record_end, 0);
            }
            server_end
                .read_exact(&mut buffer[offset + RECORD_HEADER_LEN..record_end])
                .await
                .map_err(socket_failure)?;
            let outer = buffer[offset];
            if outer == OUTER_CHANGE_CIPHER_SPEC {
                offset = record_end;
                continue;
            }
            if outer != OUTER_APPLICATION_DATA {
                return Err(ClientHandshakeError::Protocol(
                    "client finished was not application data",
                ));
            }
            let mut record = buffer[offset..record_end].to_vec();
            let established = flight
                .verify_client_finished(&mut record)
                .map_err(|error| match error {
                    RealityHandshakeError::ClientFinished => {
                        ClientHandshakeError::Protocol("client finished")
                    }
                    _ => ClientHandshakeError::Protocol("client finished"),
                })?;
            return Ok(established);
        }
    };
    let (session, established) = tokio::try_join!(client_task, server_task)?;
    Ok((session, established))
}

async fn read_server_hello<S>(
    stream: &mut S,
    client: &ClientHello,
    scratch: &mut Vec<u8>,
) -> Result<ServerHelloTemplate, ClientHandshakeError>
where
    S: AsyncRead + Unpin,
{
    let record = read_tls_record(stream, HANDSHAKE_TIMEOUT).await?;
    if record.outer_content_type() != OUTER_HANDSHAKE {
        return Err(ClientHandshakeError::Protocol(
            "server hello was not a plaintext handshake record",
        ));
    }
    scratch.clear();
    scratch.extend_from_slice(record.wire());
    let body = scratch
        .get(RECORD_HEADER_LEN..)
        .ok_or(ClientHandshakeError::Protocol("server hello record"))?;
    Ok(ServerHelloTemplate::parse(body, client)?)
}

async fn next_message<S>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    server_records: &mut Tls13RecordLayer,
    flight: &mut MessageBuffer,
) -> Result<Vec<u8>, ClientHandshakeError>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(message) = flight.take_message()? {
            return Ok(message);
        }
        let record = read_tls_record(stream, HANDSHAKE_TIMEOUT).await?;
        scratch.clear();
        scratch.extend_from_slice(record.wire());
        match record.outer_content_type() {
            OUTER_CHANGE_CIPHER_SPEC => {
                if scratch.as_slice() != change_cipher_spec_record().as_slice() {
                    return Err(ClientHandshakeError::Protocol(
                        "invalid change cipher spec record",
                    ));
                }
            }
            OUTER_APPLICATION_DATA => {
                let opened = server_records.open_in_place(scratch).map_err(|_| {
                    // Handshake keys come from the REALITY agreement; a record
                    // that will not open was not produced by our node.
                    ClientHandshakeError::Certificate(CertificateError::Binding)
                })?;
                if opened.content_type() != ContentType::Handshake {
                    return Err(ClientHandshakeError::Protocol(
                        "encrypted record was not a handshake message",
                    ));
                }
                flight.push(opened.plaintext())?;
            }
            OUTER_ALERT => {
                return Err(ClientHandshakeError::Protocol(
                    "peer sent a plaintext alert",
                ));
            }
            _ => {
                return Err(ClientHandshakeError::Protocol(
                    "unexpected record before server finished",
                ));
            }
        }
    }
}

fn socket_failure(error: io::Error) -> ClientHandshakeError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset => ClientHandshakeError::UnexpectedEof,
        _ => ClientHandshakeError::Io(error),
    }
}

struct MessageBuffer {
    bytes: Vec<u8>,
}

impl MessageBuffer {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn push(&mut self, plaintext: &[u8]) -> Result<(), ClientHandshakeError> {
        let end = self
            .bytes
            .len()
            .checked_add(plaintext.len())
            .filter(|length| *length <= MAX_HANDSHAKE_BUFFER)
            .ok_or(ClientHandshakeError::BufferAllocation)?;
        self.bytes
            .try_reserve(plaintext.len())
            .map_err(|_| ClientHandshakeError::BufferAllocation)?;
        self.bytes.extend_from_slice(plaintext);
        debug_assert_eq!(self.bytes.len(), end);
        Ok(())
    }

    fn take_message(&mut self) -> Result<Option<Vec<u8>>, ClientHandshakeError> {
        if self.bytes.len() < 4 {
            return Ok(None);
        }
        let declared = (usize::from(self.bytes[1]) << 16)
            | (usize::from(self.bytes[2]) << 8)
            | usize::from(self.bytes[3]);
        let total = declared
            .checked_add(4)
            .ok_or(ClientHandshakeError::Protocol("handshake length"))?;
        if self.bytes.len() < total {
            return Ok(None);
        }
        let message = self.bytes.drain(..total).collect();
        Ok(Some(message))
    }
}

/// Constant-time helper retained for mirror tests against server Finished bytes.
#[cfg(test)]
fn verify_data_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests;
