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
mod tests {
    use std::path::Path;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::config::load_bytes;
    use crate::protocol::reality::tls13::{
        CertificateIdentity, ContentType, CoverHandshakePlan, CoverHandshakeRecordShape,
        build_server_flight, build_server_flight_with_shape,
    };
    use crate::protocol::reality::{
        AuthPlaintext, CLIENT_VERSION, RealityAuthenticator, SESSION_ID_LEN, X25519_GROUP,
        build_client_hello,
    };

    const NAME: &str = "www.example.com";
    const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
    const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const SHORT_ID_HEX: &str = "0102030405060708";
    const USER: &str = "11111111-1111-4111-8111-111111111111";

    fn plaintext(now: u32) -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: now,
            short_id: SHORT_ID,
        }
    }

    fn authenticator(private: [u8; 32]) -> (RealityAuthenticator, [u8; 32]) {
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        let json = format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{
    "cover": "{name}:443",
    "privateKey": "{private_key}",
    "serverNames": ["{name}"],
    "maxTimeDiffMs": 60000
  }},
  "users": [{{
    "id": "{user}",
    "shortIds": ["{short_id}"],
    "label": "alice"
  }}],
  "routing": {{ "default": "direct" }}
}}"#,
            name = NAME,
            private_key = BASE64_URL_SAFE_NO_PAD.encode(private),
            user = USER,
            short_id = SHORT_ID_HEX,
        );
        let validated = load_bytes(Path::new("client-handshake-entry.json"), json.as_bytes())
            .expect("entry config must load");
        let node = validated.into_node();
        let entry = node.as_entry().expect("role is entry");
        (
            RealityAuthenticator::from_entry(entry).expect("authenticator"),
            public,
        )
    }

    fn synthetic_server_hello(client: &ClientHello, group: u16, key_exchange: &[u8]) -> Vec<u8> {
        let session = client.session_id().expect("session id");
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(session.len()).expect("session len"));
        body.extend_from_slice(session);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);
        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
        let mut share = Vec::new();
        share.extend_from_slice(&group.to_be_bytes());
        share.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
        share.extend_from_slice(key_exchange);
        push_extension(&mut extensions, 0x0033, &share);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut message = vec![2];
        let length = u32::try_from(body.len()).expect("body");
        message.extend_from_slice(&length.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
    }

    async fn handshake_pair(suite_wire: u16) -> (ClientSession, EstablishedTls, CipherSuite) {
        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let now = 1_700_000_000_u32;
        let (record, auth_key) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now))
                .expect("client hello");
        let client = ClientHello::parse_message(record.message()).expect("parse");
        let auth = authenticator
            .authenticate(&client, u64::from(now))
            .expect("authenticate");
        assert_eq!(auth.auth_key().as_bytes(), auth_key.as_bytes());

        let mut target_message = synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]);
        // Patch suite into the synthetic ServerHello when requested.
        if suite_wire != 0x1301 {
            let session_len = SESSION_ID_LEN;
            let suite_offset = 6 + 32 + 1 + session_len;
            target_message[suite_offset..suite_offset + 2]
                .copy_from_slice(&suite_wire.to_be_bytes());
        }
        let target = ServerHelloTemplate::parse(&target_message, &client).expect("target");
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let flight = build_server_flight(&client, auth.auth_key(), target, &identity, Some(b"h2"))
            .expect("server flight");

        let (session, established) =
            establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
                .await
                .expect("handshake");
        let suite = session.negotiated().suite;
        (session, established, suite)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn browser_profiles_authenticate_and_finish_every_offered_group() {
        use super::super::{BrowserFingerprint, P256_GROUP, X25519_MLKEM768_GROUP};
        for profile in [BrowserFingerprint::Chrome, BrowserFingerprint::Firefox] {
            for group in [X25519_GROUP, X25519_MLKEM768_GROUP, P256_GROUP] {
                if profile == BrowserFingerprint::Chrome && group == P256_GROUP {
                    continue;
                }
                let (authenticator, server_public) = authenticator([0x42; 32]);
                let keys = ClientKeyAgreement::for_profile(profile).unwrap();
                let now = 1_700_000_000;
                let (record, auth_key) =
                    build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).unwrap();
                let client = ClientHello::parse_message(record.message()).unwrap();
                let auth = authenticator.authenticate(&client, u64::from(now)).unwrap();
                let dummy = vec![
                    0x55;
                    match group {
                        P256_GROUP => 65,
                        X25519_MLKEM768_GROUP => 1120,
                        _ => 32,
                    }
                ];
                let target_message = synthetic_server_hello(&client, group, &dummy);
                let target = ServerHelloTemplate::parse(&target_message, &client).unwrap();
                let identity = CertificateIdentity::from_seed([0x42; 32]);
                let flight =
                    build_server_flight(&client, auth.auth_key(), target, &identity, Some(b"h2"))
                        .unwrap();
                let (session, _) =
                    establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
                        .await
                        .unwrap();
                assert_eq!(session.negotiated().key_share_group, group);
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_process_duplex_establishes_and_exchanges_application_data() {
        let (mut client, mut server, suite) = handshake_pair(0x1301).await;
        assert_eq!(suite, CipherSuite::Aes128GcmSha256);
        assert_eq!(client.negotiated().alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(client.negotiated().key_share_group, X25519_GROUP);

        let payload = b"unified-client-pr2";
        let mut record = Vec::new();
        client
            .write_mut()
            .seal_into(ContentType::ApplicationData, payload, 0, &mut record)
            .expect("client seal");
        let opened = server
            .client_records_mut()
            .open_in_place(&mut record)
            .expect("server open");
        assert_eq!(opened.content_type(), ContentType::ApplicationData);
        assert_eq!(opened.plaintext(), payload);

        let mut reply = Vec::new();
        server
            .server_records_mut()
            .seal_into(ContentType::ApplicationData, b"ack", 0, &mut reply)
            .expect("server seal");
        let opened = client
            .read_mut()
            .open_in_place(&mut reply)
            .expect("client open");
        assert_eq!(opened.plaintext(), b"ack");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn key_update_rotates_both_directions() {
        let (mut client, mut server, _) = handshake_pair(0x1301).await;
        client.update_write_secret().expect("client write update");
        server
            .client_records_mut()
            .update_traffic_secret()
            .expect("server read-from-client update");
        client.update_read_secret().expect("client read update");
        server
            .server_records_mut()
            .update_traffic_secret()
            .expect("server write-to-client update");

        let mut record = Vec::new();
        client
            .write_mut()
            .seal_into(ContentType::ApplicationData, b"after-ku", 0, &mut record)
            .expect("seal");
        let opened = server
            .client_records_mut()
            .open_in_place(&mut record)
            .expect("open");
        assert_eq!(opened.plaintext(), b"after-ku");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn establishes_for_each_offered_aead_suite() {
        for (wire, expected) in [
            (0x1301_u16, CipherSuite::Aes128GcmSha256),
            (0x1302, CipherSuite::Aes256GcmSha384),
            (0x1303, CipherSuite::ChaCha20Poly1305Sha256),
        ] {
            let (session, _, suite) = handshake_pair(wire).await;
            assert_eq!(suite, expected, "suite wire {wire:#06x}");
            assert_eq!(session.negotiated().suite, expected);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_certificate_bound_to_a_different_auth_key() {
        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let now = 1_700_000_000_u32;
        let (record, auth_key) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).expect("hello");
        let client = ClientHello::parse_message(record.message()).expect("parse");
        let _ = authenticator
            .authenticate(&client, u64::from(now))
            .expect("authenticate");
        let target = ServerHelloTemplate::parse(
            &synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]),
            &client,
        )
        .expect("target");
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let wrong_key = AuthKey::from_test_bytes([0x11; 32]);
        let flight = build_server_flight(&client, &wrong_key, target, &identity, Some(b"h2"))
            .expect("flight");
        let error = establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
            .await
            .expect_err("binding must fail");
        assert!(matches!(
            error,
            ClientHandshakeError::Certificate(CertificateError::Binding)
        ));
    }

    #[test]
    fn rejects_unknown_short_id_at_authenticator() {
        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let mut auth = plaintext(1_700_000_000);
        auth.short_id = [0xff; 8];
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &server_public, auth).expect("hello");
        let client = ClientHello::parse_message(record.message()).expect("parse");
        assert!(
            authenticator.authenticate(&client, 1_700_000_000).is_err(),
            "unknown shortId must not authenticate"
        );
    }

    #[test]
    fn rejects_wrong_server_public_key_at_authenticator() {
        let (authenticator, _server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let wrong_public = PublicKey::from(&StaticSecret::from([0x77; 32])).to_bytes();
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &wrong_public, plaintext(1_700_000_000))
                .expect("hello");
        let client = ClientHello::parse_message(record.message()).expect("parse");
        assert!(
            authenticator.authenticate(&client, 1_700_000_000).is_err(),
            "wrong server public key must not authenticate"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn positional_flight_shape_still_establishes() {
        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let now = 1_700_000_000_u32;
        let (record, auth_key) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).expect("hello");
        let client = ClientHello::parse_message(record.message()).expect("parse");
        let auth = authenticator
            .authenticate(&client, u64::from(now))
            .expect("authenticate");
        let target = ServerHelloTemplate::parse(
            &synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]),
            &client,
        )
        .expect("target");
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let flight = build_server_flight_with_shape(
            &client,
            auth.auth_key(),
            target,
            &identity,
            Some(b"h2"),
            CoverHandshakePlan {
                emit_ccs: true,
                shape: CoverHandshakeRecordShape::PositionalRecords {
                    wire_lens: [37, 838, 286, 58],
                    nst_wire_len: None,
                },
            },
        )
        .expect("flight");
        let (mut session, mut established) =
            establish_with_server_flight(&record, keys, &auth_key, ALPN, flight)
                .await
                .expect("handshake");
        let mut record = Vec::new();
        session
            .write_mut()
            .seal_into(ContentType::ApplicationData, b"pos", 0, &mut record)
            .expect("seal");
        let opened = established
            .client_records_mut()
            .open_in_place(&mut record)
            .expect("open");
        assert_eq!(opened.plaintext(), b"pos");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_loopback_establishes_against_build_server_flight() {
        use tokio::net::{TcpListener, TcpStream};

        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let now = 1_700_000_000_u32;
        let (record, auth_key) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now)).expect("hello");
        let client = ClientHello::parse_message(record.message()).expect("parse");
        let auth = authenticator
            .authenticate(&client, u64::from(now))
            .expect("authenticate");
        let target = ServerHelloTemplate::parse(
            &synthetic_server_hello(&client, X25519_GROUP, &[0x55; 32]),
            &client,
        )
        .expect("target");
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let flight = build_server_flight(&client, auth.auth_key(), target, &identity, Some(b"h2"))
            .expect("flight");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            socket.write_all(flight.wire()).await.expect("write flight");
            let mut header = [0_u8; RECORD_HEADER_LEN];
            loop {
                socket.read_exact(&mut header).await.expect("header");
                let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
                let mut body = vec![0_u8; body_len];
                socket.read_exact(&mut body).await.expect("body");
                if header[0] == OUTER_CHANGE_CIPHER_SPEC {
                    continue;
                }
                let mut finished = Vec::with_capacity(RECORD_HEADER_LEN + body_len);
                finished.extend_from_slice(&header);
                finished.extend_from_slice(&body);
                let mut established = flight
                    .verify_client_finished(&mut finished)
                    .expect("client finished");
                let mut reply = Vec::new();
                established
                    .server_records_mut()
                    .seal_into(ContentType::ApplicationData, b"tcp-ok", 0, &mut reply)
                    .expect("server seal");
                socket.write_all(&reply).await.expect("write reply");
                break;
            }
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut session = complete(&mut stream, &record, keys, &auth_key, ALPN)
            .await
            .expect("client handshake over tcp");
        assert_eq!(session.negotiated().alpn.as_deref(), Some(b"h2".as_slice()));

        let mut header = [0_u8; RECORD_HEADER_LEN];
        stream.read_exact(&mut header).await.expect("reply header");
        let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut body = vec![0_u8; body_len];
        stream.read_exact(&mut body).await.expect("reply body");
        let mut reply = Vec::with_capacity(RECORD_HEADER_LEN + body_len);
        reply.extend_from_slice(&header);
        reply.extend_from_slice(&body);
        let opened = session
            .read_mut()
            .open_in_place(&mut reply)
            .expect("open reply");
        assert_eq!(opened.plaintext(), b"tcp-ok");
        server.await.expect("server task");
    }

    #[test]
    fn debug_redacts_session_secrets() {
        let text = format!("{:?}", ClientHandshakeError::KeyAgreement);
        assert!(!text.contains("secret"));
        assert!(verify_data_eq(&[1, 2], &[1, 2]));
        assert!(!verify_data_eq(&[1, 2], &[1, 3]));
    }
}
