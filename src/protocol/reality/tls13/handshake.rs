use std::{error::Error, fmt};

use ml_kem::{EncapsulationKey768, array::Array as MlKemArray};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::protocol::reality::{AuthKey, ClientHello, X25519_GROUP, X25519_MLKEM768_GROUP};

use super::{
    CertificateIdentity, CipherSuite, ContentType, ExportedRecordState, FinishedVerifyData,
    HandshakeMessageError, ServerHelloError, ServerHelloTemplate, Tls13KeySchedule,
    Tls13KeyScheduleError, Tls13RecordError, Tls13RecordLayer, certificate_message,
    change_cipher_spec_record, encrypted_extensions, finished_message, plaintext_handshake_record,
};

const FINISHED_HANDSHAKE_TYPE: u8 = 20;
const MAX_FLIGHT_PLAINTEXT: usize = 16 * 1024;
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1_184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;

/// A REALITY TLS 1.3 server flight could not be built or authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealityHandshakeError {
    /// Secure ephemeral randomness was unavailable.
    Random,
    /// The selected client key share was missing or malformed.
    MissingClientKeyShare,
    /// X25519 produced the forbidden all-zero shared secret.
    NonContributoryKey,
    /// ML-KEM-768 key import or encapsulation failed.
    MlKem,
    /// The selected ALPN protocol was not offered by the client.
    AlpnNotOffered,
    /// Target ServerHello validation or patching failed.
    ServerHello,
    /// TLS 1.3 key derivation failed.
    KeySchedule,
    /// A bounded handshake message could not be built.
    Message,
    /// TLS 1.3 record protection failed.
    Record,
    /// A bounded transcript or flight allocation failed.
    BufferAllocation,
    /// Client Finished had the wrong content, structure, or verify data.
    ClientFinished,
}

impl fmt::Display for RealityHandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("REALITY TLS 1.3 handshake failed")
    }
}

impl Error for RealityHandshakeError {}

impl From<ServerHelloError> for RealityHandshakeError {
    fn from(_: ServerHelloError) -> Self {
        Self::ServerHello
    }
}

impl From<Tls13KeyScheduleError> for RealityHandshakeError {
    fn from(_: Tls13KeyScheduleError) -> Self {
        Self::KeySchedule
    }
}

impl From<HandshakeMessageError> for RealityHandshakeError {
    fn from(_: HandshakeMessageError) -> Self {
        Self::Message
    }
}

impl From<Tls13RecordError> for RealityHandshakeError {
    fn from(_: Tls13RecordError) -> Self {
        Self::Record
    }
}

/// Application traffic state available only after a valid ClientFinished.
pub struct EstablishedTls {
    suite: CipherSuite,
    client_records: Tls13RecordLayer,
    server_records: Tls13RecordLayer,
}

impl EstablishedTls {
    /// Returns the negotiated cipher suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the record state for data received from the client.
    pub const fn client_records_mut(&mut self) -> &mut Tls13RecordLayer {
        &mut self.client_records
    }

    /// Returns the record state for data sent to the client.
    pub const fn server_records_mut(&mut self) -> &mut Tls13RecordLayer {
        &mut self.server_records
    }

    pub(crate) fn into_record_layers(self) -> (Tls13RecordLayer, Tls13RecordLayer) {
        (self.client_records, self.server_records)
    }

    /// Rebuilds a working session from previously exported state.
    ///
    /// # Errors
    ///
    /// Rejects mismatched direction suites, key material that does not match
    /// its suite, and sequences that already reached a per-key record limit.
    pub fn from_exported_state(state: ExportedTlsState) -> Result<Self, Tls13RecordError> {
        if state.client.suite() != state.server.suite() {
            return Err(Tls13RecordError::InvalidKey);
        }
        let suite = state.client.suite();
        Ok(Self {
            suite,
            client_records: Tls13RecordLayer::from_exported_state(state.client)?,
            server_records: Tls13RecordLayer::from_exported_state(state.server)?,
        })
    }

    #[cfg(test)]
    pub(crate) const fn from_test_records(
        suite: CipherSuite,
        client_records: Tls13RecordLayer,
        server_records: Tls13RecordLayer,
    ) -> Self {
        Self {
            suite,
            client_records,
            server_records,
        }
    }
}

impl fmt::Debug for EstablishedTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EstablishedTls")
            .field("suite", &self.suite)
            .field("traffic_state", &"[REDACTED]")
            .finish()
    }
}

/// Both directions' exported application-traffic state of one session.
///
/// The single owner of a session's key material between export on one node
/// and reconstruction on another; each direction is exported from its record
/// layer via [`Tls13RecordLayer::into_exported_state`] and paired through
/// [`ExportedTlsState::from_directions`]. Key material is zeroized on drop
/// and never appears in `Debug` output.
pub struct ExportedTlsState {
    client: ExportedRecordState,
    server: ExportedRecordState,
}

impl ExportedTlsState {
    /// Reassembles both directions' exported state as received from a session
    /// handoff.
    ///
    /// Direction-suite agreement and per-key record ceilings are enforced when
    /// the state becomes a working session again through
    /// [`EstablishedTls::from_exported_state`].
    #[must_use]
    pub const fn from_directions(client: ExportedRecordState, server: ExportedRecordState) -> Self {
        Self { client, server }
    }
}

impl fmt::Debug for ExportedTlsState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportedTlsState")
            .field("client", &self.client)
            .field("server", &self.server)
            .finish()
    }
}

/// Server records ready to send, plus the only valid transition to application state.
pub struct ServerFlight {
    wire: Vec<u8>,
    server_hello_end: usize,
    encrypted_handshake_start: usize,
    client_handshake_records: Tls13RecordLayer,
    expected_client_finished: FinishedVerifyData,
    established: EstablishedTls,
}

impl ServerFlight {
    /// Returns the plaintext target-shaped ServerHello record.
    #[must_use]
    pub fn server_hello_record(&self) -> &[u8] {
        self.wire
            .get(..self.server_hello_end)
            .expect("server flight retains its ServerHello prefix")
    }

    /// Returns the fixed middlebox-compatibility record.
    #[must_use]
    pub fn change_cipher_spec(&self) -> &[u8; 6] {
        self.wire
            .get(self.server_hello_end..self.encrypted_handshake_start)
            .and_then(|record| record.try_into().ok())
            .expect("server flight retains its fixed compatibility record")
    }

    /// Returns the encrypted record containing EE through server Finished.
    #[must_use]
    pub fn encrypted_handshake_record(&self) -> &[u8] {
        self.wire
            .get(self.encrypted_handshake_start..)
            .expect("server flight retains its encrypted suffix")
    }

    /// Returns the complete contiguous flight ready for one socket write.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Authenticates an exact encrypted ClientFinished and consumes handshake state.
    ///
    /// This is the security transition after which replay reservations may be
    /// committed and application traffic may be processed.
    ///
    /// # Errors
    ///
    /// Rejects invalid record protection, content type, framing, or verify data.
    pub fn verify_client_finished(
        mut self,
        record: &mut [u8],
    ) -> Result<EstablishedTls, RealityHandshakeError> {
        let opened = self.client_handshake_records.open_in_place(record)?;
        if opened.content_type() != ContentType::Handshake {
            return Err(RealityHandshakeError::ClientFinished);
        }
        let message = opened.plaintext();
        let expected = self.expected_client_finished.as_bytes();
        let declared = message
            .get(1..4)
            .map(|bytes| {
                (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
            })
            .ok_or(RealityHandshakeError::ClientFinished)?;
        let verify_data = message
            .get(4..)
            .ok_or(RealityHandshakeError::ClientFinished)?;
        if message.first() != Some(&FINISHED_HANDSHAKE_TYPE)
            || declared != expected.len()
            || verify_data.len() != declared
            || !bool::from(verify_data.ct_eq(expected))
        {
            return Err(RealityHandshakeError::ClientFinished);
        }
        Ok(self.established)
    }
}

impl fmt::Debug for ServerFlight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerFlight")
            .field("server_hello_len", &self.server_hello_end)
            .field(
                "encrypted_record_len",
                &self
                    .wire
                    .len()
                    .saturating_sub(self.encrypted_handshake_start),
            )
            .field("handshake_state", &"[REDACTED]")
            .finish()
    }
}

/// Builds a complete target-shaped REALITY TLS 1.3 server flight.
///
/// # Errors
///
/// Rejects incompatible negotiation, invalid key shares, unavailable secure
/// randomness, cryptographic failure, and bounded allocation failure.
pub fn build_server_flight(
    client: &ClientHello,
    auth_key: &AuthKey,
    target: ServerHelloTemplate,
    identity: &CertificateIdentity,
    selected_alpn: Option<&[u8]>,
) -> Result<ServerFlight, RealityHandshakeError> {
    if let Some(protocol) = selected_alpn
        && !client.alpn_protocols().any(|offered| offered == protocol)
    {
        return Err(RealityHandshakeError::AlpnNotOffered);
    }

    let suite = target.suite();
    let group = target.key_share_group();
    let agreement = agree_key_share(client, group)?;
    let server_hello_message = target.into_patched_message(agreement.server_share.as_slice())?;

    let mut transcript = Vec::new();
    let initial_capacity = client
        .raw_message()
        .len()
        .checked_add(server_hello_message.len())
        .and_then(|length| length.checked_add(1_024))
        .ok_or(RealityHandshakeError::BufferAllocation)?;
    transcript
        .try_reserve_exact(initial_capacity)
        .map_err(|_| RealityHandshakeError::BufferAllocation)?;
    transcript.extend_from_slice(client.raw_message());
    transcript.extend_from_slice(&server_hello_message);

    let through_server_hello = suite.hash().digest(&transcript);
    let schedule = Tls13KeySchedule::new(suite, agreement.shared_secret(), &through_server_hello)?;
    let server_handshake_keys = schedule.traffic_keys(schedule.server_handshake_secret())?;
    let client_handshake_keys = schedule.traffic_keys(schedule.client_handshake_secret())?;
    let mut server_handshake_records = Tls13RecordLayer::new(suite, server_handshake_keys)?;
    let client_handshake_records = Tls13RecordLayer::new(suite, client_handshake_keys)?;

    let encrypted_extensions_message = encrypted_extensions(selected_alpn)?;
    let flight_plaintext_start = transcript.len();
    transcript.extend_from_slice(&encrypted_extensions_message);
    let certificate_der = identity.forge_certificate(auth_key)?;
    let certificate = certificate_message(&certificate_der)?;
    transcript.extend_from_slice(&certificate);
    let certificate_verify =
        identity.certificate_verify(suite.hash().digest(&transcript).as_bytes())?;
    transcript.extend_from_slice(&certificate_verify);
    let server_finished_data = schedule.finished_verify_data(
        schedule.server_handshake_secret(),
        &suite.hash().digest(&transcript),
    )?;
    let server_finished = finished_message(server_finished_data.as_bytes())?;
    transcript.extend_from_slice(&server_finished);

    let through_server_finished = suite.hash().digest(&transcript);
    let expected_client_finished = schedule
        .finished_verify_data(schedule.client_handshake_secret(), &through_server_finished)?;
    let application = schedule.application_traffic_secrets(&through_server_finished)?;
    let client_application_keys = schedule.traffic_keys(application.client())?;
    let server_application_keys = schedule.traffic_keys(application.server())?;

    let flight_plaintext = transcript
        .get(flight_plaintext_start..)
        .filter(|plaintext| plaintext.len() <= MAX_FLIGHT_PLAINTEXT)
        .ok_or(RealityHandshakeError::BufferAllocation)?;
    let mut encrypted_flight = Vec::new();
    server_handshake_records.seal_into(
        ContentType::Handshake,
        flight_plaintext,
        0,
        &mut encrypted_flight,
    )?;

    let mut wire = plaintext_handshake_record(&server_hello_message)?;
    let server_hello_end = wire.len();
    let change_cipher_spec = change_cipher_spec_record();
    wire.try_reserve_exact(change_cipher_spec.len() + encrypted_flight.len())
        .map_err(|_| RealityHandshakeError::BufferAllocation)?;
    wire.extend_from_slice(&change_cipher_spec);
    let encrypted_handshake_start = wire.len();
    wire.extend_from_slice(&encrypted_flight);

    Ok(ServerFlight {
        wire,
        server_hello_end,
        encrypted_handshake_start,
        client_handshake_records,
        expected_client_finished,
        established: EstablishedTls {
            suite,
            client_records: Tls13RecordLayer::new(suite, client_application_keys)?,
            server_records: Tls13RecordLayer::new(suite, server_application_keys)?,
        },
    })
}

struct KeyAgreement {
    server_share: ServerShare,
    shared: Zeroizing<[u8; 64]>,
    shared_len: usize,
}

impl KeyAgreement {
    fn shared_secret(&self) -> &[u8] {
        self.shared.get(..self.shared_len).unwrap_or_default()
    }
}

enum ServerShare {
    X25519([u8; 32]),
    Hybrid(Vec<u8>),
}

impl ServerShare {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::X25519(share) => share,
            Self::Hybrid(share) => share,
        }
    }
}

fn agree_key_share(
    client: &ClientHello,
    group: u16,
) -> Result<KeyAgreement, RealityHandshakeError> {
    let share = client
        .key_shares()
        .find(|share| share.group() == group)
        .ok_or(RealityHandshakeError::MissingClientKeyShare)?;
    let mut ephemeral = Zeroizing::new([0_u8; 32]);
    getrandom::fill(ephemeral.as_mut()).map_err(|_| RealityHandshakeError::Random)?;
    let secret = StaticSecret::from(*ephemeral);
    let server_public = PublicKey::from(&secret).to_bytes();

    match group {
        X25519_GROUP => {
            let client_public: [u8; 32] = share
                .data()
                .try_into()
                .map_err(|_| RealityHandshakeError::MissingClientKeyShare)?;
            let shared = secret.diffie_hellman(&PublicKey::from(client_public));
            if !shared.was_contributory() {
                return Err(RealityHandshakeError::NonContributoryKey);
            }
            let mut shared_output = Zeroizing::new([0_u8; 64]);
            shared_output[..32].copy_from_slice(shared.as_bytes());
            Ok(KeyAgreement {
                server_share: ServerShare::X25519(server_public),
                shared: shared_output,
                shared_len: 32,
            })
        }
        X25519_MLKEM768_GROUP => {
            let encapsulation_key = share
                .data()
                .get(..MLKEM768_ENCAPSULATION_KEY_LEN)
                .ok_or(RealityHandshakeError::MissingClientKeyShare)?;
            let client_public: [u8; 32] = share
                .data()
                .get(MLKEM768_ENCAPSULATION_KEY_LEN..)
                .ok_or(RealityHandshakeError::MissingClientKeyShare)?
                .try_into()
                .map_err(|_| RealityHandshakeError::MissingClientKeyShare)?;
            let encoded = MlKemArray::try_from(encapsulation_key)
                .map_err(|_| RealityHandshakeError::MlKem)?;
            let encapsulation_key =
                EncapsulationKey768::new(&encoded).map_err(|_| RealityHandshakeError::MlKem)?;
            let mut randomness = Zeroizing::new(ml_kem::B32::default());
            getrandom::fill(randomness.as_mut()).map_err(|_| RealityHandshakeError::Random)?;
            let (ciphertext, mlkem_shared) =
                encapsulation_key.encapsulate_deterministic(&randomness);
            let mlkem_shared = Zeroizing::new(mlkem_shared);
            let x25519_shared = secret.diffie_hellman(&PublicKey::from(client_public));
            if !x25519_shared.was_contributory() {
                return Err(RealityHandshakeError::NonContributoryKey);
            }

            let mut server_share = Vec::new();
            server_share
                .try_reserve_exact(MLKEM768_CIPHERTEXT_LEN + 32)
                .map_err(|_| RealityHandshakeError::BufferAllocation)?;
            server_share.extend_from_slice(ciphertext.as_ref());
            server_share.extend_from_slice(&server_public);
            let mut shared = Zeroizing::new([0_u8; 64]);
            shared[..32].copy_from_slice(mlkem_shared.as_ref());
            shared[32..].copy_from_slice(x25519_shared.as_bytes());
            Ok(KeyAgreement {
                server_share: ServerShare::Hybrid(server_share),
                shared,
                shared_len: 64,
            })
        }
        _ => Err(RealityHandshakeError::MissingClientKeyShare),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ml_kem::{
        DecapsulationKey768, Seed,
        array::Array as MlKemArray,
        kem::{Decapsulate, KeyExport},
        ml_kem_768::Ciphertext,
    };
    use tokio::io::{AsyncWriteExt, duplex};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{EstablishedTls, ExportedTlsState, RealityHandshakeError, build_server_flight};
    use crate::protocol::reality::{
        AuthKey, ClientHello, SESSION_ID_LEN, X25519_GROUP, X25519_MLKEM768_GROUP,
        client_hello::fixtures,
        tls13::{
            CertificateIdentity, CipherSuite, ContentType, ServerHelloTemplate, Tls13KeySchedule,
            Tls13RecordLayer, change_cipher_spec_record, finished_message, read_client_finished,
        },
    };

    #[tokio::test(flavor = "current_thread")]
    async fn full_x25519_flight_establishes_only_after_valid_client_finished() {
        let client_secret = StaticSecret::from([0x31; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let client = client_hello(X25519_GROUP, &client_public);
        let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
            .expect("test target must parse");
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let auth_key = AuthKey::from_test_bytes([0x99; 32]);
        let flight = build_server_flight(&client, &auth_key, target, &identity, Some(b"h2"))
            .expect("server flight must build");

        let server_hello = &flight.server_hello_record()[5..];
        let server_public: [u8; 32] = server_hello
            .get(server_hello.len() - 32..)
            .expect("test ServerHello ends with key share")
            .try_into()
            .expect("X25519 server share is fixed");
        let shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
        let mut transcript = client.raw_message().to_vec();
        transcript.extend_from_slice(server_hello);
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule =
            Tls13KeySchedule::new(suite, shared.as_bytes(), &suite.hash().digest(&transcript))
                .expect("client schedule must derive");

        let server_keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("server handshake keys must derive");
        let mut server_records =
            Tls13RecordLayer::new(suite, server_keys).expect("server record state must initialize");
        let mut encrypted = flight.encrypted_handshake_record().to_vec();
        let opened = server_records
            .open_in_place(&mut encrypted)
            .expect("server flight must authenticate");
        assert_eq!(opened.content_type(), ContentType::Handshake);
        transcript.extend_from_slice(opened.plaintext());

        let finished_data = schedule
            .finished_verify_data(
                schedule.client_handshake_secret(),
                &suite.hash().digest(&transcript),
            )
            .expect("client Finished must derive");
        let finished =
            finished_message(finished_data.as_bytes()).expect("client Finished must encode");
        let client_keys = schedule
            .traffic_keys(schedule.client_handshake_secret())
            .expect("client handshake keys must derive");
        let mut client_records =
            Tls13RecordLayer::new(suite, client_keys).expect("client record state must initialize");
        let mut record = Vec::new();
        client_records
            .seal_into(ContentType::Handshake, &finished, 0, &mut record)
            .expect("client Finished must seal");
        let mut client_wire = change_cipher_spec_record().to_vec();
        client_wire.extend_from_slice(&record);
        let (mut client_io, mut server_io) = duplex(client_wire.len());
        client_io
            .write_all(&client_wire)
            .await
            .expect("client Finished flight must be written");
        let mut established = read_client_finished(&mut server_io, flight, Duration::from_secs(1))
            .await
            .expect("valid ClientFinished must establish TLS");
        assert_eq!(established.suite(), suite);

        let application = schedule
            .application_traffic_secrets(&suite.hash().digest(&transcript))
            .expect("application secrets must derive");
        let client_application_keys = schedule
            .traffic_keys(application.client())
            .expect("client application keys must derive");
        let mut client_application = Tls13RecordLayer::new(suite, client_application_keys)
            .expect("client application state must initialize");
        let mut application_record = Vec::new();
        client_application
            .seal_into(
                ContentType::ApplicationData,
                b"VLESS request",
                0,
                &mut application_record,
            )
            .expect("client application record must seal");
        let opened = established
            .client_records_mut()
            .open_in_place(&mut application_record)
            .expect("established server must authenticate application data");
        assert_eq!(opened.plaintext(), b"VLESS request");
    }

    #[test]
    fn hybrid_share_combines_mlkem_then_x25519_like_xray() {
        let mut seed = Seed::default();
        seed.copy_from_slice(&[0x61; 64]);
        let decapsulation_key = DecapsulationKey768::from_seed(seed);
        let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes();
        let client_secret = StaticSecret::from([0x31; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let mut client_share = encapsulation_key.as_slice().to_vec();
        client_share.extend_from_slice(&client_public);
        let client = client_hello(X25519_MLKEM768_GROUP, &client_share);
        let target = ServerHelloTemplate::parse(
            &server_hello(X25519_MLKEM768_GROUP, &[0x55; 1_120]),
            &client,
        )
        .expect("hybrid target must parse");
        let flight = build_server_flight(
            &client,
            &AuthKey::from_test_bytes([0x99; 32]),
            target,
            &CertificateIdentity::from_seed([0x42; 32]),
            Some(b"h2"),
        )
        .expect("hybrid server flight must build");

        let server_hello = &flight.server_hello_record()[5..];
        let server_share = server_hello
            .get(server_hello.len() - 1_120..)
            .expect("hybrid ServerHello ends with its key share");
        let ciphertext: Ciphertext = MlKemArray::try_from(
            server_share
                .get(..1_088)
                .expect("hybrid share contains ML-KEM ciphertext"),
        )
        .expect("ML-KEM ciphertext has fixed size");
        let mlkem_shared = decapsulation_key.decapsulate(&ciphertext);
        let server_public: [u8; 32] = server_share
            .get(1_088..)
            .expect("hybrid share contains X25519 public key")
            .try_into()
            .expect("X25519 public key has fixed size");
        let x25519_shared = client_secret.diffie_hellman(&PublicKey::from(server_public));
        let mut shared = [0_u8; 64];
        shared[..32].copy_from_slice(mlkem_shared.as_ref());
        shared[32..].copy_from_slice(x25519_shared.as_bytes());

        let mut transcript = client.raw_message().to_vec();
        transcript.extend_from_slice(server_hello);
        let suite = CipherSuite::Aes128GcmSha256;
        let schedule = Tls13KeySchedule::new(suite, &shared, &suite.hash().digest(&transcript))
            .expect("hybrid client schedule must derive");
        let keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("hybrid server keys must derive");
        let mut records =
            Tls13RecordLayer::new(suite, keys).expect("hybrid record state must initialize");
        let mut encrypted = flight.encrypted_handshake_record().to_vec();
        let opened = records
            .open_in_place(&mut encrypted)
            .expect("hybrid flight must authenticate with combined shared secret");
        assert_eq!(opened.content_type(), ContentType::Handshake);
    }

    #[test]
    fn unoffered_alpn_is_rejected_before_flight() {
        let client_secret = StaticSecret::from([0x31; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let client = client_hello(X25519_GROUP, &client_public);
        let target = ServerHelloTemplate::parse(&server_hello(X25519_GROUP, &[0x55; 32]), &client)
            .expect("test target must parse");
        let result = build_server_flight(
            &client,
            &AuthKey::from_test_bytes([0x99; 32]),
            target,
            &CertificateIdentity::from_seed([0x42; 32]),
            Some(b"http/1.1"),
        );
        assert!(matches!(result, Err(RealityHandshakeError::AlpnNotOffered)));
    }

    #[test]
    fn exported_session_state_resumes_interoperation_with_the_client() {
        let suite = CipherSuite::Aes256GcmSha384;
        // `established` plays the server's view; `client_*` plays the remote
        // client holding identical key material for each direction.
        let make_layer = || {
            let transcript = suite.hash().digest(b"ClientHelloServerHello");
            let schedule = Tls13KeySchedule::new(suite, &[0x42; 32], &transcript)
                .expect("test schedule must derive");
            let keys = schedule
                .traffic_keys(schedule.server_handshake_secret())
                .expect("test keys must derive");
            Tls13RecordLayer::new(suite, keys).expect("test layer must initialize")
        };
        let mut client_writer = make_layer();
        let mut client_reader = make_layer();
        let mut established = EstablishedTls::from_test_records(suite, make_layer(), make_layer());

        // Two client-direction records before the handoff boundary.
        for index in 0..2_u8 {
            let mut record = Vec::new();
            client_writer
                .seal_into(ContentType::ApplicationData, &[index; 32], 0, &mut record)
                .expect("client record must seal");
            established
                .client_records_mut()
                .open_in_place(&mut record)
                .expect("server must open the client record");
        }

        let (client_records, server_records) = established.into_record_layers();
        let client_exported = client_records.into_exported_state();
        let server_exported = server_records.into_exported_state();
        assert_eq!(client_exported.sequence(), 2);
        assert_eq!(server_exported.sequence(), 0);
        let exported = ExportedTlsState::from_directions(client_exported, server_exported);
        let rendered = format!("{exported:?}");
        assert!(rendered.contains("[REDACTED]"));

        let mut resumed = EstablishedTls::from_exported_state(exported)
            .expect("exported session state must rebuild");
        assert_eq!(resumed.suite(), suite);

        // Uplink continuation: the client's third record opens on the resumed
        // client-direction layer.
        let mut record = Vec::new();
        client_writer
            .seal_into(ContentType::ApplicationData, b"third", 0, &mut record)
            .expect("client continuation must seal");
        let opened = resumed
            .client_records_mut()
            .open_in_place(&mut record)
            .expect("resumed layer must open the client continuation");
        assert_eq!(opened.plaintext(), b"third");
        assert_eq!(resumed.client_records_mut().records_used(), 3);

        // Downlink start: the resumed server-direction layer is at sequence 0
        // and its first record opens on the client's untouched reader.
        let mut downlink = Vec::new();
        resumed
            .server_records_mut()
            .seal_into(ContentType::ApplicationData, b"response", 0, &mut downlink)
            .expect("resumed layer must seal");
        let opened = client_reader
            .open_in_place(&mut downlink)
            .expect("client must open the resumed downlink");
        assert_eq!(opened.plaintext(), b"response");
    }

    fn client_hello(group: u16, key_exchange: &[u8]) -> ClientHello {
        ClientHello::parse_message(&fixtures::client_hello_with_key_share(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            group,
            key_exchange,
        ))
        .expect("test ClientHello must parse")
    }

    fn server_hello(group: u16, key_exchange: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(SESSION_ID_LEN as u8);
        body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
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
        let length = body.len() as u32;
        message.extend_from_slice(&length.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
    }
}
