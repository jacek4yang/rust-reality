use std::{error::Error, fmt};

use ml_kem::{EncapsulationKey768, array::Array as MlKemArray};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    crypto::{EphemeralP256Key, EphemeralX25519Key},
    protocol::reality::{AuthKey, ClientHello, P256_GROUP, X25519_GROUP, X25519_MLKEM768_GROUP},
};

use super::{
    CertificateIdentity, CipherSuite, ContentType, CoverHandshakePlan, CoverHandshakeRecordShape,
    ExportedRecordState, FinishedVerifyData, HandshakeMessageError, ServerHelloError,
    ServerHelloTemplate, Tls13KeySchedule, Tls13KeyScheduleError, Tls13RecordError,
    Tls13RecordLayer, certificate_message, change_cipher_spec_record, encrypted_extensions,
    finished_message, keys::TranscriptHasher, plaintext_handshake_record,
    record::UNPADDED_RECORD_WIRE_OVERHEAD,
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
    /// Rejects mismatched direction suites, generation secrets that do not
    /// match their suite, and sequences that reached a per-key record limit.
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
/// The single owner of a session's generation secrets between export on one
/// node and reconstruction on another; each direction is exported from its
/// record layer via [`Tls13RecordLayer::into_exported_state`] and paired through
/// [`ExportedTlsState::from_directions`]. Secrets are zeroized on drop and
/// never appear in `Debug` output.
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

    /// Returns the middlebox-compatibility record when the flight plan emitted one.
    #[must_use]
    pub fn change_cipher_spec(&self) -> Option<&[u8; 6]> {
        self.wire
            .get(self.server_hello_end..self.encrypted_handshake_start)
            .and_then(|record| record.try_into().ok())
    }

    /// Returns the encrypted record sequence containing EE through Finished.
    #[must_use]
    pub fn encrypted_handshake_records(&self) -> &[u8] {
        self.wire
            .get(self.encrypted_handshake_start..)
            .expect("server flight retains its encrypted suffix")
    }

    /// Compatibility alias for [`Self::encrypted_handshake_records`].
    ///
    /// Depending on the cover-derived plan, the returned suffix may contain
    /// one coalesced record or four positional records optionally followed by
    /// one fake NewSessionTicket record.
    #[must_use]
    pub fn encrypted_handshake_record(&self) -> &[u8] {
        self.encrypted_handshake_records()
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
                "encrypted_records_len",
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
    build_server_flight_inner(client, auth_key, target, identity, selected_alpn, None)
}

pub(crate) fn build_server_flight_with_shape(
    client: &ClientHello,
    auth_key: &AuthKey,
    target: ServerHelloTemplate,
    identity: &CertificateIdentity,
    selected_alpn: Option<&[u8]>,
    plan: CoverHandshakePlan,
) -> Result<ServerFlight, RealityHandshakeError> {
    build_server_flight_inner(
        client,
        auth_key,
        target,
        identity,
        selected_alpn,
        Some(plan),
    )
}

fn build_server_flight_inner(
    client: &ClientHello,
    auth_key: &AuthKey,
    target: ServerHelloTemplate,
    identity: &CertificateIdentity,
    selected_alpn: Option<&[u8]>,
    plan: Option<CoverHandshakePlan>,
) -> Result<ServerFlight, RealityHandshakeError> {
    let selected_alpn = match plan {
        Some(plan) => cover_compatible_alpn(client, selected_alpn, &plan),
        None => selected_alpn,
    };
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

    // Incremental transcript hash: each snapshot finalizes a clone of the
    // running state instead of re-hashing the whole transcript (RFC 8446
    // transcript-hash values are unchanged by construction).
    let mut transcript_hasher = TranscriptHasher::new(suite.hash());
    transcript_hasher.update(client.raw_message());
    transcript_hasher.update(&server_hello_message);

    let through_server_hello = transcript_hasher.snapshot();
    let schedule = Tls13KeySchedule::new(suite, agreement.shared_secret(), &through_server_hello)?;
    let server_handshake_keys = schedule.traffic_keys(schedule.server_handshake_secret())?;
    let client_handshake_keys = schedule.traffic_keys(schedule.client_handshake_secret())?;
    let mut server_handshake_records = Tls13RecordLayer::new(suite, server_handshake_keys)?;
    let client_handshake_records = Tls13RecordLayer::new(suite, client_handshake_keys)?;

    let encrypted_extensions_message = encrypted_extensions(selected_alpn)?;
    let flight_plaintext_start = transcript.len();
    transcript.extend_from_slice(&encrypted_extensions_message);
    transcript_hasher.update(&encrypted_extensions_message);
    let certificate_der = identity.forge_certificate(auth_key)?;
    let certificate = certificate_message(&certificate_der)?;
    transcript.extend_from_slice(&certificate);
    transcript_hasher.update(&certificate);
    let certificate_verify =
        identity.certificate_verify(transcript_hasher.snapshot().as_bytes())?;
    transcript.extend_from_slice(&certificate_verify);
    transcript_hasher.update(&certificate_verify);
    let server_finished_data = schedule.finished_verify_data(
        schedule.server_handshake_secret(),
        &transcript_hasher.snapshot(),
    )?;
    let server_finished = finished_message(server_finished_data.as_bytes())?;
    transcript.extend_from_slice(&server_finished);
    transcript_hasher.update(&server_finished);

    let through_server_finished = transcript_hasher.snapshot();
    let expected_client_finished = schedule
        .finished_verify_data(schedule.client_handshake_secret(), &through_server_finished)?;
    let (client_application_secret, server_application_secret) = schedule
        .application_traffic_secrets(&through_server_finished)?
        .into_parts();
    let mut server_application_records =
        Tls13RecordLayer::from_traffic_secret(suite, server_application_secret)?;

    let flight_plaintext = transcript
        .get(flight_plaintext_start..)
        .filter(|plaintext| plaintext.len() <= MAX_FLIGHT_PLAINTEXT)
        .ok_or(RealityHandshakeError::BufferAllocation)?;
    let handshake_messages = [
        encrypted_extensions_message.as_slice(),
        certificate.as_slice(),
        certificate_verify.as_slice(),
        server_finished.as_slice(),
    ];
    let (emit_ccs, shape) = match plan {
        Some(plan) => (plan.emit_ccs, Some(plan.shape)),
        None => (true, None),
    };
    let (encrypted_wire_len, largest_record_len) = match shape {
        None => {
            let wire_len = unpadded_record_wire_len(flight_plaintext.len())?;
            (wire_len, wire_len)
        }
        Some(CoverHandshakeRecordShape::Coalesced { wire_len }) => {
            shaped_record_padding(flight_plaintext.len(), wire_len)?;
            (wire_len, wire_len)
        }
        Some(CoverHandshakeRecordShape::PositionalRecords {
            wire_lens,
            nst_wire_len,
        }) => {
            let mut total = 0_usize;
            let mut largest = 0_usize;
            for (message, wire_len) in handshake_messages.iter().zip(wire_lens) {
                shaped_record_padding(message.len(), wire_len)?;
                total = total
                    .checked_add(wire_len)
                    .ok_or(RealityHandshakeError::BufferAllocation)?;
                largest = largest.max(wire_len);
            }
            if let Some(nst_wire_len) = nst_wire_len {
                shaped_record_padding(0, nst_wire_len)?;
                total = total
                    .checked_add(nst_wire_len)
                    .ok_or(RealityHandshakeError::BufferAllocation)?;
                largest = largest.max(nst_wire_len);
            }
            (total, largest)
        }
    };
    let mut encrypted_record = Vec::new();
    encrypted_record
        .try_reserve_exact(largest_record_len)
        .map_err(|_| RealityHandshakeError::BufferAllocation)?;

    let mut wire = plaintext_handshake_record(&server_hello_message)?;
    let server_hello_end = wire.len();
    let change_cipher_spec = emit_ccs.then(change_cipher_spec_record);
    let remaining_wire_len = change_cipher_spec
        .as_ref()
        .map_or(0, |record| record.len())
        .checked_add(encrypted_wire_len)
        .ok_or(RealityHandshakeError::BufferAllocation)?;
    wire.try_reserve_exact(remaining_wire_len)
        .map_err(|_| RealityHandshakeError::BufferAllocation)?;
    if let Some(change_cipher_spec) = change_cipher_spec {
        wire.extend_from_slice(&change_cipher_spec);
    }
    let encrypted_handshake_start = wire.len();
    match shape {
        None => seal_shaped_handshake_record(
            &mut server_handshake_records,
            flight_plaintext,
            unpadded_record_wire_len(flight_plaintext.len())?,
            &mut encrypted_record,
            &mut wire,
        )?,
        Some(CoverHandshakeRecordShape::Coalesced { wire_len }) => {
            seal_shaped_handshake_record(
                &mut server_handshake_records,
                flight_plaintext,
                wire_len,
                &mut encrypted_record,
                &mut wire,
            )?;
        }
        Some(CoverHandshakeRecordShape::PositionalRecords {
            wire_lens,
            nst_wire_len,
        }) => {
            for (message, wire_len) in handshake_messages.iter().zip(wire_lens) {
                seal_shaped_handshake_record(
                    &mut server_handshake_records,
                    message,
                    wire_len,
                    &mut encrypted_record,
                    &mut wire,
                )?;
            }
            if let Some(nst_wire_len) = nst_wire_len {
                let padding_len = shaped_record_padding(0, nst_wire_len)?;
                server_application_records.seal_into(
                    ContentType::ApplicationData,
                    &[],
                    padding_len,
                    &mut encrypted_record,
                )?;
                if encrypted_record.len() != nst_wire_len {
                    return Err(RealityHandshakeError::Record);
                }
                wire.extend_from_slice(&encrypted_record);
            }
        }
    }

    Ok(ServerFlight {
        wire,
        server_hello_end,
        encrypted_handshake_start,
        client_handshake_records,
        expected_client_finished,
        established: EstablishedTls {
            suite,
            client_records: Tls13RecordLayer::from_traffic_secret(
                suite,
                client_application_secret,
            )?,
            server_records: server_application_records,
        },
    })
}

/// Chooses the ALPN the generated EncryptedExtensions may claim under a
/// cover-derived flight plan.
///
/// The cover's own EncryptedExtensions is encrypted under cover-held key
/// material, so its ALPN selection is not directly readable; the first
/// positional record slot is the only observable signal. A cover that
/// negotiated no ALPN emits a minimal EncryptedExtensions record whose slot
/// cannot hold an ALPN extension, so claiming the client's first protocol
/// there fails the shaped padding and silently falls back to the cover. The
/// generated EncryptedExtensions therefore claims the caller's protocol when
/// it fits the observed slot, else the first client-offered protocol that
/// fits, else none — exactly what a real no-ALPN cover emits. A coalesced
/// shape has no per-message slot, so the caller's selection is kept and the
/// whole-flight fit check stays authoritative.
fn cover_compatible_alpn<'a>(
    client: &'a ClientHello,
    preferred: Option<&'a [u8]>,
    plan: &CoverHandshakePlan,
) -> Option<&'a [u8]> {
    let CoverHandshakeRecordShape::PositionalRecords { wire_lens, .. } = plan.shape else {
        return preferred;
    };
    let ee_slot = wire_lens[0];
    preferred
        .filter(|protocol| alpn_extension_fits_slot(protocol, ee_slot))
        .or_else(|| {
            client
                .alpn_protocols()
                .find(|protocol| alpn_extension_fits_slot(protocol, ee_slot))
        })
}

/// Returns whether an EncryptedExtensions claiming `protocol` seals inside
/// the observed cover EncryptedExtensions record slot.
fn alpn_extension_fits_slot(protocol: &[u8], ee_slot_wire_len: usize) -> bool {
    let Ok(message) = encrypted_extensions(Some(protocol)) else {
        return false;
    };
    unpadded_record_wire_len(message.len()).is_ok_and(|wire_len| wire_len <= ee_slot_wire_len)
}

fn unpadded_record_wire_len(plaintext_len: usize) -> Result<usize, RealityHandshakeError> {
    plaintext_len
        .checked_add(UNPADDED_RECORD_WIRE_OVERHEAD)
        .ok_or(RealityHandshakeError::BufferAllocation)
}

fn shaped_record_padding(
    plaintext_len: usize,
    target_wire_len: usize,
) -> Result<usize, RealityHandshakeError> {
    let natural_wire_len = unpadded_record_wire_len(plaintext_len)?;
    target_wire_len
        .checked_sub(natural_wire_len)
        .ok_or_else(|| Tls13RecordError::InvalidLength.into())
}

fn seal_shaped_handshake_record(
    records: &mut Tls13RecordLayer,
    plaintext: &[u8],
    target_wire_len: usize,
    scratch: &mut Vec<u8>,
    wire: &mut Vec<u8>,
) -> Result<(), RealityHandshakeError> {
    let padding_len = shaped_record_padding(plaintext.len(), target_wire_len)?;
    records.seal_into(ContentType::Handshake, plaintext, padding_len, scratch)?;
    if scratch.len() != target_wire_len {
        return Err(Tls13RecordError::InvalidLength.into());
    }
    wire.extend_from_slice(scratch);
    Ok(())
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
    P256([u8; 65]),
    X25519([u8; 32]),
    Hybrid(Vec<u8>),
}

impl ServerShare {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::P256(share) => share,
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
    if group == P256_GROUP {
        let ephemeral = EphemeralP256Key::generate().map_err(|_| RealityHandshakeError::Random)?;
        let server_public = ephemeral.public_key();
        let secret = ephemeral
            .agree(share.data())
            .ok_or(RealityHandshakeError::NonContributoryKey)?;
        let mut shared = Zeroizing::new([0_u8; 64]);
        shared[..32].copy_from_slice(secret.as_slice());
        return Ok(KeyAgreement {
            server_share: ServerShare::P256(server_public),
            shared,
            shared_len: 32,
        });
    }
    // One ephemeral key per exchange, consumed by exactly one agreement. The
    // private key never exists as raw bytes on this side, and there is nothing
    // to cache or precompute.
    let ephemeral = EphemeralX25519Key::generate().map_err(|_| RealityHandshakeError::Random)?;
    let server_public = *ephemeral.public_key();

    match group {
        X25519_GROUP => {
            let client_public: [u8; 32] = share
                .data()
                .try_into()
                .map_err(|_| RealityHandshakeError::MissingClientKeyShare)?;
            let shared = ephemeral
                .agree(&client_public)
                .ok_or(RealityHandshakeError::NonContributoryKey)?;
            let mut shared_output = Zeroizing::new([0_u8; 64]);
            shared_output[..32].copy_from_slice(shared.as_slice());
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
            crate::crypto::entropy::fill(randomness.as_mut())
                .map_err(|_| RealityHandshakeError::Random)?;
            let (ciphertext, mlkem_shared) =
                encapsulation_key.encapsulate_deterministic(&randomness);
            let mlkem_shared = Zeroizing::new(mlkem_shared);
            let x25519_shared = ephemeral
                .agree(&client_public)
                .ok_or(RealityHandshakeError::NonContributoryKey)?;

            let mut server_share = Vec::new();
            server_share
                .try_reserve_exact(MLKEM768_CIPHERTEXT_LEN + 32)
                .map_err(|_| RealityHandshakeError::BufferAllocation)?;
            server_share.extend_from_slice(ciphertext.as_ref());
            server_share.extend_from_slice(&server_public);
            let mut shared = Zeroizing::new([0_u8; 64]);
            shared[..32].copy_from_slice(mlkem_shared.as_ref());
            shared[32..].copy_from_slice(x25519_shared.as_slice());
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
mod tests;
