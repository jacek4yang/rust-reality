use std::{error::Error, fmt};

use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::protocol::reality::AuthKey;

const HANDSHAKE_HEADER_LEN: usize = 4;
const MAX_HANDSHAKE_BODY_LEN: usize = 0x00ff_ffff;
const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
const HANDSHAKE_CERTIFICATE: u8 = 11;
const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
const HANDSHAKE_FINISHED: u8 = 20;
const EXTENSION_ALPN: u16 = 0x0010;
const ED25519_SIGNATURE_SCHEME: u16 = 0x0807;
const CERTIFICATE_VERIFY_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

const CERTIFICATE_PUBLIC_KEY_OFFSET: usize = 72;
const CERTIFICATE_SIGNATURE_OFFSET: usize = 114;
const CERTIFICATE_PUBLIC_KEY_LEN: usize = 32;
const CERTIFICATE_SIGNATURE_LEN: usize = 64;

// Go 1.26 `x509.CreateCertificate` output for the empty Xray REALITY template.
// The per-process Ed25519 public key and REALITY HMAC are patched below.
const CERTIFICATE_TEMPLATE: [u8; 178] = [
    0x30, 0x81, 0xaf, 0x30, 0x63, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x30, 0x00, 0x30, 0x22, 0x18, 0x0f, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x30, 0x30, 0x30, 0x31, 0x30,
    0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24,
    0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e, 0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00,
    0x97, 0x96, 0x0e, 0x06, 0x98, 0x81, 0xdb, 0x12, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03,
    0x41, 0x00, 0x52, 0xc8, 0x4d, 0x3d, 0xc8, 0xf1, 0x23, 0xbb, 0x88, 0x9b, 0x05, 0x98, 0xfe, 0x11,
    0x4d, 0x36, 0xd0, 0x59, 0x9f, 0x20, 0xf3, 0xd0, 0x91, 0xb1, 0x28, 0x4a, 0x84, 0x5a, 0x5d, 0x81,
    0x8c, 0x9f, 0x85, 0x1f, 0x44, 0x10, 0x08, 0xd2, 0xf8, 0x4a, 0x5f, 0x9e, 0xbc, 0xcc, 0x8e, 0x82,
    0x43, 0xd9, 0x33, 0x2b, 0x16, 0x0c, 0x03, 0x8e, 0x52, 0xba, 0x8a, 0x2c, 0xe6, 0xf7, 0x00, 0x60,
    0x36, 0x04,
];

/// A bounded TLS handshake message could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMessageError {
    /// A length does not fit its TLS vector or repository hard bound.
    InvalidLength,
    /// Secure random identity generation failed.
    Random,
    /// A mature signature or MAC primitive rejected an invariant.
    Crypto,
    /// Reserving a bounded output buffer failed.
    BufferAllocation,
}

impl fmt::Display for HandshakeMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS 1.3 handshake message construction failed")
    }
}

impl Error for HandshakeMessageError {}

/// Process-lifetime Ed25519 identity used by the REALITY certificate flight.
///
/// The signing key is generated once and is zeroized by `ed25519-dalek` when
/// dropped. It is intentionally neither clonable nor serializable.
pub struct CertificateIdentity {
    signing_key: SigningKey,
}

impl CertificateIdentity {
    /// Generates a fresh process identity with the operating-system RNG.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system cannot provide randomness.
    pub fn generate() -> Result<Self, HandshakeMessageError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        crate::crypto::entropy::fill(seed.as_mut()).map_err(|_| HandshakeMessageError::Random)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// Builds the Xray-compatible certificate whose signature is bound to the
    /// authenticated REALITY key rather than a public PKI trust anchor.
    ///
    /// # Errors
    ///
    /// Returns an error only when the HMAC primitive rejects an invariant.
    pub fn forge_certificate(&self, auth_key: &AuthKey) -> Result<Vec<u8>, HandshakeMessageError> {
        let public_key = self.signing_key.verifying_key().to_bytes();
        let mut certificate = CERTIFICATE_TEMPLATE.to_vec();
        let public_key_end = CERTIFICATE_PUBLIC_KEY_OFFSET + CERTIFICATE_PUBLIC_KEY_LEN;
        certificate
            .get_mut(CERTIFICATE_PUBLIC_KEY_OFFSET..public_key_end)
            .ok_or(HandshakeMessageError::InvalidLength)?
            .copy_from_slice(&public_key);

        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key.as_bytes())
            .map_err(|_| HandshakeMessageError::Crypto)?;
        mac.update(&public_key);
        let signature = Zeroizing::new(mac.finalize().into_bytes());
        let signature_end = CERTIFICATE_SIGNATURE_OFFSET + CERTIFICATE_SIGNATURE_LEN;
        certificate
            .get_mut(CERTIFICATE_SIGNATURE_OFFSET..signature_end)
            .ok_or(HandshakeMessageError::InvalidLength)?
            .copy_from_slice(signature.as_slice());
        Ok(certificate)
    }

    /// Constructs a TLS 1.3 Ed25519 CertificateVerify handshake message.
    ///
    /// # Errors
    ///
    /// Rejects transcript digests that cannot fit a bounded handshake message.
    pub fn certificate_verify(
        &self,
        transcript_hash: &[u8],
    ) -> Result<Vec<u8>, HandshakeMessageError> {
        if transcript_hash.len() != 32 && transcript_hash.len() != 48 {
            return Err(HandshakeMessageError::InvalidLength);
        }
        let signed_len = 64_usize
            .checked_add(CERTIFICATE_VERIFY_CONTEXT.len())
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(transcript_hash.len()))
            .ok_or(HandshakeMessageError::InvalidLength)?;
        let mut signed = Vec::new();
        signed
            .try_reserve_exact(signed_len)
            .map_err(|_| HandshakeMessageError::BufferAllocation)?;
        signed.extend_from_slice(&[0x20; 64]);
        signed.extend_from_slice(CERTIFICATE_VERIFY_CONTEXT);
        signed.push(0);
        signed.extend_from_slice(transcript_hash);
        let signature = self.signing_key.sign(&signed).to_bytes();

        let mut body = Vec::new();
        body.try_reserve_exact(2 + 2 + signature.len())
            .map_err(|_| HandshakeMessageError::BufferAllocation)?;
        body.extend_from_slice(&ED25519_SIGNATURE_SCHEME.to_be_bytes());
        body.extend_from_slice(
            &u16::try_from(signature.len())
                .map_err(|_| HandshakeMessageError::InvalidLength)?
                .to_be_bytes(),
        );
        body.extend_from_slice(&signature);
        encode_handshake(HANDSHAKE_CERTIFICATE_VERIFY, &body)
    }

    #[cfg(test)]
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }
}

impl fmt::Debug for CertificateIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateIdentity([REDACTED])")
    }
}

/// Constructs EncryptedExtensions with at most one selected ALPN protocol.
///
/// # Errors
///
/// Rejects empty or oversized ALPN protocol identifiers and allocation failure.
pub fn encrypted_extensions(
    selected_alpn: Option<&[u8]>,
) -> Result<Vec<u8>, HandshakeMessageError> {
    let Some(protocol) = selected_alpn else {
        return encode_handshake(HANDSHAKE_ENCRYPTED_EXTENSIONS, &[0, 0]);
    };
    let protocol_len = u8::try_from(protocol.len())
        .ok()
        .filter(|length| *length != 0)
        .ok_or(HandshakeMessageError::InvalidLength)?;
    let protocol_list_len = usize::from(protocol_len) + 1;
    let alpn_body_len = protocol_list_len + 2;
    let extension_len = alpn_body_len + 4;
    let mut body = Vec::new();
    body.try_reserve_exact(extension_len + 2)
        .map_err(|_| HandshakeMessageError::BufferAllocation)?;
    body.extend_from_slice(
        &u16::try_from(extension_len)
            .map_err(|_| HandshakeMessageError::InvalidLength)?
            .to_be_bytes(),
    );
    body.extend_from_slice(&EXTENSION_ALPN.to_be_bytes());
    body.extend_from_slice(
        &u16::try_from(alpn_body_len)
            .map_err(|_| HandshakeMessageError::InvalidLength)?
            .to_be_bytes(),
    );
    body.extend_from_slice(
        &u16::try_from(protocol_list_len)
            .map_err(|_| HandshakeMessageError::InvalidLength)?
            .to_be_bytes(),
    );
    body.push(protocol_len);
    body.extend_from_slice(protocol);
    encode_handshake(HANDSHAKE_ENCRYPTED_EXTENSIONS, &body)
}

/// Wraps one DER certificate in a TLS 1.3 Certificate handshake message.
///
/// # Errors
///
/// Rejects an oversized certificate and allocation failure.
pub fn certificate_message(certificate_der: &[u8]) -> Result<Vec<u8>, HandshakeMessageError> {
    let certificate_len = certificate_der.len();
    if certificate_len == 0 || certificate_len > MAX_HANDSHAKE_BODY_LEN {
        return Err(HandshakeMessageError::InvalidLength);
    }
    let entry_len = certificate_len
        .checked_add(3 + 2)
        .ok_or(HandshakeMessageError::InvalidLength)?;
    let body_len = entry_len
        .checked_add(1 + 3)
        .ok_or(HandshakeMessageError::InvalidLength)?;
    if body_len > MAX_HANDSHAKE_BODY_LEN || entry_len > MAX_HANDSHAKE_BODY_LEN {
        return Err(HandshakeMessageError::InvalidLength);
    }

    let mut body = Vec::new();
    body.try_reserve_exact(body_len)
        .map_err(|_| HandshakeMessageError::BufferAllocation)?;
    body.push(0);
    push_u24(&mut body, entry_len)?;
    push_u24(&mut body, certificate_len)?;
    body.extend_from_slice(certificate_der);
    body.extend_from_slice(&[0, 0]);
    encode_handshake(HANDSHAKE_CERTIFICATE, &body)
}

/// Constructs a TLS Finished handshake message from suite-sized verify data.
///
/// # Errors
///
/// Rejects verify data that is neither a SHA-256 nor SHA-384 output.
pub fn finished_message(verify_data: &[u8]) -> Result<Vec<u8>, HandshakeMessageError> {
    if verify_data.len() != 32 && verify_data.len() != 48 {
        return Err(HandshakeMessageError::InvalidLength);
    }
    encode_handshake(HANDSHAKE_FINISHED, verify_data)
}

fn encode_handshake(message_type: u8, body: &[u8]) -> Result<Vec<u8>, HandshakeMessageError> {
    if body.len() > MAX_HANDSHAKE_BODY_LEN {
        return Err(HandshakeMessageError::InvalidLength);
    }
    let capacity = HANDSHAKE_HEADER_LEN
        .checked_add(body.len())
        .ok_or(HandshakeMessageError::InvalidLength)?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(capacity)
        .map_err(|_| HandshakeMessageError::BufferAllocation)?;
    message.push(message_type);
    push_u24(&mut message, body.len())?;
    message.extend_from_slice(body);
    Ok(message)
}

fn push_u24(output: &mut Vec<u8>, value: usize) -> Result<(), HandshakeMessageError> {
    if value > MAX_HANDSHAKE_BODY_LEN {
        return Err(HandshakeMessageError::InvalidLength);
    }
    let encoded = u32::try_from(value).map_err(|_| HandshakeMessageError::InvalidLength)?;
    output.extend_from_slice(&encoded.to_be_bytes()[1..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha512;

    use super::{
        CERTIFICATE_PUBLIC_KEY_LEN, CERTIFICATE_PUBLIC_KEY_OFFSET, CERTIFICATE_SIGNATURE_LEN,
        CERTIFICATE_SIGNATURE_OFFSET, CertificateIdentity, HandshakeMessageError,
        certificate_message, encrypted_extensions, finished_message,
    };
    use crate::protocol::reality::AuthKey;

    #[test]
    fn forged_certificate_matches_xray_hmac_binding() {
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        let auth_key = AuthKey::from_test_bytes([0x99; 32]);
        let certificate = identity
            .forge_certificate(&auth_key)
            .expect("fixed REALITY certificate must forge");
        let public_key = identity.signing_key.verifying_key().to_bytes();
        let public_key_end = CERTIFICATE_PUBLIC_KEY_OFFSET + CERTIFICATE_PUBLIC_KEY_LEN;
        let signature_end = CERTIFICATE_SIGNATURE_OFFSET + CERTIFICATE_SIGNATURE_LEN;

        assert_eq!(certificate.len(), 178);
        assert_eq!(
            certificate.get(CERTIFICATE_PUBLIC_KEY_OFFSET..public_key_end),
            Some(public_key.as_slice())
        );
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key.as_bytes())
            .expect("fixed HMAC key must initialize");
        mac.update(&public_key);
        assert_eq!(
            certificate.get(CERTIFICATE_SIGNATURE_OFFSET..signature_end),
            Some(mac.finalize().into_bytes().as_slice())
        );
    }

    #[test]
    fn certificate_verify_signature_is_standard_ed25519() {
        let identity = CertificateIdentity::from_seed([0x07; 32]);
        let transcript_hash = [0xab; 32];
        let message = identity
            .certificate_verify(&transcript_hash)
            .expect("fixed CertificateVerify must sign");
        assert_eq!(message[0], 15);
        assert_eq!(&message[4..6], &[0x08, 0x07]);
        assert_eq!(&message[6..8], &[0x00, 0x40]);
        let signature = Signature::try_from(&message[8..]).expect("signature must parse");

        let mut signed = vec![0x20; 64];
        signed.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signed.push(0);
        signed.extend_from_slice(&transcript_hash);
        assert!(
            identity
                .signing_key
                .verifying_key()
                .verify(&signed, &signature)
                .is_ok()
        );
    }

    #[test]
    fn handshake_vectors_have_exact_nested_lengths() {
        let empty = encrypted_extensions(None).expect("empty extensions must encode");
        assert_eq!(empty, [8, 0, 0, 2, 0, 0]);

        let h2 = encrypted_extensions(Some(b"h2")).expect("h2 must encode");
        assert_eq!(h2, [8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 3, 2, b'h', b'2']);

        let certificate = certificate_message(&[1, 2, 3]).expect("certificate must encode");
        assert_eq!(
            certificate,
            [11, 0, 0, 12, 0, 0, 0, 8, 0, 0, 3, 1, 2, 3, 0, 0]
        );

        let finished = finished_message(&[0x55; 32]).expect("Finished must encode");
        assert_eq!(&finished[..4], &[20, 0, 0, 32]);
        assert_eq!(finished.len(), 36);
    }

    #[test]
    fn rejects_invalid_alpn_certificate_and_digest_lengths() {
        assert_eq!(
            encrypted_extensions(Some(&[])),
            Err(HandshakeMessageError::InvalidLength)
        );
        assert_eq!(
            encrypted_extensions(Some(&[0; 256])),
            Err(HandshakeMessageError::InvalidLength)
        );
        assert_eq!(
            certificate_message(&[]),
            Err(HandshakeMessageError::InvalidLength)
        );
        assert_eq!(
            finished_message(&[0; 31]),
            Err(HandshakeMessageError::InvalidLength)
        );
    }

    #[test]
    fn identity_debug_is_redacted() {
        let identity = CertificateIdentity::from_seed([0x42; 32]);
        assert_eq!(format!("{identity:?}"), "CertificateIdentity([REDACTED])");
    }
}
