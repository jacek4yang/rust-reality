use crate::config::node::reality::RealityConfig;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInOut, Nonce, array::Array},
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    RealityAuthConfigError, RealityAuthError, RealityAuthenticator, SORTED_SHORT_ID_LIMIT,
    ShortIdBinding, ShortIdOwnerIndex, derive_auth_key, open_session_id,
};
use crate::{
    config::SecretString,
    protocol::reality::{
        ClientHello, X25519_GROUP, client_hello::fixtures::client_hello_with_key_share,
    },
    protocol::vless::UserId,
};

const NOW: u32 = 1_700_000_000;
const SHORT_ID: [u8; 8] = [0xaa, 0xbb, 0, 0, 0, 0, 0, 0];
const TEST_USER: UserId = UserId::new([0x42; 16]);

#[test]
fn authenticates_xray_session_id_layout() {
    let (authenticator, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
    let result = authenticator
        .authenticate(&hello, u64::from(NOW))
        .expect("valid REALITY authentication must succeed");

    assert_eq!(result.client_version(), [1, 2, 3]);
    assert_eq!(result.client_time(), NOW);
    assert_eq!(result.user_id(), TEST_USER);
    assert_eq!(
        result.auth_key().as_bytes(),
        &hex_array::<32>("913b3e7485c67fb677b4cc65906953c2f6a23eb7b6e24cf3d69091004ccd5a9d"),
        "must match Xray's Go X25519 and HKDF implementation"
    );
    assert!(!format!("{result:?}").contains("170, 187"));
}

#[test]
fn rejects_wrong_server_identity_and_private_key() {
    let (_, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
    let mut wrong_name = auth_config([0x11; 32]);
    wrong_name.server_names = Some(vec!["other.example.com".to_owned()]);
    let wrong_name = compile_config(&wrong_name, &["aabb"]).expect("configuration must compile");
    assert!(matches!(
        wrong_name.authenticate(&hello, u64::from(NOW)),
        Err(RealityAuthError::ServerName)
    ));

    let wrong_key =
        compile_config(&auth_config([0x55; 32]), &["aabb"]).expect("configuration must compile");
    assert!(matches!(
        wrong_key.authenticate(&hello, u64::from(NOW)),
        Err(RealityAuthError::OpenFailed)
    ));
}

#[test]
fn authenticates_one_label_server_name_wildcard() {
    let (_, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
    let mut config = auth_config([0x11; 32]);
    config.server_names = Some(vec!["*.example.com".to_owned()]);
    let authenticator = compile_config(&config, &["aabb"]).expect("configuration must compile");

    authenticator
        .authenticate(&hello, u64::from(NOW))
        .expect("wildcard must accept one concrete leftmost label");
}

#[test]
fn rejects_invalid_server_name_when_config_validation_is_bypassed() {
    let mut config = auth_config([0x11; 32]);
    config.server_names = Some(vec!["www.*.edu".to_owned()]);

    assert!(matches!(
        compile_config(&config, &["aabb"]),
        Err(RealityAuthConfigError::InvalidServerName)
    ));
}

#[test]
fn rejects_duplicate_short_id_ownership_when_validation_is_bypassed() {
    let config = auth_config([0x11; 32]);
    assert!(matches!(
        RealityAuthenticator::compile(
            &config,
            [(TEST_USER, "aabb"), (UserId::new([0x43; 16]), "AABB")]
        ),
        Err(RealityAuthConfigError::DuplicateShortId)
    ));
}

#[test]
fn resolves_every_short_id_to_its_exact_owner() {
    let config = auth_config([0x11; 32]);
    let other_user = UserId::new([0x43; 16]);
    let authenticator = RealityAuthenticator::compile(
        &config,
        [
            (TEST_USER, "aabb"),
            (TEST_USER, "ccdd"),
            (other_user, "0102"),
        ],
    )
    .expect("disjoint ownership must compile");

    assert_eq!(
        authenticator.short_id_owner(&[0xaa, 0xbb, 0, 0, 0, 0, 0, 0]),
        Some(TEST_USER)
    );
    assert_eq!(
        authenticator.short_id_owner(&[0xcc, 0xdd, 0, 0, 0, 0, 0, 0]),
        Some(TEST_USER)
    );
    assert_eq!(
        authenticator.short_id_owner(&[1, 2, 0, 0, 0, 0, 0, 0]),
        Some(other_user)
    );
    assert_eq!(authenticator.short_id_owner(&[9; 8]), None);
}

#[test]
fn short_id_index_switches_at_the_measured_boundary() {
    let bindings = |count: usize| {
        (0..count)
            .map(|index| ShortIdBinding {
                short_id: (index as u64).to_be_bytes(),
                user_id: UserId::new((index as u128).to_be_bytes()),
            })
            .collect()
    };

    let sorted = ShortIdOwnerIndex::from_sorted(bindings(SORTED_SHORT_ID_LIMIT));
    assert!(matches!(sorted, ShortIdOwnerIndex::Sorted(_)));

    let hashed = ShortIdOwnerIndex::from_sorted(bindings(SORTED_SHORT_ID_LIMIT + 1));
    assert!(matches!(hashed, ShortIdOwnerIndex::Hashed(_)));
    assert_eq!(
        hashed.owner(&(SORTED_SHORT_ID_LIMIT as u64).to_be_bytes()),
        Some(UserId::new((SORTED_SHORT_ID_LIMIT as u128).to_be_bytes()))
    );
}

#[test]
fn rejects_ciphertext_and_aad_tampering() {
    let (authenticator, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
    let mut tampered_ciphertext = hello.raw_message().to_vec();
    tampered_ciphertext[crate::protocol::reality::SESSION_ID_OFFSET] ^= 1;
    let tampered_ciphertext = ClientHello::parse_message(&tampered_ciphertext)
        .expect("tampered ciphertext remains structurally valid");
    assert!(matches!(
        authenticator.authenticate(&tampered_ciphertext, u64::from(NOW)),
        Err(RealityAuthError::OpenFailed)
    ));

    let mut tampered_aad = hello.raw_message().to_vec();
    // The first cipher-suite byte is outside the zeroed session ID and does
    // not alter any pre-AEAD authentication decision.
    tampered_aad[73] ^= 1;
    let tampered_aad =
        ClientHello::parse_message(&tampered_aad).expect("tampered AAD remains structurally valid");
    assert!(matches!(
        authenticator.authenticate(&tampered_aad, u64::from(NOW)),
        Err(RealityAuthError::OpenFailed)
    ));
}

#[test]
fn rejects_unknown_short_id_and_time_skew() {
    let (wrong_short_id, hello) = valid_handshake(SHORT_ID, NOW, &["0102"]);
    assert!(matches!(
        wrong_short_id.authenticate(&hello, u64::from(NOW)),
        Err(RealityAuthError::ShortId)
    ));

    let (authenticator, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
    authenticator
        .authenticate(&hello, u64::from(NOW) - 60)
        .expect("negative clock boundary must be inclusive");
    authenticator
        .authenticate(&hello, u64::from(NOW) + 60)
        .expect("positive clock boundary must be inclusive");
    assert!(matches!(
        authenticator.authenticate(&hello, u64::from(NOW) - 61),
        Err(RealityAuthError::TimeSkew)
    ));
    assert!(matches!(
        authenticator.authenticate(&hello, u64::from(NOW) + 61),
        Err(RealityAuthError::TimeSkew)
    ));
}

#[test]
fn rejects_non_contributory_x25519_share() {
    let config = auth_config([0x11; 32]);
    let authenticator = compile_config(&config, &["aabb"]).expect("configuration must compile");
    let hello = ClientHello::parse_message(&client_hello_with_key_share(
        [0x33; 32],
        &[0; 32],
        "www.example.com",
        &[],
        X25519_GROUP,
        &[0; 32],
    ))
    .expect("ClientHello must parse");

    assert!(matches!(
        authenticator.authenticate(&hello, u64::from(NOW)),
        Err(RealityAuthError::NonContributoryKey)
    ));
}

#[test]
fn nist_aes256_gcm_vector_decrypts() {
    let key = [0_u8; 32];
    let nonce = [0_u8; 12];
    let ciphertext =
        hex_array::<32>("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

    assert_eq!(
        *open_session_id(&key, &nonce, &ciphertext, &[])
            .expect("NIST AES-256-GCM vector must authenticate"),
        [0_u8; 16]
    );
}

#[test]
fn rfc5869_sha256_case_one_matches() {
    let ikm = [0x0b_u8; 22];
    let salt = hex_vec("000102030405060708090a0b0c");
    let info = hex_vec("f0f1f2f3f4f5f6f7f8f9");
    let expected = hex_vec(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut output = [0_u8; 42];

    hkdf.expand(&info, &mut output)
        .expect("RFC output length is valid");
    assert_eq!(output.as_slice(), expected);
}

#[test]
fn rfc7748_alice_bob_shared_secret_matches() {
    let alice_private = StaticSecret::from(hex_array::<32>(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob_public = PublicKey::from(hex_array::<32>(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ));
    let expected =
        hex_array::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    assert_eq!(
        alice_private.diffie_hellman(&bob_public).to_bytes(),
        expected
    );
}

fn valid_handshake(
    short_id: [u8; 8],
    client_time: u32,
    configured_short_ids: &[&str],
) -> (RealityAuthenticator, ClientHello) {
    let server_secret = StaticSecret::from([0x11; 32]);
    let client_secret = StaticSecret::from([0x22; 32]);
    let client_public = PublicKey::from(&client_secret).to_bytes();
    let shared = client_secret.diffie_hellman(&PublicKey::from(&server_secret));
    let random = [0x33; 32];
    let auth_key =
        derive_auth_key(shared.as_bytes(), &random).expect("fixed valid HKDF length must succeed");
    let zero_message = client_hello_with_key_share(
        random,
        &[0; 32],
        "www.example.com",
        &[],
        X25519_GROUP,
        &client_public,
    );
    let mut plaintext = [0_u8; 16];
    plaintext[..3].copy_from_slice(&[1, 2, 3]);
    plaintext[4..8].copy_from_slice(&client_time.to_be_bytes());
    plaintext[8..].copy_from_slice(&short_id);
    let ciphertext = seal_session_id(auth_key.as_bytes(), &[0x33; 12], &plaintext, &zero_message);
    let message = client_hello_with_key_share(
        random,
        &ciphertext,
        "www.example.com",
        &[],
        X25519_GROUP,
        &client_public,
    );
    let hello = ClientHello::parse_message(&message).expect("ClientHello must parse");
    let config = auth_config([0x11; 32]);
    let authenticator =
        compile_config(&config, configured_short_ids).expect("configuration must compile");
    (authenticator, hello)
}

fn compile_config(
    config: &RealityConfig,
    short_ids: &[&str],
) -> Result<RealityAuthenticator, RealityAuthConfigError> {
    RealityAuthenticator::compile(
        config,
        short_ids.iter().map(|short_id| (TEST_USER, *short_id)),
    )
}

fn auth_config(private_key: [u8; 32]) -> RealityConfig {
    RealityConfig {
        cover: "www.example.com:443".to_owned(),
        private_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(private_key)),
        server_names: None,
        max_time_diff_ms: None,
        cover_optimization: None,
    }
}

fn seal_session_id(
    auth_key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8; 16],
    aad: &[u8],
) -> [u8; 32] {
    let cipher = Aes256Gcm::new(&Array(*auth_key));
    let nonce: Nonce<Aes256Gcm> = Array(*nonce);
    let mut ciphertext = *plaintext;
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
        .expect("test encryption must succeed");
    let mut output = [0_u8; 32];
    output[..16].copy_from_slice(&ciphertext);
    output[16..].copy_from_slice(&tag);
    output
}

fn hex_array<const LENGTH: usize>(encoded: &str) -> [u8; LENGTH] {
    hex_vec(encoded)
        .try_into()
        .unwrap_or_else(|_| panic!("test hex must contain {LENGTH} bytes"))
}

fn hex_vec(encoded: &str) -> Vec<u8> {
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let decode = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("test hex must be lowercase"),
            };
            (decode(pair[0]) << 4) | decode(pair[1])
        })
        .collect()
}
