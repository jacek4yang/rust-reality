use std::time::Duration;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInOut, array::Array},
};

use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    CONTINUATION_STATE_VERSION, ContinuationState, HANDOFF_PROTOCOL_VERSION, HEADER_LEN,
    HandoffError, HandoffLandingKeys, HandoffPolicySnapshot, HandoffPsk, HandoffReplayCache,
    MAX_BLOB_LEN, MAX_MESSAGE_LEN, MAX_PENDING_CIPHERTEXT_LEN, MAX_PREFETCHED_PLAINTEXT_LEN,
    MAX_PREVIOUS_KEYS, MonotonicInstant, NONCE_LEN, STATE_VERSION_OFFSET, SealedDomainMatcher,
    SealedHandoffRouteRule, SealedIpNetwork, SealedPortRange, SessionKind, StaticX25519Key,
    decode_blob, encode_blob, message_len_from_header, open_transfer, seal_transfer,
};
use crate::protocol::reality::tls13::{CipherSuite, HashAlgorithm, TrafficSecret};
use crate::protocol::vless::{Address, Destination};

const NOW: u64 = 1_700_000_000;
const WINDOW: u64 = 30;

/// Key material for one landing, derived independently: the public half
/// comes from `x25519-dalek`, so every seal/open round trip in this module
/// also verifies the production public-key derivation against the
/// previous provider.
fn landing_key_pair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let public = PublicKey::from(&StaticSecret::from([seed; 32])).to_bytes();
    ([seed; 32], public)
}

fn test_state(pending: Vec<u8>, prefetched: Vec<u8>) -> ContinuationState {
    test_state_with_server_sequence(pending, prefetched, 0)
}

fn test_state_with_server_sequence(
    pending: Vec<u8>,
    prefetched: Vec<u8>,
    server_sequence: u64,
) -> ContinuationState {
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    ContinuationState::new(
        suite,
        TrafficSecret::from_bytes(suite.hash(), &[0x11; 32]).expect("client secret"),
        0x0102_0304_0506_0708,
        TrafficSecret::from_bytes(suite.hash(), &[0x12; 32]).expect("server secret"),
        server_sequence,
        true,
        SessionKind::Tcp,
        [0x33; 16],
        "public-reality",
        Destination::new(Address::Domain("example.com".to_owned()), 443),
        pending,
        prefetched,
        HandoffPolicySnapshot::tcp_placeholder(Destination::new(
            Address::Domain("example.com".to_owned()),
            443,
        )),
    )
    .expect("test state must be valid")
}

fn test_cache() -> HandoffReplayCache {
    HandoffReplayCache::new(1_024, Duration::from_secs(120)).expect("test cache")
}

fn seal(state: &ContinuationState, psk: &HandoffPsk, public: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::new();
    seal_transfer(state, psk, public, [0x44; 32], NOW, &mut message).expect("test state must seal");
    message
}

fn open_error(
    message: &[u8],
    psk: &HandoffPsk,
    secret: &[u8; 32],
    cache: &HandoffReplayCache,
    now: u64,
) -> HandoffError {
    open_transfer(
        message,
        &HandoffLandingKeys::single(psk.clone(), StaticX25519Key::new(secret)),
        cache,
        now,
        WINDOW,
    )
    .map(|_| ())
    .expect_err("transfer must fail closed")
}

fn assert_states_equal(opened: &ContinuationState, expected: &ContinuationState) {
    assert_eq!(opened.suite(), expected.suite());
    assert_eq!(
        opened.client_traffic_secret(),
        expected.client_traffic_secret()
    );
    assert_eq!(
        opened.server_traffic_secret(),
        expected.server_traffic_secret()
    );
    assert_eq!(opened.client_sequence(), expected.client_sequence());
    assert_eq!(opened.server_sequence(), expected.server_sequence());
    assert_eq!(
        opened.key_update_response_pending(),
        expected.key_update_response_pending()
    );
    assert_eq!(opened.session_kind(), expected.session_kind());
    assert_eq!(opened.inbound_tag(), expected.inbound_tag());
    assert_eq!(opened.user_id(), expected.user_id());
    assert_eq!(opened.destination(), expected.destination());
    assert_eq!(opened.policy(), expected.policy());
    assert_eq!(opened.pending_ciphertext(), expected.pending_ciphertext());
    assert_eq!(
        opened.prefetched_plaintext(),
        expected.prefetched_plaintext()
    );
}

#[test]
fn sealed_transfer_round_trips_through_landing_open() {
    let (landing_secret, landing_public) = landing_key_pair(0x77);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(b"read-ahead".to_vec(), b"prefetched".to_vec());
    let message = seal(&state, &psk, &landing_public);
    assert!(message.len() < 2 * 1_024);
    assert_eq!(
        message_len_from_header(&message[..HEADER_LEN]).expect("header must parse"),
        message.len()
    );

    let opened = open_transfer(
        &message,
        &HandoffLandingKeys::single(psk, StaticX25519Key::new(&landing_secret)),
        &test_cache(),
        NOW,
        WINDOW,
    )
    .expect("valid transfer must open");
    assert_eq!(opened.timestamp(), NOW);
    assert_eq!(opened.client_random(), &[0x44; 32]);
    assert_states_equal(opened.state(), &state);
}

#[test]
fn cloned_landing_handlers_share_keys_across_concurrent_transfers() {
    let (secret, public) = landing_key_pair(0x77);
    let psk = HandoffPsk::new([0x55; 32]);
    let keys = HandoffLandingKeys::single(psk.clone(), StaticX25519Key::new(&secret));
    let lifetime = std::sync::Arc::downgrade(&keys.active_secret);
    let cache = test_cache();
    std::thread::scope(|scope| {
        for index in 0..8 {
            let handler = keys.clone();
            let psk = &psk;
            let cache = &cache;
            scope.spawn(move || {
                let state = test_state(vec![index; 1024], vec![index; 64]);
                let message = seal(&state, psk, &public);
                let opened = open_transfer(&message, &handler, cache, NOW, WINDOW)
                    .expect("concurrent transfer must authenticate");
                assert_states_equal(opened.state(), &state);
            });
        }
        drop(keys);
    });
    // The generation owner was dropped before joining. The last handler
    // must release the allocation whose secret has zeroize-on-drop.
    assert!(lifetime.upgrade().is_none());
}

#[test]
fn empty_and_maximum_pending_buffers_round_trip() {
    let (landing_secret, landing_public) = landing_key_pair(0x78);
    let psk = HandoffPsk::new([0x56; 32]);
    for (pending, prefetched) in [
        (Vec::new(), Vec::new()),
        (
            vec![0xab; MAX_PENDING_CIPHERTEXT_LEN],
            vec![0xcd; MAX_PREFETCHED_PLAINTEXT_LEN],
        ),
    ] {
        let state = test_state(pending, prefetched);
        let message = seal(&state, &psk, &landing_public);
        assert!(message.len() <= MAX_MESSAGE_LEN);
        let opened = open_transfer(
            &message,
            &HandoffLandingKeys::single(psk.clone(), StaticX25519Key::new(&landing_secret)),
            &test_cache(),
            NOW,
            WINDOW,
        )
        .expect("bounded transfer must open");
        assert_states_equal(opened.state(), &state);
    }
}

#[test]
fn wrong_psk_and_wrong_static_key_fail_authentication() {
    let (_, landing_public) = landing_key_pair(0x79);
    let (other_secret, _) = landing_key_pair(0x7a);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    let (landing_secret, _) = landing_key_pair(0x79);
    assert_eq!(
        open_error(
            &message,
            &HandoffPsk::new([0x56; 32]),
            &landing_secret,
            &test_cache(),
            NOW,
        ),
        HandoffError::Authentication
    );
    assert_eq!(
        open_error(&message, &psk, &other_secret, &test_cache(), NOW),
        HandoffError::Authentication
    );
}

#[test]
fn mutated_header_byte_fails_aead() {
    let (landing_secret, landing_public) = landing_key_pair(0x7b);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    // A client_random byte: structure, timestamp, and nonce are untouched,
    // so the failure must come from the AEAD AD check.
    let mut tampered = message;
    tampered[62] ^= 1;
    assert_eq!(
        open_error(&tampered, &psk, &landing_secret, &test_cache(), NOW),
        HandoffError::Authentication
    );
}

#[test]
fn replayed_nonce_is_rejected_before_any_dh_work() {
    let (landing_secret, landing_public) = landing_key_pair(0x7c);
    let (other_secret, _) = landing_key_pair(0x7d);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);
    let cache = test_cache();

    open_transfer(
        &message,
        &HandoffLandingKeys::single(psk.clone(), StaticX25519Key::new(&landing_secret)),
        &cache,
        NOW,
        WINDOW,
    )
    .expect("first delivery must open");
    assert_eq!(cache.entry_count(), 1);
    // Even with the WRONG static key the replay check fires first,
    // proving the rejection happens before the DH.
    assert_eq!(
        open_error(&message, &psk, &other_secret, &cache, NOW),
        HandoffError::Replay
    );
    assert_eq!(
        open_error(&message, &psk, &landing_secret, &cache, NOW),
        HandoffError::Replay
    );
}

#[test]
fn expired_and_future_timestamps_are_rejected() {
    let (landing_secret, landing_public) = landing_key_pair(0x7e);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    for skewed_now in [NOW + WINDOW + 1, NOW - WINDOW - 1] {
        assert_eq!(
            open_error(&message, &psk, &landing_secret, &test_cache(), skewed_now),
            HandoffError::TimeWindow
        );
    }
    // Boundary values inside the window still authenticate.
    open_transfer(
        &message,
        &HandoffLandingKeys::single(psk, StaticX25519Key::new(&landing_secret)),
        &test_cache(),
        NOW + WINDOW,
        WINDOW,
    )
    .expect("window boundary must open");
}

#[test]
fn version_mismatches_fail_closed() {
    let (landing_secret, landing_public) = landing_key_pair(0x7f);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    for (offset, versions) in [(4_usize, [0, 2, 255]), (5, [0, 1, 2])] {
        for version in versions {
            let mut tampered = message.clone();
            tampered[offset] = version;
            let cache = test_cache();
            assert_eq!(
                open_error(&tampered, &psk, &landing_secret, &cache, NOW),
                HandoffError::Version
            );
            assert_eq!(
                message_len_from_header(&tampered[..HEADER_LEN]),
                Err(HandoffError::Version)
            );
            assert_eq!(cache.entry_count(), 0, "version rejection precedes replay");
        }
    }
    assert_eq!(HANDOFF_PROTOCOL_VERSION, 1);
    assert_eq!(CONTINUATION_STATE_VERSION, 3);
}

#[test]
fn v1_blob_is_rejected_before_parsing_any_legacy_fields() {
    // The authenticated inner version has its own consistency check.
    // Even a version-only v1 blob fails as State, not Length, without
    // interpreting derived keys/IVs as a v2 generation secret.
    assert_eq!(decode_blob(&[1]).unwrap_err(), HandoffError::State);
    let mut blob = Vec::new();
    encode_blob(&test_state(Vec::new(), Vec::new()), &mut blob).expect("v2 blob");
    blob[0] = 1;
    assert_eq!(decode_blob(&blob).unwrap_err(), HandoffError::State);
}

#[test]
fn authenticated_v1_inner_blob_is_rejected_as_invalid_state() {
    let (landing_secret, landing_public) = landing_key_pair(0x7f);
    let psk = HandoffPsk::new([0x55; 32]);
    let mut message = seal(&test_state(Vec::new(), Vec::new()), &psk, &landing_public);
    let header: [u8; HEADER_LEN] = message[..HEADER_LEN].try_into().expect("fixed header");
    let ephemeral: [u8; 32] = message[30..62].try_into().expect("ephemeral public");
    let shared = StaticX25519Key::new(&landing_secret)
        .agree(&ephemeral)
        .expect("shared key");
    let (key, nonce) = super::derive_aead(&header, &shared, &psk, &landing_public)
        .expect("transfer AEAD material");
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("transfer cipher");
    let body_end = message.len() - 16;
    let tag: [u8; 16] = message[body_end..].try_into().expect("detached tag");
    cipher
        .decrypt_inout_detached(
            &Array(*nonce),
            &header,
            (&mut message[HEADER_LEN..body_end]).into(),
            &Array(tag),
        )
        .expect("valid transfer must authenticate");
    message[HEADER_LEN] = 1;
    let tag = cipher
        .encrypt_inout_detached(
            &Array(*nonce),
            &header,
            (&mut message[HEADER_LEN..body_end]).into(),
        )
        .expect("seal inconsistent inner version");
    message[body_end..].copy_from_slice(&tag);
    let cache = test_cache();
    assert_eq!(
        open_error(&message, &psk, &landing_secret, &cache, NOW),
        HandoffError::State
    );
    assert_eq!(
        cache.entry_count(),
        1,
        "inner version is checked after authentication"
    );
}

#[test]
fn v3_blob_round_trips_and_rejects_legacy_versions() {
    let state = test_state(Vec::new(), Vec::new());
    let mut blob = Vec::new();
    encode_blob(&state, &mut blob).expect("v3 state must encode");
    assert_eq!(blob[0], CONTINUATION_STATE_VERSION);
    let decoded = decode_blob(&blob).expect("the v3 blob must decode");
    assert_states_equal(&decoded, &state);
    assert_eq!(decoded.session_kind(), SessionKind::Tcp);

    // Legacy v2 length/layout must not be silently reinterpreted as v3.
    let mut legacy = blob.clone();
    legacy[0] = 2;
    assert_eq!(decode_blob(&legacy).unwrap_err(), HandoffError::State);
    assert_eq!(decode_blob(&[2]).unwrap_err(), HandoffError::State);
}

#[test]
fn v3_blob_rejects_non_boolean_pending_response_and_bad_session_kind() {
    let state = test_state(Vec::new(), Vec::new());
    let mut blob = Vec::new();
    encode_blob(&state, &mut blob).expect("v3 state must encode");
    let pending_response_offset = 1 + 2 + 2 * 32 + 2 * 8;
    blob[pending_response_offset] = 2;
    assert_eq!(decode_blob(&blob).unwrap_err(), HandoffError::State);

    let mut blob = Vec::new();
    encode_blob(&state, &mut blob).expect("v3 state must encode");
    let session_kind_offset = pending_response_offset + 1;
    blob[session_kind_offset] = 0xff;
    assert_eq!(decode_blob(&blob).unwrap_err(), HandoffError::State);
}

#[test]
fn v3_xudp_session_preserves_kind_policy_prefetch_and_sequences() {
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    let destination = Destination::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 53);
    let pending = b"pending-ciphertext-bytes".to_vec();
    let prefetched = b"vision-wire-prefetched-xudp-frames".to_vec();
    let policy = HandoffPolicySnapshot::xudp_initial(destination.clone());
    let state = ContinuationState::new(
        suite,
        TrafficSecret::from_bytes(suite.hash(), &[0x21; 32]).expect("client secret"),
        9,
        TrafficSecret::from_bytes(suite.hash(), &[0x22; 32]).expect("server secret"),
        1,
        true,
        SessionKind::Xudp,
        [0xAB; 16],
        "entry-in",
        destination.clone(),
        pending.clone(),
        prefetched.clone(),
        policy.clone(),
    )
    .expect("xudp continuation");

    let (landing_secret, landing_public) = landing_key_pair(0xA1);
    let psk = HandoffPsk::new([0x5A; 32]);
    let message = seal(&state, &psk, &landing_public);
    let opened = open_transfer(
        &message,
        &HandoffLandingKeys::single(psk, StaticX25519Key::new(&landing_secret)),
        &test_cache(),
        NOW,
        WINDOW,
    )
    .expect("xudp transfer must open")
    .into_state();

    assert_eq!(opened.session_kind(), SessionKind::Xudp);
    assert_eq!(opened.inbound_tag(), "entry-in");
    assert_eq!(opened.client_sequence(), 9);
    assert_eq!(opened.server_sequence(), 1);
    assert!(opened.key_update_response_pending());
    assert_eq!(opened.pending_ciphertext(), pending.as_slice());
    assert_eq!(opened.prefetched_plaintext(), prefetched.as_slice());
    assert_eq!(opened.policy(), &policy);
    assert_eq!(opened.destination(), &destination);
    policy
        .authorize_udp_destination(&destination)
        .expect("initial dest allowed");
    let other = Destination::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 54);
    assert_eq!(
        policy.authorize_udp_destination(&other).unwrap_err(),
        HandoffError::State
    );
}

#[test]
fn sealed_multidest_policy_allows_matching_keep_and_denies_block() {
    let initial = Destination::new(Address::Ipv4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53);
    let allow_cidr = SealedHandoffRouteRule {
        allow: true,
        domains: Vec::new(),
        ips: vec![SealedIpNetwork::V4 {
            network: u32::from(std::net::Ipv4Addr::new(1, 1, 1, 0)),
            prefix: 24,
        }],
        ports: vec![SealedPortRange { start: 53, end: 53 }],
    };
    let deny_block = SealedHandoffRouteRule {
        allow: false,
        domains: Vec::new(),
        ips: vec![SealedIpNetwork::V4 {
            network: u32::from(std::net::Ipv4Addr::new(9, 9, 9, 9)),
            prefix: 32,
        }],
        ports: Vec::new(),
    };
    // Deny rule must be ordered before catch-all default.
    let policy = HandoffPolicySnapshot::xudp_with_sealed_rules(
        initial.clone(),
        vec![deny_block, allow_cidr],
        true,
    );
    assert!(policy.allow_destination_rewrites());
    policy.authorize_udp_destination(&initial).expect("initial");
    let keep_ok = Destination::new(Address::Ipv4(std::net::Ipv4Addr::new(1, 1, 1, 2)), 53);
    policy
        .authorize_udp_destination(&keep_ok)
        .expect("same /24 Keep");
    let blocked = Destination::new(Address::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)), 53);
    assert_eq!(
        policy.authorize_udp_destination(&blocked).unwrap_err(),
        HandoffError::State
    );
    let outside = Destination::new(Address::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 53);
    policy
        .authorize_udp_destination(&outside)
        .expect("default_allow covers non-matching");
}

#[test]
fn sealed_multidest_round_trips_in_continuation_blob() {
    let initial = Destination::new(Address::Ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 443);
    let rule = SealedHandoffRouteRule {
        allow: true,
        domains: vec![SealedDomainMatcher::Suffix("example.test".into())],
        ips: Vec::new(),
        ports: vec![SealedPortRange {
            start: 443,
            end: 443,
        }],
    };
    let policy = HandoffPolicySnapshot::xudp_with_sealed_rules(initial.clone(), vec![rule], false);
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    let state = ContinuationState::new(
        suite,
        TrafficSecret::from_bytes(suite.hash(), &[0x31; 32]).expect("client"),
        0,
        TrafficSecret::from_bytes(suite.hash(), &[0x32; 32]).expect("server"),
        0,
        false,
        SessionKind::Xudp,
        [0xCD; 16],
        "in",
        initial.clone(),
        Vec::new(),
        Vec::new(),
        policy.clone(),
    )
    .expect("state");
    let (landing_secret, landing_public) = landing_key_pair(0xB1);
    let psk = HandoffPsk::new([0x6A; 32]);
    let message = seal(&state, &psk, &landing_public);
    let opened = open_transfer(
        &message,
        &HandoffLandingKeys::single(psk, StaticX25519Key::new(&landing_secret)),
        &test_cache(),
        NOW,
        WINDOW,
    )
    .expect("open")
    .into_state();
    assert_eq!(opened.policy(), &policy);
    let keep = Destination::new(Address::Domain("www.example.test".into()), 443);
    opened
        .policy()
        .authorize_udp_destination(&keep)
        .expect("suffix allow");
    let other = Destination::new(Address::Domain("evil.test".into()), 443);
    assert!(opened.policy().authorize_udp_destination(&other).is_err());
}

#[test]
fn transfer_header_rejects_continuation_version_mismatch() {
    let (landing_secret, landing_public) = landing_key_pair(0xA2);
    let psk = HandoffPsk::new([0x5B; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let mut message = seal(&state, &psk, &landing_public);
    message[STATE_VERSION_OFFSET] = 2;
    assert_eq!(
        open_error(&message, &psk, &landing_secret, &test_cache(), NOW),
        HandoffError::Version
    );
}

#[test]
fn low_order_ephemeral_public_keys_are_rejected() {
    let (landing_secret, landing_public) = landing_key_pair(0x80);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    for low_order in [[0_u8; 32], [1_u8; 32]] {
        let mut crafted = message.clone();
        crafted[30..62].copy_from_slice(&low_order);
        assert_eq!(
            open_error(&crafted, &psk, &landing_secret, &test_cache(), NOW),
            HandoffError::Authentication
        );
    }
}

/// A landing mid-rotation: the new pair is active, the retired pair is
/// still accepted inside the bounded window.
fn rotating_landing_keys() -> (HandoffLandingKeys, [u8; 32], [u8; 32]) {
    let (old_secret, old_public) = landing_key_pair(0x90);
    let (new_secret, new_public) = landing_key_pair(0x91);
    let keys = HandoffLandingKeys::with_previous(
        HandoffPsk::new([0x66; 32]),
        vec![HandoffPsk::new([0x65; 32])],
        StaticX25519Key::new(&new_secret),
        vec![StaticX25519Key::new(&old_secret)],
    )
    .expect("bounded previous lists must build");
    (keys, old_public, new_public)
}

fn open_with_keys(
    message: &[u8],
    keys: &HandoffLandingKeys,
    cache: &HandoffReplayCache,
) -> Result<(), HandoffError> {
    open_transfer(message, keys, cache, NOW, WINDOW).map(|_| ())
}

#[test]
fn previous_key_pair_opens_during_the_window_and_fails_after_it_closes() {
    let (window_keys, old_public, new_public) = rotating_landing_keys();
    assert!(window_keys.rotation_window_open());
    let old_psk = HandoffPsk::new([0x65; 32]);
    let new_psk = HandoffPsk::new([0x66; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let old_message = seal(&state, &old_psk, &old_public);
    let new_message = seal(&state, &new_psk, &new_public);

    // During the window both the retired pair and the active pair open.
    let opened = open_transfer(&old_message, &window_keys, &test_cache(), NOW, WINDOW)
        .expect("a transfer sealed with the retired pair must open during the window");
    assert_states_equal(opened.state(), &state);
    open_with_keys(&new_message, &window_keys, &test_cache())
        .expect("the active pair must open during the window");

    // Once the retired keys are dropped the window is closed: the same
    // old-key transfer fails closed while the active pair still opens.
    let closed_keys = HandoffLandingKeys::single(
        HandoffPsk::new([0x66; 32]),
        StaticX25519Key::new(&landing_key_pair(0x91).0),
    );
    assert!(!closed_keys.rotation_window_open());
    assert_eq!(
        open_with_keys(&old_message, &closed_keys, &test_cache()),
        Err(HandoffError::Authentication),
        "a dropped previous key must fail closed"
    );
    open_with_keys(&new_message, &closed_keys, &test_cache())
        .expect("the active pair must open after the window closes");
}

#[test]
fn candidate_space_is_the_cross_product_of_psks_and_static_keys() {
    let (window_keys, old_public, new_public) = rotating_landing_keys();
    let old_psk = HandoffPsk::new([0x65; 32]);
    let new_psk = HandoffPsk::new([0x66; 32]);
    let state = test_state(Vec::new(), Vec::new());

    // The PSK and the static key rotate on independent schedules, so the
    // mixed combinations must open too.
    let mixed_old_psk = seal(&state, &old_psk, &new_public);
    let mixed_old_static = seal(&state, &new_psk, &old_public);
    open_with_keys(&mixed_old_psk, &window_keys, &test_cache())
        .expect("retired PSK with the active static key must open");
    open_with_keys(&mixed_old_static, &window_keys, &test_cache())
        .expect("active PSK with the retired static key must open");

    // A pair outside every candidate still fails closed.
    let (_, outside_public) = landing_key_pair(0x92);
    let outside_message = seal(&state, &HandoffPsk::new([0x67; 32]), &outside_public);
    assert_eq!(
        open_with_keys(&outside_message, &window_keys, &test_cache()),
        Err(HandoffError::Authentication)
    );
}

#[test]
fn replayed_nonce_is_rejected_across_candidate_keys() {
    let (window_keys, old_public, _) = rotating_landing_keys();
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &HandoffPsk::new([0x65; 32]), &old_public);
    let cache = test_cache();

    open_with_keys(&message, &window_keys, &cache)
        .expect("first delivery must open through a previous candidate");
    assert_eq!(cache.entry_count(), 1);
    assert_eq!(
        open_with_keys(&message, &window_keys, &cache),
        Err(HandoffError::Replay),
        "the same blob must stay rejected no matter which candidate opened it"
    );
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn replay_capacity_recovers_expired_entries_from_other_shards() {
    let cache =
        HandoffReplayCache::new(1, Duration::from_millis(100)).expect("replay policy must compile");
    let now = MonotonicInstant::now();
    cache
        .reserve_at([1; NONCE_LEN], now)
        .expect("first nonce must fit");
    assert_eq!(
        cache.reserve_at([2; NONCE_LEN], now),
        Err(HandoffError::Replay),
        "live global capacity must remain strict"
    );
    cache
        .reserve_at([2; NONCE_LEN], now + Duration::from_millis(101))
        .expect("capacity sweep must reclaim the other expired shard");
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn a_forgery_burns_exactly_one_replay_slot_regardless_of_candidate_count() {
    let (window_keys, _, new_public) = rotating_landing_keys();
    let state = test_state(Vec::new(), Vec::new());
    // Sealed under a key pair the landing does not accept at all.
    let message = seal(&state, &HandoffPsk::new([0x67; 32]), &new_public);
    let cache = test_cache();

    assert_eq!(
        open_with_keys(&message, &window_keys, &cache),
        Err(HandoffError::Authentication)
    );
    assert_eq!(
        cache.entry_count(),
        1,
        "one forged message must reserve exactly one slot, not one per candidate"
    );
    assert_eq!(
        open_with_keys(&message, &window_keys, &cache),
        Err(HandoffError::Replay)
    );
}

#[test]
fn low_order_ephemerals_are_rejected_for_every_candidate() {
    let (window_keys, _, new_public) = rotating_landing_keys();
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &HandoffPsk::new([0x66; 32]), &new_public);

    for low_order in [[0_u8; 32], [1_u8; 32]] {
        let mut crafted = message.clone();
        crafted[30..62].copy_from_slice(&low_order);
        assert_eq!(
            open_with_keys(&crafted, &window_keys, &test_cache()),
            Err(HandoffError::Authentication),
            "every candidate must run its own contributory check"
        );
    }
}

#[test]
fn previous_key_lists_are_bounded() {
    let secret = || StaticX25519Key::new(&landing_key_pair(0x93).0);
    let psk = || HandoffPsk::new([0x68; 32]);
    let too_many_psks = vec![psk(), psk(), psk()];
    assert!(
        HandoffLandingKeys::with_previous(psk(), too_many_psks, secret(), Vec::new()).is_none()
    );
    let too_many_secrets = vec![secret(), secret(), secret()];
    assert!(
        HandoffLandingKeys::with_previous(psk(), Vec::new(), secret(), too_many_secrets).is_none()
    );
    let at_bound = vec![psk(), psk()];
    assert!(HandoffLandingKeys::with_previous(psk(), at_bound, secret(), Vec::new()).is_some());
    assert_eq!(MAX_PREVIOUS_KEYS, 2);
}

#[test]
fn blob_len_above_cap_is_rejected_before_allocation() {
    let (landing_secret, landing_public) = landing_key_pair(0x81);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(Vec::new(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    let mut tampered = message;
    let over_cap = u32::try_from(MAX_BLOB_LEN + 1).expect("cap fits u32");
    tampered[110..114].copy_from_slice(&over_cap.to_be_bytes());
    assert_eq!(
        message_len_from_header(&tampered[..HEADER_LEN]),
        Err(HandoffError::Length)
    );
    assert_eq!(
        open_error(&tampered, &psk, &landing_secret, &test_cache(), NOW),
        HandoffError::Length
    );
}

#[test]
fn server_sequences_zero_and_one_open_but_two_fails_the_cross_check() {
    let (landing_secret, landing_public) = landing_key_pair(0x82);
    let psk = HandoffPsk::new([0x55; 32]);
    for server_sequence in [0, 1] {
        let state = test_state_with_server_sequence(Vec::new(), Vec::new(), server_sequence);
        let message = seal(&state, &psk, &landing_public);
        let opened = open_transfer(
            &message,
            &HandoffLandingKeys::single(psk.clone(), StaticX25519Key::new(&landing_secret)),
            &test_cache(),
            NOW,
            WINDOW,
        )
        .expect("server sequence zero or one must open");
        assert_states_equal(opened.state(), &state);
    }

    let state = test_state_with_server_sequence(Vec::new(), Vec::new(), 2);
    let message = seal(&state, &psk, &landing_public);
    assert_eq!(
        open_error(&message, &psk, &landing_secret, &test_cache(), NOW),
        HandoffError::State
    );
}

#[test]
fn oversized_pending_buffers_are_rejected_at_construction() {
    let pending = vec![0; MAX_PENDING_CIPHERTEXT_LEN + 1];
    let suite = CipherSuite::Aes128GcmSha256;
    let oversized = ContinuationState::new(
        suite,
        TrafficSecret::from_bytes(suite.hash(), &[0x11; 32]).expect("client secret"),
        0,
        TrafficSecret::from_bytes(suite.hash(), &[0x12; 32]).expect("server secret"),
        0,
        false,
        SessionKind::Tcp,
        [0x33; 16],
        "public-reality",
        Destination::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443),
        pending,
        Vec::new(),
        HandoffPolicySnapshot::tcp_placeholder(Destination::new(
            Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            443,
        )),
    );
    assert_eq!(
        oversized.unwrap_err(),
        HandoffError::State,
        "oversized pending buffer must be rejected"
    );
    // Suite/hash disagreement is rejected too.
    let mismatched = ContinuationState::new(
        suite,
        TrafficSecret::from_bytes(HashAlgorithm::Sha384, &[0x11; 48])
            .expect("mismatched client secret"),
        0,
        TrafficSecret::from_bytes(suite.hash(), &[0x12; 32]).expect("server secret"),
        0,
        false,
        SessionKind::Tcp,
        [0x33; 16],
        "public-reality",
        Destination::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443),
        Vec::new(),
        Vec::new(),
        HandoffPolicySnapshot::tcp_placeholder(Destination::new(
            Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            443,
        )),
    );
    assert_eq!(
        mismatched.unwrap_err(),
        HandoffError::State,
        "suite/key-length disagreement must be rejected"
    );
}

#[test]
fn truncated_and_trailing_messages_are_rejected() {
    let (landing_secret, landing_public) = landing_key_pair(0x83);
    let psk = HandoffPsk::new([0x55; 32]);
    let state = test_state(b"pending".to_vec(), Vec::new());
    let message = seal(&state, &psk, &landing_public);

    let truncated = &message[..message.len() - 1];
    assert_eq!(
        open_error(truncated, &psk, &landing_secret, &test_cache(), NOW),
        HandoffError::Length
    );
    let mut extended = message.clone();
    extended.push(0);
    assert_eq!(
        open_error(&extended, &psk, &landing_secret, &test_cache(), NOW),
        HandoffError::Length
    );
}

#[test]
fn debug_output_is_redacted() {
    let psk = HandoffPsk::new([0x55; 32]);
    assert_eq!(format!("{psk:?}"), "HandoffPsk([REDACTED])");
    let (secret, _) = landing_key_pair(0x94);
    let keys = HandoffLandingKeys::with_previous(
        psk,
        vec![HandoffPsk::new([0x65; 32])],
        StaticX25519Key::new(&secret),
        Vec::new(),
    )
    .expect("bounded previous lists must build");
    let rendered_keys = format!("{keys:?}");
    assert!(rendered_keys.contains("[REDACTED]"));
    assert!(!rendered_keys.contains("0x55"));
    let state = test_state(b"pending".to_vec(), Vec::new());
    let rendered = format!("{state:?}");
    assert!(!rendered.contains("0x11"));
    assert!(!rendered.contains("user_id"));
    assert!(rendered.contains("ContinuationState"));
}
