#![no_main]

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use arbitrary::{Arbitrary, Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::{
    handoff::{
        ContinuationState, HandoffLandingKeys, HandoffPsk, HandoffReplayCache, open_transfer,
        seal_transfer,
    },
    reality::tls13::{CipherSuite, TrafficKeys},
    vless::{Address, Destination},
};

// Handoff continuation reconstruction target: builds a structured
// ContinuationState, seals it into a LINE→LANDING transfer message, and
// re-opens it on the landing side. The reconstructed state must equal the
// original field-for-field. A single-bit corruption of the sealed message
// must always be rejected.

const MAX_BUFFERED: usize = 4096;

#[derive(Debug)]
struct StateSpec {
    suite: CipherSuite,
    client_key: [u8; 32],
    client_iv: [u8; 12],
    client_sequence: u64,
    server_key: [u8; 32],
    server_iv: [u8; 12],
    server_sequence: u64,
    user_id: [u8; 16],
    destination: Destination,
    pending: Vec<u8>,
    prefetched: Vec<u8>,
}

impl<'a> Arbitrary<'a> for StateSpec {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let suite = match u.arbitrary::<u8>()? % 3 {
            0 => CipherSuite::Aes128GcmSha256,
            1 => CipherSuite::Aes256GcmSha384,
            _ => CipherSuite::ChaCha20Poly1305Sha256,
        };
        let address = match u.arbitrary::<u8>()? % 3 {
            0 => Address::Ipv4(Ipv4Addr::from(u.arbitrary::<u32>()?)),
            1 => {
                let length = u.int_in_range(1..=32_usize)?;
                let mut domain = String::with_capacity(length);
                for _ in 0..length {
                    domain.push(char::from(
                        *u.choose(b"abcdefghijklmnopqrstuvwxyz0123456789.-")?,
                    ));
                }
                Address::Domain(domain)
            }
            _ => Address::Ipv6(Ipv6Addr::from(u.arbitrary::<u128>()?)),
        };
        let port = u.arbitrary::<u16>()?.max(1);
        let mut pending: Vec<u8> = u.arbitrary()?;
        pending.truncate(MAX_BUFFERED);
        let mut prefetched: Vec<u8> = u.arbitrary()?;
        prefetched.truncate(MAX_BUFFERED);
        Ok(Self {
            suite,
            client_key: u.arbitrary()?,
            client_iv: u.arbitrary()?,
            client_sequence: u.arbitrary::<u32>()?.into(),
            server_key: u.arbitrary()?,
            server_iv: u.arbitrary()?,
            // The landing accepts only a server-direction sequence of zero
            // or one; two reaches the rejection path.
            server_sequence: u64::from(u.arbitrary::<u8>()? % 3),
            user_id: u.arbitrary()?,
            destination: Destination::new(address, port),
            pending,
            prefetched,
        })
    }
}

fn traffic_keys(suite: CipherSuite, key: &[u8; 32], iv: [u8; 12]) -> Option<TrafficKeys> {
    let key_len = match suite {
        CipherSuite::Aes128GcmSha256 => 16,
        CipherSuite::Aes256GcmSha384 | CipherSuite::ChaCha20Poly1305Sha256 => 32,
    };
    TrafficKeys::from_raw_parts(&key[..key_len], iv).ok()
}

fn assert_states_equal(opened: &ContinuationState, expected: &StateSpec) {
    assert_eq!(opened.suite(), expected.suite, "suite diverged");
    assert_eq!(opened.client_sequence(), expected.client_sequence);
    assert_eq!(opened.server_sequence(), expected.server_sequence);
    assert_eq!(opened.user_id(), &expected.user_id, "user id diverged");
    assert_eq!(
        opened.destination(),
        &expected.destination,
        "destination diverged"
    );
    assert_eq!(
        opened.pending_ciphertext(),
        expected.pending,
        "pending diverged"
    );
    assert_eq!(
        opened.prefetched_plaintext(),
        expected.prefetched,
        "prefetched diverged"
    );
}

fuzz_target!(|input: &[u8]| {
    let mut unstructured = Unstructured::new(input);
    let Ok(spec) = StateSpec::arbitrary(&mut unstructured) else {
        return;
    };
    let mutation_offset = unstructured.arbitrary::<u16>().unwrap_or(0);

    let Some(client_traffic) = traffic_keys(spec.suite, &spec.client_key, spec.client_iv) else {
        return;
    };
    let Some(server_traffic) = traffic_keys(spec.suite, &spec.server_key, spec.server_iv) else {
        return;
    };
    let Ok(state) = ContinuationState::new(
        spec.suite,
        client_traffic,
        spec.client_sequence,
        server_traffic,
        spec.server_sequence,
        spec.user_id,
        spec.destination.clone(),
        spec.pending.clone(),
        spec.prefetched.clone(),
    ) else {
        return;
    };

    // Fixed synthetic landing key material; never a real key.
    let psk = HandoffPsk::new([0x55; 32]);
    let landing_public = rust_reality::crypto::StaticX25519Key::new(&[0x77; 32]).public_key();
    let keys = HandoffLandingKeys::single(
        HandoffPsk::new([0x55; 32]),
        rust_reality::crypto::StaticX25519Key::new(&[0x77; 32]),
    );
    let client_random = [0x42; 32];
    let timestamp = 1_700_000_000_u64;

    let mut message = Vec::new();
    if seal_transfer(
        &state,
        &psk,
        &landing_public,
        client_random,
        timestamp,
        &mut message,
    )
    .is_err()
    {
        return;
    }

    let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120)).expect("bounded cache");
    let opened = open_transfer(&message, &keys, &replay, timestamp, 30);
    if spec.server_sequence <= 1 {
        let transfer =
            opened.unwrap_or_else(|error| panic!("sealed transfer must open: {error:?}"));
        assert_eq!(transfer.timestamp(), timestamp);
        assert_eq!(transfer.client_random(), &client_random);
        assert_states_equal(transfer.state(), &spec);
    } else {
        assert!(
            opened.is_err(),
            "out-of-range server sequence must be rejected"
        );
    }

    // Any single-bit corruption of the sealed message must be rejected.
    let offset = usize::from(mutation_offset) % (message.len() + 1);
    if offset < message.len() {
        let mut corrupted = message.clone();
        corrupted[offset] ^= 0x01;
        let replay =
            HandoffReplayCache::new(1_024, Duration::from_secs(120)).expect("bounded cache");
        assert!(
            open_transfer(&corrupted, &keys, &replay, timestamp, 30).is_err(),
            "corrupted transfer must not open"
        );
    }
});
