#![no_main]

use std::time::{Duration, Instant};

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::{
    config::ResourceGovernorConfig,
    protocol::{
        reality::{
            ClientHello, RealityAuthError, ReplayCache, ReplayError, SESSION_ID_OFFSET,
            fuzzing::{SyntheticTranscriptSpec, synthetic_authenticator, synthetic_transcript},
        },
        vless::{RequestValidationError, UserId, fuzz_validate_short_id_owner},
    },
    runtime::ResourceGovernor,
};

#[derive(Arbitrary, Debug)]
struct AuthSpec {
    client_secret: [u8; 32],
    random: [u8; 32],
    client_version: [u8; 3],
    client_time: u32,
    short_id: [u8; 8],
    owner: [u8; 16],
    other_short_id: [u8; 8],
    other_owner: [u8; 16],
    mutation: u16,
}

fuzz_target!(|input: &[u8]| {
    let mut input = Unstructured::new(input);
    let Ok(spec) = AuthSpec::arbitrary(&mut input) else {
        return;
    };
    let transcript = synthetic_transcript(SyntheticTranscriptSpec {
        client_secret: spec.client_secret,
        random: spec.random,
        client_version: spec.client_version,
        client_time: spec.client_time,
        short_id: spec.short_id,
        owner: spec.owner,
        other_short_id: spec.other_short_id,
        other_owner: spec.other_owner,
    });

    let authenticated = transcript
        .authenticator
        .authenticate(&transcript.hello, u64::from(spec.client_time))
        .expect("synthetic REALITY transcript must authenticate");
    assert_eq!(authenticated.client_version(), spec.client_version);
    assert_eq!(authenticated.client_time(), spec.client_time);
    assert_eq!(authenticated.user_id(), transcript.owner);

    // Ownership is authoritative: a VLESS UUID from a different user must fail
    // before Addons, command, or destination validation.
    let mismatch = UserId::new(spec.other_owner);
    if mismatch != transcript.owner {
        assert_eq!(
            fuzz_validate_short_id_owner(mismatch, authenticated.user_id()),
            Err(RequestValidationError::ShortIdOwnerMismatch)
        );
    }

    // The configured timestamp boundary is inclusive at 60 seconds and rejects
    // one second beyond it, in both clock directions without integer wrapping.
    assert!(
        transcript
            .authenticator
            .authenticate(
                &transcript.hello,
                u64::from(spec.client_time).saturating_add(60)
            )
            .is_ok()
    );
    assert!(matches!(
        transcript.authenticator.authenticate(
            &transcript.hello,
            u64::from(spec.client_time).saturating_add(61)
        ),
        Err(RealityAuthError::TimeSkew)
    ));
    if spec.client_time >= 61 {
        assert!(matches!(
            transcript
                .authenticator
                .authenticate(&transcript.hello, u64::from(spec.client_time - 61)),
            Err(RealityAuthError::TimeSkew)
        ));
    }

    if spec.other_short_id != spec.short_id {
        let wrong_short_id = synthetic_authenticator(&[(spec.other_short_id, spec.other_owner)]);
        assert!(matches!(
            wrong_short_id.authenticate(&transcript.hello, u64::from(spec.client_time)),
            Err(RealityAuthError::ShortId)
        ));
    }

    // Mutating either ciphertext/tag or authenticated ClientHello data must
    // never produce a successful authentication.
    let mut corrupted = transcript.hello.raw_message().to_vec();
    let session_offset = SESSION_ID_OFFSET + usize::from(spec.mutation % 32);
    corrupted[session_offset] ^= 1;
    let corrupted =
        ClientHello::parse_message(&corrupted).expect("ciphertext mutation preserves shape");
    assert!(matches!(
        transcript
            .authenticator
            .authenticate(&corrupted, u64::from(spec.client_time)),
        Err(RealityAuthError::OpenFailed)
    ));

    let mut corrupted_aad = transcript.hello.raw_message().to_vec();
    corrupted_aad[6] ^= 1;
    let corrupted_aad =
        ClientHello::parse_message(&corrupted_aad).expect("random mutation preserves shape");
    assert!(
        transcript
            .authenticator
            .authenticate(&corrupted_aad, u64::from(spec.client_time))
            .is_err()
    );

    // A malformed session identifier is rejected before authentication.
    let mut malformed = transcript.hello.raw_message().to_vec();
    malformed[SESSION_ID_OFFSET - 1] = 31;
    assert!(ClientHello::parse_message(&malformed).is_err());

    let config = ResourceGovernorConfig {
        max_replay_entries: 4,
        handshake_timeout_ms: 10,
        replay_retention_ms: 100,
        ..ResourceGovernorConfig::default()
    };
    let replay = ReplayCache::new(ResourceGovernor::new(&config), &config);
    let started = Instant::now();

    // Pending duplicates fail. Failure/cancellation-equivalent drop rolls back.
    let pending = replay
        .fuzz_reserve_at(&transcript.hello, started)
        .expect("first replay reservation must succeed");
    assert!(matches!(
        replay.fuzz_reserve_at(&transcript.hello, started),
        Err(ReplayError::Duplicate)
    ));
    drop(pending);
    assert_eq!(replay.fuzz_entry_count(), 0);

    // Timeout removes the expired pending entry and an old reservation cannot
    // remove its replacement when the cancelled task finally drops.
    let expired = replay
        .fuzz_reserve_at(&transcript.hello, started)
        .expect("replacement after rollback must reserve");
    let replacement = replay
        .fuzz_reserve_at(&transcript.hello, started + Duration::from_millis(11))
        .expect("expired pending reservation must be replaceable");
    drop(expired);
    assert_eq!(replay.fuzz_entry_count(), 1);
    drop(replacement);
    assert_eq!(replay.fuzz_entry_count(), 0);

    // Only an explicit ClientFinished-equivalent commit persists and rejects a
    // subsequent exact ClientHello replay.
    let mut committed = replay
        .fuzz_reserve_at(&transcript.hello, started + Duration::from_millis(20))
        .expect("commit candidate must reserve");
    committed
        .fuzz_commit_at(started + Duration::from_millis(21))
        .expect("in-window ClientFinished-equivalent commit must succeed");
    drop(committed);
    assert_eq!(replay.fuzz_entry_count(), 1);
    assert!(matches!(
        replay.fuzz_reserve_at(&transcript.hello, started + Duration::from_millis(22)),
        Err(ReplayError::Duplicate)
    ));
});
