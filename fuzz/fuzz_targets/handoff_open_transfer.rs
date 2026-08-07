#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::handoff::{HandoffPsk, HandoffReplayCache, open_transfer};
use x25519_dalek::StaticSecret;

fuzz_target!(|input: &[u8]| {
    let psk = HandoffPsk::new([0x55; 32]);
    let landing_secret = StaticSecret::from([0x77; 32]);
    let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120)).expect("bounded cache");
    let _ = open_transfer(input, &psk, &landing_secret, &replay, 1_700_000_000, 30);
});
