#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::handoff::{
    HandoffLandingKeys, HandoffPsk, HandoffReplayCache, open_transfer,
};
use x25519_dalek::StaticSecret;

fuzz_target!(|input: &[u8]| {
    let keys =
        HandoffLandingKeys::single(HandoffPsk::new([0x55; 32]), StaticSecret::from([0x77; 32]));
    let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120)).expect("bounded cache");
    let _ = open_transfer(input, &keys, &replay, 1_700_000_000, 30);
});
