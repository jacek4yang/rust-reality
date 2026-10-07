#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::reality::tls13::fuzz_key_update_fragments;

const MAX_FRAGMENTS: usize = 16;
const MAX_FRAGMENT_LEN: usize = 16;

#[derive(Arbitrary, Debug)]
struct KeyUpdateInput {
    fragments: Vec<Vec<u8>>,
}

fuzz_target!(|input: KeyUpdateInput| {
    let fragments: Vec<&[u8]> = input
        .fragments
        .iter()
        .take(MAX_FRAGMENTS)
        .map(|fragment| &fragment[..fragment.len().min(MAX_FRAGMENT_LEN)])
        .collect();
    fuzz_key_update_fragments(&fragments);
});
