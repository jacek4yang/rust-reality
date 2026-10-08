#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::server::vision::fuzz_nested_tls_header_prefix;

fuzz_target!(|input: &[u8]| {
    // A prefix is plausible exactly when it can extend to the pre-existing
    // header predicate. Every fragment boundary shares this same oracle.
    let input = &input[..input.len().min(5)];
    let mut rejected = false;
    for end in 0..=input.len() {
        let prefix = &input[..end];
        let expected = (end == 0 || (20..=23).contains(&prefix[0]))
            && (end < 2 || prefix[1] == 3)
            && (end < 3 || prefix[2] <= 4);
        let actual = fuzz_nested_tls_header_prefix(prefix);
        assert_eq!(actual, expected);
        assert!(!rejected || !actual, "rejection must be monotonic");
        rejected |= !actual;
    }
});
