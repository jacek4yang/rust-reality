#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::config::fuzz_load;

// Diagnostic-render target: arbitrary bytes go through the exact `load` path
// and every failure is rendered. The span scanner, classifier, redaction, and
// renderer must never panic on malformed input, and the rendered block must
// stay plain text (no ANSI escapes) at all times.
fuzz_target!(|data: &[u8]| {
    if let Err(error) = fuzz_load(data) {
        let rendered = error.to_string();
        assert!(!rendered.contains('\u{1b}'), "ANSI escape in diagnostic");
    }
});
