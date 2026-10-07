#![no_main]

// Compile the exact tooling parser and pure evaluator without linking the
// tooling control plane into the production library or fuzz target graph.
#[path = "../../tools/rr-dev/src/bench/stability/evaluate.rs"]
mod evaluate;
#[path = "../../tools/rr-dev/src/bench/stability/schema.rs"]
mod schema;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(evidence) = schema::parse(bytes) {
        let _ = evaluate::evaluate(&evidence, &"a".repeat(64));
    }
});
