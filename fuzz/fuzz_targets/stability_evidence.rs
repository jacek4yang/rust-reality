#![no_main]

// Compile the exact tooling parser and pure evaluator without linking the
// tooling control plane into the production library or fuzz target graph.
#[path = "../../tools/rr-dev/src/bench/stability/evaluate.rs"]
mod evaluate;
#[path = "../../tools/rr-dev/src/bench/stability/observation.rs"]
mod observation;
#[path = "../../tools/rr-dev/src/bench/stability/schema.rs"]
mod schema;
#[path = "../../tools/rr-dev/src/bench/stability/vm.rs"]
mod vm;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(fixture) = schema::parse_vm_fixture(bytes) {
        let _ = vm::validate(std::path::Path::new("/fixture"), &fixture);
    }
    if let Ok(raw) = schema::parse_observation(bytes) {
        // Exercise the exact raw-field parser with arbitrary retained text.
        let _ = observation::read_ownership(&raw, 1);
    }
    if let Ok(evidence) = schema::parse(bytes) {
        let _ = evaluate::evaluate(&evidence, &"a".repeat(64));
    }
});
