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
        let root = std::path::Path::new("/fixture");
        let _ = vm::validate(root, &fixture);
        for constrained in [false, true] {
            let _ =
                vm::launch_commands(root, &fixture, std::path::Path::new("/output"), constrained);
        }
    }
    if let Ok(raw) = schema::parse_observation(bytes) {
        // Exercise the exact raw-field parser with arbitrary retained text.
        let _ = observation::read_ownership(&raw, 1);
        if let Ok(policy) = observation::startup_policy(&raw, 1) {
            if let Ok(sample) = observation::normalize(
                &raw,
                &policy,
                "native",
                schema::Artifact {
                    path: "raw.json".to_owned(),
                    sha256: "a".repeat(64),
                },
            ) {
                let _ = evaluate::evaluate_native_resources(&policy, &sample, &sample, true);
            }
        }
    }
    if let Ok(evidence) = schema::parse(bytes) {
        let _ = evaluate::evaluate(&evidence, &"a".repeat(64));
    }
});
