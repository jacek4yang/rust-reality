#![no_main]

// Compile the exact tooling parser and pure evaluator without linking the
// tooling control plane into the production library or fuzz target graph.
#[path = "../../tools/rr-dev/src/bench/stability/action.rs"]
mod action;
#[path = "../../tools/rr-dev/src/bench/stability/evaluate.rs"]
mod evaluate;
#[path = "../../tools/rr-dev/src/bench/stability/execution.rs"]
mod execution;
#[path = "../../tools/rr-dev/src/bench/stability/native_evaluate.rs"]
mod native_evaluate;
#[path = "../../tools/rr-dev/src/bench/stability/observation.rs"]
mod observation;
#[path = "../../tools/rr-dev/src/bench/stability/schema.rs"]
mod schema;
#[path = "../../tools/rr-dev/src/bench/stability/transfer.rs"]
mod transfer;
#[path = "../../tools/rr-dev/src/bench/stability/vm.rs"]
mod vm;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let _ = action::parse(bytes);
    let _ = action::warm_tcp_config(bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        for fault in [
            None,
            Some("rtt-50"),
            Some("rtt-100-loss-1"),
            Some("line-a-partition"),
        ] {
            let _ = action::qdisc(text, fault);
        }
    }
    let _ = execution::parse_environment(bytes);
    let _ = execution::product_log(bytes);
    let _ = serde_json::from_slice::<execution::Startup>(bytes);
    let _ = serde_json::from_slice::<execution::Terminal>(bytes);
    let _ = serde_json::from_slice::<execution::CellTerminal>(bytes);
    let _ = transfer::ipv4_socks_reply(bytes);
    let artifact = schema::Artifact {
        path: "raw".to_owned(),
        sha256: "a".repeat(64),
    };
    let upload = schema::UploadReceipt {
        access_log_before: artifact.clone(),
        access_log_after: artifact,
        path: "/fresh".to_owned(),
        log_boundary: 0,
        receipt_offset: 0,
        appended_matches: 1,
        bytes: 7,
        sha256: "a".repeat(64),
    };
    let _ = transfer::verify_upload(&[], bytes, &upload);
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = observation::digest_receipt(text, "/proc/42/exe");
        let _ = observation::owned_unix_rows(text, &std::collections::BTreeMap::new());
    }
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
    if let Ok(native) = schema::parse_native(bytes) {
        let _ = native_evaluate::evaluate(
            &native,
            &"a".repeat(40),
            &"a".repeat(64),
            &"a".repeat(64),
            &"a".repeat(64),
        );
    }
});
