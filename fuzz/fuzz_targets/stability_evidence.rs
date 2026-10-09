#![no_main]

#[path = "../../tools/rr-dev/src/hash.rs"]
mod hash;
#[path = "../../tools/rr-dev/src/release/matrix.rs"]
mod matrix;
#[path = "../../tools/rr-dev/src/release/receipt.rs"]
mod package_receipt;

#[path = "../../tools/rr-dev/src/perf/bootstrap.rs"]
pub mod bootstrap;
#[path = "../../tools/rr-dev/src/perf/json_in.rs"]
pub mod json_in;
#[path = "../../tools/rr-dev/src/perf/json_out.rs"]
pub mod json_out;
#[path = "../../tools/rr-dev/src/perf/stats.rs"]
pub mod stats;
mod perf {
    pub use crate::{bootstrap, json_in, json_out, stats};
}
#[path = "../../tools/rr-dev/src/deploy/netem.rs"]
mod netem;

// Compile the exact tooling parser and pure evaluator without linking the
// tooling control plane into the production library or fuzz target graph.
#[path = "../../tools/rr-dev/src/bench/stability/action.rs"]
mod action;
#[path = "../../tools/rr-dev/src/bench/stability/checks.rs"]
mod checks;
#[path = "../../tools/rr-dev/src/bench/stability/clock.rs"]
mod clock;
#[path = "../../tools/rr-dev/src/bench/stability/evaluate.rs"]
mod evaluate;
#[path = "../../tools/rr-dev/src/bench/stability/execution.rs"]
mod execution;
#[path = "../../tools/rr-dev/src/bench/stability/native_evaluate.rs"]
mod native_evaluate;
#[path = "../../tools/rr-dev/src/bench/stability/native_interop.rs"]
mod native_interop;
#[path = "../../tools/rr-dev/src/bench/stability/native_mechanism.rs"]
mod native_mechanism;
#[path = "../../tools/rr-dev/src/bench/stability/native_pressure.rs"]
mod native_pressure;
#[path = "../../tools/rr-dev/src/bench/stability/observation.rs"]
mod observation;
#[path = "../../tools/rr-dev/src/bench/stability/schema.rs"]
mod schema;
#[path = "../../tools/rr-dev/src/bench/stability/test_receipt.rs"]
mod test_receipt;
#[path = "../../tools/rr-dev/src/bench/stability/transfer.rs"]
mod transfer;
#[path = "../../tools/rr-dev/src/bench/stability/vm.rs"]
mod vm;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let _ = checks::parse_execution(bytes);
    if let Ok(receipt) = package_receipt::parse(bytes) {
        if let Ok(tier) = matrix::Tier::resolve(&receipt.tier) {
            let _ = package_receipt::verify(&receipt, &"a".repeat(40), tier);
        }
    }
    if let Ok(fragment) = serde_json::from_slice::<package_receipt::Fragment>(bytes) {
        let receipt = package_receipt::parse(include_bytes!(
            "../seeds/stability_evidence/seed_package.json"
        ))
        .unwrap();
        let tier = matrix::Tier::resolve("linux-x86_64-generic").unwrap();
        let _ = package_receipt::verify_fragment(&fragment, &receipt, tier);
    }
    if let Ok(probe) = clock::parse(bytes) {
        let contract = serde_json::from_str(schema::CONTRACT).unwrap();
        let _ = clock::verify(&probe, &contract);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let args = netem::NetemArgs {
            profiles: "/fixture/profiles".into(),
            pool_summaries: "/fixture/pools".into(),
            rtts: vec![50],
            losses: vec![0.0],
            concurrencies: vec![1],
            samples: 1,
            connections: 32,
            evaluate_performance: false,
        };
        let profile = r#"{"targetRttMs":50,"perDirectionLossPercent":0.0,"raw":{"handoff-warm":"/fixture/handoff-warm","handoff-cold":"/fixture/handoff-cold","nxr-warm":"/fixture/nxr-warm","nxr-cold":"/fixture/nxr-cold","socks-warm":"/fixture/socks-warm","socks-cold":"/fixture/socks-cold"}}"#;
        for profiles in [text, profile] {
            let _ = netem::validate_observations(&args, |path| {
                Ok(if path == args.profiles {
                    profiles
                } else if path == args.pool_summaries {
                    r#"[{"transport":"handoff"},{"transport":"nxr"},{"transport":"socks5"}]"#
                } else {
                    text
                }
                .to_owned())
            });
        }
    }
    let _ = checks::parse_ci(bytes);
    let _ = checks::parse_gate(bytes);
    let _ = native_interop::parse(bytes);
    let _ = native_interop::parse_environment(bytes);
    let _ = serde_json::from_slice::<native_mechanism::Summary>(bytes);
    let _ = serde_json::from_slice::<native_mechanism::Environment>(bytes);
    let _ = serde_json::from_slice::<native_mechanism::Contract>(bytes);
    let _ = serde_json::from_slice::<native_mechanism::Completion>(bytes);
    let _ = serde_json::from_slice::<native_mechanism::Terminal>(bytes);
    let _ = native_pressure::parse(bytes);
    if let Ok(receipt) = native_pressure::parse(include_bytes!(
        "../seeds/stability_evidence/seed_native_pressure"
    )) {
        let _ = native_pressure::transitions(bytes, &receipt);
    }
    let _ = test_receipt::parse(bytes);
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
