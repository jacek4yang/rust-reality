use super::{
    evaluate::{self, Verdict},
    schema, verify_artifact,
};
use crate::{bench::workspace::Workspace, hash};
use serde_json::{Value, json};
use std::fmt::Write as _;

fn artifact() -> Value {
    json!({"path":"synthetic-object", "sha256":"a".repeat(64)})
}

fn process(role: &str) -> Value {
    json!({"pid":42,"start_ticks":100,"boot_id":format!("boot-{role}"),"executable_sha256":"a".repeat(64)})
}

fn transfer(id: &str, line: &str, direction: &str, started: u64, size: u64) -> Value {
    json!({
        "id":id,"line":line,"direction":direction,"started_ms":started,"completed_ms":started+1,
        "expected_bytes":size,"received_bytes":size,"expected_sha256":"b".repeat(64),"received_sha256":"b".repeat(64),
        "source":artifact(),"download":if direction == "upload" { Value::Null } else { artifact() },
        "upload": if direction == "download" { Value::Null } else { json!({
            "access_log_before":artifact(),"access_log_after":artifact(),
            "path":format!("/{id}"),"log_boundary":100,"receipt_offset":100,"appended_matches":1,
            "bytes":size,"sha256":"b".repeat(64)
        })}
    })
}

#[test]
fn transfer_receipts_reconstruct_exact_payloads_and_fresh_origin_appends() {
    let workspace = Workspace::create("stability-transfer").unwrap();
    let save = |name: &str, bytes: &[u8]| {
        std::fs::write(workspace.join(name), bytes).unwrap();
        schema::Artifact {
            path: name.to_owned(),
            sha256: hash::sha256_hex(bytes),
        }
    };
    let source = save("source", b"payload");
    let download = save("download", b"payload");
    let row = |path: &str| {
        format!(
            "{}\n",
            json!({"server":"landing","method":"PUT","path":path,"client":"127.0.0.1","bytes":7,"sha256":source.sha256})
        )
    };
    let before = row("/earlier");
    let after = format!("{before}{}", row("/fresh"));
    let mut value = transfer("fresh", "line-a", "bidirectional", 0, 7);
    value["source"] = json!(source);
    value["download"] = json!(download);
    value["expected_sha256"] = json!(source.sha256);
    value["received_sha256"] = json!(source.sha256);
    value["upload"] = json!({
        "access_log_before":save("before", before.as_bytes()),
        "access_log_after":save("after", after.as_bytes()),
        "path":"/fresh","log_boundary":before.len(),"receipt_offset":before.len(),
        "appended_matches":1,"bytes":7,"sha256":source.sha256
    });
    let transfer: schema::Transfer = serde_json::from_value(value).unwrap();
    super::verify_transfer_files(workspace.path(), &transfer).unwrap();
    let receipt = transfer.upload.as_ref().unwrap();
    for invalid in [
        before.clone(),
        format!("{after}{}", row("/fresh")),
        format!("{}{}", row("/fresh"), row("/fresh")),
        after.trim_end().to_owned(),
        after.replace("\"bytes\":7", "\"bytes\":8"),
        after.replace("\"bytes\":7", "\"bytes\":7,\"bytes\":7"),
        after.replace("\"bytes\":7", "\"bytes\":7,\"unobserved\":0"),
    ] {
        assert!(
            super::transfer::verify_upload(before.as_bytes(), invalid.as_bytes(), receipt).is_err()
        );
    }
    let mut stale = receipt.clone();
    stale.log_boundary = 0;
    assert!(super::transfer::verify_upload(before.as_bytes(), after.as_bytes(), &stale).is_err());
    let mut corrupt = transfer.clone();
    corrupt.download = Some(save("corrupt", b"payloae"));
    assert!(super::verify_transfer_files(workspace.path(), &corrupt).is_err());
    corrupt = transfer.clone();
    corrupt.download = None;
    assert!(super::verify_transfer_files(workspace.path(), &corrupt).is_err());
    corrupt = transfer;
    corrupt.source = save("wrong-source", b"different");
    assert!(super::verify_transfer_files(workspace.path(), &corrupt).is_err());
}

pub(super) fn fixture() -> Value {
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let cells: Vec<_> = contract.cells.iter().map(|name| {
        let roles: Vec<_> = contract.roles.iter().map(|role| json!({
            "name":role,"process":process(role),"vcpus":if name.ends_with("/constrained") {1} else {2},
            "memory_limit_bytes":1_073_741_824_u64,"swap_limit_bytes":0,"startup":artifact(),"environment":[artifact(),artifact()],"clocks":[artifact(),artifact()],"terminal_status":artifact(),"server_logs":[artifact()],
            "policy":{
                "runtime_unix_sockets":0,"fixed_fds":7,"fixed_descriptor_targets":["/dev/null","/fixture/server.log","/fixture/server.log","anon_inode:[eventpoll]","anon_inode:[eventfd]","anon_inode:[eventpoll]","anon_inode:[eventfd]"],"listener_sockets":1,"idle_inbound_capacity":16,"dynamic_fd_budget":4096,"pipe_pair_capacity":122,
                "warm_socket_capacity":11,"active_socket_capacity":128,"relay_fd_capacity":128,
                "soft_fd_limit":8192,"replay_capacity":65536,"replay_expiry_ms":120_000,"retirement_deadline_ms":30000
            }
        })).collect();
        let cycles: Vec<_> = (0..contract.cycles).map(|index| {
            let started = u64::try_from(index).unwrap() * contract.cycle_interval_ms;
            let concurrency = contract.concurrency[index];
            let transfers: Vec<_> = ["line-a","line-b"].into_iter().flat_map(|line| {
                (0..100).map(move |count| transfer(&format!("{name}-{index}-{line}-{count}"),line,"download",started+contract.load_start_ms+(count/concurrency)*10,1_048_576))
            }).collect();
            let checkpoints: Vec<_> = contract.checkpoint_offsets_ms.iter().map(|offset| {
                let samples: Vec<_> = contract.roles.iter().map(|role| json!({
                    "observation":{"path":format!("{name}-{index}-{offset}-{role}"),"sha256":hash::sha256_hex(format!("{name}-{index}-{offset}-{role}").as_bytes())},"role":role,"process":process(role),"rss_kib":16384,"hwm_kib":16384,"pss_kib":12000,"anonymous_kib":10000,"threads":4,
                    "descriptors":{
                        "runtime_unix_sockets":0,"total":263,"idle_inbound_sockets":0,"fixed":7,"listener_sockets":1,"warm_sockets":11,"observed_tcp_sockets":12,"observed_pipe_fds":244,
                        "reconciliation":{"active_sockets":0,"active_relay_fds":0,"reserved_dynamic_permits":1},
                        "retained_pipe_pairs":122,"dirty_retained_pipe_bytes":0,
                        "held_dynamic_permits":256,"unexplained":0
                    },
                    "owners":{"handshakes":0,"fallbacks":0,"crypto_operations":0,"dns_lookups":0,
                        "pre_auth_idle_connections":0,"admitted_connections":0,"tracked_connection_tasks":0,"retired_generations":0,
                        "replay_entries":0
                    }
                })).collect();
                json!({"offset_ms":offset,"observed_ms":started+offset,"samples":samples})
            }).collect();
            json!({"index":index,"started_ms":started,"concurrency":contract.concurrency[index],"transfers":transfers,"checkpoints":checkpoints})
        }).collect();
        let mut bindings: Vec<_> = contract.roles.iter().map(|role| json!({"role":role,"identity":process(role)})).collect();
        let faults: Vec<_> = contract.faults.iter().enumerate().map(|(index,fault)| {
            let before = bindings.clone();
            if fault == "landing-restart" {
                bindings[2]["identity"]["pid"] = json!(43);
                bindings[2]["identity"]["start_ticks"] = json!(200);
            }
            let started = u64::try_from(contract.cycles).unwrap() * contract.cycle_interval_ms + u64::try_from(index).unwrap() * contract.fault_interval_ms;
            let restored = started + contract.fault_duration(fault);
            let recovery_concurrency = contract.fault_concurrency_per_line;
            let during_concurrency = contract.fault_concurrency(fault);
            let recovery: Vec<_> = ["line-a","line-b"].into_iter().flat_map(|line| (0..100).map(move |count| transfer(&format!("{name}-{fault}-{line}-recovery-{count}"),line,"download",restored+count/recovery_concurrency,1_048_576))).collect();
            let during: Vec<_> = ["line-a","line-b"].into_iter().filter(|line| fault != "landing-restart" && (fault != "line-a-partition" || *line == "line-b")).flat_map(|line| (0..100).map(move |count| transfer(&format!("{name}-{fault}-{line}-during-{count}"),line,"download",started+1+count/during_concurrency,1_048_576))).collect();
            let checkpoints: Vec<_> = contract.fault_checkpoint_offsets_ms.iter().map(|offset| {
                let mut checkpoint = cycles[0]["checkpoints"][0].clone();
                checkpoint["offset_ms"] = json!(offset);
                checkpoint["observed_ms"] = json!(started+offset);
                for sample in checkpoint["samples"].as_array_mut().unwrap() {
                    sample["observation"] = json!({"path":format!("{name}-{fault}-{offset}-{}",sample["role"]),"sha256":hash::sha256_hex(format!("{name}-{fault}-{offset}-{}",sample["role"]).as_bytes())});
                    sample["process"] = bindings.iter().find(|binding| binding["role"] == sample["role"]).unwrap()["identity"].clone();
                }
                checkpoint
            }).collect();
            let mut prefix = transfer(&format!("{name}-{fault}-prefix"),"line-a","download",started-1,4096);
            prefix["completed_ms"] = json!(if fault == "landing-restart" || fault.starts_with("rtt-") {started+1} else {restored+1});
            json!({"name":fault,"actions":[artifact(),artifact(),artifact(),artifact(),artifact(),artifact()],"started_ms":started,"restored_ms":restored,"first_admission_ms":restored+1,
                "before_processes":before,"after_processes":bindings.clone(),"recovery_transfers":recovery,"affected_prefix":prefix,
                "during_transfers":during,"checkpoints":checkpoints,"expected_failures":if fault == "landing-restart" {vec![started+1]} else {vec![]},"unexpected_failures":0})
        }).collect();
        let mut integrity = Vec::new();
        for line in ["line-a","line-b"] {
            for size in &contract.payload_bytes {
                for direction in &contract.directions {
                    integrity.push(transfer(&format!("{name}-{line}-{size}-{direction}"),line,direction,4_000_000,*size));
                }
            }
        }
        let integrity_checkpoints: Vec<_> = contract.integrity_offsets().iter().map(|offset| {
            let mut checkpoint = faults.last().unwrap()["checkpoints"][0].clone();
            checkpoint["offset_ms"] = json!(offset);
            checkpoint["observed_ms"] = json!(contract.integrity_start()+offset);
            for sample in checkpoint["samples"].as_array_mut().unwrap() {
                sample["observation"] = json!({"path":format!("{name}-integrity-{offset}-{}",sample["role"]),"sha256":hash::sha256_hex(format!("{name}-integrity-{offset}-{}",sample["role"]).as_bytes())});
            }
            checkpoint
        }).collect();
        json!({"name":name,"started_unix_ms":10000,"started":true,"completed":true,"roles":roles,"cycles":cycles,"faults":faults,"integrity_checkpoints":integrity_checkpoints,
            "final_processes":bindings,"integrity":integrity,"unexpected_exits":0,"panics":0,"oom_kills":0,"unexpected_rejections":0,"terminal":artifact()})
    }).collect();
    let checks: Vec<_> = contract.required_checks.iter().map(|name| json!({
        "name":name,"source_commit":"c".repeat(40),"candidate_sha256":"a".repeat(64),"argv":["synthetic-test"],
        "exit_code":0,"completed":true,"executed_cases":1,"failed_cases":0,"execution":artifact(),"output":artifact(),"observations":[]
    })).collect();
    let mut contract_artifact = artifact();
    contract_artifact["sha256"] = json!(hash::sha256_hex(schema::CONTRACT.as_bytes()));
    json!({"schema":"rr-stability-evidence/v1","identity":{
        "source_commit":"c".repeat(40),"source_archive":artifact(),"candidate":artifact(),"evaluator":artifact(),
        "contract":contract_artifact,"environment":artifact(),"workload":artifact()
    },"checks":checks,"cells":cells})
}

fn verdict(value: &Value) -> Verdict {
    let evidence = schema::parse(&serde_json::to_vec(value).unwrap()).unwrap();
    evaluate::evaluate(&evidence, &hash::sha256_hex(schema::CONTRACT.as_bytes())).verdict
}

#[test]
fn external_image_digest_observes_the_callers_running_executable() {
    assert_eq!(
        super::collect::running_image_digest().unwrap(),
        hash::sha256_file(std::path::Path::new("/proc/self/exe")).unwrap()
    );
}

#[test]
fn native_interop_reconstructs_payload_trace_and_external_image_bindings() {
    let workspace = Workspace::create("interop-receipt").unwrap();
    let save = |name: &str, bytes: &[u8]| {
        std::fs::write(workspace.join(name), bytes).unwrap();
        schema::Artifact {
            path: name.to_owned(),
            sha256: hash::sha256_hex(bytes),
        }
    };
    let binary = |name: &str, bytes: &[u8], identity: &str| crate::bench::identity::Binary {
        label: name.to_owned(),
        path: name.into(),
        sha256: hash::sha256_hex(bytes),
        identity: identity.to_owned(),
    };
    let rust = binary("rust-reality", b"product", "product");
    let xray = binary("xray", b"stock", "stock Xray");
    let openssl = binary(
        "openssl",
        b"openssl",
        "OpenSSL 3.5.6 7 Apr 2026\nbuilt on: fixture\n",
    );
    let mut evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    evidence.identity.candidate = save("rust-reality", b"product");
    evidence.identity.environment = save("environment.json", &serde_json::to_vec(&json!({
        "host_kernel":"Linux", "xray_sha256":xray.sha256,"xray_identity":xray.identity,"openssl_sha256":openssl.sha256
    })).unwrap());
    let payload: Vec<_> = (0_u8..=255).cycle().take(1_048_576).collect();
    let summary: Value = serde_json::from_str(
        &crate::bench::no_ccs::summary_json(
            "interop-test",
            &rust,
            &xray,
            &openssl,
            "2026-10-08T00:00:00Z",
            [1001, 1002, 1003, 1004],
            &hash::sha256_hex(&payload),
        )
        .to_python_json(),
    )
    .unwrap();
    let mut check = evidence
        .checks
        .iter()
        .find(|check| check.name == "native-interop")
        .unwrap()
        .clone();
    check.argv = concat!(
        "synthetic-object bench run --suite no-ccs-interop --rust-bin rust-reality ",
        "--xray-bin xray --openssl-bin openssl --run-id interop-test --out-dir ."
    )
    .split_whitespace()
    .map(str::to_owned)
    .collect();
    check.output = save("summary.json", &serde_json::to_vec(&summary).unwrap());
    check.observations = vec![
        save("payload-1.bin", &payload),
        save("download.bin", &payload),
        save(
            "openssl-trace.log",
            b">>> TLS 1.3, Handshake, ServerHello\n",
        ),
        save("xray", b"stock"),
        save("openssl", b"openssl"),
    ];
    assert!(super::verify_interop_receipt(workspace.path(), &check, &evidence.identity).is_ok());
    for (pointer, bad) in [
        ("/rustReality/sha256", json!("c".repeat(64))),
        ("/xray/sha256", json!("d".repeat(64))),
        ("/xray/immutableDuringRun", json!(false)),
        ("/openssl/middlebox", json!(true)),
        ("/topology/ports/cover", json!(1002)),
        ("/assertions/serverHello", json!(false)),
        ("/assertions/payloadBytes", json!(-1)),
        ("/ok", json!(false)),
    ] {
        let mut altered = summary.clone();
        *altered.pointer_mut(pointer).unwrap() = bad;
        check.output = save("summary.json", &serde_json::to_vec(&altered).unwrap());
        assert!(
            super::verify_interop_receipt(workspace.path(), &check, &evidence.identity).is_err(),
            "{pointer}"
        );
    }
    check.output = save("summary.json", &serde_json::to_vec(&summary).unwrap());
    check.observations[1] = save("download.bin", b"corrupt");
    assert!(super::verify_interop_receipt(workspace.path(), &check, &evidence.identity).is_err());
    check.observations[1] = save("download.bin", &payload);
    check.observations[2] = save(
        "openssl-trace.log",
        b">>> ServerHello\n>>> ChangeCipherSpec\n",
    );
    assert!(super::verify_interop_receipt(workspace.path(), &check, &evidence.identity).is_err());
    check.observations[2] = save("openssl-trace.log", b">>> ServerHello\n");
    check.observations.pop();
    assert!(super::verify_interop_receipt(workspace.path(), &check, &evidence.identity).is_err());
}

#[test]
fn bounded_empty_permit_backed_retention_above_historical_fd_proxy_passes() {
    assert_eq!(verdict(&fixture()), Verdict::Pass);
}

#[test]
fn required_checks_cannot_turn_opaque_success_or_another_ci_head_into_pass() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let mut check = evidence
        .checks
        .iter()
        .find(|check| check.name == "exact-head-ci")
        .unwrap()
        .clone();
    check.argv = [
        "gh",
        "run",
        "view",
        "123",
        "--json",
        super::checks::CI_FIELDS,
    ]
    .map(str::to_owned)
    .to_vec();
    let receipt = json!({"headSha":evidence.identity.source_commit,"workflowName":"CI","status":"completed",
        "conclusion":"success","databaseId":123,"url":"https://github.com/jacek4yang/rust-reality/actions/runs/123","event":"pull_request"});
    let verify = |value: &Value, check: &schema::Check| {
        super::checks::verify_ci(
            &serde_json::to_vec(value).unwrap(),
            check,
            &evidence.identity,
        )
    };
    verify(&receipt, &check).unwrap();
    for (field, value) in [
        ("headSha", json!("d".repeat(40))),
        ("workflowName", json!("Native qualification")),
        ("status", json!("in_progress")),
        ("conclusion", json!("cancelled")),
        ("databaseId", json!(124)),
        ("url", json!("https://example.com/success")),
    ] {
        let mut changed = receipt.clone();
        changed[field] = value;
        assert!(verify(&changed, &check).is_err(), "{field}");
    }
    check.argv = vec!["true".to_owned()];
    assert!(verify(&receipt, &check).is_err());
    let workspace = Workspace::create("opaque-check").unwrap();
    let check = &evidence.checks[0];
    assert!(super::verify_required_check(workspace.path(), check, &evidence.identity).is_err());
}

#[test]
fn check_execution_requires_observed_child_and_final_identity() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let check = &evidence.checks[0];
    let receipt = json!({
        "argv":check.argv,"started_unix_ms":100,"completed_unix_ms":200,
        "pid":123,"start_ticks":"456","boot_id":"fixture-boot","exit_code":0,
        "primary_error":null,"finalization_errors":[],
        "source_commit":[evidence.identity.source_commit,evidence.identity.source_commit],
        "candidate_sha256":[evidence.identity.candidate.sha256,evidence.identity.candidate.sha256],
        "evaluator_sha256":[evidence.identity.evaluator.sha256,evidence.identity.evaluator.sha256],
        "stdout":check.output,"stderr":check.output,
    });
    let verify = |value: &Value| {
        let parsed = super::checks::parse_execution(&serde_json::to_vec(value).unwrap())?;
        super::checks::verify_execution(&parsed, check, &evidence.identity)
    };
    assert!(verify(&receipt).is_ok());
    for (pointer, replacement) in [
        ("/argv", json!(["true"])),
        ("/pid", json!(null)),
        ("/start_ticks", json!("0")),
        ("/boot_id", json!("")),
        ("/completed_unix_ms", json!(99)),
        ("/exit_code", json!(1)),
        ("/primary_error", json!("original failure")),
        (
            "/finalization_errors",
            json!(["final identity read failed"]),
        ),
        ("/source_commit/1", json!("substituted")),
        ("/candidate_sha256/1", json!("changed")),
        ("/evaluator_sha256/1", json!("changed")),
        ("/stdout/path", json!("substituted")),
    ] {
        let mut invalid = receipt.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(verify(&invalid).is_err(), "{pointer}");
    }
    let mut missing = receipt;
    missing.as_object_mut().unwrap().remove("primary_error");
    assert!(verify(&missing).is_err());
}

#[test]
fn authoritative_gate_receipt_requires_every_current_stage_and_retained_log() {
    let workspace = Workspace::create("full-gate-receipt").unwrap();
    std::fs::create_dir_all(workspace.join("retained/gate/logs")).unwrap();
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let mut check = evidence.checks[0].clone();
    let labels = crate::check::required_stage_labels();
    check.executed_cases = labels.len() as u64;
    check.argv = vec![
        evidence.identity.evaluator.path.clone(),
        "check".to_owned(),
        "--all".to_owned(),
        "--output".to_owned(),
        "json".to_owned(),
        "--log-dir".to_owned(),
        "/original-run/logs".to_owned(),
    ];
    let stages: Vec<_> = labels.iter().enumerate().map(|(index,label)| {
        for suffix in ["stdout","stderr"] {
            let path = format!("retained/gate/logs/{index}.{suffix}");
            std::fs::write(workspace.join(&path), b"retained stage output\n").unwrap();
            check.observations.push(schema::Artifact {path,sha256:hash::sha256_hex(b"retained stage output\n")});
        }
        json!({"elapsedMilliseconds":index+1,"index":index+1,"label":label,"reason":null,"status":"PASS",
            "stdoutLog":format!("{index}.stdout"),"stderrLog":format!("{index}.stderr")})
    }).collect();
    let receipt = json!({"attempted":labels.len(),"command":"check","elapsedMilliseconds":1000,
        "logDirectory":"/original-run/logs","passed":labels.len(),"protocol":"rr-dev-result/v1",
        "schemaVersion":1,"scope":"all","slowestStage":{"elapsedMilliseconds":labels.len(),"index":labels.len(),"label":labels.last().unwrap()},
        "stages":stages,"status":"PASS","total":labels.len()});
    let bind = |value: &Value, check: &mut schema::Check| {
        let bytes = serde_json::to_vec(value).unwrap();
        std::fs::write(workspace.join("retained/gate/gate.json"), &bytes).unwrap();
        check.output = schema::Artifact {
            path: "retained/gate/gate.json".to_owned(),
            sha256: hash::sha256_hex(&bytes),
        };
    };
    bind(&receipt, &mut check);
    assert_eq!(
        super::verify_required_check(workspace.path(), &check, &evidence.identity)
            .unwrap()
            .verdict,
        Verdict::Pass
    );
    for (pointer, value) in [
        ("/stages/0/status", json!("FAIL")),
        ("/stages/0/label", json!("true")),
        ("/stages/0/reason", json!("failed")),
        ("/stages/0/stdoutLog", json!("0.stderr")),
        ("/stages/0/stdoutLog", json!("..")),
        ("/stages/0/stdoutLog", json!("/absolute.log")),
        ("/total", json!(1)),
        ("/scope", json!("fast")),
        ("/logDirectory", json!("/substituted-run/logs")),
        ("/stages", json!([])),
    ] {
        let mut invalid = receipt.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        bind(&invalid, &mut check);
        assert!(
            super::verify_required_check(workspace.path(), &check, &evidence.identity).is_err(),
            "{pointer}"
        );
    }
    bind(&receipt, &mut check);
    check.argv[6] = "/another-run/logs".to_owned();
    assert!(super::verify_required_check(workspace.path(), &check, &evidence.identity).is_err());
    check.argv[6] = "/original-run/logs".to_owned();
    check.observations.pop();
    assert!(super::verify_required_check(workspace.path(), &check, &evidence.identity).is_err());
}

#[test]
fn lifecycle_receipts_require_named_unfiltered_tests_and_complete_totals() {
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let cases: std::collections::BTreeSet<_> =
        contract.deterministic_tests.values().flatten().collect();
    let mut text = format!("running {} tests\n", cases.len());
    for name in &cases {
        writeln!(&mut text, "test {name} ... ok").unwrap();
    }
    writeln!(&mut text,"\ntest result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",cases.len()).unwrap();
    for (name, required) in &contract.deterministic_tests {
        let mut check = evidence
            .checks
            .iter()
            .find(|check| check.name == *name)
            .unwrap()
            .clone();
        check.executed_cases = required.len() as u64;
        check.argv = [
            "cargo", "test", "--lib", "--locked", "--", "--color", "never",
        ]
        .map(str::to_owned)
        .to_vec();
        super::test_receipt::verify(text.as_bytes(), &check, &contract).unwrap();
        let ignored = text
            .replace(
                &format!("test {} ... ok", required[0]),
                &format!("test {} ... ignored", required[0]),
            )
            .replace(
                &format!("{} passed", cases.len()),
                &format!("{} passed", cases.len() - 1),
            )
            .replace("0 ignored", "1 ignored");
        super::test_receipt::parse(ignored.as_bytes()).unwrap();
        assert!(super::test_receipt::verify(ignored.as_bytes(), &check, &contract).is_err());
        check.argv = vec!["true".to_owned()];
        assert!(super::test_receipt::verify(text.as_bytes(), &check, &contract).is_err());
    }
    for invalid in [
        text.trim_end().to_owned(),
        format!("{text}{text}"),
        text.replace(" ... ok", " ... FAILED"),
        text.replace("0 filtered out", "1 filtered out"),
        text.replace("finished in 0.01s", "finished in NaNs"),
        text.replace("0 failed", "-1 failed"),
        text.replace("\ntest result:", "\ntest duplicated ... ok\ntest result:"),
    ] {
        assert!(super::test_receipt::parse(invalid.as_bytes()).is_err());
    }
}

#[test]
fn execution_receipts_reject_unobserved_kernels_profiles_and_terminal_failures() {
    use super::execution;
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let cell = evidence.cells.last().unwrap();
    let role = &cell.roles[0];
    let environment = json!({"observed_unix_ms":9000,"boot_id":format!("{}\n", role.process.boot_id),
        "online_cpus":"0\n","meminfo":"MemTotal: 984564 kB\nSwapTotal: 0 kB\n",
        "swaps":"Filename Type Size Used Priority\n","vmstat":"oom_kill 0\n","kernel":"6.8.0\n","errors":[]});
    let parse = |value: &Value| execution::parse_environment(&serde_json::to_vec(value).unwrap());
    let before = parse(&environment).unwrap();
    let mut after_value = environment.clone();
    after_value["observed_unix_ms"] = json!(5_000_000);
    let after = parse(&after_value).unwrap();
    assert_eq!(
        execution::environment_pair(&before, &after, role, cell).unwrap(),
        0
    );
    for (key, value) in [
        ("vmstat", json!("oom_kill 0 extra\n")),
        ("vmstat", json!("pgfault 0\n")),
        ("vmstat", json!("oom_kill 0\noom_kill 0\n")),
        ("meminfo", json!("MemTotal: 984564 MB\nSwapTotal: 0 kB\n")),
        ("meminfo", json!("MemTotal: 984564 kB\nSwapTotal: 1 kB\n")),
        (
            "swaps",
            json!("Filename Type Size Used Priority\n/swap file 1024 0 -2\n"),
        ),
        ("errors", json!(["permission denied"])),
        ("online_cpus", json!("0-3\n")),
    ] {
        let mut invalid = after_value.clone();
        invalid[key] = value;
        assert!(parse(&invalid).is_err(), "{key}");
    }
    after_value["vmstat"] = json!("oom_kill 1\n");
    assert_eq!(
        execution::environment_pair(&before, &parse(&after_value).unwrap(), role, cell).unwrap(),
        1
    );
    after_value["boot_id"] = json!("another-boot\n");
    assert!(
        execution::environment_pair(&before, &parse(&after_value).unwrap(), role, cell).is_err()
    );

    let terminal = json!({"role":role.name,"boot_id":role.process.boot_id,"started_unix_ms":cell.started_unix_ms,
        "completed_unix_ms":5_000_000,"candidate_sha256":evidence.identity.candidate.sha256,
        "evaluator_sha256":evidence.identity.evaluator.sha256,"primary_error":null,"finalization_errors":[]});
    let verify = |value: &Value| {
        execution::terminal(
            &serde_json::to_vec(value).unwrap(),
            role,
            cell,
            &evidence.identity,
            5_000_000,
        )
    };
    verify(&terminal).unwrap();
    for (key, value) in [
        ("completed_unix_ms", json!(4_999_999)),
        ("primary_error", json!("unexpected exit")),
        ("evaluator_sha256", json!("changed")),
        ("finalization_errors", json!(["missing final identity"])),
    ] {
        let mut invalid = terminal.clone();
        invalid[key] = value;
        assert!(verify(&invalid).is_err());
    }
    let mut invalid = terminal;
    invalid.as_object_mut().unwrap().remove("primary_error");
    assert!(verify(&invalid).is_err());
}

#[test]
fn product_logs_cannot_hide_rejections_panics_or_truncated_records() {
    let valid = "{\"event\":\"server_starting\",\"level\":\"info\",\"timestampUnixMs\":1}\n";
    super::execution::product_log(valid.as_bytes()).unwrap();
    for invalid in [
        String::new(),
        valid.trim_end().to_owned(),
        valid.replace("\"event\":", "\"event\":\"connection_rejected\",\"event\":"),
        valid.replace("\"timestampUnixMs\":1", "\"timestampUnixMs\":-1"),
    ] {
        assert!(super::execution::product_log(invalid.as_bytes()).is_err());
    }
    let panic = format!("{valid}thread 'main' panicked at test\n");
    assert_eq!(
        super::execution::product_log(panic.as_bytes())
            .unwrap()
            .panics,
        1
    );
    for name in [
        "connection_rejected",
        "configuration_rejected",
        "admission_limited",
    ] {
        assert_eq!(
            super::execution::product_log(valid.replace("server_starting", name).as_bytes())
                .unwrap()
                .rejections,
            1
        );
    }
}

#[test]
fn startup_and_cell_terminal_receipts_require_explicit_complete_outcomes() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let role = &evidence.cells[0].roles[0];
    let startup = json!({"label":"server","pid":role.process.pid,
        "start_ticks":role.process.start_ticks.to_string(),"image_sha256":role.process.executable_sha256,
        "image_error":null,"readiness_error":null});
    let verify =
        |value: &Value| super::execution::startup(&serde_json::to_vec(value).unwrap(), role);
    verify(&startup).unwrap();
    for (field, value) in [
        ("pid", json!(999)),
        ("start_ticks", json!("+100")),
        ("image_error", json!("missing executable")),
        ("readiness_error", json!("timeout")),
    ] {
        let mut invalid = startup.clone();
        invalid[field] = value;
        assert!(verify(&invalid).is_err());
    }
    let mut invalid = startup;
    invalid.as_object_mut().unwrap().remove("image_error");
    assert!(verify(&invalid).is_err());
    assert!(
        serde_json::from_str::<super::execution::CellTerminal>(r#"{"finalization_errors":[]}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<super::execution::CellTerminal>(
            r#"{"primary_error":null,"finalization_errors":[]}"#
        )
        .is_ok()
    );
}

#[test]
fn netem_receipts_require_the_installed_fixed_delay_loss_and_restoration() {
    let clean = r#"[{"kind":"fq_codel","root":true,"options":{"limit":10240}}]"#;
    super::action::qdisc(clean, None).unwrap();
    let netem = json!([{"kind":"netem","root":true,"options":{"limit":1000,"ecn":false,"gap":0,
        "delay":{"delay":0.05,"jitter":0.0,"correlation":0.0},"loss-random":{"loss":0.01,"correlation":0.0}}}]);
    super::action::qdisc(&netem.to_string(), Some("rtt-100-loss-1")).unwrap();
    assert!(super::action::qdisc(&netem.to_string(), None).is_err());
    assert!(super::action::qdisc(clean, Some("rtt-100-loss-1")).is_err());
    for (pointer, value) in [
        ("/0/root", json!(false)),
        ("/0/options/limit", json!(2000)),
        ("/0/options/delay/delay", json!(50)),
        ("/0/options/delay/jitter", json!(0.01)),
        ("/0/options/loss-random/loss", json!(1)),
        ("/0/options/loss-random/correlation", json!(0.1)),
        ("/0/options/ecn", json!(true)),
        ("/0/options/delay/delay", json!("NaN")),
    ] {
        let mut changed = netem.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            super::action::qdisc(&changed.to_string(), Some("rtt-100-loss-1")).is_err(),
            "{pointer}"
        );
    }
    for invalid in [
        "[]",
        "[{}]",
        r#"[{"kind":"tbf"}]"#,
        r#"[{"kind":"netem","root":true,"options":{"limit":1000,"ecn":false,"gap":0,"delay":{"delay":0.05,"delay":0.1,"jitter":0,"correlation":0}}}]"#,
    ] {
        assert!(super::action::qdisc(invalid, Some("rtt-100")).is_err());
    }
    let partition = r#"[{"kind":"netem","root":true,"options":{"limit":1000,"ecn":false,"gap":0,"loss-random":{"loss":1,"correlation":0}}}]"#;
    super::action::qdisc(partition, Some("line-a-partition")).unwrap();
}

#[test]
fn fault_actions_require_successful_commands_and_timely_generation_publication() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let cell = &evidence.cells[0];
    let role = &cell.roles[0];
    let fault = &cell.faults[0];
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let started = cell.started_unix_ms + fault.started_ms + contract.clock_guard_ms();
    let action = json!({"role":role.name,"boot_id":role.process.boot_id,"started_unix_ms":started,
        "completed_unix_ms":started+1,"name":fault.name,"begin":true,"commands":[],"error":null,
        "configuration_sha256":"c".repeat(64),"warm_tcp":true,"termination_signal":null});
    let verify = |value: &Value| {
        let receipt = super::action::parse(&serde_json::to_vec(value).unwrap())?;
        super::action::verify(&receipt, role, cell, fault, &contract)
    };
    verify(&action).unwrap();
    for (key, value) in [
        ("started_unix_ms", json!(started - 1)),
        ("completed_unix_ms", json!(started + 2001)),
        ("error", json!("kill failed")),
        ("boot_id", json!("substituted")),
        ("warm_tcp", json!(false)),
        ("termination_signal", json!(9)),
        ("configuration_sha256", json!("")),
    ] {
        let mut changed = action.clone();
        changed[key] = value;
        assert!(verify(&changed).is_err());
    }
    let receipt = super::action::parse(&serde_json::to_vec(&action).unwrap()).unwrap();
    let publication = format!(
        "{}\n",
        json!({"event":"configuration_published","timestampUnixMs":started+100,"generation":1})
    );
    super::action::publication(publication.as_bytes(), &receipt, 2000).unwrap();
    for invalid in [
        String::new(),
        format!("{publication}{publication}"),
        publication.replace(&(started + 100).to_string(), &(started + 2001).to_string()),
        publication.replace("\"generation\":1", "\"generation\":0"),
    ] {
        assert!(super::action::publication(invalid.as_bytes(), &receipt, 2000).is_err());
    }
    assert!(
        !super::action::warm_tcp_config(br#"{"outbounds":{"landing-1":{"warmTcp":false}}}"#)
            .unwrap()
    );
    assert!(super::action::warm_tcp_config(br#"{"outbounds":{"landing-1":{}}}"#).is_err());
}

#[test]
fn network_fault_commands_cannot_substitute_interface_exit_status_or_kernel_receipt() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let cell = &evidence.cells[0];
    let role = &cell.roles[0];
    let fault = cell
        .faults
        .iter()
        .find(|fault| fault.name == "rtt-50")
        .unwrap();
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let started = cell.started_unix_ms + fault.started_ms + contract.clock_guard_ms();
    let command = |argv: Vec<&str>, stdout: &str, offset: u64| {
        json!({"argv":argv,
        "stdout":stdout,"stderr":"","exit_code":0,"started_unix_ms":started+offset,"completed_unix_ms":started+offset+1})
    };
    let clean = r#"[{"kind":"fq_codel","root":true}]"#;
    let shaped = r#"[{"kind":"netem","root":true,"options":{"limit":1000,"ecn":false,"gap":0,"delay":{"delay":0.025,"jitter":0,"correlation":0}}}]"#;
    let show = vec!["tc", "-j", "qdisc", "show", "dev", "data0"];
    let action = json!({"role":role.name,"boot_id":role.process.boot_id,"started_unix_ms":started,
        "completed_unix_ms":started+100,"name":fault.name,"begin":true,"error":null,
        "configuration_sha256":"c".repeat(64),"warm_tcp":true,"termination_signal":null,
        "commands":[command(show.clone(),clean,0),command(vec!["tc","qdisc","replace","dev","data0","root","netem","delay","25ms"],"",10),command(show,shaped,20)]});
    let verify = |value: &Value| {
        let receipt = super::action::parse(&serde_json::to_vec(value).unwrap())?;
        super::action::verify(&receipt, role, cell, fault, &contract)
    };
    verify(&action).unwrap();
    for (pointer, value) in [
        ("/commands/1/argv/4", json!("eth0")),
        ("/commands/1/exit_code", json!(1)),
        ("/commands/2/stdout", json!(clean)),
        ("/commands/0/stdout", json!(shaped)),
        ("/commands/2/started_unix_ms", json!(started)),
        ("/commands/2/completed_unix_ms", json!(started + 101)),
        ("/commands/1/stderr", json!("unknown option")),
        ("/commands", json!([])),
    ] {
        let mut changed = action.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(verify(&changed).is_err(), "{pointer}");
    }
}

#[test]
fn adversarial_resource_mutations_fail() {
    let valid = fixture();
    for (field, value) in [
        ("descriptors/total", 264),
        ("descriptors/unexplained", 1),
        ("descriptors/retained_pipe_pairs", 123),
        ("descriptors/dirty_retained_pipe_bytes", 1),
        ("descriptors/reconciliation/active_sockets", 1),
        ("owners/admitted_connections", 1),
        ("owners/tracked_connection_tasks", 1),
        ("owners/retired_generations", 1),
        ("owners/handshakes", 1),
        ("owners/fallbacks", 1),
        ("owners/crypto_operations", 1),
        ("owners/dns_lookups", 1),
        ("hwm_kib", 150_000),
    ] {
        let mut changed = valid.clone();
        *changed
            .pointer_mut(&format!(
                "/cells/0/cycles/7/checkpoints/7/samples/2/{field}"
            ))
            .unwrap() = json!(value);
        assert_eq!(verdict(&changed), Verdict::Fail, "{field}");
    }
}

#[test]
fn identity_integrity_receipt_and_coverage_mutations_are_rejected() {
    let valid = fixture();
    for (pointer, value) in [
        (
            "/cells/0/cycles/1/checkpoints/0/samples/0/process/pid",
            json!(43),
        ),
        (
            "/cells/0/cycles/1/checkpoints/0/samples/0/process/executable_sha256",
            json!("d".repeat(64)),
        ),
        (
            "/cells/0/cycles/0/transfers/0/received_sha256",
            json!("d".repeat(64)),
        ),
        ("/cells/0/integrity/0/upload/receipt_offset", json!(99)),
        ("/cells/0/integrity/0/upload/appended_matches", json!(2)),
        ("/cells/0/integrity_checkpoints", json!([])),
        ("/cells/0/integrity_checkpoints/3/observed_ms", json!(0)),
        (
            "/cells/0/integrity_checkpoints/3/samples/0/owners/retired_generations",
            json!(1),
        ),
        (
            "/cells/0/integrity_checkpoints/3/samples/0/process/pid",
            json!(999),
        ),
        ("/cells/0/oom_kills", json!(1)),
        ("/cells/0/unexpected_exits", json!(1)),
        ("/cells/0/cycles/0/checkpoints/1/observed_ms", json!(5000)),
        ("/cells/0/cycles/0/checkpoints", json!([])),
        ("/cells/0/cycles/0/transfers", json!([])),
        ("/cells/0/cycles", json!([])),
        ("/cells/0/faults", json!([])),
        ("/cells/0/faults/0/actions", json!([])),
        ("/cells/0/roles/2/process/boot_id", json!("boot-line-a")),
        ("/checks/0/source_commit", json!("d".repeat(40))),
        ("/checks/0/executed_cases", json!(0)),
        ("/identity/contract/sha256", json!("d".repeat(64))),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(verdict(&changed), Verdict::Pass, "{pointer}");
    }
}

#[test]
fn not_run_fail_and_invalid_remain_distinct() {
    let mut value = fixture();
    value["cells"].as_array_mut().unwrap().pop();
    assert_eq!(verdict(&value), Verdict::NotRun);
    value["checks"][0]["exit_code"] = json!(1);
    assert_eq!(verdict(&value), Verdict::Fail);
    value["checks"][0]["completed"] = json!(false);
    assert_eq!(verdict(&value), Verdict::Invalid);
}

#[test]
fn strict_schema_rejects_unknown_fields_and_invalid_numbers() {
    let valid = fixture();
    for value in [json!(-1), json!(1.5), json!("NaN"), Value::Null] {
        let mut changed = valid.clone();
        changed["cells"][0]["cycles"][0]["checkpoints"][0]["samples"][0]["rss_kib"] = value;
        assert!(schema::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut changed = valid.clone();
    changed["unexpected"] = json!(true);
    assert!(schema::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut impossible = valid.clone();
    impossible["cells"][0]["cycles"][0]["checkpoints"][0]["samples"][0]["rss_kib"] =
        json!(u64::MAX);
    assert_eq!(verdict(&impossible), Verdict::Invalid);
    let raw = serde_json::to_string(&valid).unwrap();
    let duplicate = raw.replacen("\"schema\":", "\"schema\":\"duplicate\",\"schema\":", 1);
    assert!(schema::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn fault_receipts_cannot_hide_late_retention_or_substitute_coverage() {
    let valid = fixture();
    for (pointer, value) in [
        ("/cells/0/faults/0/checkpoints", json!([])),
        (
            "/cells/0/faults/0/checkpoints/4/samples/0/owners/retired_generations",
            json!(1),
        ),
        (
            "/cells/0/faults/0/checkpoints/4/samples/0/owners/tracked_connection_tasks",
            json!(1),
        ),
        (
            "/cells/0/faults/0/checkpoints/4/samples/0/hwm_kib",
            json!(150_000),
        ),
        (
            "/cells/0/faults/4/checkpoints/0/samples/2/process/pid",
            json!(42),
        ),
        ("/cells/0/faults/5/during_transfers", json!([])),
        ("/cells/0/faults/6/during_transfers", json!([])),
        ("/cells/0/faults/0/expected_failures", json!([1_464_001])),
        ("/cells/0/faults/4/expected_failures", json!([])),
        (
            "/cells/0/faults/0/affected_prefix/started_ms",
            json!(1_464_000),
        ),
        (
            "/cells/0/faults/0/affected_prefix/completed_ms",
            json!(1_464_001),
        ),
        ("/cells/0/faults/0/started_ms", json!(1)),
        ("/cells/0/faults/0/checkpoints/4/observed_ms", json!(1)),
        ("/cells/0/cycles/0/transfers/0/started_ms", json!(0)),
        ("/cells/0/cycles/0/concurrency", json!(32)),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(verdict(&changed), Verdict::Pass, "{pointer}");
    }
    let mut changed = valid.clone();
    changed["cells"][0]["cycles"][1]["checkpoints"][0]["samples"][0]["observation"] =
        valid["cells"][0]["cycles"][0]["checkpoints"][0]["samples"][0]["observation"].clone();
    assert_eq!(verdict(&changed), Verdict::Invalid);
    let mut changed = valid;
    for transfer in changed["cells"][0]["cycles"][0]["transfers"]
        .as_array_mut()
        .unwrap()
    {
        transfer["started_ms"] = json!(3000);
        transfer["completed_ms"] = json!(3001);
    }
    assert_eq!(verdict(&changed), Verdict::Invalid);
}

#[test]
fn fault_traffic_requires_both_lines_and_overlapping_matrix_concurrency() {
    let valid = fixture();
    let mut changed = valid.clone();
    changed["cells"][0]["faults"][0]["recovery_transfers"]
        .as_array_mut()
        .unwrap()
        .retain(|transfer| transfer["line"] == "line-a");
    assert_eq!(verdict(&changed), Verdict::Invalid);
    let mut changed = valid.clone();
    for transfer in changed["cells"][0]["faults"][6]["during_transfers"]
        .as_array_mut()
        .unwrap()
    {
        if transfer["line"] == "line-b" {
            for field in ["started_ms", "completed_ms"] {
                transfer[field] = json!(transfer[field].as_u64().unwrap() + 1000);
            }
        }
    }
    assert_eq!(verdict(&changed), Verdict::Invalid);
    let mut changed = valid;
    let start = changed["cells"][0]["faults"][6]["started_ms"]
        .as_u64()
        .unwrap()
        + 1;
    for transfer in changed["cells"][0]["faults"][6]["during_transfers"]
        .as_array_mut()
        .unwrap()
    {
        transfer["started_ms"] = json!(start);
        transfer["completed_ms"] = json!(start + 1);
    }
    assert_eq!(verdict(&changed), Verdict::Invalid);
}

#[test]
fn recovered_permits_cannot_be_hidden_as_unopened_reservations() {
    let mut changed = fixture();
    let descriptors =
        &mut changed["cells"][0]["cycles"][7]["checkpoints"][7]["samples"][0]["descriptors"];
    descriptors["reconciliation"]["reserved_dynamic_permits"] = json!(2);
    descriptors["held_dynamic_permits"] = json!(257);
    assert_eq!(verdict(&changed), Verdict::Fail);
}

#[test]
fn native_reconstruction_and_resource_gate_fail_closed() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let baseline = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let raw =
        schema::parse_observation(&serde_json::to_vec(&raw_observation(baseline, policy)).unwrap())
            .unwrap();
    let startup = super::observation::startup_policy(&raw, 1).unwrap();
    let sample =
        super::observation::normalize(&raw, &startup, "native", baseline.observation.clone())
            .unwrap();
    assert_eq!(
        evaluate::evaluate_native_resources(&startup, &sample, &sample, true).verdict,
        Verdict::Pass
    );
    let mut leaked = sample.clone();
    leaked.owners.retired_generations = 1;
    assert_eq!(
        evaluate::evaluate_native_resources(&startup, &sample, &leaked, true).verdict,
        Verdict::Fail
    );
    leaked = sample.clone();
    leaked.hwm_kib += 65_537;
    assert_eq!(
        evaluate::evaluate_native_resources(&startup, &sample, &leaked, false).verdict,
        Verdict::Fail
    );
    let mut unknown = raw;
    unknown.descriptors.insert(999, "/unowned/file".to_owned());
    assert!(
        super::observation::normalize(&unknown, &startup, "native", baseline.observation.clone())
            .is_err()
    );
}

#[test]
fn runtime_unix_descriptors_have_kernel_backed_fixed_startup_ownership() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let mut raw =
        schema::parse_observation(&serde_json::to_vec(&raw_observation(sample, policy)).unwrap())
            .unwrap();
    // Tokio retains both ends of its signal socket pair and a cloned receiver.
    for (fd, inode) in [(997, 900), (998, 901), (999, 900)] {
        raw.descriptors.insert(fd, format!("socket:[{inode}]"));
    }
    for read in &mut raw.descriptor_reads {
        read.descriptors.clone_from(&raw.descriptors);
    }
    raw.unix_sockets = Some("Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000003 00000000 00000000 0001 03 900\n0000000000000000: 00000003 00000000 00000000 0001 03 901\n".to_owned());
    let startup = super::observation::startup_policy(&raw, 1).unwrap();
    let normalized =
        super::observation::normalize(&raw, &startup, "native", sample.observation.clone())
            .unwrap();
    assert_eq!(normalized.descriptors.runtime_unix_sockets, 3);
    assert_eq!(
        evaluate::evaluate_native_resources(&startup, &normalized, &normalized, true).verdict,
        Verdict::Pass
    );
    raw.descriptors.insert(1000, "socket:[900]".to_owned());
    assert!(
        super::observation::normalize(&raw, &startup, "native", sample.observation.clone())
            .is_err()
    );
}

#[test]
fn collection_receipts_reject_substitution_and_exclude_unowned_socket_paths() {
    let digest = "a".repeat(64);
    let valid = format!("{digest}  /proc/42/exe\n");
    assert_eq!(
        super::observation::digest_receipt(&valid, "/proc/42/exe").unwrap(),
        digest
    );
    for changed in [
        valid.replace("42", "43"),
        format!("{valid}{valid}"),
        valid.replace('a', "z"),
    ] {
        assert!(super::observation::digest_receipt(&changed, "/proc/42/exe").is_err());
    }
    let table = "Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000003 00000000 00000000 0001 03 100\n0000000000000000: 00000003 00000000 00000000 0001 03 101 /unrelated/private/path\n";
    let owned = [(3, "socket:[100]".to_owned())].into_iter().collect();
    let retained = super::observation::owned_unix_rows(table, &owned).unwrap();
    assert!(retained.contains("03 100\n"));
    assert!(!retained.contains("101"));
    assert!(!retained.contains("private"));
    for changed in [
        table.replace("100", "-1"),
        table.replace("101", "100"),
        table.replace("Num", "unexpected"),
    ] {
        assert!(super::observation::owned_unix_rows(&changed, &owned).is_err());
    }
}

fn native_fixture() -> Value {
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let base = fixture();
    let mut policy = base["cells"][0]["roles"][0]["policy"].clone();
    policy["active_socket_capacity"] = json!(4096);
    policy["relay_fd_capacity"] = json!(4096);
    let policies: Vec<_> = contract
        .native_roles
        .iter()
        .map(|role| json!({"role":role,"policy":policy}))
        .collect();
    let workload = 11_000_u64;
    let recovery = workload + contract.native_duration_ms;
    let mut phases = vec![("baseline".to_owned(), 10_000)];
    phases.extend((1..=3).map(|round| (format!("round-{round}"), workload + round * 1000)));
    phases.extend(
        contract
            .native_recovery_offsets_ms
            .iter()
            .map(|offset| (format!("recovery-{offset}"), recovery + offset)),
    );
    phases.push(("terminal".to_owned(), recovery + 181_000));
    let checkpoints: Vec<_> = phases.into_iter().map(|(phase, time)| {
        let samples: Vec<_> = contract.native_roles.iter().enumerate().map(|(index, role)| {
            let mut sample = base["cells"][0]["cycles"][0]["checkpoints"][0]["samples"][0].clone();
            sample["role"] = json!(role);
            sample["process"]["pid"] = json!(42+index);
            sample["process"]["boot_id"] = json!("native-boot");
            sample["observation"] = json!({"path":format!("{phase}-{role}.json"),"sha256":hash::sha256_hex(format!("{phase}-{role}").as_bytes())});
            sample
        }).collect();
        let observations: Vec<_> = samples.iter().map(|sample| sample["observation"].clone()).collect();
        json!({"phase":phase,"started_unix_ms":time,"observations":observations,"samples":samples,"errors":[]})
    }).collect();
    json!({"source_commit":"c".repeat(40),"candidate_sha256":"a".repeat(64),"evaluator_sha256":"a".repeat(64),
        "contract_sha256":hash::sha256_hex(schema::CONTRACT.as_bytes()),"duration_ms":contract.native_duration_ms,
        "workload_started_unix_ms":workload,"recovery_started_unix_ms":recovery,"policies":policies,"checkpoints":checkpoints,
        "primary_error":null,"finalization_errors":[]})
}

#[test]
fn native_offline_coverage_and_identity_cannot_be_claimed_from_a_short_pass() {
    let evaluate = |value: &Value| {
        let receipt = schema::parse_native(&serde_json::to_vec(value).unwrap()).unwrap();
        super::native_evaluate::evaluate(
            &receipt,
            &"c".repeat(40),
            &"a".repeat(64),
            &"a".repeat(64),
            &hash::sha256_hex(schema::CONTRACT.as_bytes()),
        )
        .verdict
    };
    let valid = native_fixture();
    assert_eq!(evaluate(&valid), Verdict::Pass);
    for (pointer, value) in [
        ("/duration_ms", json!(30_000)),
        ("/candidate_sha256", json!("d".repeat(64))),
        ("/source_commit", json!("d".repeat(40))),
        ("/evaluator_sha256", json!("d".repeat(64))),
        (
            "/checkpoints/6/samples/0/owners/retired_generations",
            json!(1),
        ),
        ("/checkpoints/6/samples/0/hwm_kib", json!(100_000)),
        ("/checkpoints/6/samples/0/process/pid", json!(999)),
        ("/checkpoints/0/samples/0/process/pid", json!(43)),
        ("/checkpoints/6/started_unix_ms", json!(1)),
        ("/checkpoints/6/samples", json!([])),
        ("/checkpoints/6/phase", json!("round-1")),
        ("/primary_error", json!("workload failed")),
        ("/finalization_errors", json!(["changed binary"])),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(evaluate(&changed), Verdict::Pass, "{pointer}");
    }
}

#[test]
fn native_offline_verification_reconstructs_bound_raw_samples() {
    let workspace = Workspace::create("stability-native-offline").unwrap();
    let mut receipt =
        schema::parse_native(&serde_json::to_vec(&native_fixture()).unwrap()).unwrap();
    for checkpoint in &mut receipt.checkpoints {
        for (index, sample) in checkpoint.samples.iter_mut().enumerate() {
            let policy = &receipt
                .policies
                .iter()
                .find(|policy| policy.role == sample.role)
                .unwrap()
                .policy;
            let mut raw = raw_observation(sample, policy);
            raw["started_unix_ms"] = json!(checkpoint.started_unix_ms);
            raw["completed_unix_ms"] = json!(checkpoint.started_unix_ms + 1);
            raw["ownership_log"] = json!(raw["ownership_log"].as_str().unwrap().replace(
                "\"timestampUnixMs\":9000",
                &format!("\"timestampUnixMs\":{}", checkpoint.started_unix_ms - 1000)
            ));
            let bytes = serde_json::to_vec(&raw).unwrap();
            std::fs::write(workspace.join(&sample.observation.path), &bytes).unwrap();
            sample.observation.sha256 = hash::sha256_hex(&bytes);
            checkpoint.observations[index] = sample.observation.clone();
        }
    }
    let bytes = serde_json::to_vec(&receipt).unwrap();
    std::fs::write(workspace.join("native.json"), &bytes).unwrap();
    let artifact = schema::Artifact {
        path: "native.json".to_owned(),
        sha256: hash::sha256_hex(&bytes),
    };
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    assert_eq!(
        super::verify_native_receipt(workspace.path(), &artifact, &evidence.identity)
            .unwrap()
            .verdict,
        Verdict::Pass
    );
    std::fs::write(
        workspace.join(&receipt.checkpoints[6].samples[0].observation.path),
        b"changed",
    )
    .unwrap();
    assert_eq!(
        super::verify_native_receipt(workspace.path(), &artifact, &evidence.identity)
            .unwrap()
            .verdict,
        Verdict::Invalid
    );
}

#[test]
fn checked_in_seeds_reach_valid_resource_and_vm_reconstruction() {
    let pressure = super::native_pressure::parse(include_bytes!(
        "../../../../../fuzz/seeds/stability_evidence/seed_native_pressure"
    ))
    .unwrap();
    super::native_pressure::transitions(
        include_bytes!("../../../../../fuzz/seeds/stability_evidence/seed_pressure_events.jsonl"),
        &pressure,
    )
    .unwrap();
    let raw = schema::parse_observation(include_bytes!(
        "../../../../../fuzz/seeds/stability_evidence/seed_owned_unix.json"
    ))
    .unwrap();
    let policy = super::observation::startup_policy(&raw, 1).unwrap();
    let artifact = schema::Artifact {
        path: "synthetic.json".to_owned(),
        sha256: "a".repeat(64),
    };
    let sample = super::observation::normalize(&raw, &policy, "seed", artifact).unwrap();
    assert_eq!(
        evaluate::evaluate_native_resources(&policy, &sample, &sample, true).verdict,
        Verdict::Pass
    );
    let native = schema::parse_native(include_bytes!(
        "../../../../../fuzz/seeds/stability_evidence/seed_native_receipt.json"
    ))
    .unwrap();
    assert_eq!(
        super::native_evaluate::evaluate(
            &native,
            &"a".repeat(40),
            &"a".repeat(64),
            &"a".repeat(64),
            &"a".repeat(64)
        )
        .verdict,
        Verdict::Pass
    );
    let vm = schema::parse_vm_fixture(include_bytes!(
        "../../../../../fuzz/seeds/stability_evidence/seed_vm_fixture.json"
    ))
    .unwrap();
    super::vm::validate(std::path::Path::new("/fixture"), &vm).unwrap();
}

#[test]
fn artifact_verification_rejects_missing_changed_and_escaping_objects() {
    let workspace = Workspace::create("stability-artifacts").unwrap();
    let mut artifact = schema::Artifact {
        path: "object".to_owned(),
        sha256: hash::sha256_hex(b"bound"),
    };
    assert!(verify_artifact(workspace.path(), &artifact).is_err());
    std::fs::write(workspace.join("object"), b"bound").unwrap();
    verify_artifact(workspace.path(), &artifact).unwrap();
    std::fs::write(workspace.join("object"), b"changed").unwrap();
    assert!(verify_artifact(workspace.path(), &artifact).is_err());
    artifact.path = "../object".to_owned();
    assert!(verify_artifact(workspace.path(), &artifact).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("object", workspace.join("link")).unwrap();
        artifact.path = "link".to_owned();
        assert!(verify_artifact(workspace.path(), &artifact).is_err());
    }
}

fn raw_observation(sample: &schema::Sample, policy: &schema::Policy) -> Value {
    let mut descriptors = serde_json::Map::new();
    for target in &policy.fixed_descriptor_targets {
        descriptors.insert(descriptors.len().to_string(), json!(target));
    }
    for index in 1..=12 {
        descriptors.insert(
            descriptors.len().to_string(),
            json!(format!("socket:[{index}]")),
        );
    }
    for index in 0..244 {
        descriptors.insert(
            descriptors.len().to_string(),
            json!(format!("pipe:[{}]", index / 2)),
        );
    }
    let log = [
        json!({"timestampUnixMs":1,"level":"info","event":"configuration_published","generation":0}),
        json!({"timestampUnixMs":9000,"level":"debug","event":"connection_task_ownership","address":"127.0.0.1:9444","tracked_tasks":0}),
        json!({"timestampUnixMs":9000,"level":"debug","event":"resource_ownership","handshakes":0,"fallbacks":0,"crypto_operations":0,"dns_lookups":0,"pre_auth_idle_connections":0,"pre_auth_idle_capacity":16,"fd_capacity":4096,"pipe_pair_capacity":122,"warm_socket_capacity":11,
            "replay_capacity":65536,"replay_expiry_ms":120_000,"retirement_deadline_ms":30000,"generation":0,"admitted_connections":0,"replay_entries":0,"fd_units_in_use":256,"retained_pipe_pairs":122,"retained_pipe_bytes":0,"warm_ready":11,"warm_connecting":0}),
    ].into_iter().fold(String::new(), |mut text, value| { writeln!(&mut text, "{value}").unwrap(); text });
    json!({
        "pid":sample.process.pid,"started_unix_ms":10000,"completed_unix_ms":10050,
        "initial_start_ticks":"100","final_start_ticks":"100","boot_id":sample.process.boot_id,
        "initial_executable_sha256":sample.process.executable_sha256,"final_executable_sha256":sample.process.executable_sha256,
        "status":"VmRSS: 16384 kB\nVmHWM: 16384 kB\nThreads: 4\n","smaps_rollup":"Pss: 12000 kB\nAnonymous: 10000 kB\n",
        "limits":"Max open files            8192                 8192                 files\n",
        "descriptors":descriptors,
        "descriptor_reads":[
            {"descriptors":descriptors,"closed_during_read":[],"errors":[]},
            {"descriptors":descriptors,"closed_during_read":[],"errors":[]}
        ],
        "unix_sockets":"Num RefCount Protocol Flags Type St Inode Path\n","closed_during_read":[],"ownership_log":log,"errors":[]
    })
}

#[test]
fn ownership_requires_contiguous_publications_and_known_retirements() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let mut raw = raw_observation(sample, policy);
    let original = raw["ownership_log"].as_str().unwrap().to_owned();
    let publication = |generation| {
        format!(
            "{}\n",
            json!({"timestampUnixMs":2,"level":"info","event":"configuration_published","generation":generation})
        )
    };
    let retirement = |generation| {
        format!(
            "{}\n",
            json!({"timestampUnixMs":3,"level":"debug","event":"generation_retired","generation":generation})
        )
    };
    let (initial, counters) = original.split_once('\n').unwrap();
    let observe = |log: String| {
        raw["ownership_log"] = json!(log);
        let parsed = schema::parse_observation(&serde_json::to_vec(&raw).unwrap()).unwrap();
        super::observation::read_ownership(&parsed, 1)
    };
    let mut observe = observe;
    let counters = counters.replace("\"generation\":0", "\"generation\":2");
    assert!(observe(format!("{initial}\n{}{counters}", publication(2))).is_err());
    assert!(
        observe(format!(
            "{initial}\n{}{}{counters}",
            publication(2),
            publication(1)
        ))
        .is_err()
    );
    assert!(
        observe(format!(
            "{initial}\n{}{}{}{counters}",
            publication(1),
            publication(2),
            retirement(99)
        ))
        .is_err()
    );
    // Retirement of the old runtime may race the next publication's log. Both
    // complete histories are valid, and every unretired old owner is counted.
    for history in [
        format!("{}{}{}", retirement(0), publication(1), publication(2)),
        format!("{}{}{}", publication(1), publication(2), retirement(0)),
    ] {
        observe(format!("{initial}\n{history}{counters}")).unwrap();
    }
}

#[test]
fn raced_census_is_reported_before_deriving_an_ownership_deficit() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let mut value = raw_observation(sample, policy);
    value["closed_during_read"] = json!([117]);
    value["ownership_log"] = json!(
        value["ownership_log"]
            .as_str()
            .unwrap()
            .replace("\"fd_units_in_use\":256", "\"fd_units_in_use\":0")
    );
    let raw = schema::parse_observation(&serde_json::to_vec(&value).unwrap()).unwrap();
    let error = super::observation::normalize(&raw, policy, "landing", sample.observation.clone())
        .unwrap_err();
    assert!(error.contains("descriptor census raced"), "{error}");
    assert!(
        error.contains("117"),
        "retain the actual vanished FD: {error}"
    );
    // The original incomplete evidence must never become a valid sample.
    assert!(super::observation::verify(&raw, sample, policy).is_err());
}

#[test]
fn descriptor_sweep_history_is_bounded_complete_and_first_match_only() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let base = raw_observation(sample, policy);
    let complete = base["descriptor_reads"][0].clone();
    let verify = |reads: Value| {
        let mut value = base.clone();
        value["descriptor_reads"] = reads;
        let raw = schema::parse_observation(&serde_json::to_vec(&value).unwrap()).unwrap();
        super::observation::verify(&raw, sample, policy)
    };
    let mut churn = complete.clone();
    churn["closed_during_read"] = json!([117]);
    verify(json!([churn, complete, complete])).unwrap();
    // An extra sweep after success would permit cherry-picking resource counts.
    for reads in [
        json!([]),
        json!([complete]),
        json!([complete, complete, complete]),
    ] {
        assert!(verify(reads).is_err());
    }
    let mut denied = complete.clone();
    denied["errors"] = json!(["permission denied"]);
    assert!(verify(json!([denied, complete, complete])).is_err());
    let mut substituted = complete.clone();
    substituted["descriptors"]["0"] = json!("socket:[99999]");
    assert!(verify(json!([complete, substituted])).is_err());
    assert!(
        verify(json!([
            churn, churn, churn, churn, churn, complete, complete
        ]))
        .is_err()
    );
}

#[test]
fn normalized_ownership_requires_fresh_complete_raw_observations() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let raw = raw_observation(sample, policy);
    let verify = |value: &Value| {
        let raw = schema::parse_observation(&serde_json::to_vec(value).unwrap()).unwrap();
        super::observation::verify(&raw, sample, policy)
    };
    verify(&raw).unwrap();
    for (pointer, value) in [
        ("/final_start_ticks", json!("101")),
        ("/final_executable_sha256", json!("d".repeat(64))),
        ("/closed_during_read", json!([123])),
        (
            "/status",
            json!("VmRSS: 16384 kB\nVmRSS: 16384 kB\nVmHWM: 16384 kB\nThreads: 4\n"),
        ),
        ("/smaps_rollup", Value::Null),
        ("/completed_unix_ms", json!(12001)),
        ("/ownership_log", Value::Null),
        ("/descriptors/20", json!("/unexpected-open-file")),
        ("/errors", json!(["permission denied"])),
        (
            "/status",
            json!("VmRSS: 16384 MB\nVmHWM: 16384 kB\nThreads: 4\n"),
        ),
        (
            "/status",
            json!("VmRSS: 16384 kB\nVmHWM: 16384 kB\nThreads: 4 trailing\n"),
        ),
        ("/smaps_rollup", json!("Pss: 12000\nAnonymous: 10000 kB\n")),
        ("/limits", json!("Max open files 8192 garbage files\n")),
    ] {
        let mut changed = raw.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(verify(&changed).is_err(), "{pointer}");
    }
    let log = raw["ownership_log"].as_str().unwrap();
    for changed_log in [
        log.replace("\"retained_pipe_bytes\":0", "\"retained_pipe_bytes\":null"),
        log.replace(
            "\"tracked_tasks\":0",
            "\"tracked_tasks\":0,\"tracked_tasks\":1",
        ),
        log.replace("\"replay_entries\":0", "\"replay_entries\":1"),
        log.replace("\"pipe_pair_capacity\":122", "\"pipe_pair_capacity\":123"),
        log.replace("\"fd_capacity\":4096", "\"fd_capacity\":8192"),
        log.replace("\"warm_socket_capacity\":11", "\"warm_socket_capacity\":12"),
        log.replace("\"timestampUnixMs\":9000", "\"timestampUnixMs\":1"),
        log.lines()
            .filter(|line| !line.contains("connection_task_ownership"))
            .fold(String::new(), |mut text, line| {
                writeln!(&mut text, "{line}").unwrap();
                text
            }),
    ] {
        let mut changed = raw.clone();
        changed["ownership_log"] = json!(changed_log);
        assert!(verify(&changed).is_err());
    }
}

#[test]
fn raw_observations_cannot_be_reused_for_another_cycle_or_window() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let raw =
        schema::parse_observation(&serde_json::to_vec(&raw_observation(sample, policy)).unwrap())
            .unwrap();
    super::observation::verify_checkpoint_time(&raw, 10000, 0, 2000).unwrap();
    assert!(super::observation::verify_checkpoint_time(&raw, 10000, 183_000, 2000).is_err());
    assert!(super::observation::verify_checkpoint_time(&raw, 7000, 0, 2000).is_err());
    assert!(super::observation::verify_checkpoint_time(&raw, u64::MAX, 1, 2000).is_err());
}

#[test]
fn raw_descriptor_keys_cannot_overwrite_an_observation() {
    let evidence = schema::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let raw = serde_json::to_string(&raw_observation(sample, policy)).unwrap();
    for key in ["0", "00"] {
        let duplicate = raw.replace(
            "\"descriptors\":{",
            &format!("\"descriptors\":{{\"{key}\":\"forged\","),
        );
        assert!(schema::parse_observation(duplicate.as_bytes()).is_err());
    }
}

#[test]
fn bounded_pre_auth_idle_tasks_are_counted_without_exempting_leaked_work() {
    let mut value = fixture();
    for cell in value["cells"].as_array_mut().unwrap() {
        for cycle in cell["cycles"].as_array_mut().unwrap() {
            for checkpoint in cycle["checkpoints"].as_array_mut().unwrap() {
                let landing = &mut checkpoint["samples"][2];
                landing["descriptors"]["warm_sockets"] = json!(0);
                landing["descriptors"]["idle_inbound_sockets"] = json!(11);
                landing["owners"]["pre_auth_idle_connections"] = json!(11);
                landing["owners"]["admitted_connections"] = json!(11);
                landing["owners"]["tracked_connection_tasks"] = json!(11);
            }
        }
    }
    assert_eq!(verdict(&value), Verdict::Pass);
    let evidence = schema::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    let sample = &evidence.cells[0].cycles[0].checkpoints[0].samples[2];
    let policy = &evidence.cells[0].roles[2].policy;
    let mut raw = raw_observation(sample, policy);
    let log = raw["ownership_log"]
        .as_str()
        .unwrap()
        .replace(
            "\"pre_auth_idle_connections\":0",
            "\"pre_auth_idle_connections\":11",
        )
        .replace("\"admitted_connections\":0", "\"admitted_connections\":11")
        .replace("\"tracked_tasks\":0", "\"tracked_tasks\":11")
        .replace("\"warm_ready\":11", "\"warm_ready\":0");
    raw["ownership_log"] = json!(log);
    let raw = schema::parse_observation(&serde_json::to_vec(&raw).unwrap()).unwrap();
    super::observation::verify(&raw, sample, policy).unwrap();
    for field in ["admitted_connections", "tracked_connection_tasks"] {
        let mut changed = value.clone();
        changed["cells"][0]["cycles"][7]["checkpoints"][7]["samples"][2]["owners"][field] =
            json!(12);
        assert_eq!(verdict(&changed), Verdict::Fail);
    }
    value["cells"][0]["roles"][2]["policy"]["idle_inbound_capacity"] = json!(10);
    assert_eq!(verdict(&value), Verdict::Fail);
}

#[test]
fn active_churn_does_not_subtract_a_periodic_counter_from_a_newer_census() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let baseline = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let mut raw: schema::Observation =
        serde_json::from_value(raw_observation(baseline, policy)).unwrap();
    // Nine accepted/dialled sockets appeared after the last periodic record.
    // Both raw reads agree; the old permit counter must not fabricate a leak.
    for fd in 900..909 {
        raw.descriptors
            .insert(fd, format!("socket:[{}]", 99000 + fd));
    }
    for read in &mut raw.descriptor_reads {
        read.descriptors.clone_from(&raw.descriptors);
    }
    let sample =
        super::observation::normalize_active(&raw, policy, "native", baseline.observation.clone())
            .unwrap();
    assert!(sample.descriptors.reconciliation.is_none());
    super::observation::verify(&raw, &sample, policy).unwrap();
    assert_eq!(
        evaluate::evaluate_native_resources(policy, baseline, &sample, false).verdict,
        Verdict::Pass
    );
    // The same active-only evidence cannot masquerade as recovered ownership.
    assert_eq!(
        evaluate::evaluate_native_resources(policy, baseline, &sample, true).verdict,
        Verdict::Invalid
    );
    let error = super::observation::normalize(&raw, policy, "native", baseline.observation.clone())
        .unwrap_err();
    assert!(
        error.contains("ownership evidence is not coherent"),
        "{error}"
    );
    let mut forged = sample;
    forged.descriptors.observed_tcp_sockets -= 1;
    assert!(super::observation::verify(&raw, &forged, policy).is_err());
}

#[test]
fn active_sampling_still_rejects_real_caps_dirty_retention_and_unknown_descriptors() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let baseline = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let mut raw: schema::Observation =
        serde_json::from_value(raw_observation(baseline, policy)).unwrap();
    let sample =
        super::observation::normalize_active(&raw, policy, "native", baseline.observation.clone())
            .unwrap();
    for mutation in 0..4 {
        let mut invalid = sample.clone();
        match mutation {
            0 => invalid.descriptors.held_dynamic_permits = policy.dynamic_fd_budget + 1,
            1 => invalid.descriptors.dirty_retained_pipe_bytes = 1,
            2 => {
                invalid.descriptors.observed_tcp_sockets = policy.dynamic_fd_budget + 2;
                invalid.descriptors.total = invalid.descriptors.observed_tcp_sockets
                    + invalid.descriptors.observed_pipe_fds
                    + invalid.descriptors.fixed
                    + invalid.descriptors.runtime_unix_sockets;
            }
            _ => invalid.owners.replay_entries = policy.replay_capacity + 1,
        }
        assert_eq!(
            evaluate::evaluate_native_resources(policy, baseline, &invalid, false).verdict,
            Verdict::Fail
        );
    }
    raw.descriptors.insert(999, "/unexpected-file".to_owned());
    for read in &mut raw.descriptor_reads {
        read.descriptors.clone_from(&raw.descriptors);
    }
    assert!(
        super::observation::normalize_active(&raw, policy, "native", baseline.observation.clone())
            .is_err()
    );
}

#[test]
fn incoherent_recovery_is_invalid_not_a_product_failure_or_a_pass() {
    let mut value = fixture();
    value["cells"][0]["cycles"][7]["checkpoints"][7]["samples"][2]["descriptors"]["held_dynamic_permits"] =
        json!(0);
    assert_eq!(verdict(&value), Verdict::Invalid);
    let mut value = fixture();
    value["cells"][0]["cycles"][7]["checkpoints"][7]["samples"][2]["descriptors"]["reconciliation"] =
        Value::Null;
    assert_eq!(verdict(&value), Verdict::Invalid);
}

#[test]
fn active_reload_can_precede_the_next_counter_without_hiding_recovery_retirement() {
    let evidence: schema::Evidence = serde_json::from_value(fixture()).unwrap();
    let baseline = &evidence.cells[0].cycles[0].checkpoints[0].samples[0];
    let policy = &evidence.cells[0].roles[0].policy;
    let mut raw: schema::Observation =
        serde_json::from_value(raw_observation(baseline, policy)).unwrap();
    let timestamp = raw.completed_unix_ms;
    writeln!(raw.ownership_log.as_mut().unwrap(), "{}", json!({
        "timestampUnixMs":timestamp,"level":"info","event":"configuration_published","generation":1
    })).unwrap();
    let sample =
        super::observation::normalize_active(&raw, policy, "native", baseline.observation.clone())
            .unwrap();
    assert_eq!(sample.owners.retired_generations, 1);
    assert_eq!(
        evaluate::evaluate_native_resources(policy, baseline, &sample, false).verdict,
        Verdict::Pass
    );
    assert!(
        super::observation::normalize(&raw, policy, "native", baseline.observation.clone())
            .is_err()
    );
    writeln!(
        raw.ownership_log.as_mut().unwrap(),
        "{}",
        json!({
            "timestampUnixMs":timestamp,"level":"debug","event":"generation_retired","generation":0
        })
    )
    .unwrap();
    let sample =
        super::observation::normalize_active(&raw, policy, "native", baseline.observation.clone())
            .unwrap();
    assert_eq!(sample.owners.retired_generations, 0);
    // A forged future generation still cannot be justified by a known reload.
    raw.ownership_log = raw
        .ownership_log
        .map(|log| log.replace("\"generation\":1", "\"generation\":99"));
    assert!(
        super::observation::normalize_active(&raw, policy, "native", baseline.observation.clone())
            .is_err()
    );
}

#[test]
fn injected_evictions_require_exact_peer_reason_time_and_one_use() {
    use super::execution::product_log_with_faults;
    let event = json!({"event":"connection_rejected","level":"warn","timestampUnixMs":105,
        "peer":"192.0.2.5:43028","reason":"authentication"});
    let encode = |value: &Value| format!("{value}\n").into_bytes();
    let proof = || vec![("192.0.2.5:43028".to_owned(), 100, 110)];
    let mut remaining = proof();
    assert_eq!(
        product_log_with_faults(&encode(&event), &mut remaining, &mut None)
            .unwrap()
            .rejections,
        0
    );
    assert!(remaining.is_empty());
    assert_eq!(
        product_log_with_faults(&encode(&event), &mut remaining, &mut None)
            .unwrap()
            .rejections,
        1
    );
    for (field, value) in [
        ("peer", json!("192.0.2.5:43029")),
        ("reason", json!("outbound")),
        ("event", json!("configuration_rejected")),
        ("event", json!("admission_limited")),
        ("timestampUnixMs", json!(99)),
        ("timestampUnixMs", json!(111)),
    ] {
        let mut changed = event.clone();
        changed[field] = value;
        assert_eq!(
            product_log_with_faults(&encode(&changed), &mut proof(), &mut None)
                .unwrap()
                .rejections,
            1
        );
    }
    let duplicate = format!("{event}\n{event}\n");
    assert_eq!(
        product_log_with_faults(duplicate.as_bytes(), &mut proof(), &mut None)
            .unwrap()
            .rejections,
        1
    );
    let duplicate_peer = String::from_utf8(encode(&event))
        .unwrap()
        .replace("\"peer\":", "\"peer\":\"192.0.2.5:1\",\"peer\":");
    assert!(product_log_with_faults(duplicate_peer.as_bytes(), &mut proof(), &mut None).is_err());
}

#[test]
fn stale_eviction_peers_are_exact_socket_rows_not_substring_matches() {
    let value = json!({"role":"landing","boot_id":"fixture","started_unix_ms":100,
        "completed_unix_ms":110,"name":"stale","begin":true,"error":null,
        "configuration_sha256":"a".repeat(64),"termination_signal":null,"warm_tcp":null,
        "commands":[{"argv":[],"started_unix_ms":101,"completed_unix_ms":109,
        "exit_code":0,"stdout":"Netid Recv-Q Send-Q Local Address:Port Peer Address:Port Process\ntcp 0 0 192.0.2.6:9443 192.0.2.5:43028\n","stderr":""}]});
    let parse = |v: &Value| super::action::parse(&serde_json::to_vec(v).unwrap()).unwrap();
    assert_eq!(
        super::action::stale_evictions(&parse(&value)).unwrap(),
        vec![("192.0.2.5:43028".to_owned(), 101, 109)]
    );
    for row in [
        "tcp 0 0 192.0.2.6:9444 192.0.2.5:43028",
        "tcp 0 0 192.0.2.6:9443 192.0.2.50:43028",
        "tcp 0 0 192.0.2.6:9443 192.0.2.5:0",
        "tcp 0 0 192.0.2.6:9443 192.0.2.5:43028 trailing",
        "tcp 0 0 192.0.2.6:9443 192.0.2.5:43028\ntcp 0 0 192.0.2.6:9443 192.0.2.5:43028",
        "",
    ] {
        let mut changed = value.clone();
        changed["commands"][0]["stdout"] = json!(format!("header\n{row}\n"));
        assert!(super::action::stale_evictions(&parse(&changed)).is_err());
    }
}

#[test]
fn restart_disconnect_matches_only_one_witnessed_handoff_epipe() {
    use super::execution::product_log_with_faults;
    let event = json!({"event":"connection_rejected","level":"warn","timestampUnixMs":105,
        "peer":"127.0.0.1:43028","reason":"outbound","failure":{"stage":"handoff_relay","cause":"io","errno":32}});
    let encode = |v: &Value| format!("{v}\n").into_bytes();
    let proof = || Some(("127.0.0.1:43028".to_owned(), 100, 110));
    let mut expected = proof();
    assert_eq!(
        product_log_with_faults(&encode(&event), &mut vec![], &mut expected)
            .unwrap()
            .rejections,
        0
    );
    assert!(expected.is_none());
    assert_eq!(
        product_log_with_faults(&encode(&event), &mut vec![], &mut expected)
            .unwrap()
            .rejections,
        1
    );
    for (pointer, value) in [
        ("/peer", json!("127.0.0.1:43029")),
        ("/reason", json!("authentication")),
        ("/failure/stage", json!("connect")),
        ("/failure/cause", json!("timeout")),
        ("/failure/errno", json!(104)),
        ("/timestampUnixMs", json!(99)),
        ("/timestampUnixMs", json!(111)),
        ("/event", json!("admission_limited")),
    ] {
        let mut changed = event.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            product_log_with_faults(&encode(&changed), &mut vec![], &mut proof())
                .unwrap()
                .rejections,
            1,
            "{pointer}"
        );
    }
}

#[test]
fn duplicate_restart_failure_fields_are_invalid_not_expected() {
    let bytes = br#"{"event":"connection_rejected","level":"warn","timestampUnixMs":105,"peer":"127.0.0.1:43028","reason":"outbound","failure":{"stage":"handoff_relay","cause":"io","errno":104,"errno":32}}
"#;
    let mut proof = Some(("127.0.0.1:43028".to_owned(), 100, 110));
    assert!(super::execution::product_log_with_faults(bytes, &mut vec![], &mut proof).is_err());
    assert!(proof.is_some());
}

#[test]
fn restart_ingress_requires_one_exact_owned_connection_and_successful_census() {
    let value = json!({"role":"line-a","boot_id":"fixture","started_unix_ms":100,"completed_unix_ms":110,
        "name":"landing-restart","begin":true,"error":null,"configuration_sha256":"a".repeat(64),
        "termination_signal":null,"warm_tcp":true,"commands":[{
        "argv":["ss","-Hnt","state","established","src","127.0.0.1","(","sport","=",":9443",")"],
        "started_unix_ms":101,"completed_unix_ms":109,"exit_code":0,"stderr":"", "stdout":"0 0 127.0.0.1:9443 127.0.0.1:43028\n"}]});
    let parse = |v: &Value| super::action::parse(&serde_json::to_vec(v).unwrap()).unwrap();
    assert_eq!(
        super::action::restart_ingress(&parse(&value)).unwrap(),
        "127.0.0.1:43028"
    );
    for (pointer, new) in [
        ("/role", json!("line-b")),
        ("/begin", json!(false)),
        ("/commands/0/exit_code", json!(1)),
        ("/commands/0/stderr", json!("netlink denied")),
        ("/commands/0/completed_unix_ms", json!(111)),
        ("/commands/0/stdout", json!("")),
        (
            "/commands/0/stdout",
            json!("0 0 127.0.0.1:9443 192.0.2.5:43028\n"),
        ),
        (
            "/commands/0/stdout",
            json!("0 0 127.0.0.1:9443 127.0.0.1:43028\n0 0 127.0.0.1:9443 127.0.0.1:43029\n"),
        ),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = new;
        assert!(
            super::action::restart_ingress(&parse(&changed)).is_err(),
            "{pointer}"
        );
    }
}
