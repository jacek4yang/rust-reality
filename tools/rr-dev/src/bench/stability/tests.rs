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

fn fixture() -> Value {
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let cells: Vec<_> = contract.cells.iter().map(|name| {
        let roles: Vec<_> = contract.roles.iter().map(|role| json!({
            "name":role,"process":process(role),"vcpus":if name.ends_with("/constrained") {1} else {2},
            "memory_limit_bytes":1_073_741_824_u64,"swap_limit_bytes":0,"startup":artifact(),
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
                        "runtime_unix_sockets":0,"total":263,"idle_inbound_sockets":0,"fixed":7,"listener_sockets":1,"warm_sockets":11,"active_sockets":0,
                        "active_relay_fds":0,"retained_pipe_pairs":122,"dirty_retained_pipe_bytes":0,
                        "held_dynamic_permits":256,"reserved_dynamic_permits":1,"unexplained":0
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
            let recovery: Vec<_> = (0..100).map(|count| transfer(&format!("{name}-{fault}-recovery-{count}"),"line-a","download",restored,1_048_576)).collect();
            let during: Vec<_> = ["line-a","line-b"].into_iter().flat_map(|line| (0..100).map(move |count| transfer(&format!("{name}-{fault}-{line}-during-{count}"),line,"download",started+1,1_048_576))).collect();
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
            json!({"name":fault,"started_ms":started,"restored_ms":restored,"first_admission_ms":restored+1,
                "before_processes":before,"after_processes":bindings.clone(),"recovery_transfers":recovery,"affected_prefix":transfer(&format!("{name}-{fault}-prefix"),"line-a","download",started,4096),
                "during_transfers":during,"checkpoints":checkpoints,"expected_failures":[],"unexpected_failures":0})
        }).collect();
        let mut integrity = Vec::new();
        for line in ["line-a","line-b"] {
            for size in &contract.payload_bytes {
                for direction in &contract.directions {
                    integrity.push(transfer(&format!("{name}-{line}-{size}-{direction}"),line,direction,4_000_000,*size));
                }
            }
        }
        json!({"name":name,"started_unix_ms":10000,"started":true,"completed":true,"roles":roles,"cycles":cycles,"faults":faults,
            "final_processes":bindings,"integrity":integrity,"unexpected_exits":0,"panics":0,"oom_kills":0,"unexpected_rejections":0,"terminal":artifact()})
    }).collect();
    let checks: Vec<_> = contract.required_checks.iter().map(|name| json!({
        "name":name,"source_commit":"c".repeat(40),"candidate_sha256":"a".repeat(64),"argv":["synthetic-test"],
        "exit_code":0,"completed":true,"executed_cases":1,"failed_cases":0,"output":artifact()
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
fn bounded_empty_permit_backed_retention_above_historical_fd_proxy_passes() {
    assert_eq!(verdict(&fixture()), Verdict::Pass);
}

#[test]
fn adversarial_resource_mutations_fail() {
    let valid = fixture();
    for (field, value) in [
        ("descriptors/total", 264),
        ("descriptors/unexplained", 1),
        ("descriptors/retained_pipe_pairs", 123),
        ("descriptors/dirty_retained_pipe_bytes", 1),
        ("descriptors/held_dynamic_permits", 0),
        ("descriptors/active_sockets", 1),
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
        ("/cells/0/oom_kills", json!(1)),
        ("/cells/0/unexpected_exits", json!(1)),
        ("/cells/0/cycles/0/checkpoints/1/observed_ms", json!(5000)),
        ("/cells/0/cycles/0/checkpoints", json!([])),
        ("/cells/0/cycles/0/transfers", json!([])),
        ("/cells/0/cycles", json!([])),
        ("/cells/0/faults", json!([])),
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
fn recovered_permits_cannot_be_hidden_as_unopened_reservations() {
    let mut changed = fixture();
    let descriptors =
        &mut changed["cells"][0]["cycles"][7]["checkpoints"][7]["samples"][0]["descriptors"];
    descriptors["reserved_dynamic_permits"] = json!(2);
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
        "descriptors":descriptors,"unix_sockets":"Num RefCount Protocol Flags Type St Inode Path\n","closed_during_read":[],"ownership_log":log,"errors":[]
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
