use super::{
    evaluate::{self, Verdict},
    schema, verify_artifact,
};
use crate::{bench::workspace::Workspace, hash};
use serde_json::{Value, json};

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
        "upload": if direction == "download" { Value::Null } else { json!({
            "path":format!("/{id}"),"log_boundary":100,"receipt_offset":100,"appended_matches":1,
            "bytes":size,"sha256":"b".repeat(64)
        })}
    })
}

fn fixture() -> Value {
    let contract: schema::Contract = serde_json::from_str(schema::CONTRACT).unwrap();
    let cells: Vec<_> = contract.cells.iter().map(|name| {
        let roles: Vec<_> = contract.roles.iter().map(|role| json!({
            "name":role,"process":process(role),"vcpus":if name.ends_with("/constrained") {1} else {2},
            "memory_limit_bytes":1_073_741_824_u64,"swap_limit_bytes":0,"startup":artifact(),
            "policy":{
                "fixed_fds":7,"listener_sockets":1,"dynamic_fd_budget":4096,"pipe_pair_capacity":122,
                "warm_socket_capacity":11,"active_socket_capacity":128,"relay_fd_capacity":128,
                "soft_fd_limit":8192,"replay_capacity":65536,"replay_expiry_ms":120_000,"retirement_deadline_ms":30000
            }
        })).collect();
        let cycles: Vec<_> = (0..contract.cycles).map(|index| {
            let started = u64::try_from(index).unwrap() * contract.cycle_interval_ms;
            let transfers: Vec<_> = ["line-a","line-b"].into_iter().flat_map(|line| {
                (0..100).map(move |count| transfer(&format!("{name}-{index}-{line}-{count}"),line,"download",started,1_048_576))
            }).collect();
            let checkpoints: Vec<_> = contract.checkpoint_offsets_ms.iter().map(|offset| {
                let samples: Vec<_> = contract.roles.iter().map(|role| json!({
                    "role":role,"process":process(role),"rss_kib":16384,"pss_kib":12000,"anonymous_kib":10000,"threads":4,
                    "descriptors":{
                        "total":263,"fixed":7,"listener_sockets":1,"warm_sockets":11,"active_sockets":0,
                        "active_relay_fds":0,"retained_pipe_pairs":122,"dirty_retained_pipe_bytes":0,
                        "held_dynamic_permits":256,"reserved_dynamic_permits":1,"unexplained":0
                    },
                    "owners":{
                        "active_connections":0,"completed_connections":0,"retired_generations":0,
                        "cancelled_operations":0,"replay_entries":0,"expired_replay_entries":0,"unattributed_retained_bytes":0
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
            let started = 2_000_000 + u64::try_from(index).unwrap() * 100_000;
            let recovery: Vec<_> = (0..100).map(|count| transfer(&format!("{name}-{fault}-recovery-{count}"),"line-a","download",started+10000,1_048_576)).collect();
            json!({"name":fault,"started_ms":started,"restored_ms":started+10000,"first_admission_ms":started+10001,
                "before_processes":before,"after_processes":bindings.clone(),"recovery_transfers":recovery,"affected_prefix":transfer(&format!("{name}-{fault}-prefix"),"line-a","download",started,4096),
                "line_b_progress_bytes":4096,"expected_failures":[],"unexpected_failures":0})
        }).collect();
        let mut integrity = Vec::new();
        for line in ["line-a","line-b"] {
            for size in &contract.payload_bytes {
                for direction in &contract.directions {
                    integrity.push(transfer(&format!("{name}-{line}-{size}-{direction}"),line,direction,4_000_000,*size));
                }
            }
        }
        json!({"name":name,"started":true,"completed":true,"roles":roles,"cycles":cycles,"faults":faults,
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
        ("owners/active_connections", 1),
        ("owners/completed_connections", 1),
        ("owners/retired_generations", 1),
        ("owners/cancelled_operations", 1),
        ("owners/expired_replay_entries", 1),
        ("owners/unattributed_retained_bytes", 1),
        ("rss_kib", 100_000),
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
