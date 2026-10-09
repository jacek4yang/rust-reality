use super::{schema, verify_mechanism_receipt};
use crate::{
    bench::{
        deployment::{Plan, PlanKind},
        workspace::Workspace,
    },
    deploy::netem,
    hash,
};
use serde_json::{Value, json};

fn save(workspace: &Workspace, name: &str, bytes: &[u8]) -> schema::Artifact {
    std::fs::write(workspace.join(name), bytes).unwrap();
    schema::Artifact {
        path: name.to_owned(),
        sha256: hash::sha256_hex(bytes),
    }
}

fn refresh(workspace: &Workspace, check: &mut schema::Check, name: &str, bytes: &[u8]) {
    let artifact = save(workspace, name, bytes);
    if check.output.path == name {
        check.output = artifact;
    } else {
        *check
            .observations
            .iter_mut()
            .find(|artifact| artifact.path == name)
            .unwrap() = artifact;
    }
}

#[allow(clippy::too_many_lines)]
fn fixture() -> (Workspace, schema::Identity, schema::Check) {
    let workspace = Workspace::create("mechanism-receipt").unwrap();
    let root = workspace.join("run");
    let rtt = root.join("rtt");
    std::fs::create_dir_all(&rtt).unwrap();
    let (profiles, pool_summaries) = netem::tests::build_mechanism_fixture(&rtt, 1.0, 32);
    let report = netem::validate(&netem::NetemArgs {
        profiles,
        pool_summaries,
        rtts: vec![50, 100, 200],
        losses: vec![0.0],
        concurrencies: vec![1],
        samples: 6,
        connections: 32,
        evaluate_performance: true,
    })
    .unwrap();
    assert!(report.passed, "{}", report.json);
    let evidence: schema::Evidence = serde_json::from_value(super::tests::fixture()).unwrap();
    let mut identity = evidence.identity;
    let mut check = evidence
        .checks
        .into_iter()
        .find(|check| check.name == "native-mechanism")
        .unwrap();
    let xray = save(&workspace, "xray", b"stock Xray fixture");
    identity.environment = save(
        &workspace,
        "environment.json",
        &serde_json::to_vec(&json!({
            "host_kernel":"Linux", "xray_sha256":xray.sha256, "xray_identity":"stock Xray",
            "openssl_sha256":"d".repeat(64)
        }))
        .unwrap(),
    );
    check.argv = [
        identity.evaluator.path.as_str(),
        "bench",
        "run",
        "--suite",
        "deployment",
        "--deployment-plan",
        "mechanism",
        "--rust-bin",
        "/frozen/product",
        "--xray-bin",
        "/frozen/xray",
        "--run-id",
        "mechanism-test",
        "--out-dir",
        root.to_str().unwrap(),
    ]
    .map(str::to_owned)
    .to_vec();
    check.executed_cases = 18;
    check.observations = vec![xray];
    for path in std::fs::read_dir(&rtt).unwrap() {
        let path = path.unwrap().path();
        check.observations.push(schema::Artifact {
            path: path
                .strip_prefix(workspace.path())
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            sha256: hash::sha256_file(&path).unwrap(),
        });
    }
    let program: Value = serde_json::from_str(
        &Plan::reviewed(PlanKind::Mechanism)
            .to_json()
            .to_compact_json(),
    )
    .unwrap();
    let mut summary: Value = serde_json::from_slice(include_bytes!(
        "../../../../../fuzz/seeds/stability_evidence/seed_native_mechanism"
    ))
    .unwrap();
    summary["program"] = program.clone();
    summary["netemProfiles"] = serde_json::from_str(&report.json).unwrap();
    check.output = save(
        &workspace,
        "run/summary.json",
        &serde_json::to_vec(&summary).unwrap(),
    );
    let environment = json!({"schemaVersion":1,"runId":"mechanism-test", "harnessCommit":identity.source_commit,
        "harnessSha256":identity.evaluator.sha256, "rustRealityBin":"/frozen/product", "rustRealitySha256":identity.candidate.sha256,
        "rustRealityIdentity":json!({"gitCommit":identity.source_commit,"version":"fixture"}).to_string(),
        "xrayBin":"/frozen/xray","xraySha256":check.observations[0].sha256,"xrayIdentity":"stock Xray","hostLock":"1:2"});
    let terminal = json!({"ok":true,"primaryError":null,"checks":[
        {"name":"file:rust-reality","ok":true,"error":null},
        {"name":"file:xray","ok":true,"error":null},
        {"name":"image:harness","ok":true,"error":null}]});
    let contract = json!({"schemaVersion":1,"phase":"complete","suite":"benchmark-deployment","runId":"mechanism-test",
        "plan":program,"summary":{"path":root.join("summary.json"),"sha256":check.output.sha256}});
    let contract = save(
        &workspace,
        "run/run-contract.json",
        &serde_json::to_vec(&contract).unwrap(),
    );
    let completion = json!({"schemaVersion":1,"status":"COMPLETE","exitCode":0,"runId":"mechanism-test",
        "collector":"benchmark-deployment","evidence":{"path":root.join("run-contract.json"),"sha256":contract.sha256}});
    check.observations.push(contract);
    for (name, value) in [
        ("run/environment.json", environment),
        ("run/attempt-terminal.json", terminal),
        ("run/run-completion.json", completion),
        (
            "run/summary-netem.json",
            serde_json::from_str(&report.json).unwrap(),
        ),
    ] {
        check
            .observations
            .push(save(&workspace, name, &serde_json::to_vec(&value).unwrap()));
    }
    (workspace, identity, check)
}

#[test]
fn mechanism_requires_bound_raw_matrix_and_exact_publication() {
    let (workspace, identity, check) = fixture();
    verify_mechanism_receipt(workspace.path(), &check, &identity).unwrap();
    for (name, pointer, value) in [
        (
            "run/summary.json",
            "/performanceVerdict",
            json!("NOT_EVALUATED"),
        ),
        ("run/summary.json", "/program/samples", json!(1)),
        (
            "run/environment.json",
            "/harnessSha256",
            json!("b".repeat(64)),
        ),
        (
            "run/environment.json",
            "/rustRealitySha256",
            json!("b".repeat(64)),
        ),
        (
            "run/environment.json",
            "/xrayIdentity",
            json!("substituted"),
        ),
        ("run/attempt-terminal.json", "/checks/1/ok", json!(false)),
        (
            "run/run-completion.json",
            "/evidence/sha256",
            json!("b".repeat(64)),
        ),
    ] {
        let original = std::fs::read(workspace.join(name)).unwrap();
        let mut changed: Value = serde_json::from_slice(&original).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let mut claim = check.clone();
        refresh(
            &workspace,
            &mut claim,
            name,
            &serde_json::to_vec(&changed).unwrap(),
        );
        assert!(
            verify_mechanism_receipt(workspace.path(), &claim, &identity).is_err(),
            "{name}{pointer}"
        );
        std::fs::write(workspace.join(name), original).unwrap();
    }
    let raw_name = "run/rtt/rtt50-handoff-warm.jsonl";
    let mut missing = check.clone();
    missing
        .observations
        .retain(|artifact| artifact.path != raw_name);
    assert!(verify_mechanism_receipt(workspace.path(), &missing, &identity).is_err());
    let original = std::fs::read_to_string(workspace.join(raw_name)).unwrap();
    for bytes in [
        original.lines().skip(1).collect::<Vec<_>>().join("\n"),
        "NaN\n".to_owned(),
    ] {
        let mut changed = check.clone();
        refresh(&workspace, &mut changed, raw_name, bytes.as_bytes());
        assert!(verify_mechanism_receipt(workspace.path(), &changed, &identity).is_err());
    }
    std::fs::write(workspace.join(raw_name), original).unwrap();
    let mut escaped = check.clone();
    let name = "run/rtt/profiles.jsonl";
    let original = std::fs::read_to_string(workspace.join(name)).unwrap();
    refresh(
        &workspace,
        &mut escaped,
        name,
        original
            .replace("rtt50-handoff-warm.jsonl", "../outside.jsonl")
            .as_bytes(),
    );
    assert!(verify_mechanism_receipt(workspace.path(), &escaped, &identity).is_err());
    let mut failed_performance = check.clone();
    netem::tests::build_mechanism_fixture(&workspace.join("run/rtt"), 0.2, 32);
    for artifact in &mut failed_performance.observations {
        if artifact.path.starts_with("run/rtt/") {
            artifact.sha256 = hash::sha256_file(&workspace.join(&artifact.path)).unwrap();
        }
    }
    assert!(verify_mechanism_receipt(workspace.path(), &failed_performance, &identity).is_err());
}
