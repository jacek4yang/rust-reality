use super::*;

fn doc(text: &str) -> Value {
    json_in::parse(text).expect("fixture must parse")
}

#[test]
fn metric_key_sanitisation_matches_the_legacy_regex() {
    // A maximal run of disallowed characters collapses to ONE underscore, which is
    // what `[^A-Za-z0-9._-]+` with a `+` quantifier does.
    assert_eq!(sanitise_metric_key("bidi:1:1"), "bidi_1_1");
    assert_eq!(
        sanitise_metric_key("direct-upload:32:1"),
        "direct-upload_32_1"
    );
    assert_eq!(sanitise_metric_key("a::b"), "a_b", "a run collapses to one");
    assert_eq!(
        sanitise_metric_key("keep.dots_and-dashes"),
        "keep.dots_and-dashes"
    );
    assert_eq!(sanitise_metric_key("sp ace"), "sp_ace");
}

#[test]
fn the_recorded_matrix_metric_ids_are_reproduced() {
    // From the recorded v1.8.0 report.
    assert_eq!(
        format!("matrix-c1:{}:throughput", sanitise_metric_key("bidi:1:1")),
        "matrix-c1:bidi_1_1:throughput"
    );
    assert_eq!(
        format!(
            "matrix-c1:{}:p99-latency",
            sanitise_metric_key("direct-upload:32:1")
        ),
        "matrix-c1:direct-upload_32_1:p99-latency"
    );
}

#[test]
fn is_close_matches_the_python_relative_tolerance() {
    assert!(is_close(1.0, 1.0, 1e-9));
    assert!(is_close(1.0, 1.0 + 1e-10, 1e-9));
    assert!(!is_close(1.0, 1.0 + 1e-8, 1e-9));
    assert!(!is_close(f64::NAN, f64::NAN, 1e-9));
    assert!(is_close(0.0, 0.0, 1e-9));
}

#[test]
fn device_inode_format_is_validated_strictly() {
    assert!(valid_device_inode("43:509895"));
    assert!(!valid_device_inode("0:1"), "a leading zero is refused");
    assert!(!valid_device_inode("43:0"), "inode zero is refused");
    assert!(!valid_device_inode("43"), "both parts are required");
    assert!(!valid_device_inode("a:b"));
    assert!(!valid_device_inode(""));
}

#[test]
fn ratios_for_rows_pairs_by_block_implementation_and_concurrency() {
    let rows = vec![
        doc(r#"{"block":1,"implementation":"baseline","concurrency":1,"t":100.0}"#),
        doc(r#"{"block":1,"implementation":"candidate","concurrency":1,"t":110.0}"#),
        // A different concurrency must not contaminate the c1 cell.
        doc(r#"{"block":1,"implementation":"baseline","concurrency":32,"t":400.0}"#),
        doc(r#"{"block":1,"implementation":"candidate","concurrency":32,"t":200.0}"#),
    ];
    assert_eq!(
        ratios_for_rows(&rows, 1, 1, "t", "ctx").expect("valid"),
        vec![1.1]
    );
    assert_eq!(
        ratios_for_rows(&rows, 1, 32, "t", "ctx").expect("valid"),
        vec![0.5]
    );
}

#[test]
fn a_missing_side_in_any_block_fails_closed() {
    let rows = vec![doc(
        r#"{"block":1,"implementation":"candidate","concurrency":1,"t":110.0}"#,
    )];
    let error = ratios_for_rows(&rows, 1, 1, "t", "ctx").expect_err("must fail");
    assert!(matches!(error, LoadError::Rule { .. }), "{error}");
}

#[test]
fn a_non_positive_measurement_is_refused_before_any_ratio() {
    let rows = vec![
        doc(r#"{"block":1,"implementation":"baseline","concurrency":1,"t":0.0}"#),
        doc(r#"{"block":1,"implementation":"candidate","concurrency":1,"t":110.0}"#),
    ];
    assert!(matches!(
        ratios_for_rows(&rows, 1, 1, "t", "ctx"),
        Err(LoadError::Evidence(_))
    ));
}

#[test]
fn integrity_rows_are_excluded_from_cell_coverage() {
    let rows = vec![
        doc(r#"{"scenario":"bidi","payloadBytes":1048576,"concurrency":1}"#),
        doc(r#"{"scenario":"integrity","payloadBytes":1048576,"concurrency":1}"#),
    ];
    let keys = raw_cell_keys(&rows).expect("valid");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].to_string(), "bidi:1:1");
}

#[test]
fn every_matrix_arm_requires_one_latency_per_request() {
    let valid = doc(
        r#"{"invalid":false,"bytesVerified":true,"throughputMiBPerSecond":2.0,"perRequestSeconds":[1.0,1.5]}"#,
    );
    validate_matrix_sample(&valid, "cell", 2).expect("two requests were timed");

    let partial = doc(
        r#"{"invalid":false,"bytesVerified":true,"throughputMiBPerSecond":2.0,"perRequestSeconds":[1.0]}"#,
    );
    let error = validate_matrix_sample(&partial, "cell", 2)
        .expect_err("a missing request latency must invalidate the row");
    assert!(
        error.to_string().contains("latency count mismatch"),
        "{error}"
    );

    let failed_xray = doc(
        r#"{"invalid":true,"bytesVerified":false,"throughputMiBPerSecond":2.0,"perRequestSeconds":[1.0,1.5]}"#,
    );
    assert!(
        validate_matrix_sample(&failed_xray, "cell", 2).is_err(),
        "the unpaired Xray arm is still required interoperability evidence"
    );
}

#[test]
fn matrix_summary_key_must_name_its_own_cell_fields() {
    verify_matrix_cell_key("bidi:32:1", "bidi", 32, 1, "cell").expect("matching key");
    assert!(
        verify_matrix_cell_key("bidi:32:1", "bidi", 1, 1, "cell").is_err(),
        "a swapped payload must not put another cell's data under this metric ID"
    );
    assert!(
        verify_matrix_cell_key("bidi:32:1", "fallback", 32, 1, "cell").is_err(),
        "a swapped scenario must not be accepted"
    );
}

#[test]
fn matrix_sample_conservation_rejects_an_unselected_extra_row() {
    let summary = doc(
        r#"{"totals":{"cells":1,"samples":3,"invalidSamples":0},"cells":{"direct-download:1:1":{"samplesPerImplementation":1,"implementations":{"baseline":{"samples":1,"validSamples":1,"invalidSamples":0},"final":{"samples":1,"validSamples":1,"invalidSamples":0},"xray":{"samples":1,"validSamples":1,"invalidSamples":0}}}}}"#,
    );
    let cells = summary
        .field("matrix", "cells")
        .and_then(|value| value.as_object("matrix.cells"))
        .unwrap();
    let row = |direction: &str| {
        doc(&format!(
            r#"{{"scenario":"direct-download","direction":"{direction}"}}"#,
        ))
    };
    let valid = vec![row("download"), row("download"), row("download")];
    verify_matrix_sample_conservation(&summary, cells, &valid)
        .expect("the declared three arms conserve three rows");

    let summary_with_four = doc(
        r#"{"totals":{"cells":1,"samples":4,"invalidSamples":0},"cells":{"direct-download:1:1":{"samplesPerImplementation":1,"implementations":{"baseline":{"samples":1,"validSamples":1,"invalidSamples":0},"final":{"samples":1,"validSamples":1,"invalidSamples":0},"xray":{"samples":1,"validSamples":1,"invalidSamples":0}}}}}"#,
    );
    let cells_with_four = summary_with_four
        .field("matrix", "cells")
        .and_then(|value| value.as_object("matrix.cells"))
        .unwrap();
    let mut extra = valid;
    extra.push(row("upload"));
    assert!(
        verify_matrix_sample_conservation(&summary_with_four, cells_with_four, &extra).is_err(),
        "a row that no cell selects must not disappear from the census"
    );
}

#[test]
fn matrix_integrity_requires_three_matching_sha_verified_transfers() {
    let digest = "a".repeat(64);
    let aggregate = |label: &str, invalid: bool| {
        format!(
            r#""{label}":{{"invalid":{invalid},"payloadBytes":1048576,"wallSeconds":1.0,"sha256":{{"match":true,"origin":"{digest}","received":"{digest}"}}}}"#,
        )
    };
    let summary = doc(&format!(
        r#"{{"integrity":{{{},{},{}}}}}"#,
        aggregate("baseline", false),
        aggregate("final", false),
        aggregate("xray", false),
    ));
    let row = |label: &str, verified: bool| {
        doc(&format!(
            r#"{{"implementation":"{label}","scenario":"integrity","direction":"download","payloadBytes":1048576,"concurrency":1,"sampleIndex":0,"invalid":false,"bytesVerified":{verified},"wallSeconds":1.0,"throughputMiBPerSecond":1.0,"perRequestSeconds":[1.0],"sha256":{{"match":true,"origin":"{digest}","received":"{digest}"}}}}"#,
        ))
    };
    let valid = vec![row("baseline", true), row("final", true), row("xray", true)];
    verify_matrix_integrity(&summary, &valid).expect("all three transfers are complete");

    let corrupt = vec![
        row("baseline", true),
        row("final", true),
        row("xray", false),
    ];
    assert!(
        verify_matrix_integrity(&summary, &corrupt).is_err(),
        "an unverified Xray transfer must invalidate the matrix"
    );
}

#[test]
fn duplicate_matrix_binary_registrations_are_rejected() {
    let candidate = BinaryIdentity {
        commit: "a".repeat(40),
        sha256: "c".repeat(64),
    };
    let baseline = BinaryIdentity {
        commit: "b".repeat(40),
        sha256: "d".repeat(64),
    };
    let summary = doc(&format!(
        r#"{{"status":"COMPLETE","performanceVerdict":"NOT_EVALUATED","failures":[],"totals":{{"invalidSamples":0}},"identity":{{"candidateCommit":"{}","baselineCommit":"{}","repositoryHead":"{}","binariesPinned":true,"binaries":{{"final":{{"sha256":"{}"}},"baseline":{{"sha256":"{}"}},"xray":{{"sha256":"{}"}}}}}}}}"#,
        candidate.commit,
        baseline.commit,
        candidate.commit,
        candidate.sha256,
        baseline.sha256,
        "e".repeat(64),
    ));
    let row = |label: &str| {
        format!(
            r#"{{"label":"{label}","sha256":"{}","sourceCommit":"{}","buildId":"01","identity":"present"}}"#,
            candidate.sha256, candidate.commit,
        )
    };
    let contract = doc(&format!(
        r#"{{"phase":"complete","exploratory":false,"script":{{"harnessCommit":"{}"}},"binaries":[{},{},{}]}}"#,
        candidate.commit,
        row("candidate"),
        row("candidate"),
        row("xray"),
    ));
    let error = verify_matrix_identity(&summary, &contract, &candidate, &baseline)
        .expect_err("duplicate labels must fail before any host-lock check");
    assert!(
        error.to_string().contains("labels must be unique"),
        "{error}"
    );
}

#[test]
fn verified_files_are_parsed_from_the_hashed_snapshot() {
    let temp =
        std::env::temp_dir().join(format!("rr-dev-evidence-snapshot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("temp run dir");
    let bytes = b"{}\n";
    let digest = sha256_bytes(bytes);
    let mut files = BTreeMap::new();
    for name in WorkloadKind::Matrix.required_files() {
        std::fs::write(temp.join(name), bytes).expect("write evidence fixture");
        files.insert((*name).to_owned(), Value::Str(digest.clone()));
    }
    let verified = verify_files(&temp.to_string_lossy(), &files, WorkloadKind::Matrix)
        .expect("fixture hashes match");

    std::fs::write(temp.join("summary.json"), b"not JSON")
        .expect("mutate the path after verification");
    assert!(
        verified.json("summary.json").is_ok(),
        "parsing must use the exact bytes whose digest was recorded"
    );
    assert_eq!(verified.hashes["summary.json"], digest);
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn block_count_bounds_match_the_exact_gate() {
    assert!(validate_block_count(12, "k").is_ok());
    assert!(validate_block_count(16, "k").is_ok());
    assert!(validate_block_count(11, "k").is_err());
    assert!(validate_block_count(17, "k").is_err());
}

#[test]
fn the_cpu_metric_rejects_a_disagreeing_recorded_ratio() {
    use std::fmt::Write as _;

    // The collector and evaluator compute this ratio independently; disagreement
    // means one of them is wrong, so it must not be silently preferred.
    let mut blocks = String::from("[");
    for index in 0..12 {
        if index > 0 {
            blocks.push(',');
        }
        blocks.push_str(r#"{"baseline":2.0,"candidate":1.0,"candidateVsBaseline":0.5}"#);
    }
    blocks.push(']');
    let good = doc(&format!(r#"{{"serverCpuPerGiB":{{"blocks":{blocks}}}}}"#));
    let metric = cpu_metric(&good, "serverCpuPerGiB", 12, "fallback", "secondsPerGiB")
        .expect("consistent ratios must be accepted");
    assert_eq!(metric.id, "fallback:server-cpu");
    assert_eq!(metric.direction, Direction::LowerIsBetter);

    // Twelve blocks, one of which disagrees. Using a single block would let the
    // block-count check reject it first and mask the cross-check entirely - a
    // masking that mutation testing caught.
    let mut mixed = String::from("[");
    for index in 0..12 {
        if index > 0 {
            mixed.push(',');
        }
        let recorded = if index == 7 { "0.9" } else { "0.5" };
        let _ = write!(
            mixed,
            r#"{{"baseline":2.0,"candidate":1.0,"candidateVsBaseline":{recorded}}}"#
        );
    }
    mixed.push(']');
    let bad = doc(&format!(r#"{{"serverCpuPerGiB":{{"blocks":{mixed}}}}}"#));
    let error = cpu_metric(&bad, "serverCpuPerGiB", 12, "fallback", "secondsPerGiB")
        .expect_err("a disagreeing recorded ratio must be refused");
    assert!(
        matches!(error, LoadError::Rule { ref message, .. } if message.contains("block 8")),
        "the failing block must be named: {error}"
    );
}

#[test]
fn the_cpu_metric_requires_exactly_the_declared_block_count() {
    let one = doc(
        r#"{"serverCpuPerGiB":{"blocks":[{"baseline":2.0,"candidate":1.0,"candidateVsBaseline":0.5}]}}"#,
    );
    assert!(
        cpu_metric(&one, "serverCpuPerGiB", 12, "fallback", "secondsPerGiB").is_err(),
        "one block cannot satisfy a twelve-block declaration"
    );
}

#[test]
fn host_lock_coordination_identity_needs_a_contract() {
    let lock = HostLock {
        protocol_version: 1,
        path: "/tmp/x.lock".to_owned(),
        device_inode: "43:1".to_owned(),
        mode: "dedicatedKeeper".to_owned(),
        keeper_pid: 2,
        keeper_starttime: "10".to_owned(),
        keeper_exe: "/usr/bin/python3".to_owned(),
        parent_pid: 3,
        parent_starttime: "9".to_owned(),
        keeper_helper: ArtifactIdentity {
            path: "/h.py".to_owned(),
            sha256: "a".repeat(64),
        },
        contract: None,
    };
    assert!(
        lock.coordination_identity().is_none(),
        "a lock without a verified contract has no coordination identity"
    );
    let with_contract = HostLock {
        contract: Some(ArtifactIdentity {
            path: "/c.sh".to_owned(),
            sha256: "b".repeat(64),
        }),
        ..lock
    };
    let identity = with_contract
        .coordination_identity()
        .expect("a verified contract yields an identity");
    assert_eq!(identity.len(), 7, "the projection is exactly seven fields");
    assert_eq!(identity[5], "a".repeat(64), "keeper helper digest");
    assert_eq!(identity[6], "b".repeat(64), "contract digest");
}

/// Locates a file beside the checkout, where evidence archives live.
fn evidence(relative: &str) -> Option<std::path::PathBuf> {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .map(|ancestor| ancestor.join(relative))
        .find(|candidate| candidate.is_file())
}

#[test]
fn the_real_recorded_matrix_evidence_reproduces_its_24_metrics() {
    // The first proof that the loader implementation matches the specification:
    // run the actual v1.8.0 matrix evidence through the real code path and require
    // the recorded metric identities and values, not merely a plausible count.
    let Some(summary_path) =
        evidence("artifacts/v180-release-gate/gates/matrix-formal-r01/summary.json")
    else {
        eprintln!("recorded matrix evidence unavailable; skipping");
        return;
    };
    let samples_path = summary_path
        .parent()
        .expect("summary has a parent")
        .join("samples.jsonl");

    let summary = load_json(&summary_path).expect("summary must load");
    let rows = load_jsonl(&samples_path).expect("samples must load");
    let cells = summary
        .as_object("summary")
        .expect("summary is an object")
        .get("cells")
        .expect("cells are present")
        .as_object("summary.cells")
        .expect("cells is an object");

    // Coverage must hold in both directions before any metric is produced.
    let summary_keys: Vec<CellKey> = cells
        .keys()
        .map(|key| CellKey::parse(key).expect("recorded cell keys parse"))
        .collect();
    let raw_keys = raw_cell_keys(&rows).expect("raw keys");
    contract::validate_coverage(&summary_keys, &raw_keys)
        .expect("recorded summary cells must exactly cover raw samples");

    let mut metrics = Vec::new();
    for (key, cell) in cells {
        metrics.extend(
            matrix_cell_metrics(key, cell, &rows, "matrix-c1")
                .unwrap_or_else(|error| panic!("cell {key}: {error}")),
        );
    }

    assert_eq!(
        metrics.len(),
        24,
        "twelve protected cells yield twenty-four matrix metrics"
    );

    // Spot-check two recorded metrics by identity and by value. These are the
    // smallest and largest raw p-values in the recorded family, so they exercise
    // both orientations and the full deterministic path.
    let p99 = metrics
        .iter()
        .find(|metric| metric.id == "matrix-c1:direct-upload_32_1:p99-latency")
        .expect("the recorded p99 metric identity must be reproduced");
    assert_eq!(p99.direction, Direction::LowerIsBetter);
    assert_eq!(p99.blocks.len(), 12);
    assert_eq!(p99.median_ratio, 1.028_454_451_654_484_5);
    assert_eq!(p99.mean_log_benefit, -0.058_513_158_852_144_67);
    assert_eq!(p99.raw_p_value, 0.052_734_375);
    assert_eq!(p99.improvement_raw_p_value, 0.947_509_765_625);

    let throughput = metrics
        .iter()
        .find(|metric| metric.id == "matrix-c1:framed-upload_32_1:throughput")
        .expect("the recorded throughput metric identity must be reproduced");
    assert_eq!(throughput.direction, Direction::HigherIsBetter);
    assert_eq!(throughput.median_ratio, 1.006_459_443_017_899_5);
    assert_eq!(throughput.raw_p_value, 0.966_552_734_375);
    assert_eq!(throughput.improvement_raw_p_value, 0.033_691_406_25);

    // Every metric must carry one of the two expected suffixes and no duplicates.
    let mut ids: Vec<&str> = metrics.iter().map(|metric| metric.id.as_str()).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(before, ids.len(), "metric identities must be unique");
    for id in &ids {
        assert!(
            id.ends_with(":throughput") || id.ends_with(":p99-latency"),
            "unexpected metric identity {id}"
        );
        assert!(id.starts_with("matrix-c1:"), "unexpected workload in {id}");
    }
}

#[test]
fn the_real_recorded_paired_evidence_reproduces_its_8_metrics() {
    // Completes the census: five setup metrics plus three fallback metrics, run
    // through the real code path against the recorded v1.8.0 evidence.
    let Some(manifest_path) =
        evidence("artifacts/v180-release-gate/gates/evaluator-manifest-r01.json")
    else {
        eprintln!("recorded manifest unavailable; skipping");
        return;
    };
    let manifest = load_json(&manifest_path).expect("manifest loads");
    let candidate = BinaryIdentity {
        commit: manifest
            .field("$", "candidate")
            .and_then(|v| v.str_field("candidate", "commit"))
            .expect("candidate commit")
            .to_owned(),
        sha256: manifest
            .field("$", "candidate")
            .and_then(|v| v.str_field("candidate", "sha256"))
            .expect("candidate sha")
            .to_owned(),
    };
    let baseline = BinaryIdentity {
        commit: manifest
            .field("$", "baseline")
            .and_then(|v| v.str_field("baseline", "commit"))
            .expect("baseline commit")
            .to_owned(),
        sha256: manifest
            .field("$", "baseline")
            .and_then(|v| v.str_field("baseline", "sha256"))
            .expect("baseline sha")
            .to_owned(),
    };

    let workloads = manifest.array_field("$", "workloads").expect("workloads");
    let mut all_ids = Vec::new();
    let mut counts = BTreeMap::new();
    for entry in workloads {
        let kind_text = entry.str_field("workload", "kind").expect("kind");
        let Some(kind) = WorkloadKind::parse(kind_text) else {
            panic!("unknown kind {kind_text}");
        };
        if kind == WorkloadKind::Matrix {
            continue;
        }
        let name = entry.str_field("workload", "name").expect("name");
        let run_dir = entry.str_field("workload", "runDir").expect("runDir");
        let files = entry
            .field("workload", "files")
            .and_then(|v| v.as_object("files"))
            .expect("files")
            .clone();

        let (metrics, input) =
            evaluate_pair_run(name, kind, run_dir, &files, &candidate, &baseline)
                .unwrap_or_else(|error| panic!("{name}: {error}"));

        // The report input must come from this same pass.
        assert_eq!(input.name, name);
        assert_eq!(input.kind, kind);
        assert_eq!(input.status, "COMPLETE");
        assert_eq!(input.data_quality_verdict, "PASS");
        assert_eq!(input.collector_performance_verdict, "NOT_EVALUATED");
        assert_eq!(
            input.files.len(),
            kind.required_files().len(),
            "every declared file must be hashed"
        );
        assert!(
            input.host_lock.coordination_identity().is_some(),
            "a verified paired run must yield a coordination identity"
        );

        counts.insert(name.to_owned(), metrics.len());
        all_ids.extend(metrics.into_iter().map(|metric| metric.id));
    }

    assert_eq!(counts.get("setup"), Some(&5), "setup yields five metrics");
    assert_eq!(
        counts.get("fallback"),
        Some(&3),
        "fallback yields three metrics"
    );

    all_ids.sort();
    assert_eq!(
        all_ids,
        vec![
            "fallback:c1:p99-latency".to_owned(),
            "fallback:c1:throughput".to_owned(),
            "fallback:server-cpu".to_owned(),
            "setup:c1:p99-latency".to_owned(),
            "setup:c1:throughput".to_owned(),
            "setup:c32:p99-latency".to_owned(),
            "setup:c32:throughput".to_owned(),
            "setup:server-cpu".to_owned(),
        ],
        "the recorded paired metric identities must be reproduced exactly"
    );
}

#[test]
fn raw_sample_order_is_compared_as_a_sequence_not_a_set() {
    // Reordering rows preserves the multiset but breaks the recorded execution
    // sequence. Sorting before comparison would accept this, which mutation
    // testing showed the real-evidence test alone does not catch.
    let Some(summary_path) =
        evidence("artifacts/v180-release-gate/gates/matrix-formal-r01/summary.json")
    else {
        eprintln!("recorded matrix evidence unavailable; skipping");
        return;
    };
    let samples_path = summary_path
        .parent()
        .expect("summary has a parent")
        .join("samples.jsonl");
    let summary = load_json(&summary_path).expect("summary loads");
    let rows = load_jsonl(&samples_path).expect("samples load");
    let cells = summary
        .as_object("summary")
        .expect("object")
        .get("cells")
        .expect("cells")
        .as_object("cells")
        .expect("object");
    let (key, cell) = cells.iter().next().expect("at least one cell");

    // Baseline: the untouched order is accepted.
    matrix_cell_metrics(key, cell, &rows, "matrix-c1").expect("recorded order is valid");

    // Reverse every row. Same elements, different sequence.
    let mut reversed = rows.clone();
    reversed.reverse();
    let error = matrix_cell_metrics(key, cell, &reversed, "matrix-c1")
        .expect_err("a permuted execution order must be refused");
    assert!(
        matches!(error, LoadError::Rule { ref message, .. }
                 if message.contains("raw sample order")),
        "the order rule must be what rejects it: {error}"
    );
}

#[test]
fn a_declared_file_outside_the_run_directory_is_refused() {
    // The containment guard: a manifest must not be able to reach outside the
    // evidence directory through a crafted relative name.
    let temp = std::env::temp_dir().join(format!("rr-dev-escape-{}", std::process::id()));
    let run_dir = temp.join("run");
    std::fs::create_dir_all(&run_dir).expect("temp run dir");
    let outside = temp.join("outside.json");
    std::fs::write(&outside, b"{}").expect("write outside file");
    // A symlink named like a required file, pointing out of the run directory.
    let planted = run_dir.join("summary.json");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &planted).expect("symlink");

    let digest = sha256_file(&outside).expect("hash");
    let mut files = BTreeMap::new();
    for name in WorkloadKind::Matrix.required_files() {
        files.insert((*name).to_owned(), Value::Str(digest.clone()));
    }
    let result = verify_files(&run_dir.to_string_lossy(), &files, WorkloadKind::Matrix);
    assert!(
        result.is_err(),
        "a symlink escaping the run directory must be refused"
    );

    let _ = std::fs::remove_dir_all(&temp);
}
