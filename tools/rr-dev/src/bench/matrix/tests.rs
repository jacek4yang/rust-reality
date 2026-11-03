use super::*;
use crate::bench::evidence::RunDirectory;

fn plan() -> CellPlan {
    CellPlan {
        payloads_mib: vec![1, 32, 512],
        concurrencies: vec![1, 4, 32],
        large_concurrencies: vec![1, 32],
        large_payload_mib: 512,
        include: Vec::new(),
        exclude: Vec::new(),
    }
}

/// The script's documented default plan: 6 scenarios × (2 small payloads × 3
/// concurrencies) + 6 × (1 large payload × 2 concurrencies) = 48 cells.
#[test]
fn the_default_plan_is_forty_eight_cells() {
    let cells = plan().cells();
    assert_eq!(cells.len(), 48);
    assert_eq!(
        cells.iter().filter(|cell| cell.payload_mib == 512).count(),
        12,
        "the large payload uses the reduced concurrency set"
    );
    for scenario in SCENARIOS {
        assert_eq!(
            cells
                .iter()
                .filter(|cell| cell.scenario == scenario)
                .count(),
            8
        );
    }
}

#[test]
fn cell_keys_follow_the_filter_syntax() {
    let cell = Cell {
        scenario: Scenario::DirectUpload,
        payload_mib: 32,
        concurrency: 1,
    };
    assert_eq!(cell.key(), "direct-upload:32:1");
}

/// The filters from the script's own documentation.
#[test]
fn the_documented_filters_select_what_the_script_says() {
    let mut context = plan();
    context.include = vec!["direct-*:32:*".to_owned(), "fallback:*:*".to_owned()];
    context.exclude = vec!["*:512:32".to_owned()];
    let cells = context.cells();
    assert!(
        cells
            .iter()
            .all(|cell| cell.key().starts_with("direct-") || cell.key().starts_with("fallback:"))
    );
    assert!(
        !cells.iter().any(|cell| cell.key().ends_with(":512:32")),
        "the skip pattern must win over the include"
    );
    // Included: direct-{download,upload}:32:{1,4,32} = 6, plus fallback at
    // 1 and 32 MiB × {1,4,32} and at 512 MiB × {1,32} = 8, so 14. The skip
    // then removes fallback:512:32, leaving 13.
    assert_eq!(cells.len(), 13);
    assert!(cells.iter().any(|cell| cell.key() == "fallback:512:1"));
}

#[test]
fn glob_matching_follows_fnmatch() {
    assert!(matches("*", "anything:1:1"));
    assert!(matches("direct-*:32:*", "direct-upload:32:4"));
    assert!(!matches("direct-*:32:*", "framed-upload:32:4"));
    assert!(matches("*:512:32", "bidi:512:32"));
    assert!(!matches("*:512:32", "bidi:512:1"));
    // `*` spans separators, as fnmatch does.
    assert!(matches("bidi*32", "bidi:512:32"));
    assert!(matches("?idi:1:1", "bidi:1:1"));
    assert!(!matches("?idi:1:1", "bbidi:1:1"));
    assert!(matches("framed-download:1:1", "framed-download:1:1"));
    assert!(!matches("framed-download:1:1", "framed-download:1:10"));
    // Trailing stars may match nothing at all.
    assert!(matches("bidi:1:1***", "bidi:1:1"));
}

#[test]
fn a_scenario_knows_its_direction_origin_and_connection_count() {
    assert_eq!(Scenario::FramedDownload.direction(), "download");
    assert_eq!(Scenario::DirectUpload.direction(), "upload");
    assert_eq!(Scenario::Bidi.direction(), "bidi");
    // A fallback request never reaches the TLS origin; it is relayed to the
    // plain one, which is what makes it a fallback test.
    assert_eq!(Scenario::Fallback.origin_scheme(), "http");
    assert_eq!(Scenario::DirectDownload.origin_scheme(), "https");
    assert_eq!(Scenario::Bidi.origin_scheme(), "https");
    // bidi opens a download and an upload per unit of concurrency.
    assert_eq!(Scenario::Bidi.connections(4), 8);
    assert_eq!(Scenario::FramedDownload.connections(4), 4);
    assert!(Scenario::Bidi.uploads());
    assert!(!Scenario::Fallback.uploads());
}

#[test]
fn scenarios_round_trip_through_their_names() {
    for scenario in SCENARIOS {
        assert_eq!(Scenario::parse(scenario.as_str()).unwrap(), scenario);
    }
    assert!(Scenario::parse("sideways").is_err());
}

#[test]
fn the_sample_count_follows_the_payload_size() {
    let plan = plan();
    assert_eq!(plan.samples_for(32, 5, 3), 5);
    assert_eq!(plan.samples_for(512, 5, 3), 3);
}

#[test]
fn the_record_document_matches_the_driver_shape() {
    let mut record = SampleRecord {
        commit: "a".repeat(40),
        implementation: "final".to_owned(),
        cell: Cell {
            scenario: Scenario::Bidi,
            payload_mib: 32,
            concurrency: 4,
        },
        sample_index: 2,
        wall_seconds: Some(2.0),
        throughput_mib_per_second: Some(128.0),
        per_request_seconds: vec![0.5, 0.6],
        bytes_verified: true,
        invalid: false,
        invalid_reason: None,
    };
    let rendered = record.to_json().to_python_json();
    assert!(rendered.contains("\"schemaVersion\": 1"));
    assert!(rendered.contains("\"scenario\": \"bidi\""));
    assert!(rendered.contains("\"direction\": \"bidi\""));
    assert!(rendered.contains("\"payloadBytes\": 33554432"));
    assert!(rendered.contains("\"bytesVerified\": true"));
    assert!(rendered.contains("\"invalidReason\": null"));

    // Reasons accumulate rather than replacing each other, so a sample that
    // failed twice says both things.
    record.invalidate("origin error");
    record.invalidate("tunnel bypass suspected");
    let rendered = record.to_json().to_python_json();
    assert!(rendered.contains("\"invalid\": true"));
    assert!(rendered.contains("origin error; tunnel bypass suspected"));

    // A failed workload records nulls rather than zeros, which would look
    // like a real measurement of nothing.
    let failed = SampleRecord {
        wall_seconds: None,
        throughput_mib_per_second: None,
        per_request_seconds: Vec::new(),
        bytes_verified: false,
        ..record
    };
    let rendered = failed.to_json().to_python_json();
    assert!(rendered.contains("\"wallSeconds\": null"));
    assert!(rendered.contains("\"throughputMiBPerSecond\": null"));
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rr-bench-matrix-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unpublished_run(name: &str) -> (Scratch, RunDirectory) {
    let scratch = Scratch::new(name);
    let run = RunDirectory::create(&scratch.0.join("run")).unwrap();
    run.write_new("environment.json", "{\"phase\":\"measured\"}\n")
        .unwrap();
    (scratch, run)
}

#[test]
fn invalid_matrix_diagnostics_are_never_marked_complete() {
    let (_scratch, run) = unpublished_run("invalid-completion");
    let summary = Summary {
        document: Json::Null,
        total: 3,
        invalid: 1,
    };

    let error = publish_complete_matrix(
        &run,
        "{\"phase\":\"complete\"}\n",
        "run-1",
        &summary,
        || Ok(()),
    )
    .unwrap_err();

    assert!(error.contains("1 of 3 samples invalid"), "{error}");
    assert!(
        !run.join("completion.json").exists(),
        "an invalid matrix must remain visibly incomplete"
    );
}

#[test]
fn failed_final_checks_are_never_marked_complete() {
    let (_scratch, run) = unpublished_run("failed-final-check");
    let summary = Summary {
        document: Json::Null,
        total: 3,
        invalid: 0,
    };

    let error = publish_complete_matrix(
        &run,
        "{\"phase\":\"complete\"}\n",
        "run-1",
        &summary,
        || Err("pipe-page restoration was not verified".to_owned()),
    )
    .unwrap_err();

    assert!(error.contains("restoration was not verified"), "{error}");
    assert!(
        !run.join("completion.json").exists(),
        "failed final checks must leave the run visibly incomplete"
    );
}

#[test]
fn valid_matrix_is_marked_complete_after_final_checks() {
    let (_scratch, run) = unpublished_run("valid-completion");
    let summary = Summary {
        document: Json::Null,
        total: 3,
        invalid: 0,
    };
    let mut checked = false;

    publish_complete_matrix(
        &run,
        "{\"phase\":\"complete\"}\n",
        "run-1",
        &summary,
        || {
            checked = true;
            Ok(())
        },
    )
    .unwrap();

    assert!(checked, "final checks must run before publication");
    assert!(run.join("completion.json").is_file());
}
