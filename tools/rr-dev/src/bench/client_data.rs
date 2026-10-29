//! Client data samples inside the existing paired process/identity lifecycle.
//!
//! Reuses the matrix transfer driver and origin guards. Setup, integrity and
//! resource observations are outside each data CPU window. Bidi means separate
//! simultaneous upload and download connections, not duplex on one socket.

use std::{path::Path, time::Instant};

use super::{guards, matrix, schedstat};
use crate::{hash, perf::json_out::Json};

pub(super) const SCENARIOS: [matrix::Scenario; 5] = [
    matrix::Scenario::FramedDownload,
    matrix::Scenario::DirectDownload,
    matrix::Scenario::FramedUpload,
    matrix::Scenario::DirectUpload,
    matrix::Scenario::Bidi,
];

pub(super) struct Plan<'a> {
    pub payload_mib: u64,
    pub samples: usize,
    pub concurrencies: &'a [usize],
    pub endpoints: matrix::Endpoints,
    pub pid: u32,
    pub workspace: &'a Path,
    pub output: &'a Path,
}

pub(super) struct Row {
    pub scenario: matrix::Scenario,
    pub concurrency: usize,
    pub mib_per_second: f64,
    pub cpu_seconds_per_gib: f64,
}

pub(super) fn capture(plan: &Plan<'_>) -> Result<Vec<Row>, String> {
    let payload = plan
        .workspace
        .join(format!("payload-{}.bin", plan.payload_mib));
    let digest = hash::sha256_file(&payload)?;
    matrix::integrity_transfer(plan.endpoints, plan.payload_mib, &digest)?;
    write(
        plan.output,
        "data-integrity.json",
        &Json::object([
            ("payloadSha256", Json::string(digest)),
            ("directDownloadSha256Verified", Json::Bool(true)),
            (
                "uploadValidation",
                Json::string("fresh origin byte-count receipts"),
            ),
        ]),
    )?;
    let mut rows = Vec::new();
    for scenario in SCENARIOS {
        for &concurrency in plan.concurrencies {
            // Warm exactly the cell being measured, and fail on warm-up errors.
            matrix::run_workload(
                scenario,
                plan.endpoints,
                plan.payload_mib,
                concurrency,
                plan.workspace,
            )?;
            let mut uploads = guards::LineTracker::new(
                plan.workspace
                    .join(format!("{}-put.jsonl", scenario.origin_scheme())),
            );
            uploads.drain();
            for sample in 0..plan.samples {
                rows.push(measure(plan, scenario, concurrency, sample, &mut uploads)?);
            }
        }
    }
    Ok(rows)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "bounded payload and concurrency counts"
)]
fn measure(
    plan: &Plan<'_>,
    scenario: matrix::Scenario,
    concurrency: usize,
    sample: usize,
    uploads: &mut guards::LineTracker,
) -> Result<Row, String> {
    let scheme = scenario.origin_scheme();
    let port = if scheme == "https" {
        plan.endpoints.https
    } else {
        plan.endpoints.http
    };
    let origin_before = guards::fetch_origin_stats(port, scheme)?;
    let before = schedstat::CpuSnapshot::capture(plan.pid)?;
    let started = Instant::now();
    let outcome = matrix::run_workload(
        scenario,
        plan.endpoints,
        plan.payload_mib,
        concurrency,
        plan.workspace,
    )?;
    let after = schedstat::CpuSnapshot::capture(plan.pid)?;
    let cpu = schedstat::delta(&before, &after, started.elapsed().as_nanos())?;
    let origin_after = guards::fetch_origin_stats(port, scheme)?;
    let receipts = uploads.new_lines();
    let total_mib = plan.payload_mib as f64 * outcome.requests as f64;
    let row = Row {
        scenario,
        concurrency,
        mib_per_second: total_mib / outcome.wall_seconds,
        cpu_seconds_per_gib: cpu.milliseconds() / 1000.0 / (total_mib / 1024.0),
    };
    // Persist observations before validating guards, including failed receipts.
    write(
        plan.output,
        &format!("data-{}-c{concurrency}-s{sample}.json", scenario.as_str()),
        &Json::object([
            ("scenario", Json::string(scenario.as_str())),
            ("concurrency", integer(concurrency)),
            ("sample", integer(sample)),
            ("requests", integer(outcome.requests)),
            (
                "payloadMiB",
                Json::Int(i64::try_from(plan.payload_mib).unwrap_or(i64::MAX)),
            ),
            ("wallSeconds", Json::Float(outcome.wall_seconds)),
            (
                "perRequestSeconds",
                Json::Array(
                    outcome
                        .per_request_seconds
                        .iter()
                        .copied()
                        .map(Json::Float)
                        .collect(),
                ),
            ),
            ("mibPerSecond", Json::Float(row.mib_per_second)),
            ("cpuSecondsPerGiB", Json::Float(row.cpu_seconds_per_gib)),
            ("schedstat", cpu.to_json()),
            ("originBefore", stats(origin_before)),
            ("originAfter", stats(origin_after)),
            (
                "uploadReceipts",
                Json::Array(receipts.iter().map(Json::string).collect()),
            ),
        ]),
    )?;
    validate_sample(&row, origin_before, origin_after)?;
    if scenario.uploads() {
        guards::verify_uploads(
            &receipts,
            concurrency,
            i64::try_from(plan.payload_mib * 1024 * 1024).map_err(|e| e.to_string())?,
            scheme,
        )
        .map_err(|errors| errors.join("; "))?;
    }
    Ok(row)
}

fn validate_sample(
    row: &Row,
    before: guards::OriginStats,
    after: guards::OriginStats,
) -> Result<(), String> {
    if !row.mib_per_second.is_finite()
        || row.mib_per_second <= 0.0
        || !row.cpu_seconds_per_gib.is_finite()
        || row.cpu_seconds_per_gib <= 0.0
    {
        return Err(
            "client data requires positive finite throughput and attributed CPU".to_owned(),
        );
    }
    if let Some(errors) = guards::origin_error_delta(before, after)? {
        return Err(format!("client data origin reported {errors} errors"));
    }
    Ok(())
}

fn integer(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn stats(value: guards::OriginStats) -> Json {
    Json::object([
        ("errors", Json::Int(value.errors)),
        ("gets", Json::Int(value.gets)),
        ("puts", Json::Int(value.puts)),
    ])
}

fn write(directory: &Path, name: &str, value: &Json) -> Result<(), String> {
    std::fs::write(directory.join(name), value.to_python_json())
        .map_err(|error| format!("could not retain client data sample {name}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cpu_and_origin_failures_cannot_be_fast_passes() {
        let clean = guards::OriginStats {
            errors: 0,
            gets: 1,
            puts: 0,
        };
        let mut row = Row {
            scenario: matrix::Scenario::DirectDownload,
            concurrency: 1,
            mib_per_second: 100.0,
            cpu_seconds_per_gib: 0.2,
        };
        assert!(validate_sample(&row, clean, clean).is_ok());
        assert!(validate_sample(&row, clean, guards::OriginStats { errors: 1, ..clean }).is_err());
        row.cpu_seconds_per_gib = 0.0;
        assert!(validate_sample(&row, clean, clean).is_err());
        row.cpu_seconds_per_gib = 0.2;
        row.mib_per_second = f64::INFINITY;
        assert!(validate_sample(&row, clean, clean).is_err());
    }
}
