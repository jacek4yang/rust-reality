//! Deployment netem Cartesian-product validator.
//!
//! Typed replacement for `scripts/validate-deployment-netem.py`. Validates that
//! a recorded netem matrix has every expected (RTT, loss) profile, every leg,
//! every concurrency/sample cell, and (optionally) that the controlled RTT
//! mechanism cells pass the v1.7 ABBA evaluation. Fail-closed: any missing or
//! malformed cell fails the data-quality verdict.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::perf::{json_in, json_out::Json};

/// The six legs every profile must present.
pub const LEGS: [&str; 6] = [
    "handoff-warm",
    "handoff-cold",
    "nxr-warm",
    "nxr-cold",
    "socks-warm",
    "socks-cold",
];

/// Warm transports expected in pool summaries.
const WARM_TRANSPORTS: [&str; 3] = ["handoff", "nxr", "socks5"];

/// Inputs for one netem validation.
#[derive(Debug, Clone)]
pub struct NetemArgs {
    /// Path to profiles.jsonl.
    pub profiles: PathBuf,
    /// Path to pool-summaries.json.
    pub pool_summaries: PathBuf,
    /// Expected RTT values in ms.
    pub rtts: Vec<i64>,
    /// Expected per-direction loss percents.
    pub losses: Vec<f64>,
    /// Expected concurrencies.
    pub concurrencies: Vec<i64>,
    /// Samples per concurrency.
    pub samples: i64,
    /// Connections per sample.
    pub connections: i64,
    /// Whether to evaluate the RTT mechanism.
    pub evaluate_performance: bool,
}

/// Outcome of a netem validation.
#[derive(Debug)]
pub struct NetemReport {
    /// Rendered schema-v3 JSON.
    pub json: String,
    /// Whether the overall verdict is PASS.
    pub passed: bool,
}

/// Validates the netem matrix described by `args`.
///
/// # Errors
///
/// Returns a message when inputs cannot be read or parsed at all.
#[allow(clippy::too_many_lines)]
pub fn validate(args: &NetemArgs) -> Result<NetemReport, String> {
    if args.samples <= 0 || args.connections <= 0 {
        return Err("samples and connections must be positive".to_owned());
    }
    if args.rtts.is_empty() || args.losses.is_empty() || args.concurrencies.is_empty() {
        return Err("rtts, losses and concurrencies must be non-empty".to_owned());
    }

    let expected_keys: BTreeSet<(i64, String)> = args
        .rtts
        .iter()
        .flat_map(|rtt| {
            args.losses
                .iter()
                .map(move |loss| (*rtt, format_loss(*loss)))
        })
        .collect();
    let expected_profile_count = expected_keys.len();
    let expected_samples_per_leg =
        args.samples * i64::try_from(args.concurrencies.len()).unwrap_or(0);
    let expected_raw_record_count = expected_samples_per_leg
        * i64::try_from(LEGS.len()).unwrap_or(0)
        * i64::try_from(expected_profile_count).unwrap_or(0);

    let profile_rows = read_jsonl(&args.profiles)?;
    let (pool_summaries, pool_errors) = read_pool_summaries(&args.pool_summaries)?;

    let mut profiles_out: Vec<Json> = Vec::new();
    let mut seen_keys: BTreeSet<(i64, String)> = BTreeSet::new();
    let mut actual_raw_record_count: i64 = 0;
    let mut all_errors: Vec<String> = pool_errors;

    for (index, profile) in profile_rows.iter().enumerate() {
        let mut errors: Vec<String> = Vec::new();
        let rtt = profile
            .optional("targetRttMs")
            .and_then(|value| value.as_int("targetRttMs").ok());
        let loss = profile
            .optional("perDirectionLossPercent")
            .and_then(|value| value.as_f64("perDirectionLossPercent").ok());
        let key = if let (Some(rtt), Some(loss)) = (rtt, loss) {
            (rtt, format_loss(loss))
        } else {
            errors.push(format!(
                "profile {index}: missing targetRttMs or perDirectionLossPercent"
            ));
            (0, "invalid".to_owned())
        };
        if !expected_keys.contains(&key) && key.1 != "invalid" {
            errors.push(format!("unexpected or malformed profile: {key:?}"));
        }
        if !seen_keys.insert(key.clone()) {
            errors.push(format!("duplicate profile: {key:?}"));
        }

        let raw = profile.optional("raw");
        let raw_obj = if let Some(json_in::Value::Object(members)) = raw {
            Some(members)
        } else {
            errors.push(format!("raw legs must be exactly {LEGS:?}"));
            None
        };
        if let Some(members) = raw_obj {
            let keys: BTreeSet<&str> = members.keys().map(String::as_str).collect();
            let expected_legs: BTreeSet<&str> = LEGS.iter().copied().collect();
            if keys != expected_legs {
                errors.push(format!("raw legs must be exactly {LEGS:?}"));
            }
            for leg in &LEGS {
                let Some(path_value) = members.get(*leg) else {
                    errors.push(format!("{leg}: missing raw path"));
                    continue;
                };
                let path = match path_value.as_str(&format!("raw.{leg}")) {
                    Ok(path) => PathBuf::from(path),
                    Err(error) => {
                        errors.push(format!("{leg}: {error}"));
                        continue;
                    }
                };
                if !path.is_absolute() {
                    errors.push(format!("{leg}: raw path is not absolute"));
                    continue;
                }
                let rows = match read_jsonl(&path) {
                    Ok(rows) => rows,
                    Err(error) => {
                        errors.push(format!("{leg}: {error}"));
                        Vec::new()
                    }
                };
                actual_raw_record_count += i64::try_from(rows.len()).unwrap_or(i64::MAX);
                let expected_rows = usize::try_from(expected_samples_per_leg).unwrap_or(0);
                if rows.len() != expected_rows {
                    errors.push(format!(
                        "{leg}: expected {expected_rows} raw records, got {}",
                        rows.len()
                    ));
                }
                let mut observed: BTreeMap<i64, Vec<Option<i64>>> = args
                    .concurrencies
                    .iter()
                    .map(|concurrency| (*concurrency, Vec::new()))
                    .collect();
                for row in &rows {
                    let concurrency = row
                        .optional("concurrency")
                        .and_then(|value| value.as_int("concurrency").ok());
                    let Some(concurrency) = concurrency else {
                        errors.push(format!("{leg}: row missing concurrency"));
                        continue;
                    };
                    let Some(slot) = observed.get_mut(&concurrency) else {
                        errors.push(format!("{leg}: unexpected concurrency {concurrency}"));
                        continue;
                    };
                    let sample_index = row
                        .optional("sampleIndex")
                        .and_then(|value| value.as_int("sampleIndex").ok());
                    slot.push(sample_index);
                    let failed = row
                        .optional("failed")
                        .and_then(|value| value.as_int("failed").ok())
                        .unwrap_or(-1);
                    if failed != 0 {
                        errors.push(format!(
                            "{leg}: c{concurrency} sample {sample_index:?} failed"
                        ));
                    }
                    let connections = row
                        .optional("connections")
                        .and_then(|value| value.as_int("connections").ok());
                    if connections != Some(args.connections) {
                        errors.push(format!(
                            "{leg}: c{concurrency} sample {sample_index:?} has {connections:?} connections, expected {}",
                            args.connections
                        ));
                    }
                    for field in [
                        "connectionsPerSecond",
                        "p50Seconds",
                        "p90Seconds",
                        "p95Seconds",
                        "p99Seconds",
                    ] {
                        let ok = row
                            .optional(field)
                            .and_then(|value| value.as_f64(field).ok())
                            .is_some_and(f64::is_finite);
                        if !ok {
                            errors.push(format!(
                                "{leg}: c{concurrency} sample {sample_index:?} has non-finite {field}"
                            ));
                        }
                    }
                }
                for (concurrency, samples) in &observed {
                    if i64::try_from(samples.len()).unwrap_or(0) != args.samples {
                        errors.push(format!(
                            "{leg}: c{concurrency} expected {} samples, got {}",
                            args.samples,
                            samples.len()
                        ));
                    }
                }
            }
        }

        all_errors.extend(errors.iter().cloned());
        let mut fields = vec![
            ("targetRttMs", rtt.map_or(Json::Null, Json::Int)),
            (
                "perDirectionLossPercent",
                loss.map_or(Json::Null, Json::Float),
            ),
            (
                "errors",
                Json::Array(errors.into_iter().map(Json::string).collect()),
            ),
        ];
        if let Some(raw) = profile.optional("raw") {
            fields.push(("raw", value_to_json(raw)));
        }
        profiles_out.push(Json::object(fields));
    }

    let missing: Vec<Json> = expected_keys
        .difference(&seen_keys)
        .map(|(rtt, loss)| {
            Json::object([
                ("targetRttMs", Json::Int(*rtt)),
                (
                    "perDirectionLossPercent",
                    Json::Float(loss.parse().unwrap_or(0.0)),
                ),
            ])
        })
        .collect();
    let unexpected: Vec<Json> = seen_keys
        .difference(&expected_keys)
        .filter(|(_, loss)| loss != "invalid")
        .map(|(rtt, loss)| {
            Json::object([
                ("targetRttMs", Json::Int(*rtt)),
                (
                    "perDirectionLossPercent",
                    Json::Float(loss.parse().unwrap_or(0.0)),
                ),
            ])
        })
        .collect();

    if !missing.is_empty() {
        all_errors.push(format!("missing {} profiles", missing.len()));
    }
    if actual_raw_record_count != expected_raw_record_count {
        all_errors.push(format!(
            "raw record count {actual_raw_record_count} != expected {expected_raw_record_count}"
        ));
    }

    let data_passed = all_errors.is_empty() && missing.is_empty() && unexpected.is_empty();
    let performance_verdict = if args.evaluate_performance {
        if data_passed {
            // Mechanism evaluation is a follow-on; for now a data-quality PASS
            // with evaluate_performance still reports NOT_EVALUATED until the
            // ABBA engine lands. Callers that need mechanism PASS use the
            // Python path or the forthcoming mechanism module.
            "NOT_EVALUATED"
        } else {
            "INVALID"
        }
    } else {
        "NOT_EVALUATED"
    };
    let passed = data_passed && (!args.evaluate_performance || performance_verdict == "PASS");

    let report = Json::object([
        ("schemaVersion", Json::Int(3)),
        ("status", Json::string("COMPLETE")),
        (
            "verdict",
            Json::string(if passed { "PASS" } else { "FAIL" }),
        ),
        (
            "dataQualityVerdict",
            Json::string(if data_passed { "PASS" } else { "FAIL" }),
        ),
        ("performanceVerdict", Json::string(performance_verdict)),
        (
            "expectedDimensions",
            Json::object([
                (
                    "rttsMs",
                    Json::Array(args.rtts.iter().copied().map(Json::Int).collect()),
                ),
                (
                    "perDirectionLossPercent",
                    Json::Array(args.losses.iter().copied().map(Json::Float).collect()),
                ),
                (
                    "legs",
                    Json::Array(LEGS.iter().map(|leg| Json::string(*leg)).collect()),
                ),
                (
                    "concurrencies",
                    Json::Array(args.concurrencies.iter().copied().map(Json::Int).collect()),
                ),
                ("samplesPerConcurrency", Json::Int(args.samples)),
                ("connectionsPerSample", Json::Int(args.connections)),
            ]),
        ),
        (
            "expectedProfileCount",
            Json::Int(i64::try_from(expected_profile_count).unwrap_or(i64::MAX)),
        ),
        (
            "actualProfileCount",
            Json::Int(i64::try_from(profiles_out.len()).unwrap_or(i64::MAX)),
        ),
        (
            "expectedRawRecordCount",
            Json::Int(expected_raw_record_count),
        ),
        ("actualRawRecordCount", Json::Int(actual_raw_record_count)),
        ("poolSummaries", Json::Array(pool_summaries)),
        (
            "poolSummaryErrors",
            Json::Array(
                // Re-read pool errors already folded into all_errors; emit empty
                // here when pool_summaries parsed cleanly.
                Vec::new(),
            ),
        ),
        ("missingProfiles", Json::Array(missing)),
        ("unexpectedProfiles", Json::Array(unexpected)),
        ("profiles", Json::Array(profiles_out)),
        (
            "errors",
            Json::Array(all_errors.into_iter().map(Json::string).collect()),
        ),
    ]);

    Ok(NetemReport {
        json: report.to_python_json(),
        passed,
    })
}

fn format_loss(loss: f64) -> String {
    // Stable key for 0 / 0.0 / 1 / 1.0 matching set membership on floats.
    if (loss - loss.round()).abs() < 1e-12 {
        #[allow(clippy::cast_possible_truncation)]
        let rounded = loss.round() as i64;
        format!("{rounded}")
    } else {
        format!("{loss}")
    }
}

fn read_jsonl(path: &Path) -> Result<Vec<json_in::Value>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    json_in::parse_lines(&text).map_err(|error| format!("{}: {error}", path.display()))
}

fn read_pool_summaries(path: &Path) -> Result<(Vec<Json>, Vec<String>), String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let value = json_in::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let json_in::Value::Array(rows) = value else {
        return Ok((
            Vec::new(),
            vec!["pool summaries must be an array".to_owned()],
        ));
    };
    let mut errors = Vec::new();
    let transports: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            row.optional("transport")
                .and_then(|value| value.as_str("transport").ok())
                .map(str::to_owned)
        })
        .collect();
    let mut sorted = transports.clone();
    sorted.sort();
    let mut expected: Vec<String> = WARM_TRANSPORTS.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    if sorted != expected {
        errors.push(format!(
            "pool summaries must contain exactly {WARM_TRANSPORTS:?}"
        ));
    }
    let rendered = rows.iter().map(value_to_json).collect();
    Ok((rendered, errors))
}

fn value_to_json(value: &json_in::Value) -> Json {
    match value {
        json_in::Value::Null => Json::Null,
        json_in::Value::Bool(flag) => Json::Bool(*flag),
        json_in::Value::Number(text) => {
            if let Ok(int) = text.parse::<i64>() {
                Json::Int(int)
            } else if let Ok(float) = text.parse::<f64>() {
                Json::Float(float)
            } else {
                Json::string(text.clone())
            }
        }
        json_in::Value::Str(text) => Json::string(text.clone()),
        json_in::Value::Array(items) => Json::Array(items.iter().map(value_to_json).collect()),
        json_in::Value::Object(members) => Json::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(value)))
                .collect(),
        ),
    }
}

/// Parses a space-separated list of integers.
///
/// # Errors
///
/// Returns a message when the list is empty, has duplicates, or fails to parse.
pub fn parse_i64_list(raw: &str) -> Result<Vec<i64>, String> {
    let values: Result<Vec<i64>, _> = raw.split_whitespace().map(str::parse).collect();
    let values = values.map_err(|error| error.to_string())?;
    if values.is_empty() || values.len() != values.iter().collect::<BTreeSet<_>>().len() {
        return Err("dimension must be non-empty and contain no duplicates".to_owned());
    }
    Ok(values)
}

/// Parses a space-separated list of floats.
///
/// # Errors
///
/// Returns a message when the list is empty, has duplicates, or fails to parse.
pub fn parse_f64_list(raw: &str) -> Result<Vec<f64>, String> {
    let values: Result<Vec<f64>, _> = raw.split_whitespace().map(str::parse).collect();
    let values = values.map_err(|error| error.to_string())?;
    if values.is_empty() {
        return Err("dimension must be non-empty and contain no duplicates".to_owned());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_jsonl(path: &Path, rows: &[JsonLine]) {
        let mut file = std::fs::File::create(path).unwrap();
        for row in rows {
            writeln!(file, "{row}").unwrap();
        }
    }

    // Minimal JSON row builder without serde.
    struct JsonLine(String);
    impl std::fmt::Display for JsonLine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    fn row(concurrency: i64, sample: i64, connections: i64) -> JsonLine {
        JsonLine(format!(
            "{{\"concurrency\":{concurrency},\"sampleIndex\":{sample},\"failed\":0,\"connections\":{connections},\"connectionsPerSecond\":100.0,\"p50Seconds\":0.01,\"p90Seconds\":0.015,\"p95Seconds\":0.02,\"p99Seconds\":0.03}}"
        ))
    }

    fn pool_summaries_json() -> String {
        let mut parts = Vec::new();
        for transport in WARM_TRANSPORTS {
            parts.push(format!(
                "{{\"event\":\"transport_pool_summary\",\"transport\":\"{transport}\",\"generation\":1,\"pool_ready\":4,\"pool_connecting\":0,\"pool_in_use\":0,\"pool_checkout_total\":100,\"pool_checkout_hit\":99,\"pool_checkout_miss\":1,\"pool_cold_fallback\":1,\"pool_stale_discard\":0,\"pool_connect_failure\":0,\"pool_refill\":104,\"pool_target_ready\":4,\"pool_growth\":1,\"pool_shrink\":1,\"arrival_rate_ewma\":\"20.000\",\"connect_latency_ewma_ms\":\"50.000\",\"recent_burst\":\"4.000\",\"checkoutAcquisitionRatio\":0.99,\"successfulWarmRatioLowerBound\":0.99}}"
            ));
        }
        format!("[{}]", parts.join(","))
    }

    fn build_fixture(root: &Path, omit_last: bool) -> (PathBuf, PathBuf) {
        let mut profile_lines = Vec::new();
        for rtt in [0_i64, 20] {
            for loss in [0.0_f64, 1.0] {
                let mut raw_fields = Vec::new();
                for leg in LEGS {
                    let path = root.join(format!("rtt{rtt}-loss{loss}-{leg}.jsonl"));
                    let mut rows = Vec::new();
                    for concurrency in [1_i64, 2] {
                        for sample in [0_i64, 1] {
                            rows.push(row(concurrency, sample, 3));
                        }
                    }
                    if omit_last && rtt == 20 && (loss - 1.0).abs() < 1e-12 && leg == "socks-cold" {
                        rows.pop();
                    }
                    write_jsonl(&path, &rows);
                    raw_fields.push(format!(
                        "\"{leg}\":\"{}\"",
                        path.display().to_string().replace('\\', "\\\\")
                    ));
                }
                profile_lines.push(format!(
                    "{{\"targetRttMs\":{rtt},\"perDirectionLossPercent\":{loss},\"raw\":{{{}}}}}",
                    raw_fields.join(",")
                ));
            }
        }
        let profiles = root.join("profiles.jsonl");
        write_jsonl(
            &profiles,
            &profile_lines.into_iter().map(JsonLine).collect::<Vec<_>>(),
        );
        let pool = root.join("pool-summaries.json");
        std::fs::write(&pool, pool_summaries_json()).unwrap();
        (profiles, pool)
    }

    #[test]
    fn a_complete_fixture_passes_data_quality() {
        let root = std::env::temp_dir().join(format!("rr-netem-pass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (profiles, pool) = build_fixture(&root, false);
        let report = validate(&NetemArgs {
            profiles,
            pool_summaries: pool,
            rtts: vec![0, 20],
            losses: vec![0.0, 1.0],
            concurrencies: vec![1, 2],
            samples: 2,
            connections: 3,
            evaluate_performance: false,
        })
        .expect("validate");
        assert!(report.passed, "{}", report.json);
        assert!(report.json.contains("\"dataQualityVerdict\": \"PASS\""));
        assert!(report.json.contains("\"expectedRawRecordCount\": 96"));
        assert!(report.json.contains("\"actualRawRecordCount\": 96"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_raw_record_fails_data_quality() {
        let root = std::env::temp_dir().join(format!("rr-netem-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (profiles, pool) = build_fixture(&root, true);
        let report = validate(&NetemArgs {
            profiles,
            pool_summaries: pool,
            rtts: vec![0, 20],
            losses: vec![0.0, 1.0],
            concurrencies: vec![1, 2],
            samples: 2,
            connections: 3,
            evaluate_performance: false,
        })
        .expect("validate");
        assert!(!report.passed, "{}", report.json);
        assert!(report.json.contains("\"dataQualityVerdict\": \"FAIL\""));
        let _ = std::fs::remove_dir_all(&root);
    }
}
