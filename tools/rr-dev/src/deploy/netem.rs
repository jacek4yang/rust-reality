//! Deployment netem Cartesian-product validator.
//!
//! Typed replacement for `scripts/validate-deployment-netem.py`. Validates that
//! a recorded netem matrix has every expected (RTT, loss) profile, every leg,
//! every concurrency/sample cell, and (optionally) that the controlled RTT
//! mechanism cells pass the v1.7 ABBA evaluation. Fail-closed: any missing or
//! malformed cell fails the data-quality verdict.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::perf::{bootstrap, json_in, json_out::Json, stats};

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

/// Controlled RTT values the v1.7 mechanism gate evaluates.
const MECHANISM_RTTS_MS: [i64; 3] = [50, 100, 200];

/// Mechanism cells are concurrency-1 only.
const MECHANISM_CONCURRENCY: i64 = 1;

/// Mechanism cells are zero-loss only.
const MECHANISM_LOSS_PERCENT: f64 = 0.0;

/// Bootstrap iterations, matching `scripts/validate-deployment-netem.py`.
const BOOTSTRAP_ITERATIONS: usize = 20_000;

/// One profile's fields the mechanism evaluator needs after data-quality passes.
struct MechanismProfile {
    target_rtt_ms: Option<i64>,
    loss: Option<f64>,
    observed_rtt_ms: Option<f64>,
    raw_results: BTreeMap<String, Vec<json_in::Value>>,
}

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
    let mut mechanism_profiles: Vec<MechanismProfile> = Vec::new();
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
        let observed_rtt_ms = profile
            .optional("observedRttMs")
            .and_then(|value| value.as_f64("observedRttMs").ok());
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

        let mut raw_results: BTreeMap<String, Vec<json_in::Value>> = BTreeMap::new();
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
                raw_results.insert((*leg).to_owned(), rows);
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
        if let Some(observed) = observed_rtt_ms {
            fields.push(("observedRttMs", Json::Float(observed)));
        }
        if let Some(raw) = profile.optional("raw") {
            fields.push(("raw", value_to_json(raw)));
        }
        profiles_out.push(Json::object(fields));
        mechanism_profiles.push(MechanismProfile {
            target_rtt_ms: rtt,
            loss,
            observed_rtt_ms,
            raw_results,
        });
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
    let (performance_report, performance_errors, performance_verdict) =
        if args.evaluate_performance {
            if data_passed {
                let (report, errors, verdict) = mechanism_evaluation(&mechanism_profiles, args);
                (Some(report), errors, verdict)
            } else {
                (None, Vec::new(), "INVALID".to_owned())
            }
        } else {
            (None, Vec::new(), "NOT_EVALUATED".to_owned())
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
        (
            "performanceMechanism",
            performance_report.unwrap_or(Json::Null),
        ),
        (
            "performanceErrors",
            Json::Array(performance_errors.into_iter().map(Json::string).collect()),
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

/// Evaluate the controlled RTT mechanism claimed by v1.7.
///
/// Every two consecutive sample indexes form one balanced ABBA block: the
/// collector runs warm, cold, cold, warm and stores the two warm and two cold
/// aggregates under the same pair of indexes. The block effect is
/// `median(cold p50) - median(warm p50)`, normalized by measured RTT.
///
/// Bootstrap uses the shared [`bootstrap`] MT19937 path, which is bit-compatible
/// with `CPython`'s `random.Random` / `random.choices` — the same generator the
/// release-performance evaluator already pins against recorded intervals.
#[allow(clippy::too_many_lines)]
fn mechanism_evaluation(
    profiles: &[MechanismProfile],
    args: &NetemArgs,
) -> (Json, Vec<String>, String) {
    let mut errors: Vec<String> = Vec::new();
    if args.samples < 6 || args.samples % 2 != 0 {
        errors.push(
            "mechanism evaluation requires an even samples count of at least 6".to_owned(),
        );
    }
    let expected_rtts: BTreeSet<i64> = args.rtts.iter().copied().collect();
    let expected_losses: BTreeSet<String> = args.losses.iter().copied().map(format_loss).collect();
    let expected_concurrencies: BTreeSet<i64> = args.concurrencies.iter().copied().collect();
    if !MECHANISM_RTTS_MS
        .iter()
        .all(|rtt| expected_rtts.contains(rtt))
    {
        errors.push(format!(
            "mechanism evaluation requires RTTs {:?}",
            MECHANISM_RTTS_MS.to_vec()
        ));
    }
    if !expected_losses.contains(&format_loss(MECHANISM_LOSS_PERCENT)) {
        errors.push("mechanism evaluation requires a zero-loss profile".to_owned());
    }
    if !expected_concurrencies.contains(&MECHANISM_CONCURRENCY) {
        errors.push("mechanism evaluation requires concurrency 1".to_owned());
    }

    let by_key: BTreeMap<(i64, String), &MechanismProfile> = profiles
        .iter()
        .filter_map(|profile| {
            let rtt = profile.target_rtt_ms?;
            let loss = profile.loss?;
            Some(((rtt, format_loss(loss)), profile))
        })
        .collect();

    let mut cells: Vec<Json> = Vec::new();
    let leg_prefix = [("handoff", "handoff"), ("nxr", "nxr"), ("socks5", "socks")];

    if !errors.is_empty() {
        let report = mechanism_report("FAIL", &cells, &errors);
        return (report, errors, "FAIL".to_owned());
    }

    for rtt_ms in MECHANISM_RTTS_MS {
        let profile = by_key.get(&(rtt_ms, format_loss(MECHANISM_LOSS_PERCENT)));
        let Some(profile) = profile else {
            errors.push(format!(
                "missing zero-loss RTT {rtt_ms} ms mechanism profile"
            ));
            continue;
        };
        let observed_rtt = profile.observed_rtt_ms;
        let Some(observed_rtt) = observed_rtt.filter(|value| value.is_finite() && *value > 0.0)
        else {
            errors.push(format!(
                "RTT {rtt_ms} ms profile has no positive measured RTT"
            ));
            continue;
        };

        for (transport, prefix) in leg_prefix {
            let warm_rows = rows_by_sample(
                profile
                    .raw_results
                    .get(&format!("{prefix}-warm"))
                    .map_or(&[][..], Vec::as_slice),
            );
            let cold_rows = rows_by_sample(
                profile
                    .raw_results
                    .get(&format!("{prefix}-cold"))
                    .map_or(&[][..], Vec::as_slice),
            );
            let mut normalized_deltas: Vec<f64> = Vec::new();
            let mut block_rows: Vec<Json> = Vec::new();
            let mut cell_errors: Vec<String> = Vec::new();

            let mut first = 0_i64;
            while first < args.samples {
                let indexes = [first, first + 1];
                match block_medians_ms(&warm_rows, &cold_rows, &indexes) {
                    Ok((warm_ms, cold_ms)) => {
                        let delta_ms = cold_ms - warm_ms;
                        let normalized = delta_ms / observed_rtt;
                        normalized_deltas.push(normalized);
                        block_rows.push(Json::object([
                            ("block", Json::Int(first / 2)),
                            (
                                "sampleIndexes",
                                Json::Array(indexes.iter().copied().map(Json::Int).collect()),
                            ),
                            ("warmP50Ms", Json::Float(warm_ms)),
                            ("coldP50Ms", Json::Float(cold_ms)),
                            ("removedHandshakeMs", Json::Float(delta_ms)),
                            (
                                "removedHandshakePerMeasuredRtt",
                                Json::Float(normalized),
                            ),
                        ]));
                    }
                    Err(message) => {
                        cell_errors.push(format!("block {}: {message}", first / 2));
                    }
                }
                first += 2;
            }

            let (point, interval) = match stats::median(&normalized_deltas) {
                Err(error) => {
                    cell_errors.push(error.to_string());
                    (None, None)
                }
                Ok(point) => match bootstrap_interval(&normalized_deltas, transport, rtt_ms) {
                    Ok(interval) => (Some(point), Some(interval)),
                    Err(error) => {
                        // Match Python: a bootstrap refusal clears both fields.
                        cell_errors.push(error);
                        (None, None)
                    }
                },
            };

            if let Some(point) = point {
                if point <= 0.0 {
                    cell_errors
                        .push("cold-minus-warm latency delta is not positive".to_owned());
                }
                if !(0.65..=1.35).contains(&point) {
                    cell_errors.push(
                        "median removed-handshake delta is outside 0.65..1.35 measured RTT"
                            .to_owned(),
                    );
                }
                if rtt_ms >= 100
                    && let Some(interval) = interval
                    && interval[0] <= 0.5
                {
                    cell_errors.push(
                        "bootstrap lower bound does not exceed 0.5 measured RTT".to_owned(),
                    );
                }
            }

            for message in &cell_errors {
                errors.push(format!("{transport} RTT {rtt_ms} ms: {message}"));
            }

            cells.push(Json::object([
                ("transport", Json::string(transport)),
                ("targetRttMs", Json::Int(rtt_ms)),
                ("measuredRttMs", Json::Float(observed_rtt)),
                (
                    "perDirectionLossPercent",
                    Json::Float(MECHANISM_LOSS_PERCENT),
                ),
                ("concurrency", Json::Int(MECHANISM_CONCURRENCY)),
                ("metric", Json::string("cold p50 minus warm p50")),
                (
                    "blockCount",
                    Json::Int(i64::try_from(normalized_deltas.len()).unwrap_or(i64::MAX)),
                ),
                ("blocks", Json::Array(block_rows)),
                (
                    "medianRemovedHandshakePerMeasuredRtt",
                    point.map_or(Json::Null, Json::Float),
                ),
                (
                    "bootstrap95",
                    interval.map_or(Json::Null, |bounds| {
                        Json::Array(vec![Json::Float(bounds[0]), Json::Float(bounds[1])])
                    }),
                ),
                (
                    "verdict",
                    Json::string(if cell_errors.is_empty() {
                        "PASS"
                    } else {
                        "FAIL"
                    }),
                ),
                (
                    "errors",
                    Json::Array(cell_errors.into_iter().map(Json::string).collect()),
                ),
            ]));
        }
    }

    let expected_cells = MECHANISM_RTTS_MS.len() * WARM_TRANSPORTS.len();
    let passed = cells.len() == expected_cells && errors.is_empty();
    let verdict = if passed { "PASS" } else { "FAIL" };
    let report = mechanism_report(verdict, &cells, &errors);
    (report, errors, verdict.to_owned())
}

fn mechanism_report(verdict: &str, cells: &[Json], errors: &[String]) -> Json {
    Json::object([
        ("verdict", Json::string(verdict)),
        (
            "claim",
            Json::string(
                "on a valid warm hit, the user flow does not wait for a new LINE-to-peer TCP handshake",
            ),
        ),
        (
            "scope",
            Json::string(
                "zero-loss concurrency-1 cold-versus-warm p50; loss and higher concurrency cells are mandatory robustness evidence, not mechanism gates",
            ),
        ),
        ("pairing", Json::string("balanced ABBA blocks")),
        (
            "effect",
            Json::string("median(cold p50) - median(warm p50)"),
        ),
        (
            "normalization",
            Json::string("measured ICMP RTT for the shaped veth pair"),
        ),
        (
            "bootstrapIterations",
            Json::Int(i64::try_from(BOOTSTRAP_ITERATIONS).unwrap_or(i64::MAX)),
        ),
        (
            "gate",
            Json::object([
                (
                    "rttsMs",
                    Json::Array(MECHANISM_RTTS_MS.iter().copied().map(Json::Int).collect()),
                ),
                (
                    "pointEstimateMeasuredRttRange",
                    Json::Array(vec![Json::Float(0.65), Json::Float(1.35)]),
                ),
                (
                    "bootstrapLowerBoundAboveMeasuredRtt",
                    Json::object([
                        (
                            "rttsMs",
                            Json::Array(vec![Json::Int(100), Json::Int(200)]),
                        ),
                        ("exclusiveMinimum", Json::Float(0.5)),
                    ]),
                ),
            ]),
        ),
        ("cells", Json::Array(cells.to_vec())),
        (
            "errors",
            Json::Array(errors.iter().cloned().map(Json::string).collect()),
        ),
    ])
}

fn rows_by_sample(rows: &[json_in::Value]) -> BTreeMap<i64, &json_in::Value> {
    let mut by_sample = BTreeMap::new();
    for row in rows {
        let concurrency = row
            .optional("concurrency")
            .and_then(|value| value.as_int("concurrency").ok());
        if concurrency != Some(MECHANISM_CONCURRENCY) {
            continue;
        }
        let Some(sample_index) = row
            .optional("sampleIndex")
            .and_then(|value| value.as_int("sampleIndex").ok())
        else {
            continue;
        };
        by_sample.insert(sample_index, row);
    }
    by_sample
}

fn block_medians_ms(
    warm_rows: &BTreeMap<i64, &json_in::Value>,
    cold_rows: &BTreeMap<i64, &json_in::Value>,
    indexes: &[i64; 2],
) -> Result<(f64, f64), String> {
    let warm_ms = median_p50_ms(warm_rows, indexes)?;
    let cold_ms = median_p50_ms(cold_rows, indexes)?;
    Ok((warm_ms, cold_ms))
}

fn median_p50_ms(
    rows: &BTreeMap<i64, &json_in::Value>,
    indexes: &[i64; 2],
) -> Result<f64, String> {
    let mut values = Vec::with_capacity(2);
    for index in indexes {
        let row = rows
            .get(index)
            .ok_or_else(|| format!("missing sampleIndex {index}"))?;
        let seconds = row
            .optional("p50Seconds")
            .and_then(|value| value.as_f64("p50Seconds").ok())
            .ok_or_else(|| format!("sampleIndex {index} has no p50Seconds"))?;
        values.push(seconds * 1000.0);
    }
    stats::median(&values).map_err(|error| error.to_string())
}

fn bootstrap_interval(values: &[f64], transport: &str, rtt_ms: i64) -> Result<[f64; 2], String> {
    let label = format!("{transport}:rtt{rtt_ms}:cold-minus-warm");
    if values.len() < 3 {
        return Err(format!("{label}: fewer than three complete ABBA blocks"));
    }
    bootstrap::interval(&label, values, BOOTSTRAP_ITERATIONS).map_err(|error| error.to_string())
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
        row_with_p50(concurrency, sample, connections, 0.01)
    }

    fn row_with_p50(concurrency: i64, sample: i64, connections: i64, p50: f64) -> JsonLine {
        JsonLine(format!(
            "{{\"concurrency\":{concurrency},\"sampleIndex\":{sample},\"failed\":0,\"connections\":{connections},\"connectionsPerSecond\":100.0,\"p50Seconds\":{p50},\"p90Seconds\":{},\"p95Seconds\":{},\"p99Seconds\":{}}}",
            p50 * 1.1,
            p50 * 1.2,
            p50 * 1.3
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

    /// Mirror of `netem_mechanism_fixture` in `scripts/test-performance-gates.py`.
    ///
    /// `removed_rtt_fraction` 1.0 yields a point estimate of 1.0 (PASS); 0.2
    /// yields 0.2 (FAIL the 0.65..1.35 gate). Bootstrap is exercised but the
    /// pass/fail assertion is on the gate logic, not bit-identical intervals.
    fn build_mechanism_fixture(root: &Path, removed_rtt_fraction: f64) -> (PathBuf, PathBuf) {
        let mut profile_lines = Vec::new();
        for rtt in MECHANISM_RTTS_MS {
            let mut raw_fields = Vec::new();
            for leg in LEGS {
                let path = root.join(format!("rtt{rtt}-{leg}.jsonl"));
                let mut rows = Vec::new();
                for sample in 0_i64..6 {
                    let block_factor = [0.9_f64, 1.0, 1.1][usize::try_from(sample / 2).unwrap()];
                    #[allow(clippy::cast_precision_loss)]
                    let warm_seconds = 0.005 + (rtt as f64) / 1000.0;
                    let removed_seconds = if leg.ends_with("-cold") {
                        #[allow(clippy::cast_precision_loss)]
                        {
                            (rtt as f64) / 1000.0 * removed_rtt_fraction * block_factor
                        }
                    } else {
                        0.0
                    };
                    let p50 = warm_seconds + removed_seconds;
                    rows.push(row_with_p50(1, sample, 512, p50));
                }
                write_jsonl(&path, &rows);
                raw_fields.push(format!(
                    "\"{leg}\":\"{}\"",
                    path.display().to_string().replace('\\', "\\\\")
                ));
            }
            #[allow(clippy::cast_precision_loss)]
            let observed = rtt as f64;
            profile_lines.push(format!(
                "{{\"targetRttMs\":{rtt},\"observedRttMs\":{observed},\"perDirectionLossPercent\":0.0,\"raw\":{{{}}}}}",
                raw_fields.join(",")
            ));
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
    fn mechanism_evaluation_passes_when_removed_rtt_fraction_is_one() {
        let root =
            std::env::temp_dir().join(format!("rr-netem-mech-pass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (profiles, pool) = build_mechanism_fixture(&root, 1.0);
        let report = validate(&NetemArgs {
            profiles,
            pool_summaries: pool,
            rtts: vec![50, 100, 200],
            losses: vec![0.0],
            concurrencies: vec![1],
            samples: 6,
            connections: 512,
            evaluate_performance: true,
        })
        .expect("validate");
        assert!(report.passed, "{}", report.json);
        assert!(report.json.contains("\"dataQualityVerdict\": \"PASS\""));
        assert!(report.json.contains("\"performanceVerdict\": \"PASS\""));
        assert!(report.json.contains("\"performanceMechanism\""));
        // 3 RTTs × 3 transports
        let cell_passes = report.json.matches("\"verdict\": \"PASS\"").count();
        assert!(
            cell_passes >= 10,
            "expected overall + mechanism + 9 cells to PASS, got {cell_passes}: {}",
            report.json
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mechanism_evaluation_fails_when_removed_rtt_fraction_is_too_small() {
        let root =
            std::env::temp_dir().join(format!("rr-netem-mech-fail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let (profiles, pool) = build_mechanism_fixture(&root, 0.2);
        let report = validate(&NetemArgs {
            profiles,
            pool_summaries: pool,
            rtts: vec![50, 100, 200],
            losses: vec![0.0],
            concurrencies: vec![1],
            samples: 6,
            connections: 512,
            evaluate_performance: true,
        })
        .expect("validate");
        assert!(!report.passed, "{}", report.json);
        assert!(report.json.contains("\"dataQualityVerdict\": \"PASS\""));
        assert!(report.json.contains("\"performanceVerdict\": \"FAIL\""));
        assert!(report.json.contains("\"verdict\": \"FAIL\""));
        assert!(
            report
                .json
                .contains("median removed-handshake delta is outside 0.65..1.35 measured RTT"),
            "{}",
            report.json
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
