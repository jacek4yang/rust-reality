//! Typed validation and reporting for machine-profile evidence.
//!
//! The legacy profile pipeline split one policy across `profile-summarize.py`
//! and `profile-report.py`.  This module keeps the same fail-closed rules in one
//! place: all three cgroup runs must be present and uniquely scoped, swap and
//! OOM status must be known and zero, sampled series must be complete, both
//! workload families must be clean, and both connection ladders must finish.

#![allow(
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    reason = "profile evidence is bounded and the report mirrors one explicit schema"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::{Path, PathBuf},
};

use crate::perf::{
    json_in::{self, Value},
    json_out::Json,
};

const EXPECTED_RUNS: [&str; 3] = ["nogeo", "geo", "tuned"];
const PRESSURE_KEYS: [&str; 4] = [
    "resource_pressure_changed",
    "descriptor_pressure_changed",
    "admission_limited",
    "connection_rejected",
];

/// Inputs that identify and bound one class summary.
#[derive(Debug, Clone)]
pub struct Request {
    /// Directory containing `cells.jsonl` and `samples-*.tsv`.
    pub class_dir: PathBuf,
    /// Stable class label.
    pub class: String,
    /// `dedicated` or `standard`.
    pub resource_mode: String,
    /// Requested CPU quota percentage.
    pub cpu_quota_percent: i64,
    /// Human-readable requested memory maximum.
    pub memory_max: String,
    /// Requested memory maximum in bytes.
    pub memory_max_bytes: i64,
    /// Requested swap maximum, required to be zero.
    pub memory_swap_max_bytes: i64,
}

/// A complete class summary and its gate verdict.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Whether every class contract passed.
    pub passed: bool,
    /// `summary.json` document.
    pub json: Json,
    /// `summary.md` document.
    pub markdown: String,
}

#[derive(Debug, Clone, Default)]
struct Churn {
    rate_median: Option<f64>,
    p50_ms_worst: f64,
    p99_ms_worst: f64,
    failed_total: i64,
    cpu_total: f64,
    samples: usize,
}

#[derive(Debug, Clone, Default)]
struct Download {
    throughput_median: Option<f64>,
    size_mismatches: i64,
    errors: Vec<String>,
    cpu_total: f64,
    samples: usize,
}

#[derive(Debug, Clone, Default)]
struct LadderLevel {
    level: i64,
    held: i64,
    established: i64,
    new_failures: i64,
    new_pressure: i64,
    pressure_state: Option<String>,
    rss: i64,
    fds: i64,
    memory_current: i64,
    oom_kills: Option<i64>,
    oom_known: bool,
    server_alive: bool,
}

#[derive(Debug, Clone, Default)]
struct Ladder {
    levels: Vec<LadderLevel>,
    max_clean_level: i64,
    max_established: i64,
    establishment_evidence: bool,
    first_pressure_level: Option<i64>,
    oom_kills: Option<i64>,
    oom_known: bool,
    completed: bool,
    abort_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct SeriesRun {
    path: PathBuf,
    exists: bool,
    rows: usize,
    invalid_rows: usize,
    swap_max: Option<i64>,
    passed: bool,
}

#[derive(Debug, Clone, Default)]
struct Peaks {
    passed: bool,
    rss_max: i64,
    fd_max: i64,
    memory_current_max: i64,
    swap_current_max: i64,
    rows: usize,
    invalid_rows: usize,
    by_run: BTreeMap<String, SeriesRun>,
    unexpected_files: Vec<PathBuf>,
}

fn read_cells(path: &Path) -> Result<Vec<Value>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    json_in::parse_lines(&raw).map_err(|error| format!("{}: {error}", path.display()))
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.optional(key)
}

fn string(value: &Value, key: &str) -> Option<String> {
    field(value, key)?.as_str(key).ok().map(str::to_owned)
}

fn integer(value: &Value, key: &str) -> Option<i64> {
    field(value, key)?.as_int(key).ok()
}

fn number(value: &Value, key: &str) -> Option<f64> {
    field(value, key)?.as_f64(key).ok()
}

fn boolean(value: &Value, key: &str) -> Option<bool> {
    field(value, key)?.as_bool(key).ok()
}

fn object<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let candidate = field(value, key)?;
    matches!(candidate, Value::Object(_)).then_some(candidate)
}

fn positive(value: Option<i64>) -> bool {
    matches!(value, Some(number) if number > 0)
}

fn nonnegative(value: Option<i64>) -> bool {
    matches!(value, Some(number) if number >= 0)
}

fn cpu_matches(quota: Option<i64>, period: Option<i64>, percent: i64) -> bool {
    positive(quota)
        && positive(period)
        && percent > 0
        && quota
            .zip(period)
            .is_some_and(|(q, p)| q * 100 == percent * p)
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    values.retain(|value| value.is_finite());
    values.sort_unstable_by(f64::total_cmp);
    match values.len() {
        0 => None,
        length if length % 2 == 1 => Some(values[length / 2]),
        length => Some(values[length / 2 - 1].midpoint(values[length / 2])),
    }
}

fn input_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Number(text) => text.parse::<i64>().map_or_else(
            |_| Json::Float(text.parse::<f64>().unwrap_or(f64::NAN)),
            Json::Int,
        ),
        Value::Str(text) => Json::string(text.clone()),
        Value::Array(items) => Json::Array(items.iter().map(input_to_json).collect()),
        Value::Object(members) => Json::object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), input_to_json(value))),
        ),
    }
}

fn json_optional_i64(value: Option<i64>) -> Json {
    value.map_or(Json::Null, Json::Int)
}

fn json_optional_f64(value: Option<f64>) -> Json {
    value.map_or(Json::Null, Json::Float)
}

fn json_optional_string(value: Option<&str>) -> Json {
    value.map_or(Json::Null, Json::string)
}

fn int_usize(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn summarize_churn(cells: &[Value], concurrency: i64) -> Option<Churn> {
    let rows: Vec<&Value> = cells
        .iter()
        .filter(|row| {
            string(row, "cell").as_deref() == Some("churn")
                && integer(row, "concurrency") == Some(concurrency)
        })
        .collect();
    (!rows.is_empty()).then(|| Churn {
        rate_median: median(
            rows.iter()
                .filter_map(|row| number(row, "connectionsPerSecond"))
                .collect(),
        ),
        p50_ms_worst: rows
            .iter()
            .filter_map(|row| number(row, "p50Seconds"))
            .fold(0.0, f64::max)
            * 1000.0,
        p99_ms_worst: rows
            .iter()
            .filter_map(|row| number(row, "p99Seconds"))
            .fold(0.0, f64::max)
            * 1000.0,
        failed_total: rows.iter().filter_map(|row| integer(row, "failed")).sum(),
        cpu_total: rows
            .iter()
            .filter_map(|row| number(row, "serverCpuSeconds"))
            .sum(),
        samples: rows.len(),
    })
}

fn churn_json(value: Option<&Churn>) -> Json {
    value.map_or(Json::Null, |summary| {
        Json::object([
            (
                "connectionsPerSecondMedian",
                json_optional_f64(summary.rate_median),
            ),
            ("p50MsWorst", Json::Float(summary.p50_ms_worst)),
            ("p99MsWorst", Json::Float(summary.p99_ms_worst)),
            ("failedTotal", Json::Int(summary.failed_total)),
            ("serverCpuSecondsTotal", Json::Float(summary.cpu_total)),
            ("samples", int_usize(summary.samples)),
        ])
    })
}

fn summarize_download(cells: &[Value], concurrency: i64) -> Option<Download> {
    let rows: Vec<&Value> = cells
        .iter()
        .filter(|row| {
            string(row, "cell").as_deref() == Some("download")
                && integer(row, "concurrency") == Some(concurrency)
        })
        .collect();
    (!rows.is_empty()).then(|| Download {
        throughput_median: median(
            rows.iter()
                .filter_map(|row| number(row, "throughputMiBPerSecond"))
                .collect(),
        ),
        size_mismatches: rows
            .iter()
            .filter_map(|row| integer(row, "sizeMismatches"))
            .sum(),
        errors: rows
            .iter()
            .filter_map(|row| field(row, "errors"))
            .filter_map(|errors| errors.as_array("errors").ok())
            .flatten()
            .filter_map(|error| error.as_str("error").ok().map(str::to_owned))
            .collect(),
        cpu_total: rows
            .iter()
            .filter_map(|row| number(row, "serverCpuSeconds"))
            .sum(),
        samples: rows.len(),
    })
}

fn download_json(value: Option<&Download>) -> Json {
    value.map_or(Json::Null, |summary| {
        Json::object([
            (
                "throughputMiBPerSecondMedian",
                json_optional_f64(summary.throughput_median),
            ),
            ("sizeMismatches", Json::Int(summary.size_mismatches)),
            (
                "errors",
                Json::Array(summary.errors.iter().cloned().map(Json::string).collect()),
            ),
            ("serverCpuSecondsTotal", Json::Float(summary.cpu_total)),
            ("samples", int_usize(summary.samples)),
        ])
    })
}

fn event_count(row: &Value, key: &str) -> i64 {
    object(row, "logEvents")
        .and_then(|events| integer(events, key))
        .unwrap_or(0)
}

fn baseline_event_count(row: &Value, key: &str) -> i64 {
    object(row, "logEventBaseline")
        .and_then(|events| integer(events, key))
        .unwrap_or(0)
}

fn summarize_ladder(cells: &[Value], tag: Option<&str>) -> Option<Ladder> {
    let rows: Vec<&Value> = cells
        .iter()
        .filter(|row| {
            if string(row, "cell").as_deref() != Some("ladder") {
                return false;
            }
            match (field(row, "tag"), tag) {
                (None | Some(Value::Null), None) => true,
                (Some(Value::Str(observed)), Some(expected)) => observed == expected,
                _ => false,
            }
        })
        .collect();
    if rows.is_empty() {
        return None;
    }
    let mut grouped: BTreeMap<i64, Vec<&Value>> = BTreeMap::new();
    let mut order = Vec::new();
    for row in &rows {
        let level = integer(row, "level").unwrap_or(0);
        if !grouped.contains_key(&level) {
            order.push(level);
        }
        grouped.entry(level).or_default().push(row);
    }
    let evidence = rows.iter().all(|row| {
        string(row, "establishmentEvidence").as_deref() == Some("successful-socks-connect")
    });
    let first = rows.first().copied();
    let mut previous_events: BTreeMap<&str, i64> = PRESSURE_KEYS
        .into_iter()
        .map(|key| (key, first.map_or(0, |row| baseline_event_count(row, key))))
        .collect();
    let mut previous_failed = 0;
    let mut summary = Ladder {
        establishment_evidence: evidence,
        oom_known: true,
        ..Ladder::default()
    };
    for level in order {
        let group = grouped.get(&level).expect("grouped level exists");
        let established = group
            .iter()
            .filter_map(|row| integer(row, "serverEstablishedSessions"))
            .max()
            .unwrap_or(-1);
        let held = group
            .iter()
            .filter_map(|row| integer(row, "connectionsHeld"))
            .max()
            .unwrap_or(0);
        let mut new_pressure = 0;
        let mut new_failures = 0;
        let mut oom = 0;
        let mut oom_known = true;
        let mut alive = true;
        let mut state = None;
        let mut rss = 0;
        let mut fds = 0;
        let mut memory_current = 0;
        for row in group {
            for key in PRESSURE_KEYS {
                let observed = event_count(row, key);
                let previous = previous_events.get(key).copied().unwrap_or(0);
                new_pressure += (observed - previous).max(0);
                previous_events.insert(key, observed.max(previous));
            }
            let failed = integer(row, "connectionsFailedTotal").unwrap_or(0);
            new_failures += (failed - previous_failed).max(0);
            previous_failed = previous_failed.max(failed);
            if let Some(value) = integer(row, "cgroupOomKills").filter(|value| *value >= 0) {
                oom = oom.max(value);
            } else {
                oom_known = false;
                summary.oom_known = false;
            }
            alive &= boolean(row, "serverAlive").unwrap_or(false);
            state = string(row, "latestPressureState").or(state);
            rss = rss.max(integer(row, "serverRssBytes").unwrap_or(0));
            fds = fds.max(integer(row, "serverFdCount").unwrap_or(0));
            memory_current = memory_current.max(integer(row, "cgroupMemoryCurrent").unwrap_or(0));
            if field(row, "ladderComplete").is_some() {
                summary.completed = boolean(row, "ladderComplete").unwrap_or(false);
                summary.abort_reason = string(row, "abortReason");
            }
        }
        summary.max_established = summary.max_established.max(established);
        if oom_known {
            summary.oom_kills = Some(summary.oom_kills.unwrap_or(0).max(oom));
        }
        let clean = oom_known
            && established * 100 >= level * 98
            && new_pressure == 0
            && new_failures == 0
            && oom == 0
            && alive;
        if clean {
            summary.max_clean_level = summary.max_clean_level.max(level);
        } else if summary.first_pressure_level.is_none() {
            summary.first_pressure_level = Some(level);
        }
        summary.levels.push(LadderLevel {
            level,
            held,
            established,
            new_failures,
            new_pressure,
            pressure_state: state,
            rss,
            fds,
            memory_current,
            oom_kills: oom_known.then_some(oom),
            oom_known,
            server_alive: alive,
        });
    }
    if !summary.oom_known {
        summary.oom_kills = None;
    }
    Some(summary)
}

fn ladder_json(value: Option<&Ladder>) -> Json {
    value.map_or(Json::Null, |summary| {
        Json::object([
            (
                "levels",
                Json::Array(
                    summary
                        .levels
                        .iter()
                        .map(|level| {
                            Json::object([
                                ("level", Json::Int(level.level)),
                                ("held", Json::Int(level.held)),
                                ("established", Json::Int(level.established)),
                                ("newFailures", Json::Int(level.new_failures)),
                                ("newPressureEvents", Json::Int(level.new_pressure)),
                                (
                                    "latestPressureState",
                                    json_optional_string(level.pressure_state.as_deref()),
                                ),
                                ("serverRssBytes", Json::Int(level.rss)),
                                ("serverFdCount", Json::Int(level.fds)),
                                ("cgroupMemoryCurrent", Json::Int(level.memory_current)),
                                ("cgroupOomKills", json_optional_i64(level.oom_kills)),
                                ("cgroupOomStatusKnown", Json::Bool(level.oom_known)),
                                ("serverAlive", Json::Bool(level.server_alive)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("maxCleanLevel", Json::Int(summary.max_clean_level)),
            ("maxEstablishedSessions", Json::Int(summary.max_established)),
            (
                "establishmentEvidence",
                Json::object([
                    ("kind", Json::string("successful-socks-connect")),
                    ("pass", Json::Bool(summary.establishment_evidence)),
                ]),
            ),
            (
                "firstPressureLevel",
                json_optional_i64(summary.first_pressure_level),
            ),
            ("oomKills", json_optional_i64(summary.oom_kills)),
            ("oomStatusKnown", Json::Bool(summary.oom_known)),
            ("completed", Json::Bool(summary.completed)),
            (
                "abortReason",
                json_optional_string(summary.abort_reason.as_deref()),
            ),
        ])
    })
}

fn peaks_from_samples(class_dir: &Path) -> Result<Peaks, String> {
    let expected: BTreeMap<PathBuf, &str> = EXPECTED_RUNS
        .into_iter()
        .map(|run| (class_dir.join(format!("samples-{run}.tsv")), run))
        .collect();
    let mut observed = BTreeSet::new();
    let entries = std::fs::read_dir(class_dir)
        .map_err(|error| format!("could not read {}: {error}", class_dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|error| format!("could not read {}: {error}", class_dir.display()))?
            .path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with("samples-")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("tsv"))
            })
        {
            observed.insert(path);
        }
    }
    let mut peaks = Peaks {
        unexpected_files: observed
            .difference(&expected.keys().cloned().collect())
            .cloned()
            .collect(),
        ..Peaks::default()
    };
    for (path, run) in expected {
        let mut series = SeriesRun {
            path: path.clone(),
            ..SeriesRun::default()
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            peaks.by_run.insert(run.to_owned(), series);
            continue;
        };
        series.exists = true;
        let mut run_swap_max = 0;
        for line in raw.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 5 {
                series.invalid_rows += 1;
                peaks.invalid_rows += 1;
                continue;
            }
            let parsed: Option<Vec<i64>> =
                parts.iter().map(|part| part.parse::<i64>().ok()).collect();
            let Some(parsed) = parsed.filter(|values| values.iter().all(|value| *value >= 0))
            else {
                series.invalid_rows += 1;
                peaks.invalid_rows += 1;
                continue;
            };
            series.rows += 1;
            peaks.rows += 1;
            peaks.rss_max = peaks.rss_max.max(parsed[1]);
            peaks.fd_max = peaks.fd_max.max(parsed[2]);
            peaks.memory_current_max = peaks.memory_current_max.max(parsed[3]);
            peaks.swap_current_max = peaks.swap_current_max.max(parsed[4]);
            run_swap_max = run_swap_max.max(parsed[4]);
        }
        series.swap_max = (series.rows > 0).then_some(run_swap_max);
        series.passed = series.rows > 0 && series.invalid_rows == 0 && run_swap_max == 0;
        peaks.by_run.insert(run.to_owned(), series);
    }
    peaks.passed = peaks.unexpected_files.is_empty()
        && EXPECTED_RUNS
            .iter()
            .all(|run| peaks.by_run.get(*run).is_some_and(|series| series.passed));
    Ok(peaks)
}

fn series_json(peaks: &Peaks) -> Json {
    Json::object(peaks.by_run.iter().map(|(run, series)| {
        (
            run.clone(),
            Json::object([
                ("path", Json::string(series.path.display().to_string())),
                ("exists", Json::Bool(series.exists)),
                ("rows", int_usize(series.rows)),
                ("invalidRows", int_usize(series.invalid_rows)),
                ("swapMaxBytes", json_optional_i64(series.swap_max)),
                ("pass", Json::Bool(series.passed)),
            ]),
        )
    }))
}

fn resource_boundaries(cells: &[Value], request: &Request) -> (bool, Json) {
    let startups: Vec<&Value> = cells
        .iter()
        .filter(|cell| string(cell, "cell").as_deref() == Some("startup"))
        .collect();
    let mut run_counts: BTreeMap<&str, i64> =
        EXPECTED_RUNS.into_iter().map(|run| (run, 0)).collect();
    let mut units = Vec::new();
    let mut groups = Vec::new();
    let mut scopes = Vec::new();
    let machine_required = request.resource_mode == "dedicated";
    for startup in &startups {
        let run = string(startup, "run").unwrap_or_default();
        if let Some(count) = run_counts.get_mut(run.as_str()) {
            *count += 1;
        }
        let machine = object(startup, "machineReport");
        let evidence = object(startup, "cgroupEvidence");
        let requested = evidence.and_then(|value| object(value, "requested"));
        let actual = evidence.and_then(|value| object(value, "actual"));
        let unit = evidence.and_then(|value| string(value, "unit"));
        let group = evidence.and_then(|value| string(value, "controlGroup"));
        if let Some(unit) = &unit {
            units.push(unit.clone());
        }
        if let Some(group) = &group {
            groups.push(group.clone());
        }
        let unit_matches = unit
            .as_ref()
            .zip(group.as_ref())
            .is_some_and(|(unit, group)| {
                group.starts_with('/') && group.rsplit('/').next() == Some(unit)
            });
        let machine_values = machine.is_some_and(|machine| {
            string(machine, "memory_source").as_deref() == Some("cgroup_v2")
                && integer(machine, "memory_max") == Some(request.memory_max_bytes)
                && integer(machine, "memory_total") == Some(request.memory_max_bytes)
                && cpu_matches(
                    integer(machine, "cpu_quota_us"),
                    integer(machine, "cpu_period_us"),
                    request.cpu_quota_percent,
                )
        });
        let machine_matches = if machine_required {
            machine_values
        } else {
            machine.is_none()
        };
        let evidence_matches = evidence.is_some_and(|evidence| {
            integer(evidence, "schemaVersion") == Some(1)
                && boolean(evidence, "matchesRequested") == Some(true)
                && EXPECTED_RUNS.contains(&run.as_str())
                && unit_matches
                && requested.is_some_and(|requested| {
                    integer(requested, "cpuQuotaPercent") == Some(request.cpu_quota_percent)
                        && integer(requested, "memoryMaxBytes") == Some(request.memory_max_bytes)
                        && integer(requested, "memorySwapMaxBytes")
                            == Some(request.memory_swap_max_bytes)
                })
                && actual.is_some_and(|actual| {
                    cpu_matches(
                        integer(actual, "cpuQuotaUs"),
                        integer(actual, "cpuPeriodUs"),
                        request.cpu_quota_percent,
                    ) && integer(actual, "memoryMaxBytes") == Some(request.memory_max_bytes)
                        && integer(actual, "memorySwapMaxBytes")
                            == Some(request.memory_swap_max_bytes)
                        && integer(actual, "memorySwapCurrentBytes") == Some(0)
                })
        });
        scopes.push(Json::object([
            ("run", Json::string(run)),
            ("machineReportRequired", Json::Bool(machine_required)),
            ("machineReportPresent", Json::Bool(machine.is_some())),
            ("machineReportMatches", Json::Bool(machine_matches)),
            ("cgroupEvidenceMatches", Json::Bool(evidence_matches)),
            ("pass", Json::Bool(machine_matches && evidence_matches)),
            ("evidence", evidence.map_or(Json::Null, input_to_json)),
        ]));
    }
    let observed: BTreeSet<String> = startups
        .iter()
        .filter_map(|startup| string(startup, "run"))
        .collect();
    let expected: BTreeSet<String> = EXPECTED_RUNS.iter().map(|run| (*run).to_owned()).collect();
    let runs_match = observed == expected
        && EXPECTED_RUNS
            .iter()
            .all(|run| run_counts.get(run).copied() == Some(1))
        && startups.len() == EXPECTED_RUNS.len();
    let unique = units.len() == EXPECTED_RUNS.len()
        && units.iter().collect::<BTreeSet<_>>().len() == EXPECTED_RUNS.len()
        && groups.len() == EXPECTED_RUNS.len()
        && groups.iter().collect::<BTreeSet<_>>().len() == EXPECTED_RUNS.len();
    let scopes_pass = scopes.iter().all(|scope| match scope {
        Json::Object(fields) => matches!(fields.get("pass"), Some(Json::Bool(true))),
        _ => false,
    });
    let passed = runs_match && unique && scopes_pass;
    (
        passed,
        Json::object([
            ("pass", Json::Bool(passed)),
            (
                "expected",
                Json::object([
                    ("resourceMode", Json::string(request.resource_mode.clone())),
                    ("machineReportRequired", Json::Bool(machine_required)),
                    ("cpuQuotaPercent", Json::Int(request.cpu_quota_percent)),
                    ("memoryMaxBytes", Json::Int(request.memory_max_bytes)),
                    (
                        "memorySwapMaxBytes",
                        Json::Int(request.memory_swap_max_bytes),
                    ),
                    (
                        "runs",
                        Json::Array(EXPECTED_RUNS.iter().copied().map(Json::string).collect()),
                    ),
                ]),
            ),
            ("scopeCount", int_usize(scopes.len())),
            (
                "runCounts",
                Json::object(
                    run_counts
                        .iter()
                        .map(|(run, count)| ((*run).to_owned(), Json::Int(*count))),
                ),
            ),
            ("runsMatch", Json::Bool(runs_match)),
            ("scopesUnique", Json::Bool(unique)),
            ("scopes", Json::Array(scopes)),
        ]),
    )
}

fn first_startup<'a>(cells: &'a [Value], run: &str) -> Option<&'a Value> {
    cells.iter().find(|cell| {
        string(cell, "cell").as_deref() == Some("startup")
            && string(cell, "run").as_deref() == Some(run)
    })
}

fn startup_value<'a>(cells: &'a [Value], name: &str) -> Option<&'a Value> {
    first_startup(cells, "geo")
        .and_then(|startup| field(startup, name))
        .or_else(|| first_startup(cells, "nogeo").and_then(|startup| field(startup, name)))
}

fn startup_report(cells: &[Value], name: &str) -> Json {
    startup_value(cells, name).map_or(Json::Null, input_to_json)
}

fn idle_report(cells: &[Value], run: &str) -> Json {
    first_startup(cells, run)
        .and_then(|startup| field(startup, "idle"))
        .map_or_else(|| Json::object([] as [(&str, Json); 0]), input_to_json)
}

fn cell_swap_values(cells: &[Value]) -> Vec<Option<i64>> {
    cells
        .iter()
        .filter_map(|cell| match string(cell, "cell").as_deref() {
            Some("startup") => {
                Some(object(cell, "idle").and_then(|idle| integer(idle, "cgroupMemorySwapCurrent")))
            }
            Some("ladder" | "cgroup_final") => Some(integer(cell, "cgroupMemorySwapCurrent")),
            _ => None,
        })
        .collect()
}

fn mib(value: i64) -> f64 {
    value as f64 / 1024.0 / 1024.0
}

fn fmt_optional(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.0}"))
}

fn append_ladder_markdown(markdown: &mut String, title: &str, ladder: Option<&Ladder>) {
    let Some(ladder) = ladder else {
        return;
    };
    let _ = writeln!(
        markdown,
        "Idle-connection ladder ({}):\n",
        title.to_lowercase()
    );
    markdown.push_str(
        "| level | established | new fails | new pressure events | RSS MiB | cgroup MiB | fds | state |\n",
    );
    markdown.push_str("|---|---|---|---|---|---|---|---|\n");
    for level in &ladder.levels {
        let _ = writeln!(
            markdown,
            "| {} | {} | {} | {} | {:.1} | {:.1} | {} | {} |",
            level.level,
            level.established,
            level.new_failures,
            level.new_pressure,
            mib(level.rss),
            mib(level.memory_current),
            level.fds,
            level.pressure_state.as_deref().unwrap_or("")
        );
    }
    markdown.push('\n');
}

/// Summarizes one class directory without invoking Python or a shell.
///
/// # Errors
///
/// Returns a diagnostic for malformed input or an invalid request. A completed
/// but failing measurement is returned as `Outcome { passed: false, .. }` so the
/// aggregate report can retain every class's evidence.
pub fn summarize(request: &Request) -> Result<Outcome, String> {
    if !matches!(request.resource_mode.as_str(), "dedicated" | "standard") {
        return Err("resource mode must be dedicated or standard".to_owned());
    }
    if request.cpu_quota_percent <= 0
        || request.memory_max_bytes <= 0
        || request.memory_swap_max_bytes != 0
    {
        return Err("resource limits must be positive with swap exactly zero".to_owned());
    }
    let cells = read_cells(&request.class_dir.join("cells.jsonl"))?;
    let startup_nogeo = first_startup(&cells, "nogeo");
    let startup_geo = first_startup(&cells, "geo");
    let churn8 = summarize_churn(&cells, 8);
    let churn32 = summarize_churn(&cells, 32);
    let download1 = summarize_download(&cells, 1);
    let download32 = summarize_download(&cells, 32);
    let ladder = summarize_ladder(&cells, None);
    let tuned = summarize_ladder(&cells, Some("tuned"));
    let peaks = peaks_from_samples(&request.class_dir)?;
    let (boundaries_pass, boundaries) = resource_boundaries(&cells, request);

    let swap_values = cell_swap_values(&cells);
    let swap_known = !swap_values.is_empty() && swap_values.iter().all(Option::is_some);
    let swap_cell_max =
        swap_known.then(|| swap_values.iter().flatten().copied().max().unwrap_or(-1));
    let swap_pass =
        boundaries_pass && peaks.passed && peaks.swap_current_max == 0 && swap_cell_max == Some(0);
    let swap_json = Json::object([
        ("pass", Json::Bool(swap_pass)),
        ("cellStatusKnown", Json::Bool(swap_known)),
        ("cellSamples", int_usize(swap_values.len())),
        ("cellMaxBytes", json_optional_i64(swap_cell_max)),
        ("seriesRows", int_usize(peaks.rows)),
        ("seriesInvalidRows", int_usize(peaks.invalid_rows)),
        ("seriesMaxBytes", Json::Int(peaks.swap_current_max)),
        ("seriesByRun", series_json(&peaks)),
        (
            "seriesUnexpectedFiles",
            Json::Array(
                peaks
                    .unexpected_files
                    .iter()
                    .map(|path| Json::string(path.display().to_string()))
                    .collect(),
            ),
        ),
    ]);

    let finals: Vec<&Value> = cells
        .iter()
        .filter(|cell| string(cell, "cell").as_deref() == Some("cgroup_final"))
        .collect();
    let mut oom_values = vec![
        ladder.as_ref().and_then(|value| value.oom_kills),
        tuned.as_ref().and_then(|value| value.oom_kills),
    ];
    oom_values.extend(
        finals
            .iter()
            .map(|final_cell| integer(final_cell, "cgroupOomKills")),
    );
    let oom_known = !oom_values.is_empty()
        && oom_values
            .iter()
            .all(|value| value.is_some_and(|value| value >= 0));
    let oom_kills = oom_known.then(|| oom_values.iter().flatten().copied().max().unwrap_or(0));
    let churn_ok = churn8
        .as_ref()
        .zip(churn32.as_ref())
        .is_some_and(|(a, b)| a.failed_total == 0 && b.failed_total == 0);
    let download_ok = download1
        .as_ref()
        .zip(download32.as_ref())
        .is_some_and(|(a, b)| {
            a.errors.is_empty()
                && b.errors.is_empty()
                && a.size_mismatches == 0
                && b.size_mismatches == 0
        });
    let ladder_ok = |value: Option<&Ladder>| {
        value.is_some_and(|ladder| {
            ladder.completed
                && ladder.abort_reason.is_none()
                && ladder.max_clean_level > 0
                && ladder.establishment_evidence
        })
    };
    let passed = churn_ok
        && download_ok
        && oom_kills == Some(0)
        && ladder_ok(ladder.as_ref())
        && ladder_ok(tuned.as_ref())
        && boundaries_pass
        && swap_pass;

    let ladder_fd_max = ladder
        .iter()
        .chain(tuned.iter())
        .flat_map(|ladder| ladder.levels.iter().map(|level| level.fds))
        .max()
        .unwrap_or(0);
    let cgroup_memory_peak = cells
        .iter()
        .filter(|cell| {
            matches!(
                string(cell, "cell").as_deref(),
                Some("ladder" | "cgroup_final")
            )
        })
        .filter_map(|cell| integer(cell, "cgroupMemoryPeak"))
        .max();
    let idle = idle_report(&cells, "nogeo");
    let assets = idle_report(&cells, "geo");
    let summary = Json::object([
        ("class", Json::string(request.class.clone())),
        ("resourceMode", Json::string(request.resource_mode.clone())),
        (
            "cgroupLimits",
            Json::object([
                ("cpuQuotaPercent", Json::Int(request.cpu_quota_percent)),
                ("memoryMax", Json::string(request.memory_max.clone())),
                ("memoryMaxBytes", Json::Int(request.memory_max_bytes)),
                (
                    "memorySwapMaxBytes",
                    Json::Int(request.memory_swap_max_bytes),
                ),
            ]),
        ),
        ("resourceBoundaryEvidence", boundaries),
        ("swapEvidence", swap_json),
        ("pass", Json::Bool(passed)),
        (
            "derivedBudgets",
            Json::object([
                ("machineReport", startup_report(&cells, "machineReport")),
                (
                    "descriptorBudgetReport",
                    startup_report(&cells, "descriptorBudgetReport"),
                ),
                (
                    "relayBackendReport",
                    startup_report(&cells, "relayBackendReport"),
                ),
            ]),
        ),
        ("idle", idle.clone()),
        ("assets", assets.clone()),
        (
            "churn",
            Json::object([
                ("c8", churn_json(churn8.as_ref())),
                ("c32", churn_json(churn32.as_ref())),
            ]),
        ),
        (
            "download512MiB",
            Json::object([
                ("c1", download_json(download1.as_ref())),
                ("c32", download_json(download32.as_ref())),
            ]),
        ),
        ("ladder", ladder_json(ladder.as_ref())),
        ("ladderTuned", ladder_json(tuned.as_ref())),
        (
            "peaks",
            Json::object([
                ("cgroupMemoryPeak", json_optional_i64(cgroup_memory_peak)),
                (
                    "cgroupMemoryCurrentMax",
                    Json::Int(peaks.memory_current_max),
                ),
                (
                    "cgroupMemorySwapCurrentMax",
                    Json::Int(peaks.swap_current_max),
                ),
                ("serverRssMax", Json::Int(peaks.rss_max)),
                ("serverFdMax", Json::Int(peaks.fd_max.max(ladder_fd_max))),
                ("cgroupOomKills", json_optional_i64(oom_kills)),
                ("cgroupOomStatusKnown", Json::Bool(oom_known)),
            ]),
        ),
    ]);

    let idle_value = startup_nogeo.and_then(|cell| object(cell, "idle"));
    let asset_value = startup_geo.and_then(|cell| object(cell, "idle"));
    let mut markdown = format!(
        "# {} (resourceMode={}, CPUQuota={}%, MemoryMax={}, MemorySwapMax={})\n\n",
        request.class,
        request.resource_mode,
        request.cpu_quota_percent,
        request.memory_max,
        request.memory_swap_max_bytes
    );
    let machine = startup_value(&cells, "machineReport");
    let descriptor = startup_value(&cells, "descriptorBudgetReport");
    let relays = startup_value(&cells, "relayBackendReport")
        .and_then(|report| field(report, "backends"))
        .and_then(|backends| backends.as_array("relayBackendReport.backends").ok());
    let relay_available = |name: &str| {
        relays.and_then(|backends| {
            backends.iter().find_map(|backend| {
                (string(backend, "backend").as_deref() == Some(name))
                    .then(|| boolean(backend, "available"))
                    .flatten()
            })
        })
    };
    markdown.push_str("Derived budgets (machine_report / descriptor_budget_report):\n\n");
    let _ = writeln!(
        markdown,
        "- cpus visible: {}, cpu.max quota: {}/{} us",
        machine
            .and_then(|value| integer(value, "available_cpus"))
            .unwrap_or(0),
        machine
            .and_then(|value| integer(value, "cpu_quota_us"))
            .unwrap_or(0),
        machine
            .and_then(|value| integer(value, "cpu_period_us"))
            .unwrap_or(0)
    );
    let _ = writeln!(
        markdown,
        "- memory: source={} max={:.1} MiB total={:.1} MiB",
        machine
            .and_then(|value| string(value, "memory_source"))
            .unwrap_or_default(),
        mib(machine
            .and_then(|value| integer(value, "memory_max"))
            .unwrap_or(0)),
        mib(machine
            .and_then(|value| integer(value, "memory_total"))
            .unwrap_or(0))
    );
    let _ = writeln!(
        markdown,
        "- fd: soft {} -> effective {} (raised: {})",
        machine
            .and_then(|value| integer(value, "fd_soft_limit"))
            .unwrap_or(0),
        machine
            .and_then(|value| integer(value, "fd_effective_soft_limit"))
            .unwrap_or(0),
        machine
            .and_then(|value| boolean(value, "fd_soft_limit_raised"))
            .unwrap_or(false)
    );
    let _ = writeln!(
        markdown,
        "- fd budget: reserve {} + headroom {} -> effective {} (clamped: {})",
        descriptor
            .and_then(|value| integer(value, "fd_fixed_reserve"))
            .unwrap_or(0),
        descriptor
            .and_then(|value| integer(value, "fd_safety_headroom"))
            .unwrap_or(0),
        descriptor
            .and_then(|value| integer(value, "fd_effective_budget"))
            .unwrap_or(0),
        descriptor
            .and_then(|value| boolean(value, "fd_clamped"))
            .unwrap_or(false)
    );
    let _ = writeln!(
        markdown,
        "- relay backends: buffered={}, splice={}\n",
        if relay_available("buffered") == Some(true) {
            "ok"
        } else {
            "unavailable"
        },
        if relay_available("splice") == Some(true) {
            "ok"
        } else {
            "unavailable"
        }
    );
    markdown.push_str("| metric | value |\n|---|---|\n");
    let _ = writeln!(
        markdown,
        "| idle RSS (no assets) | {:.1} MiB (cgroup {:.1} MiB, {} fds) |",
        mib(idle_value
            .and_then(|value| integer(value, "serverRssBytes"))
            .unwrap_or(0)),
        mib(idle_value
            .and_then(|value| integer(value, "cgroupMemoryCurrent"))
            .unwrap_or(0)),
        idle_value
            .and_then(|value| integer(value, "serverFdCount"))
            .unwrap_or(0)
    );
    let _ = writeln!(
        markdown,
        "| assets RSS (geo loaded) | {:.1} MiB (cgroup {:.1} MiB, {} fds) |",
        mib(asset_value
            .and_then(|value| integer(value, "serverRssBytes"))
            .unwrap_or(0)),
        mib(asset_value
            .and_then(|value| integer(value, "cgroupMemoryCurrent"))
            .unwrap_or(0)),
        asset_value
            .and_then(|value| integer(value, "serverFdCount"))
            .unwrap_or(0)
    );
    if let Some(churn) = &churn8 {
        let _ = writeln!(
            markdown,
            "| setup churn c8 | {} conn/s, p99 {:.0} ms, failed {} |",
            fmt_optional(churn.rate_median),
            churn.p99_ms_worst,
            churn.failed_total
        );
    }
    if let Some(churn) = &churn32 {
        let _ = writeln!(
            markdown,
            "| setup churn c32 | {} conn/s, p99 {:.0} ms, failed {} |",
            fmt_optional(churn.rate_median),
            churn.p99_ms_worst,
            churn.failed_total
        );
    }
    if let Some(download) = &download1 {
        let _ = writeln!(
            markdown,
            "| 512 MiB download c1 | {} MiB/s |",
            fmt_optional(download.throughput_median)
        );
    }
    if let Some(download) = &download32 {
        let _ = writeln!(
            markdown,
            "| 512 MiB download c32 | {} MiB/s |",
            fmt_optional(download.throughput_median)
        );
    }
    if let Some(ladder) = &ladder {
        let _ = writeln!(
            markdown,
            "| max clean idle-connection level (default policy) | {} |",
            ladder.max_clean_level
        );
        let _ = writeln!(
            markdown,
            "| first pressure level (default policy) | {} |",
            ladder
                .first_pressure_level
                .map_or_else(|| "None".to_owned(), |level| level.to_string())
        );
        let _ = writeln!(
            markdown,
            "| max established sessions (default policy) | {} |",
            ladder.max_established
        );
    }
    if let Some(tuned) = &tuned {
        let _ = writeln!(
            markdown,
            "| max clean idle-connection level (tuned policy) | {} |",
            tuned.max_clean_level
        );
        let _ = writeln!(
            markdown,
            "| first pressure level (tuned policy) | {} |",
            tuned
                .first_pressure_level
                .map_or_else(|| "None".to_owned(), |level| level.to_string())
        );
        let _ = writeln!(
            markdown,
            "| max established sessions (tuned policy) | {} |",
            tuned.max_established
        );
        let _ = writeln!(
            markdown,
            "| tuned ladder completed | {} ({}) |",
            tuned.completed,
            tuned.abort_reason.as_deref().unwrap_or("no abort")
        );
    }
    let _ = writeln!(markdown, "| oom_kills | {} |", oom_kills.unwrap_or(-1));
    let _ = writeln!(
        markdown,
        "| cgroup resource-boundary evidence | {boundaries_pass} ({} scopes) |",
        EXPECTED_RUNS.len()
    );
    let _ = writeln!(
        markdown,
        "| swap.current evidence | {swap_pass} (cells max {:.1} MiB, series max {:.1} MiB) |",
        mib(swap_cell_max.unwrap_or(0)),
        mib(peaks.swap_current_max)
    );
    let _ = writeln!(
        markdown,
        "| peak cgroup memory.current | {:.1} MiB |",
        mib(peaks.memory_current_max)
    );
    let _ = writeln!(
        markdown,
        "| peak cgroup memory.peak | {:.1} MiB |",
        mib(cgroup_memory_peak.unwrap_or(0))
    );
    let _ = writeln!(
        markdown,
        "| peak server RSS | {:.1} MiB |",
        mib(peaks.rss_max)
    );
    let _ = writeln!(
        markdown,
        "| peak server FDs | {} |",
        peaks.fd_max.max(ladder_fd_max)
    );
    let _ = writeln!(markdown, "| **pass** | {passed} |\n");
    append_ladder_markdown(&mut markdown, "Default policy", ladder.as_ref());
    append_ladder_markdown(&mut markdown, "Tuned policy", tuned.as_ref());
    Ok(Outcome {
        passed,
        json: summary,
        markdown,
    })
}

/// Writes one class summary without overwriting existing authority.
///
/// # Errors
///
/// Returns a diagnostic when either output already exists or cannot be written.
pub fn write_summary(request: &Request, outcome: &Outcome) -> Result<(), String> {
    write_new(
        &request.class_dir.join("summary.json"),
        &outcome.json.to_python_json(),
    )?;
    write_new(&request.class_dir.join("summary.md"), &outcome.markdown)
}

fn write_new(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

/// Builds the aggregate gate JSON from completed class summaries.
#[must_use]
pub fn aggregate(class_rows: &[(PathBuf, Outcome)]) -> (bool, Json) {
    let passed = !class_rows.is_empty() && class_rows.iter().all(|(_, outcome)| outcome.passed);
    let rows = class_rows
        .iter()
        .map(|(path, outcome)| {
            let class = match &outcome.json {
                Json::Object(fields) => match fields.get("class") {
                    Some(Json::Str(class)) => class.clone(),
                    _ => String::new(),
                },
                _ => String::new(),
            };
            Json::object([
                ("path", Json::string(path.display().to_string())),
                ("class", Json::string(class)),
                (
                    "summarizerExitStatus",
                    Json::Int(i64::from(!outcome.passed)),
                ),
                ("pass", Json::Bool(outcome.passed)),
            ])
        })
        .collect();
    (
        passed,
        Json::object([("pass", Json::Bool(passed)), ("classes", Json::Array(rows))]),
    )
}

/// Renders the cross-class human summary from in-memory class summaries.
#[must_use]
pub fn cross_class_markdown(
    class_rows: &[(PathBuf, Outcome)],
    environment: Option<&Value>,
) -> String {
    let mut out = String::from("# rust-reality machine-profile validation\n\n");
    if let Some(environment) = environment {
        let _ = writeln!(
            out,
            "- commit: `{}`",
            string(environment, "commit").unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "- binary: `{}` sha256 `{}`",
            string(environment, "binary").unwrap_or_default(),
            string(environment, "binarySha256").unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "- host: {}, kernel {}, client {}",
            string(environment, "host").unwrap_or_default(),
            string(environment, "kernel").unwrap_or_default(),
            string(environment, "xray").unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "- measured: {} — {}\n",
            string(environment, "dateUtc").unwrap_or_default(),
            string(environment, "note").unwrap_or_default()
        );
    }
    out.push_str(
        "| class | mode | pass | idle RSS MiB | assets RSS MiB | churn c8 conn/s (p99 ms) | churn c32 conn/s (p99 ms) | 512MiB c1 MiB/s | 512MiB c32 MiB/s | clean lvl (default) | clean lvl (tuned) | first pressure (tuned) | oom | peak cgroup MiB | peak FDs |\n",
    );
    out.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for (_, outcome) in class_rows {
        let rendered = outcome.json.to_python_json();
        let Ok(value) = json_in::parse(&rendered) else {
            continue;
        };
        let idle = object(&value, "idle");
        let assets = object(&value, "assets");
        let churn = object(&value, "churn");
        let churn8 = churn.and_then(|value| object(value, "c8"));
        let churn32 = churn.and_then(|value| object(value, "c32"));
        let download_summaries = object(&value, "download512MiB");
        let download_c1 = download_summaries.and_then(|value| object(value, "c1"));
        let download_c32 = download_summaries.and_then(|value| object(value, "c32"));
        let ladder = object(&value, "ladder");
        let tuned = object(&value, "ladderTuned");
        let peaks = object(&value, "peaks");
        let _ = writeln!(
            out,
            "| {} | {} | {} | {:.1} | {:.1} | {} ({}) | {} ({}) | {} | {} | {} | {} | {} | {} | {:.1} | {} |",
            string(&value, "class").unwrap_or_default(),
            string(&value, "resourceMode").unwrap_or_default(),
            boolean(&value, "pass").unwrap_or(false),
            mib(idle
                .and_then(|value| integer(value, "serverRssBytes"))
                .unwrap_or(0)),
            mib(assets
                .and_then(|value| integer(value, "serverRssBytes"))
                .unwrap_or(0)),
            fmt_optional(churn8.and_then(|value| number(value, "connectionsPerSecondMedian"))),
            fmt_optional(churn8.and_then(|value| number(value, "p99MsWorst"))),
            fmt_optional(churn32.and_then(|value| number(value, "connectionsPerSecondMedian"))),
            fmt_optional(churn32.and_then(|value| number(value, "p99MsWorst"))),
            fmt_optional(
                download_c1.and_then(|value| number(value, "throughputMiBPerSecondMedian"))
            ),
            fmt_optional(
                download_c32.and_then(|value| number(value, "throughputMiBPerSecondMedian"))
            ),
            ladder
                .and_then(|value| integer(value, "maxCleanLevel"))
                .unwrap_or(0),
            tuned
                .and_then(|value| integer(value, "maxCleanLevel"))
                .unwrap_or(0),
            tuned
                .and_then(|value| integer(value, "firstPressureLevel"))
                .map_or_else(|| "None".to_owned(), |value| value.to_string()),
            peaks
                .and_then(|value| integer(value, "cgroupOomKills"))
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            mib(peaks
                .and_then(|value| integer(value, "cgroupMemoryPeak"))
                .unwrap_or(0)),
            peaks
                .and_then(|value| integer(value, "serverFdMax"))
                .unwrap_or(0)
        );
    }
    out.push_str("\n## Derived budgets per class\n\n");
    out.push_str(
        "| class | cpus seen | cpu.max us | memory total MiB | fd soft -> effective | fd budget | fd clamped |\n",
    );
    out.push_str("|---|---|---|---|---|---|---|\n");
    for (_, outcome) in class_rows {
        let rendered = outcome.json.to_python_json();
        let Ok(value) = json_in::parse(&rendered) else {
            continue;
        };
        let budgets = object(&value, "derivedBudgets");
        let machine = budgets.and_then(|value| object(value, "machineReport"));
        let descriptor = budgets.and_then(|value| object(value, "descriptorBudgetReport"));
        let _ = writeln!(
            out,
            "| {} | {} | {}/{} | {:.1} | {} -> {} | {} | {} |",
            string(&value, "class").unwrap_or_default(),
            machine
                .and_then(|value| integer(value, "available_cpus"))
                .unwrap_or(0),
            machine
                .and_then(|value| integer(value, "cpu_quota_us"))
                .unwrap_or(0),
            machine
                .and_then(|value| integer(value, "cpu_period_us"))
                .unwrap_or(0),
            mib(machine
                .and_then(|value| integer(value, "memory_total"))
                .unwrap_or(0)),
            machine
                .and_then(|value| integer(value, "fd_soft_limit"))
                .unwrap_or(0),
            machine
                .and_then(|value| integer(value, "fd_effective_soft_limit"))
                .unwrap_or(0),
            descriptor
                .and_then(|value| integer(value, "fd_effective_budget"))
                .unwrap_or(0),
            descriptor
                .and_then(|value| boolean(value, "fd_clamped"))
                .unwrap_or(false)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_matches_python_statistics_for_even_and_odd_sets() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![3.0]), Some(3.0));
        assert_eq!(median(vec![4.0, 2.0]), Some(3.0));
        assert_eq!(median(vec![9.0, 1.0, 5.0]), Some(5.0));
    }

    #[test]
    fn unknown_oom_status_can_never_be_clean() {
        let row = json_in::parse(
            r#"{"cell":"ladder","tag":null,"level":100,"connectionsHeld":100,
            "serverEstablishedSessions":100,"establishmentEvidence":"successful-socks-connect",
            "connectionsFailedTotal":0,"serverAlive":true,"serverRssBytes":1,
            "serverFdCount":2,"cgroupMemoryCurrent":3,"cgroupOomKills":null,
            "logEvents":{},"latestPressureState":null,"ladderComplete":true,
            "abortReason":null}"#,
        )
        .unwrap();
        let ladder = summarize_ladder(&[row], None).unwrap();
        assert!(!ladder.oom_known);
        assert_eq!(ladder.oom_kills, None);
        assert_eq!(ladder.max_clean_level, 0);
    }

    #[test]
    fn pressure_deltas_are_counted_once_across_rechecks() {
        let rows = json_in::parse_lines(
            r#"{"cell":"ladder","tag":"tuned","level":10,"connectionsHeld":10,"serverEstablishedSessions":10,"establishmentEvidence":"successful-socks-connect","connectionsFailedTotal":0,"serverAlive":true,"serverRssBytes":1,"serverFdCount":2,"cgroupMemoryCurrent":3,"cgroupOomKills":0,"logEvents":{"resource_pressure_changed":1},"latestPressureState":"high"}
{"cell":"ladder","tag":"tuned","level":10,"connectionsHeld":10,"serverEstablishedSessions":10,"establishmentEvidence":"successful-socks-connect","connectionsFailedTotal":0,"serverAlive":true,"serverRssBytes":1,"serverFdCount":2,"cgroupMemoryCurrent":3,"cgroupOomKills":0,"logEvents":{"resource_pressure_changed":1},"latestPressureState":"high","ladderComplete":true,"abortReason":null}
"#,
        )
        .unwrap();
        let ladder = summarize_ladder(&rows, Some("tuned")).unwrap();
        assert_eq!(ladder.levels[0].new_pressure, 1);
        assert_eq!(ladder.first_pressure_level, Some(10));
    }

    #[test]
    fn absolute_log_counters_are_normalized_to_the_ladder_baseline() {
        let rows = json_in::parse_lines(
            r#"{"cell":"ladder","tag":null,"level":100,"connectionsHeld":100,"serverEstablishedSessions":100,"establishmentEvidence":"successful-socks-connect","connectionsFailedTotal":0,"serverAlive":true,"serverRssBytes":1,"serverFdCount":2,"cgroupMemoryCurrent":3,"cgroupOomKills":0,"logEventBaseline":{"connection_rejected":3},"logEvents":{"connection_rejected":3},"latestPressureState":null,"ladderComplete":true,"abortReason":null}
"#,
        )
        .unwrap();
        let ladder = summarize_ladder(&rows, None).unwrap();
        assert_eq!(ladder.levels[0].new_pressure, 0);
        assert_eq!(ladder.max_clean_level, 100);
        assert_eq!(ladder.first_pressure_level, None);
    }
}
