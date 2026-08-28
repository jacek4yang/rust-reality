//! CPU attribution for a measured server process — `perf stat` capture and its
//! fail-closed validator.
//!
//! Every formal A/B harness charges the server's CPU to the work it did, and every
//! one of them refused to accept a `perf stat` run it could not fully trust. The
//! validator here is a direct port of the `validate_perf_csv` shell function that
//! `benchmark-fallback-ab.sh` and `benchmark-setup-rate.sh` each embedded verbatim:
//! an event that was not counted, counted twice, multiplexed below 95% of the
//! window, reported with a non-positive enabled time, or missing entirely is an
//! error rather than a number that quietly understates CPU.
//!
//! `benchmark-setup-rate-xray.sh` used a weaker one-event extraction —
//! `awk -F, '$3 == "task-clock" {print $1}'` guarded by a plain-decimal regex — so
//! that contract is kept separate in [`task_clock_only`] rather than silently
//! strengthened. Strengthening it would change what that harness accepts, and this
//! migration is not the place to alter a measurement contract.
//!
//! ## Evidence compatibility
//!
//! [`PerfRecord::to_json`] reproduces `perf.json` exactly: `schemaVersion` 1, an
//! `events` object keyed by event name with `value` / `unit` /
//! `enabledNanoseconds` / `runningPercent`, and the hoisted
//! `taskClockMilliseconds`. The original wrote it with `sort_keys=True`, which is
//! what [`Json`] already does.
//!
//! ## Parsing
//!
//! `perf stat --no-big-num -x,` emits unquoted comma-separated fields — no
//! thousands separators, no embedded commas, no quoting — so fields are split on
//! `,` directly. Rows with fewer than five fields are skipped, which is how the
//! original's `csv.reader` loop stepped over `perf`'s `# started on …` header.

use std::collections::BTreeMap;
use std::path::Path;

use crate::perf::json_out::Json;

/// The three events the formal harnesses require of every measured slot.
pub const REQUIRED_EVENTS: [&str; 3] = ["task-clock", "instructions", "context-switches"];

/// The single event the Xray setup-rate comparator collects.
pub const TASK_CLOCK_ONLY: [&str; 1] = ["task-clock"];

/// The units `perf` may report task-clock in.
const TASK_CLOCK_UNITS: [&str; 2] = ["msec", "ms"];

/// The narrowest multiplexing fraction an accepted event may have been counted for.
const MIN_RUNNING_PERCENT: f64 = 95.0;

/// The widest running percentage `perf` may report, allowing for its rounding.
const MAX_RUNNING_PERCENT: f64 = 100.01;

/// One validated `perf stat` event.
#[derive(Debug, Clone, PartialEq)]
pub struct PerfEvent {
    /// The counter value.
    pub value: f64,
    /// The unit `perf` reported, empty for dimensionless counters.
    pub unit: String,
    /// Nanoseconds the counter was enabled for.
    pub enabled_nanoseconds: f64,
    /// Percentage of the window the counter actually ran for.
    pub running_percent: f64,
}

impl PerfEvent {
    fn to_json(&self) -> Json {
        Json::object([
            ("value", Json::Float(self.value)),
            ("unit", Json::string(self.unit.clone())),
            (
                "enabledNanoseconds",
                Json::Float(self.enabled_nanoseconds),
            ),
            ("runningPercent", Json::Float(self.running_percent)),
        ])
    }
}

/// A validated `perf stat` capture for one measurement slot.
#[derive(Debug, Clone, PartialEq)]
pub struct PerfRecord {
    /// The accepted events, keyed by `perf` event name.
    pub events: BTreeMap<String, PerfEvent>,
    /// The task-clock value, hoisted as the aggregators read it.
    pub task_clock_milliseconds: f64,
}

impl PerfRecord {
    /// Renders the legacy `perf.json` document.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            (
                "events",
                Json::object(
                    self.events
                        .iter()
                        .map(|(name, event)| (name.clone(), event.to_json())),
                ),
            ),
            (
                "taskClockMilliseconds",
                Json::Float(self.task_clock_milliseconds),
            ),
        ])
    }
}

/// Validates a `perf stat -x,` capture, requiring every event in `required`.
///
/// Fails closed on anything that would make the number untrustworthy: an event
/// `perf` did not count, a duplicate row for one event, a value that is negative
/// or non-finite, a non-positive enabled window, multiplexing below
/// [`MIN_RUNNING_PERCENT`], a task-clock reported in an unexpected unit, or a
/// required event that never appeared.
///
/// # Errors
///
/// Returns the first violation, phrased as the original did.
pub fn parse_csv(text: &str, required: &[&str]) -> Result<PerfRecord, String> {
    let mut events: BTreeMap<String, PerfEvent> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(',').collect();
        // `perf`'s header lines have fewer than five fields; the original's
        // csv.reader loop skipped them the same way.
        if fields.len() < 5 {
            continue;
        }
        let event = fields[2].trim();
        if !required.contains(&event) {
            continue;
        }
        if events.contains_key(event) {
            return Err(format!("duplicate perf event: {event}"));
        }
        let raw_value = fields[0].trim();
        if raw_value.starts_with('<') {
            return Err(format!("perf event was not counted: {event}: {raw_value}"));
        }
        let running_raw = fields[4].trim().trim_end_matches('%');
        let (Ok(value), Ok(enabled_nanoseconds), Ok(running_percent)) = (
            raw_value.parse::<f64>(),
            fields[3].trim().parse::<f64>(),
            running_raw.parse::<f64>(),
        ) else {
            return Err(format!("malformed perf event {event}: {line}"));
        };
        if !(value.is_finite() && enabled_nanoseconds.is_finite() && running_percent.is_finite()) {
            return Err(format!("non-finite perf event: {event}"));
        }
        if value < 0.0
            || enabled_nanoseconds <= 0.0
            || !(MIN_RUNNING_PERCENT..=MAX_RUNNING_PERCENT).contains(&running_percent)
        {
            return Err(format!(
                "invalid perf event {event}: value={value}, enabled={enabled_nanoseconds}, \
                 running={running_percent}%"
            ));
        }
        let unit = fields[1].trim();
        if event == "task-clock" && !TASK_CLOCK_UNITS.contains(&unit) {
            return Err(format!("unexpected task-clock unit: {unit:?}"));
        }
        events.insert(
            event.to_owned(),
            PerfEvent {
                value,
                unit: unit.to_owned(),
                enabled_nanoseconds,
                running_percent,
            },
        );
    }

    let mut missing: Vec<&str> = required
        .iter()
        .filter(|event| !events.contains_key(**event))
        .copied()
        .collect();
    if !missing.is_empty() {
        missing.sort_unstable();
        return Err(format!("missing perf events: {}", missing.join(", ")));
    }
    let task_clock_milliseconds = events
        .get("task-clock")
        .map_or(0.0, |event| event.value);
    Ok(PerfRecord {
        events,
        task_clock_milliseconds,
    })
}

/// Extracts task-clock alone, reproducing the Xray comparator's weaker contract.
///
/// `benchmark-setup-rate-xray.sh` ran `awk -F, '$3 == "task-clock" {print $1}'` and
/// required the result to match `^[0-9]+(\.[0-9]+)?$`. That rejects `<not counted>`
/// and exponential notation, and — because the awk output would then span two
/// lines and fail the anchored match — it also rejects a duplicated event. It does
/// *not* check multiplexing. Kept exactly as it was.
///
/// # Errors
///
/// Returns a message when no single plain-decimal task-clock value is present.
pub fn task_clock_only(text: &str) -> Result<f64, String> {
    let matches: Vec<&str> = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').collect();
            (fields.len() >= 3 && fields[2] == "task-clock").then(|| fields[0])
        })
        .collect();
    let [raw] = matches.as_slice() else {
        return Err(format!(
            "perf stat produced {} task-clock rows, expected exactly one",
            matches.len()
        ));
    };
    if !is_plain_decimal(raw) {
        return Err(format!("perf stat produced no task-clock value: {raw:?}"));
    }
    raw.parse::<f64>()
        .map_err(|error| format!("task-clock is not a number: {error}"))
}

/// Whether `text` matches the harness's `^[0-9]+(\.[0-9]+)?$`.
fn is_plain_decimal(text: &str) -> bool {
    let (integer, fraction) = text.split_once('.').map_or((text, None), |(whole, rest)| {
        (whole, Some(rest))
    });
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    digits(integer) && fraction.is_none_or(digits)
}

/// Builds the `perf stat` command the harnesses ran, as `(program, args)`.
///
/// Reproduces
/// `sudo -n perf stat --no-big-num -x, -e <events> -p <pid> -o <csv> -- <workload>`:
/// `--no-big-num` keeps values machine-parseable, `-x,` selects the CSV form,
/// `-p` attaches to the already-running server, and the workload after `--` bounds
/// the measurement window. `sudo -n` never prompts, so a host without passwordless
/// sudo fails immediately instead of blocking a benchmark.
#[must_use]
pub fn stat_command(
    pid: u32,
    events: &[&str],
    csv: &Path,
    workload: &[String],
) -> (String, Vec<String>) {
    let mut args = vec![
        "-n".to_owned(),
        "perf".to_owned(),
        "stat".to_owned(),
        "--no-big-num".to_owned(),
        "-x,".to_owned(),
        "-e".to_owned(),
        events.join(","),
        "-p".to_owned(),
        pid.to_string(),
        "-o".to_owned(),
        csv.display().to_string(),
        "--".to_owned(),
    ];
    args.extend_from_slice(workload);
    ("sudo".to_owned(), args)
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "these are golden-parity tests: the values are exact decimal literals \
              from the scripts' own SELF_TEST capture, so an epsilon would defeat them"
)]
mod tests {
    use super::*;

    /// The valid capture from the scripts' own `SELF_TEST` block.
    const VALID: &str = "12.500,msec,task-clock,100000000,100.00,,\n\
                         12345,,instructions,100000000,100.00,,\n\
                         10,,context-switches,100000000,100.00,,\n";

    #[test]
    fn the_script_self_test_capture_is_accepted() {
        let record = parse_csv(VALID, &REQUIRED_EVENTS).expect("the self-test capture is valid");
        assert_eq!(record.task_clock_milliseconds, 12.5);
        let names: Vec<&str> = record.events.keys().map(String::as_str).collect();
        assert_eq!(names, ["context-switches", "instructions", "task-clock"]);
        assert_eq!(record.events["task-clock"].unit, "msec");
        assert_eq!(record.events["instructions"].value, 12_345.0);
        assert_eq!(record.events["context-switches"].enabled_nanoseconds, 1e8);
    }

    /// The `SELF_TEST` negative case: multiplexed below 95% must not pass.
    #[test]
    fn a_capture_multiplexed_below_ninety_five_percent_is_rejected() {
        let low = VALID.replace("12.500,msec,task-clock,100000000,100.00", "12.500,msec,task-clock,100000000,94.99");
        let error = parse_csv(&low, &REQUIRED_EVENTS).unwrap_err();
        assert!(error.contains("invalid perf event task-clock"), "{error}");
        // 95.00 exactly is the boundary and is accepted; 100.01 is the upper bound.
        let boundary = VALID.replace("task-clock,100000000,100.00", "task-clock,100000000,95.00");
        assert!(parse_csv(&boundary, &REQUIRED_EVENTS).is_ok());
        let above = VALID.replace("task-clock,100000000,100.00", "task-clock,100000000,100.02");
        assert!(parse_csv(&above, &REQUIRED_EVENTS).is_err());
    }

    #[test]
    fn an_uncounted_event_is_rejected_rather_than_read_as_zero() {
        let uncounted = VALID.replace("12345,,instructions", "<not counted>,,instructions");
        let error = parse_csv(&uncounted, &REQUIRED_EVENTS).unwrap_err();
        assert!(error.contains("was not counted"), "{error}");
    }

    #[test]
    fn a_duplicate_event_row_is_rejected() {
        let duplicated = format!("{VALID}11,,context-switches,100000000,100.00,,\n");
        let error = parse_csv(&duplicated, &REQUIRED_EVENTS).unwrap_err();
        assert_eq!(error, "duplicate perf event: context-switches");
    }

    #[test]
    fn a_missing_event_is_named() {
        let partial = "12.500,msec,task-clock,100000000,100.00,,\n";
        let error = parse_csv(partial, &REQUIRED_EVENTS).unwrap_err();
        assert_eq!(error, "missing perf events: context-switches, instructions");
    }

    #[test]
    fn a_task_clock_in_an_unexpected_unit_is_rejected() {
        let seconds = VALID.replace("12.500,msec,task-clock", "12.500,sec,task-clock");
        let error = parse_csv(&seconds, &REQUIRED_EVENTS).unwrap_err();
        assert!(error.contains("unexpected task-clock unit"), "{error}");
        // `ms` is the other accepted spelling.
        let ms = VALID.replace("12.500,msec,task-clock", "12.500,ms,task-clock");
        assert!(parse_csv(&ms, &REQUIRED_EVENTS).is_ok());
    }

    #[test]
    fn malformed_and_non_finite_rows_are_rejected() {
        let malformed = VALID.replace("12345,,instructions", "not-a-number,,instructions");
        assert!(
            parse_csv(&malformed, &REQUIRED_EVENTS)
                .unwrap_err()
                .contains("malformed perf event instructions")
        );
        let infinite = VALID.replace("12345,,instructions", "inf,,instructions");
        assert!(
            parse_csv(&infinite, &REQUIRED_EVENTS)
                .unwrap_err()
                .contains("non-finite perf event")
        );
        let no_window = VALID.replace("instructions,100000000,100.00", "instructions,0,100.00");
        assert!(
            parse_csv(&no_window, &REQUIRED_EVENTS)
                .unwrap_err()
                .contains("invalid perf event instructions")
        );
    }

    /// `perf -o` writes a header before the CSV; the original stepped over it by
    /// ignoring short rows, and so does this.
    #[test]
    fn the_perf_output_header_is_skipped() {
        let with_header = format!("# started on Thu Aug 28 12:00:00 2026\n\n{VALID}");
        assert!(parse_csv(&with_header, &REQUIRED_EVENTS).is_ok());
    }

    /// Events outside the required set are ignored, not rejected.
    #[test]
    fn an_unrequested_event_is_ignored() {
        let extra = format!("{VALID}99,,page-faults,100000000,100.00,,\n");
        let record = parse_csv(&extra, &REQUIRED_EVENTS).expect("extra events are ignored");
        assert!(!record.events.contains_key("page-faults"));
    }

    #[test]
    fn the_perf_json_document_matches_the_legacy_shape() {
        let record = parse_csv(VALID, &REQUIRED_EVENTS).unwrap();
        let rendered = record.to_json().to_python_json();
        assert_eq!(
            rendered,
            "{\n  \"events\": {\n    \"context-switches\": {\n      \"enabledNanoseconds\": \
             100000000.0,\n      \"runningPercent\": 100.0,\n      \"unit\": \"\",\n      \
             \"value\": 10.0\n    },\n    \"instructions\": {\n      \"enabledNanoseconds\": \
             100000000.0,\n      \"runningPercent\": 100.0,\n      \"unit\": \"\",\n      \
             \"value\": 12345.0\n    },\n    \"task-clock\": {\n      \"enabledNanoseconds\": \
             100000000.0,\n      \"runningPercent\": 100.0,\n      \"unit\": \"msec\",\n      \
             \"value\": 12.5\n    }\n  },\n  \"schemaVersion\": 1,\n  \
             \"taskClockMilliseconds\": 12.5\n}\n"
        );
    }

    #[test]
    fn the_xray_comparator_extraction_keeps_its_weaker_contract() {
        assert_eq!(task_clock_only(VALID).unwrap(), 12.5);
        // Plain integers are accepted.
        assert_eq!(
            task_clock_only("42,msec,task-clock,100000000,100.00,,\n").unwrap(),
            42.0
        );
        // Its regex rejects `<not counted>` and exponential notation.
        assert!(task_clock_only("<not counted>,msec,task-clock,1,100.00,,\n").is_err());
        assert!(task_clock_only("1e5,msec,task-clock,1,100.00,,\n").is_err());
        assert!(task_clock_only("-3.0,msec,task-clock,1,100.00,,\n").is_err());
        // No row at all, and two rows, both fail the anchored shell match.
        assert!(task_clock_only("12345,,instructions,1,100.00,,\n").is_err());
        assert!(task_clock_only(&format!("{VALID}13.0,msec,task-clock,1,100.00,,\n")).is_err());
        // It deliberately does *not* police multiplexing, unlike parse_csv.
        assert_eq!(
            task_clock_only("12.5,msec,task-clock,100000000,10.00,,\n").unwrap(),
            12.5
        );
    }

    #[test]
    fn the_perf_command_matches_the_legacy_invocation() {
        let (program, args) = stat_command(
            4242,
            &REQUIRED_EVENTS,
            Path::new("/out/slot/perf.csv"),
            &["driver".to_owned(), "--samples".to_owned(), "3".to_owned()],
        );
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            [
                "-n",
                "perf",
                "stat",
                "--no-big-num",
                "-x,",
                "-e",
                "task-clock,instructions,context-switches",
                "-p",
                "4242",
                "-o",
                "/out/slot/perf.csv",
                "--",
                "driver",
                "--samples",
                "3",
            ]
        );

        // The Xray comparator collects task-clock alone.
        let (_, args) = stat_command(7, &TASK_CLOCK_ONLY, Path::new("/p.csv"), &[]);
        assert_eq!(args[6], "task-clock");
        assert_eq!(args.last().unwrap(), "--");
    }
}
