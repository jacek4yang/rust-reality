//! The fallback-relay throughput workload.
//!
//! `benchmark-fallback-ab.sh` measures the REALITY *fallback* path: a plain HTTP
//! client connects straight to the server's listener, presents no REALITY
//! handshake, and the server relays it to its configured cover target — which the
//! run points at a local origin. There is no SOCKS client and no tunnel; the
//! measurement is how fast bytes move through that relay.
//!
//! So unlike the setup-rate workload this one carries a real payload (32 MiB by
//! default) and reports MiB/s. Concurrency here sets the *number of transfers* in
//! a sample as well as the parallelism: the script ran `conc` transfers across
//! `conc` workers.
//!
//! ## Integrity is part of the measurement
//!
//! Every transfer's byte count is compared against the expected payload size, and
//! the sample records what each one actually observed. A relay that truncates
//! under load is not a fast relay, so a short read invalidates the sample rather
//! than being averaged into a throughput figure.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::{perf::json_out::Json, process::Tool};

/// Per-transfer deadline, as the script passed to curl.
const MAX_TIME_SECONDS: u64 = 300;

/// What one fallback throughput slot measures.
#[derive(Debug, Clone)]
pub struct ThroughputPlan {
    /// The server listener the client connects directly to.
    pub server_port: u16,
    /// Payload size in MiB; the origin serves `payload-<mib>.bin`.
    pub payload_mib: u64,
    /// Concurrency levels, each measured `samples` times.
    pub concurrencies: Vec<usize>,
    /// Samples per concurrency level.
    pub samples: usize,
    /// The implementation label recorded on every row.
    pub implementation: String,
    /// The block this slot belongs to.
    pub block: usize,
    /// The position within the block.
    pub position: usize,
}

impl ThroughputPlan {
    /// Expected bytes per transfer.
    #[must_use]
    pub const fn expected_bytes(&self) -> u64 {
        self.payload_mib * 1024 * 1024
    }

    /// The URL a client fetches through the fallback relay.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/payload-{}.bin",
            self.server_port, self.payload_mib
        )
    }
}

/// One measured (concurrency, sample) row.
#[derive(Debug, Clone)]
pub struct ThroughputRow {
    /// Block number.
    pub block: usize,
    /// Position within the block.
    pub position: usize,
    /// Implementation label.
    pub implementation: String,
    /// Concurrency level, which is also the transfer count.
    pub concurrency: usize,
    /// Sample index within this concurrency level.
    pub sample_index: usize,
    /// Transfers attempted.
    pub requests: usize,
    /// Transfers that failed or came back short.
    pub failed: usize,
    /// Expected bytes per transfer.
    pub bytes_expected_per_request: u64,
    /// Bytes each transfer actually observed, in completion order.
    pub bytes_observed: Vec<u64>,
    /// Wall-clock seconds covering the concurrent set.
    pub wall_seconds: f64,
    /// Aggregate throughput in MiB/s.
    pub throughput_mib_per_second: f64,
    /// Per-transfer seconds for the transfers that succeeded.
    pub per_request_seconds: Vec<f64>,
}

impl ThroughputRow {
    /// Renders the row as the driver wrote it.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let int = |value: usize| Json::Int(i64::try_from(value).unwrap_or(i64::MAX));
        Json::object([
            ("block", int(self.block)),
            ("position", int(self.position)),
            (
                "implementation",
                Json::string(self.implementation.clone()),
            ),
            ("concurrency", int(self.concurrency)),
            ("sampleIndex", int(self.sample_index)),
            ("requests", int(self.requests)),
            ("failed", int(self.failed)),
            (
                "bytesExpectedPerRequest",
                Json::Int(i64::try_from(self.bytes_expected_per_request).unwrap_or(i64::MAX)),
            ),
            (
                "bytesObserved",
                Json::Array(
                    self.bytes_observed
                        .iter()
                        .map(|bytes| Json::Int(i64::try_from(*bytes).unwrap_or(i64::MAX)))
                        .collect(),
                ),
            ),
            ("wallSeconds", Json::Float(self.wall_seconds)),
            (
                "throughputMiBPerSecond",
                Json::Float(self.throughput_mib_per_second),
            ),
            (
                "perRequestSeconds",
                Json::Array(
                    self.per_request_seconds
                        .iter()
                        .copied()
                        .map(Json::Float)
                        .collect(),
                ),
            ),
        ])
    }
}

/// Downloads the payload straight from the server listener.
///
/// The workspace proxy environment sets `NO_PROXY` with `127.0.0.1`, so every
/// proxy variable is stripped: a curl that quietly bypassed the listener would
/// measure a direct fetch from the origin and report it as relay throughput.
///
/// # Errors
///
/// Returns the transfer failure, including a short read.
pub fn curl_direct(url: &str, expected_bytes: u64) -> Result<(u64, f64), String> {
    let mut curl = Tool::new("curl");
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        curl = curl.env(name, "");
    }
    let outcome = curl
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            &MAX_TIME_SECONDS.to_string(),
            "--output",
            "/dev/null",
            "--write-out",
            "%{size_download} %{time_total}",
            url,
        ])
        .probe()
        .map_err(|error| format!("could not run curl: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "curl exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let mut fields = outcome.trimmed_stdout().split_whitespace();
    let (Some(bytes), Some(seconds), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err("malformed curl output".to_owned());
    };
    let (Ok(bytes), Ok(seconds)) = (bytes.parse::<u64>(), seconds.parse::<f64>()) else {
        return Err("malformed curl output".to_owned());
    };
    if bytes != expected_bytes {
        return Err(format!("short read: {bytes} of {expected_bytes} bytes"));
    }
    Ok((bytes, seconds))
}

/// Runs one sample: `concurrency` transfers across `concurrency` workers.
#[must_use]
pub fn run_sample(plan: &ThroughputPlan, concurrency: usize, sample_index: usize) -> ThroughputRow {
    let url = plan.url();
    let expected = plan.expected_bytes();
    let next = AtomicUsize::new(0);
    let started = Instant::now();
    let mut observed = Vec::with_capacity(concurrency);
    let mut latencies = Vec::with_capacity(concurrency);
    let mut failed = 0_usize;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..concurrency.max(1))
            .map(|_| {
                let next = &next;
                let url = &url;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        if next.fetch_add(1, Ordering::Relaxed) >= concurrency {
                            break;
                        }
                        mine.push(curl_direct(url, expected));
                    }
                    mine
                })
            })
            .collect();
        for handle in handles {
            let Ok(results) = handle.join() else {
                failed += 1;
                continue;
            };
            for result in results {
                match result {
                    Ok((bytes, seconds)) => {
                        observed.push(bytes);
                        latencies.push(seconds);
                    }
                    Err(_) => failed += 1,
                }
            }
        }
    });
    let wall_seconds = started.elapsed().as_secs_f64();
    #[expect(
        clippy::cast_precision_loss,
        reason = "transfer counts are small integers, exact in f64"
    )]
    let throughput = if wall_seconds > 0.0 {
        (plan.payload_mib as f64) * (observed.len() as f64) / wall_seconds
    } else {
        0.0
    };
    ThroughputRow {
        block: plan.block,
        position: plan.position,
        implementation: plan.implementation.clone(),
        concurrency,
        sample_index,
        requests: observed.len() + failed,
        failed,
        bytes_expected_per_request: expected,
        bytes_observed: observed,
        wall_seconds,
        throughput_mib_per_second: throughput,
        per_request_seconds: latencies,
    }
}

/// Warms the relay path with three transfers.
///
/// # Errors
///
/// Returns the failure; a relay that never carried a byte must not be measured.
pub fn warm_up(plan: &ThroughputPlan) -> Result<(), String> {
    let url = plan.url();
    for attempt in 1..=3 {
        curl_direct(&url, plan.expected_bytes())
            .map_err(|error| format!("warm-up transfer {attempt} failed: {error}"))?;
    }
    Ok(())
}

/// Runs every (concurrency, sample) cell of one slot.
///
/// # Errors
///
/// Returns a message when the row count is short or any transfer failed or came
/// back with the wrong byte count.
pub fn run_slot(plan: &ThroughputPlan) -> Result<Vec<ThroughputRow>, String> {
    let mut rows = Vec::with_capacity(plan.concurrencies.len() * plan.samples);
    for concurrency in &plan.concurrencies {
        for sample_index in 0..plan.samples {
            rows.push(run_sample(plan, *concurrency, sample_index));
        }
    }
    let expected_rows = plan.samples * plan.concurrencies.len();
    if rows.len() != expected_rows {
        return Err(format!(
            "incomplete or corrupt fallback samples: expected {expected_rows} rows, produced {}",
            rows.len()
        ));
    }
    let expected = plan.expected_bytes();
    if let Some(bad) = rows.iter().find(|row| {
        row.failed > 0
            || row.requests != row.concurrency
            || row.bytes_observed.iter().any(|bytes| *bytes != expected)
    }) {
        return Err(format!(
            "incomplete or corrupt fallback samples: concurrency {} sample {} had {} failure(s) \
             across {} request(s)",
            bad.concurrency, bad.sample_index, bad.failed, bad.requests
        ));
    }
    Ok(rows)
}

/// Reads rows back from a slot's `samples.json`.
///
/// # Errors
///
/// Returns a message when the file is missing or not an array of rows.
pub fn read_rows(path: &std::path::Path) -> Result<Vec<ThroughputRow>, String> {
    use crate::perf::json_in::{self, Value};
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let Ok(Value::Array(items)) = json_in::parse(&raw) else {
        return Err(format!("{} is not an array of rows", path.display()));
    };
    items
        .iter()
        .map(|item| {
            let number = |name: &str| -> Result<f64, String> {
                match item.field("row", name) {
                    Ok(Value::Number(text)) => text
                        .parse::<f64>()
                        .map_err(|error| format!("row.{name} is not a number: {error}")),
                    _ => Err(format!("row.{name} is missing or not a number")),
                }
            };
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "row counters are small non-negative integers"
            )]
            let count = |name: &str| -> Result<usize, String> { Ok(number(name)? as usize) };
            let numbers = |name: &str| -> Vec<f64> {
                match item.field("row", name) {
                    Ok(Value::Array(values)) => values
                        .iter()
                        .filter_map(|value| match value {
                            Value::Number(text) => text.parse::<f64>().ok(),
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                }
            };
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "byte counts here are far below 2^53"
            )]
            let observed = numbers("bytesObserved")
                .into_iter()
                .map(|value| value as u64)
                .collect();
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "byte counts here are far below 2^53"
            )]
            let expected = number("bytesExpectedPerRequest")? as u64;
            Ok(ThroughputRow {
                block: count("block")?,
                position: count("position")?,
                implementation: item
                    .field("row", "implementation")
                    .and_then(|field| field.as_str("row.implementation"))
                    .map_err(|error| error.to_string())?
                    .to_owned(),
                concurrency: count("concurrency")?,
                sample_index: count("sampleIndex")?,
                requests: count("requests")?,
                failed: count("failed")?,
                bytes_expected_per_request: expected,
                bytes_observed: observed,
                wall_seconds: number("wallSeconds")?,
                throughput_mib_per_second: number("throughputMiBPerSecond")?,
                per_request_seconds: numbers("perRequestSeconds"),
            })
        })
        .collect()
}

/// Renders a slot's rows as the driver's `samples.json`.
#[must_use]
pub fn rows_json(rows: &[ThroughputRow]) -> Json {
    Json::Array(rows.iter().map(ThroughputRow::to_json).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ThroughputPlan {
        ThroughputPlan {
            server_port: 8080,
            payload_mib: 32,
            concurrencies: vec![1, 4, 32],
            samples: 3,
            implementation: "baseline".to_owned(),
            block: 1,
            position: 1,
        }
    }

    #[test]
    fn the_url_and_size_follow_the_payload() {
        let plan = plan();
        assert_eq!(plan.url(), "http://127.0.0.1:8080/payload-32.bin");
        assert_eq!(plan.expected_bytes(), 33_554_432);
    }

    /// The row shape is what the aggregator and the archived evidence expect.
    #[test]
    fn the_row_document_matches_the_driver_shape() {
        let row = ThroughputRow {
            block: 2,
            position: 3,
            implementation: "candidate".to_owned(),
            concurrency: 4,
            sample_index: 1,
            requests: 4,
            failed: 0,
            bytes_expected_per_request: 33_554_432,
            bytes_observed: vec![33_554_432; 4],
            wall_seconds: 2.0,
            throughput_mib_per_second: 64.0,
            per_request_seconds: vec![0.5, 0.6, 0.7, 0.8],
        };
        let rendered = row.to_json().to_python_json();
        assert!(rendered.contains("\"implementation\": \"candidate\""));
        assert!(rendered.contains("\"throughputMiBPerSecond\": 64.0"));
        assert!(rendered.contains("\"bytesExpectedPerRequest\": 33554432"));
        assert!(rendered.contains("\"bytesObserved\""));
        assert!(rendered.contains("\"perRequestSeconds\""));
        assert!(rendered.contains("\"failed\": 0"));
    }

    /// A relay that truncates under load is not a fast relay, so a short read
    /// invalidates the slot rather than being averaged in.
    #[test]
    fn a_short_read_or_failure_invalidates_the_slot() {
        let mut rows = [ThroughputRow {
            block: 1,
            position: 1,
            implementation: "baseline".to_owned(),
            concurrency: 1,
            sample_index: 0,
            requests: 1,
            failed: 0,
            bytes_expected_per_request: 33_554_432,
            bytes_observed: vec![33_554_432],
            wall_seconds: 1.0,
            throughput_mib_per_second: 32.0,
            per_request_seconds: vec![1.0],
        }];
        // Sanity: the well-formed row passes the same predicate the slot applies.
        let expected = 33_554_432_u64;
        assert!(!rows.iter().any(|row| row.failed > 0
            || row.requests != row.concurrency
            || row.bytes_observed.iter().any(|bytes| *bytes != expected)));

        rows[0].bytes_observed = vec![1024];
        assert!(rows.iter().any(|row| row
            .bytes_observed
            .iter()
            .any(|bytes| *bytes != expected)));

        rows[0].bytes_observed = vec![expected];
        rows[0].failed = 1;
        assert!(rows.iter().any(|row| row.failed > 0));
    }

    /// A closed port fails rather than hanging, and reports curl's own message.
    #[test]
    fn a_transfer_to_a_closed_port_fails() {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let error =
            curl_direct(&format!("http://127.0.0.1:{port}/payload-1.bin"), 1024).unwrap_err();
        assert!(error.contains("curl exited"), "{error}");
    }

    #[test]
    fn a_slot_with_no_reachable_server_is_refused() {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut plan = plan();
        plan.server_port = port;
        plan.payload_mib = 1;
        plan.concurrencies = vec![1];
        plan.samples = 1;
        let error = run_slot(&plan).unwrap_err();
        assert!(
            error.starts_with("incomplete or corrupt fallback samples:"),
            "{error}"
        );
        assert!(warm_up(&plan).is_err());
    }
}
