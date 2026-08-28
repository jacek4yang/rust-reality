//! Shared benchmark measurement summary and report assembly.
//!
//! The A/B tunnel-download suites (real-path, xray, vision-direct) each collect a
//! sequence of per-run samples for two implementations and summarise them into a
//! schema-v1 report. This module owns the pure statistics and report shape so the
//! suites differ only in how they *collect* samples, not in how they *summarise*
//! them. Nothing here performs I/O, so the decision logic is unit-tested.

use crate::perf::json_out::Json;

/// One transfer sample.
#[derive(Debug, Clone)]
pub struct Sample {
    /// The implementation that produced it, e.g. `rust-reality` or `xray`.
    pub implementation: String,
    /// Whether the transfer succeeded (exact byte count and success status).
    pub ok: bool,
    /// Observed throughput in bytes per second, when the transfer succeeded.
    pub bytes_per_second: Option<f64>,
}

/// Per-implementation throughput summary in MiB/s.
#[derive(Debug, Clone, PartialEq)]
pub struct ImplementationSummary {
    /// The implementation name.
    pub implementation: String,
    /// Number of successful samples summarised.
    pub samples: usize,
    /// Median MiB/s.
    pub median: f64,
    /// Minimum MiB/s.
    pub minimum: f64,
    /// Maximum MiB/s.
    pub maximum: f64,
}

const MIB: f64 = 1_048_576.0;

/// Summarises the successful samples for `implementation`, or `None` if there are
/// none. Matches `benchmark-real-path.sh`: sort ascending, median at `len / 2`.
#[must_use]
pub fn summarise(samples: &[Sample], implementation: &str) -> Option<ImplementationSummary> {
    let mut speeds: Vec<f64> = samples
        .iter()
        .filter(|sample| sample.implementation == implementation)
        .filter_map(|sample| sample.bytes_per_second)
        .map(|bytes| bytes / MIB)
        .collect();
    if speeds.is_empty() {
        return None;
    }
    speeds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(ImplementationSummary {
        implementation: implementation.to_owned(),
        samples: speeds.len(),
        median: speeds[speeds.len() / 2],
        minimum: speeds[0],
        maximum: speeds[speeds.len() - 1],
    })
}

/// The alternating A/B order `benchmark-real-path.sh` uses: even indices go to the
/// first implementation, odd to the second.
#[must_use]
pub fn alternating_order(first: &str, second: &str, runs: usize) -> Vec<String> {
    (0..runs)
        .map(|index| {
            if index % 2 == 0 {
                first.to_owned()
            } else {
                second.to_owned()
            }
        })
        .collect()
}

/// Renders a per-implementation summary as JSON.
#[must_use]
pub fn summary_json(summary: &ImplementationSummary) -> Json {
    Json::object([
        (
            "samples",
            Json::Int(i64::try_from(summary.samples).unwrap_or(i64::MAX)),
        ),
        ("medianMiBPerSecond", Json::Float(summary.median)),
        ("minMiBPerSecond", Json::Float(summary.minimum)),
        ("maxMiBPerSecond", Json::Float(summary.maximum)),
    ])
}

/// The number of failed samples.
#[must_use]
pub fn failure_count(samples: &[Sample]) -> usize {
    samples.iter().filter(|sample| !sample.ok).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(implementation: &str, ok: bool, mib_per_second: f64) -> Sample {
        Sample {
            implementation: implementation.to_owned(),
            ok,
            bytes_per_second: ok.then_some(mib_per_second * MIB),
        }
    }

    #[test]
    fn summary_is_median_min_max_over_successful_samples() {
        let samples = vec![
            sample("rust-reality", true, 10.0),
            sample("rust-reality", true, 30.0),
            sample("rust-reality", true, 20.0),
            sample("xray", false, 0.0),
        ];
        let rust = summarise(&samples, "rust-reality").expect("rust summary");
        assert_eq!(rust.samples, 3);
        assert!((rust.median - 20.0).abs() < 1e-9);
        assert!((rust.minimum - 10.0).abs() < 1e-9);
        assert!((rust.maximum - 30.0).abs() < 1e-9);
        // xray had only a failed sample, so it summarises to None.
        assert!(summarise(&samples, "xray").is_none());
    }

    #[test]
    fn alternating_order_matches_the_script() {
        assert_eq!(
            alternating_order("rust-reality", "xray", 4),
            vec!["rust-reality", "xray", "rust-reality", "xray"]
        );
    }

    #[test]
    fn failure_count_counts_only_failures() {
        let samples = vec![
            sample("rust-reality", true, 1.0),
            sample("xray", false, 0.0),
            sample("rust-reality", false, 0.0),
        ];
        assert_eq!(failure_count(&samples), 2);
    }
}
