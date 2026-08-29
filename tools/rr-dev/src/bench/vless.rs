//! The VLESS-encryption A/B.
//!
//! Unlike the rest of the family this compares Xray against *itself*: the same
//! build, the same REALITY transport, the same Vision flow, the same client and
//! the same origins, differing only in whether the inner VLESS layer is
//! `encryption: none` or VLESS Encryption. That is what makes the ratio
//! attributable to the encryption layer rather than to anything else.
//!
//! ## Two things that would otherwise bias the result
//!
//! Both paths are warmed before measurement, and for VLESS Encryption the warm-up
//! is what obtains the reusable ticket — so the measured setup path is its
//! intended 0-RTT mode rather than a first-contact handshake it would never do
//! twice in production. The report says so in its limitations, because it does
//! favour the encrypted side.
//!
//! And the measurement order is shuffled rather than run mode-by-mode, so a
//! machine that warms up or thermally throttles over the run cannot systematically
//! favour whichever mode went first. The shuffle is seeded and recorded, so the
//! order is reproducible evidence rather than an unrepeatable accident.

use crate::{
    perf::{bootstrap::PythonRandom, json_out::Json, stats},
    process::Tool,
};

/// The two modes under comparison.
pub const MODES: [&str; 2] = ["none", "vless-encryption"];

/// The shuffle seed the harness records, `"VLES"` as big-endian ASCII.
pub const ORDER_SEED: u64 = 0x0000_564C_4553;

/// The key material an Xray VLESS-Encryption pair needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionKeys {
    /// The server's `decryption` string.
    pub decryption: String,
    /// The client's `encryption` string.
    pub encryption: String,
}

/// Extracts the `decryption`/`encryption` pair from `xray vlessenc` output.
///
/// The tool prints JSON-ish lines; the harness took the first of each with `sed`,
/// and this keeps that, because a later line describes a different profile.
///
/// # Errors
///
/// Returns a message when either field is absent.
pub fn parse_vlessenc(output: &str) -> Result<EncryptionKeys, String> {
    let first = |field: &str| -> Option<String> {
        let prefix = format!("\"{field}\": \"");
        output.lines().find_map(|line| {
            let rest = line.trim().strip_prefix(prefix.as_str())?;
            rest.strip_suffix('"').map(str::to_owned)
        })
    };
    let (Some(decryption), Some(encryption)) = (first("decryption"), first("encryption")) else {
        return Err("xray vlessenc output was not understood".to_owned());
    };
    Ok(EncryptionKeys {
        decryption,
        encryption,
    })
}

/// Runs `xray vlessenc` and parses its key pair.
///
/// # Errors
///
/// Returns a message when the tool fails or its output is not understood.
pub fn generate_encryption_keys(xray_bin: &std::path::Path) -> Result<EncryptionKeys, String> {
    let outcome = Tool::new(xray_bin.display().to_string())
        .arg("vlessenc")
        .probe()
        .map_err(|error| format!("xray vlessenc failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "xray vlessenc exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    parse_vlessenc(outcome.trimmed_stdout())
}

/// The measurement order: `samples` of each mode, shuffled and recorded.
#[must_use]
pub fn measurement_order(samples: usize) -> Vec<String> {
    let mut order: Vec<String> = (0..samples)
        .flat_map(|_| MODES.into_iter().map(str::to_owned))
        .collect();
    PythonRandom::seeded(ORDER_SEED).shuffle(&mut order);
    order
}

/// A process's accumulated CPU seconds, from `utime + stime` in `/proc`.
///
/// # Errors
///
/// Returns a message when the process is gone or its stat line is unreadable.
pub fn cpu_seconds(pid: u32) -> Result<f64, String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("could not read the CPU time of PID {pid}: {error}"))?;
    // The command name can contain spaces and parentheses, so fields are counted
    // from after the final ')'.
    let rest = raw
        .rfind(')')
        .and_then(|index| raw.get(index + 2..))
        .ok_or_else(|| format!("PID {pid} has a malformed stat line"))?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let (Some(utime), Some(stime)) = (fields.get(11), fields.get(12)) else {
        return Err(format!("PID {pid} has a short stat line"));
    };
    let (Ok(utime), Ok(stime)) = (utime.parse::<f64>(), stime.parse::<f64>()) else {
        return Err(format!("PID {pid} has non-numeric CPU times"));
    };
    // USER_HZ is 100 on every Linux architecture Go and Rust support here.
    Ok((utime + stime) / 100.0)
}

/// One measured throughput or setup sample.
#[derive(Debug, Clone)]
pub struct ModeSample {
    /// Which mode produced it.
    pub mode: String,
    /// The measured values, by field name.
    pub values: Vec<(String, f64)>,
}

impl ModeSample {
    /// The value of one field, if present.
    #[must_use]
    pub fn value(&self, field: &str) -> Option<f64> {
        self.values
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| *value)
    }
}

/// Summarises one field across a mode's samples.
///
/// # Errors
///
/// Returns a message when the mode has no samples for the field.
pub fn summarise_field(samples: &[ModeSample], mode: &str, field: &str) -> Result<Json, String> {
    let values: Vec<f64> = samples
        .iter()
        .filter(|sample| sample.mode == mode)
        .filter_map(|sample| sample.value(field))
        .collect();
    if values.is_empty() {
        return Err(format!("{mode} has no {field} samples"));
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "sample counts here are small integers"
    )]
    let mean = stats::fsum(&values) / values.len() as f64;
    let median = stats::median(&values).map_err(|error| error.to_string())?;
    let minimum = values.iter().copied().fold(f64::INFINITY, f64::min);
    let maximum = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    Ok(Json::object([
        ("mean", Json::Float(mean)),
        ("p50", Json::Float(median)),
        ("minimum", Json::Float(minimum)),
        ("maximum", Json::Float(maximum)),
    ]))
}

/// Reads one summarised statistic back out of a rendered summary.
fn statistic(summary: &Json, mode: &str, field: &str, key: &str) -> Option<f64> {
    let Json::Object(modes) = summary else {
        return None;
    };
    let Json::Object(fields) = modes.get(mode)? else {
        return None;
    };
    let Json::Object(stats) = fields.get(field)? else {
        return None;
    };
    match stats.get(key)? {
        Json::Float(value) => Some(*value),
        _ => None,
    }
}

/// The three ratios the report records.
///
/// # Errors
///
/// Returns a message when a statistic is missing or its denominator is zero.
pub fn ratios_json(summary: &Json) -> Result<Json, String> {
    let ratio = |field: &str, key: &str| -> Result<f64, String> {
        let base = statistic(summary, "none", field, key)
            .ok_or_else(|| format!("none has no {field}.{key}"))?;
        let encrypted = statistic(summary, "vless-encryption", field, key)
            .ok_or_else(|| format!("vless-encryption has no {field}.{key}"))?;
        if base == 0.0 {
            return Err(format!("{field}.{key} for none is zero"));
        }
        Ok(encrypted / base)
    };
    Ok(Json::object([
        (
            "encryptedToNoneP50Throughput",
            Json::Float(ratio("throughputMiBPerSecond", "p50")?),
        ),
        (
            "encryptedToNoneMeanServerCpuPerGiB",
            Json::Float(ratio("serverCpuSecondsPerGiB", "mean")?),
        ),
        (
            "encryptedToNoneP50ConnectionsPerSecond",
            Json::Float(ratio("connectionsPerSecond", "p50")?),
        ),
    ]))
}

/// The limitations the report states about itself.
#[must_use]
pub fn limitations_json() -> Json {
    Json::Array(
        [
            "single-host loopback; results are host-specific, not universal",
            "both modes use the same Xray build, REALITY, Vision, client, and origins",
            "VLESS Encryption is measured after ticket warm-up, favoring its 0-RTT setup path",
            "server CPU excludes client-side encryption and the origin",
        ]
        .into_iter()
        .map(Json::string)
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_pair_is_taken_from_the_first_matching_lines() {
        let output = "\"decryption\": \"mlkem768x25519plus.native.0rtt.SEED\"\n\
                      \"encryption\": \"mlkem768x25519plus.native.0rtt.PUB\"\n\
                      \"decryption\": \"a-later-profile\"\n";
        let keys = parse_vlessenc(output).unwrap();
        assert_eq!(keys.decryption, "mlkem768x25519plus.native.0rtt.SEED");
        assert_eq!(keys.encryption, "mlkem768x25519plus.native.0rtt.PUB");
        assert!(parse_vlessenc("nothing useful").is_err());
        assert!(parse_vlessenc("\"decryption\": \"only-one\"").is_err());
    }

    /// The order is shuffled so a machine that warms up over the run cannot
    /// favour whichever mode went first, and seeded so it stays reproducible.
    #[test]
    fn the_measurement_order_is_shuffled_balanced_and_reproducible() {
        let order = measurement_order(5);
        assert_eq!(order.len(), 10);
        for mode in MODES {
            assert_eq!(order.iter().filter(|entry| *entry == mode).count(), 5);
        }
        assert_ne!(
            order,
            (0..5)
                .flat_map(|_| MODES.into_iter().map(str::to_owned))
                .collect::<Vec<String>>(),
            "an unshuffled order would run mode by mode"
        );
        assert_eq!(order, measurement_order(5), "the seed makes it reproducible");
        assert_eq!(order[0], "vless-encryption");
    }

    #[test]
    fn cpu_time_is_read_for_a_live_process() {
        let seconds = cpu_seconds(std::process::id()).unwrap();
        assert!(seconds >= 0.0);
        assert!(cpu_seconds(u32::MAX).is_err());
    }

    fn sample(mode: &str, throughput: f64, cpu: f64, rate: f64) -> ModeSample {
        ModeSample {
            mode: mode.to_owned(),
            values: vec![
                ("throughputMiBPerSecond".to_owned(), throughput),
                ("serverCpuSecondsPerGiB".to_owned(), cpu),
                ("connectionsPerSecond".to_owned(), rate),
            ],
        }
    }

    #[test]
    fn a_field_summary_reports_mean_median_and_bounds() {
        let samples = vec![
            sample("none", 100.0, 1.0, 50.0),
            sample("none", 200.0, 3.0, 70.0),
            sample("vless-encryption", 80.0, 2.0, 40.0),
        ];
        let rendered = summarise_field(&samples, "none", "throughputMiBPerSecond")
            .unwrap()
            .to_python_json();
        assert!(rendered.contains("\"mean\": 150.0"));
        assert!(rendered.contains("\"p50\": 150.0"));
        assert!(rendered.contains("\"minimum\": 100.0"));
        assert!(rendered.contains("\"maximum\": 200.0"));
        assert!(summarise_field(&samples, "none", "absent").is_err());
        assert!(summarise_field(&samples, "missing-mode", "throughputMiBPerSecond").is_err());
    }

    #[test]
    fn the_ratios_compare_the_encrypted_mode_against_none() {
        let samples = vec![
            sample("none", 100.0, 1.0, 50.0),
            sample("vless-encryption", 80.0, 2.0, 40.0),
        ];
        let mut summary: Vec<(String, Json)> = Vec::new();
        for mode in MODES {
            let mut fields: Vec<(String, Json)> = Vec::new();
            for field in [
                "throughputMiBPerSecond",
                "serverCpuSecondsPerGiB",
                "connectionsPerSecond",
            ] {
                fields.push((
                    field.to_owned(),
                    summarise_field(&samples, mode, field).unwrap(),
                ));
            }
            summary.push((mode.to_owned(), Json::object(fields)));
        }
        let rendered = ratios_json(&Json::object(summary)).unwrap().to_python_json();
        assert!(rendered.contains("\"encryptedToNoneP50Throughput\": 0.8"));
        assert!(rendered.contains("\"encryptedToNoneMeanServerCpuPerGiB\": 2.0"));
        assert!(rendered.contains("\"encryptedToNoneP50ConnectionsPerSecond\": 0.8"));
    }

    /// The warm-up favours the encrypted side, and the report has to say so.
    #[test]
    fn the_limitations_disclose_the_warm_up_bias() {
        let rendered = limitations_json().to_python_json();
        assert!(rendered.contains("favoring its 0-RTT setup path"));
        assert!(rendered.contains("server CPU excludes client-side encryption"));
    }
}
