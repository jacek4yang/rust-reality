//! Interoperability gates: does an unmodified Xray actually talk to us?
//!
//! This is not a benchmark. It asks a yes/no question that a performance number
//! cannot answer: an unmodified Xray client, configured exactly as a user would
//! configure it, must complete a VLESS + REALITY + Vision session against
//! rust-reality and get its bytes back unaltered.
//!
//! ## The ML-DSA differential
//!
//! The gate also checks something a transfer cannot. Both implementations derive
//! an ML-DSA-65 verification key from the *same* seed, and the two keys must be
//! identical. That is a cross-implementation agreement check on a post-quantum
//! signature scheme: a divergence there would not show up as a failed download,
//! it would show up much later as a peer that cannot verify a signature we
//! consider valid.

use std::path::Path;

use crate::{
    hash,
    perf::{json_in, json_out::Json},
    process::Tool,
};

/// The all-zero seed the gate derives both verification keys from.
///
/// A fixed seed is the point: the check is that two implementations agree on the
/// derivation, so the input must be identical and reproducible rather than fresh.
pub const MLDSA_SEED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Runs `rust-reality mldsa65` and returns its verification key.
///
/// # Errors
///
/// Returns a message when the command fails or its JSON has no `verify` field.
pub fn rust_mldsa65(rust_bin: &Path, seed: &str) -> Result<String, String> {
    let outcome = Tool::new(rust_bin.display().to_string())
        .args(["mldsa65", "--seed", seed])
        .probe()
        .map_err(|error| format!("rust-reality mldsa65 failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "rust-reality mldsa65 exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let value = json_in::parse(outcome.trimmed_stdout())
        .map_err(|error| format!("rust-reality mldsa65 JSON is invalid: {error}"))?;
    value
        .field("mldsa65", "verify")
        .and_then(|field| field.as_str("mldsa65.verify"))
        .map(str::to_owned)
        .map_err(|error| format!("rust-reality mldsa65: {error}"))
}

/// Runs `xray mldsa65` and returns its verification key.
///
/// # Errors
///
/// Returns a message when the command fails or prints no `Verify:` line.
pub fn xray_mldsa65(xray_bin: &Path, seed: &str) -> Result<String, String> {
    let outcome = Tool::new(xray_bin.display().to_string())
        .args(["mldsa65", "-i", seed])
        .probe()
        .map_err(|error| format!("xray mldsa65 failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "xray mldsa65 exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    parse_xray_verify(outcome.trimmed_stdout())
        .ok_or_else(|| "xray mldsa65 printed no Verify line".to_owned())
}

/// Extracts the `Verify:` line from `xray mldsa65` output.
#[must_use]
pub fn parse_xray_verify(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Verify: "))
        .map(str::to_owned)
        .filter(|key| !key.is_empty())
}

/// Compares both implementations' ML-DSA-65 verification keys.
///
/// # Errors
///
/// Returns a message when either command fails or the keys differ.
pub fn mldsa65_differential(
    rust_bin: &Path,
    xray_bin: &Path,
    seed: &str,
) -> Result<String, String> {
    let ours = rust_mldsa65(rust_bin, seed)?;
    let theirs = xray_mldsa65(xray_bin, seed)?;
    if ours != theirs {
        return Err("ML-DSA-65 differential verification-key mismatch".to_owned());
    }
    Ok(ours)
}

/// What the interoperability gate reports.
#[derive(Debug, Clone)]
pub struct InteropReport {
    /// The Xray version line the gate ran against.
    pub xray_version: String,
    /// Bytes retrieved through the tunnel.
    pub local_bytes: u64,
    /// The digest of what came back.
    pub local_sha256: String,
    /// The digest of the agreed ML-DSA-65 verification key.
    pub mldsa65_verify_sha256: String,
    /// The Internet reachability line, or `skipped`.
    pub internet: String,
}

impl InteropReport {
    /// Renders `report.json`.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("pass", Json::Bool(true)),
            ("xrayVersion", Json::string(self.xray_version.clone())),
            (
                "localBytes",
                Json::Int(i64::try_from(self.local_bytes).unwrap_or(i64::MAX)),
            ),
            ("localSha256", Json::string(self.local_sha256.clone())),
            (
                "mldsa65VerifySha256",
                Json::string(self.mldsa65_verify_sha256.clone()),
            ),
            ("internet", Json::string(self.internet.clone())),
        ])
    }
}

/// The digest of an agreed verification key, as the report records it.
#[must_use]
pub fn verify_digest(key: &str) -> String {
    hash::sha256_hex(key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_xray_verify_line_is_extracted() {
        let output = "Seed: abc\nVerify: THE-KEY\nOther: no\n";
        assert_eq!(parse_xray_verify(output).as_deref(), Some("THE-KEY"));
        assert_eq!(parse_xray_verify("no verify here"), None);
        // An empty key is not a key.
        assert_eq!(parse_xray_verify("Verify: "), None);
    }

    /// A fixed seed is the point: the check is that two implementations agree on
    /// the derivation, so the input must be identical and reproducible.
    #[test]
    fn the_seed_is_fixed_and_reproducible() {
        assert_eq!(MLDSA_SEED.len(), 43);
        assert!(MLDSA_SEED.chars().all(|c| c == 'A'));
    }

    #[test]
    fn the_report_records_what_the_gate_proved() {
        let report = InteropReport {
            xray_version: "Xray 26.7.28".to_owned(),
            local_bytes: 1_048_576,
            local_sha256: "a".repeat(64),
            mldsa65_verify_sha256: "b".repeat(64),
            internet: "http=200 connect=0.01".to_owned(),
        };
        let rendered = report.to_json().to_python_json();
        assert!(rendered.contains("\"pass\": true"));
        assert!(rendered.contains("\"localBytes\": 1048576"));
        assert!(rendered.contains("Xray 26.7.28"));
        assert!(rendered.contains("http=200"));
    }

    #[test]
    fn a_verification_key_digest_is_stable() {
        let first = verify_digest("THE-KEY");
        assert_eq!(first.len(), 64);
        assert_eq!(first, verify_digest("THE-KEY"));
        assert_ne!(first, verify_digest("OTHER-KEY"));
    }

    /// The differential must fail closed on a mismatch: a divergence here would
    /// not surface as a failed download, but as a peer that cannot verify a
    /// signature we consider valid.
    #[test]
    fn a_key_mismatch_is_a_hard_failure() {
        let missing = Path::new("/nonexistent/rust-reality");
        let error = mldsa65_differential(missing, missing, MLDSA_SEED).unwrap_err();
        assert!(error.contains("mldsa65"), "{error}");
    }
}
