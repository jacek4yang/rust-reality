//! Evidence admissibility: what the evaluator will accept as measurement input.
//!
//! Deliberately separate from JSON syntax. A file can parse cleanly and still be
//! inadmissible evidence — wrong schema version, a non-positive throughput, a block
//! that never completed. Keeping the two apart is what stops malformed-but-parseable
//! evidence from reaching statistical code, where it would produce a p-value that
//! looks authoritative and means nothing.
//!
//! Every rule here is transcribed from `scripts/evaluate-release-performance.py` and
//! verified against its observed behaviour. Where the Python is strict, this is
//! strict; where it is permissive, this is permissive. Migration parity, not
//! improvement.

use std::collections::BTreeMap;

/// The only evidence schema version the evaluator accepts.
pub const SUPPORTED_SCHEMA_VERSION: u64 = 1;

/// Which implementation produced a sample.
///
/// The two arms of every paired comparison. Modelled as an enum rather than a
/// string so a mismatch cannot silently become a third bucket that pairs with
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ImplementationRole {
    /// The reference side of the comparison.
    Baseline,
    /// The side under test.
    Candidate,
}

impl ImplementationRole {
    /// Parses the wire spelling used in evidence rows and order manifests.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "baseline" => Some(Self::Baseline),
            "candidate" => Some(Self::Candidate),
            _ => None,
        }
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Candidate => "candidate",
        }
    }
}

/// Which evidence family a workload directory belongs to.
///
/// The kind decides which files must be present, so it is validated before any
/// file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkloadKind {
    /// Paired setup-rate run with an explicit ABBA order manifest.
    SetupAbba,
    /// Paired fallback run with an explicit ABBA order manifest.
    FallbackAbba,
    /// The formal protected matrix.
    Matrix,
}

impl WorkloadKind {
    /// Parses the wire spelling used by the manifest.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "setup-abba" => Some(Self::SetupAbba),
            "fallback-abba" => Some(Self::FallbackAbba),
            "matrix" => Some(Self::Matrix),
            _ => None,
        }
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SetupAbba => "setup-abba",
            Self::FallbackAbba => "fallback-abba",
            Self::Matrix => "matrix",
        }
    }

    /// The files this kind must supply, each with a recorded digest.
    ///
    /// Transcribed from `FILES_BY_KIND`. A workload that omits one of these is
    /// rejected before evaluation rather than silently evaluated on partial data.
    #[must_use]
    pub const fn required_files(self) -> &'static [&'static str] {
        match self {
            Self::SetupAbba | Self::FallbackAbba => &[
                "summary.json",
                "environment.json",
                "order.json",
                "raw-samples.jsonl",
                "completion.json",
            ],
            Self::Matrix => &[
                "summary.json",
                "samples.jsonl",
                "run-contract.json",
                "run-completion.json",
            ],
        }
    }

    /// Every kind a complete evaluation requires.
    ///
    /// Transcribed from `REQUIRED_KINDS`: a manifest missing any of these is
    /// incomplete evidence, not a smaller valid run.
    #[must_use]
    pub const fn required_kinds() -> [Self; 3] {
        [Self::SetupAbba, Self::FallbackAbba, Self::Matrix]
    }
}

/// Why evidence was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The schema version is absent or unsupported.
    UnsupportedSchema {
        /// What the manifest claimed, rendered for the message.
        found: String,
    },
    /// A required field is missing or has the wrong JSON type.
    Field {
        /// Dotted path to the offending field.
        path: String,
        /// What was expected there.
        expected: &'static str,
    },
    /// A numeric measurement was not a positive finite number.
    NotPositive {
        /// Where the value came from.
        context: String,
    },
    /// A required workload kind is absent from the manifest.
    MissingKind {
        /// The absent kind.
        kind: &'static str,
    },
    /// A workload kind appeared more than once.
    DuplicateKind {
        /// The repeated kind.
        kind: String,
    },
    /// An unrecognised workload kind.
    UnknownKind {
        /// What the manifest said.
        found: String,
    },
    /// A required evidence file is missing from a workload entry.
    MissingFile {
        /// The workload kind.
        kind: &'static str,
        /// The absent file.
        file: String,
    },
    /// A workload entry declares a file the kind does not define.
    UnexpectedFile {
        /// The workload kind.
        kind: &'static str,
        /// The extra file.
        file: String,
    },
    /// A recorded digest did not match the file on disk.
    DigestMismatch {
        /// The file that failed.
        file: String,
        /// The digest the manifest recorded.
        expected: String,
        /// The digest computed from the file.
        actual: String,
    },
    /// A digest field was not a lowercase hexadecimal SHA-256.
    MalformedDigest {
        /// The file whose digest was malformed.
        file: String,
        /// The offending text.
        found: String,
    },
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema { found } => write!(
                formatter,
                "evidence schemaVersion must be {SUPPORTED_SCHEMA_VERSION}, found {found}"
            ),
            Self::Field { path, expected } => {
                write!(formatter, "{path}: expected {expected}")
            }
            Self::NotPositive { context } => {
                write!(formatter, "{context} must be a positive finite number")
            }
            Self::MissingKind { kind } => {
                write!(
                    formatter,
                    "evidence is missing the required {kind} workload"
                )
            }
            Self::DuplicateKind { kind } => {
                write!(formatter, "workload kind {kind} appears more than once")
            }
            Self::UnknownKind { found } => {
                write!(formatter, "unknown workload kind {found}")
            }
            Self::MissingFile { kind, file } => {
                write!(formatter, "{kind}: missing required evidence file {file}")
            }
            Self::UnexpectedFile { kind, file } => {
                write!(formatter, "{kind}: unexpected evidence file {file}")
            }
            Self::DigestMismatch {
                file,
                expected,
                actual,
            } => write!(
                formatter,
                "{file}: digest mismatch, manifest recorded {expected} but the file hashes to {actual}"
            ),
            Self::MalformedDigest { file, found } => {
                write!(
                    formatter,
                    "{file}: digest {found} is not a lowercase hex SHA-256"
                )
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

/// Validates a measurement value the way the evaluator's `positive_number` does.
///
/// Accepts any finite JSON number strictly greater than zero, whether it was
/// written as an integer or a float. Rejects zero, negatives, NaN and both
/// infinities. Booleans are rejected because Python excludes `bool` explicitly
/// despite it being an `int` subclass; in Rust a JSON `true` is simply not a
/// number, so the same inputs are refused for a structural reason.
///
/// This runs before the log transform. A zero or negative ratio would otherwise
/// become `-inf` or `NaN` and poison every statistic downstream.
///
/// # Errors
///
/// Returns [`EvidenceError::NotPositive`] for anything outside that set.
pub fn positive_number(value: Option<f64>, context: &str) -> Result<f64, EvidenceError> {
    match value {
        Some(number) if number.is_finite() && number > 0.0 => Ok(number),
        _ => Err(EvidenceError::NotPositive {
            context: context.to_owned(),
        }),
    }
}

/// One binary's recorded identity.
///
/// Both sides of a comparison carry this, and the evaluator refuses to proceed if
/// the evidence does not match what the manifest claims. Comparing measurements
/// from the wrong binaries while still emitting a p-value is the failure this
/// prevents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryIdentity {
    /// Source commit the binary was built from.
    pub commit: String,
    /// SHA-256 of the binary itself.
    pub sha256: String,
}

/// One workload entry from the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadEntry {
    /// Which evidence family this is.
    pub kind: WorkloadKind,
    /// Human-facing name used to build metric identifiers.
    pub name: String,
    /// Directory holding the evidence files.
    pub run_dir: std::path::PathBuf,
    /// Recorded digest for each required file.
    pub files: BTreeMap<String, String>,
}

/// A validated evaluator manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Release tier the evidence belongs to.
    pub tier: String,
    /// Identity of the candidate binary.
    pub candidate: BinaryIdentity,
    /// Identity of the baseline binary.
    pub baseline: BinaryIdentity,
    /// Resample count for the reporting-only bootstrap.
    pub bootstrap_iterations: usize,
    /// Workload entries, one per required kind.
    pub workloads: Vec<WorkloadEntry>,
}

impl Manifest {
    /// Returns the entry for one kind.
    #[must_use]
    pub fn workload(&self, kind: WorkloadKind) -> Option<&WorkloadEntry> {
        self.workloads.iter().find(|entry| entry.kind == kind)
    }
}

/// Whether `text` is a lowercase hexadecimal SHA-256 digest.
///
/// Case matters: the manifest is machine-generated in lowercase, and accepting
/// mixed case would let two spellings of the same digest compare unequal.
#[must_use]
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "admissibility and pairing are exact: a value either is the recorded \
              measurement or it is different evidence, so an epsilon would hide the bug"
)]
mod tests {
    use super::*;

    #[test]
    fn positive_number_accepts_exactly_what_python_accepts() {
        // Probed against the Python original rather than assumed.
        assert_eq!(positive_number(Some(1.0), "x"), Ok(1.0));
        assert_eq!(positive_number(Some(1.5), "x"), Ok(1.5));
        assert_eq!(positive_number(Some(1e-300), "x"), Ok(1e-300));
        assert_eq!(positive_number(Some(1e300), "x"), Ok(1e300));
    }

    #[test]
    fn positive_number_rejects_exactly_what_python_rejects() {
        for bad in [0.0, -1.0, -0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                matches!(
                    positive_number(Some(bad), "field"),
                    Err(EvidenceError::NotPositive { .. })
                ),
                "{bad} must be refused before the log transform"
            );
        }
        assert!(matches!(
            positive_number(None, "field"),
            Err(EvidenceError::NotPositive { .. })
        ));
    }

    #[test]
    fn a_zero_ratio_never_reaches_the_log_transform() {
        // The reason this validation exists: ln(0) is -inf, which would make every
        // downstream statistic meaningless while still producing a number.
        assert!(positive_number(Some(0.0), "ratio").is_err());
        assert_eq!(0.0_f64.ln(), f64::NEG_INFINITY);
    }

    #[test]
    fn each_workload_kind_declares_the_files_python_requires() {
        assert_eq!(
            WorkloadKind::SetupAbba.required_files(),
            [
                "summary.json",
                "environment.json",
                "order.json",
                "raw-samples.jsonl",
                "completion.json"
            ]
        );
        assert_eq!(
            WorkloadKind::FallbackAbba.required_files(),
            WorkloadKind::SetupAbba.required_files(),
            "the two paired kinds share one file set in the original"
        );
        assert_eq!(
            WorkloadKind::Matrix.required_files(),
            [
                "summary.json",
                "samples.jsonl",
                "run-contract.json",
                "run-completion.json"
            ]
        );
    }

    #[test]
    fn the_required_kind_set_matches_the_original() {
        let kinds = WorkloadKind::required_kinds();
        assert_eq!(kinds.len(), 3);
        for expected in ["setup-abba", "fallback-abba", "matrix"] {
            assert!(
                kinds.iter().any(|kind| kind.as_str() == expected),
                "{expected} must remain required"
            );
        }
    }

    #[test]
    fn wire_spellings_round_trip() {
        for role in [ImplementationRole::Baseline, ImplementationRole::Candidate] {
            assert_eq!(ImplementationRole::parse(role.as_str()), Some(role));
        }
        assert_eq!(ImplementationRole::parse("control"), None);
        for kind in WorkloadKind::required_kinds() {
            assert_eq!(WorkloadKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(WorkloadKind::parse("matrix-conc"), None);
    }

    #[test]
    fn digest_recognition_is_strict_about_length_and_case() {
        let valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(is_sha256_hex(valid));
        assert!(!is_sha256_hex(&valid.to_uppercase()), "case must be exact");
        assert!(!is_sha256_hex(&valid[..63]), "length must be exact");
        assert!(!is_sha256_hex(&format!("{valid}0")));
        assert!(!is_sha256_hex(
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!is_sha256_hex(""));
    }

    #[test]
    fn manifest_lookup_finds_each_kind() {
        let manifest = Manifest {
            tier: "portable".to_owned(),
            candidate: BinaryIdentity {
                commit: "a".repeat(40),
                sha256: "b".repeat(64),
            },
            baseline: BinaryIdentity {
                commit: "c".repeat(40),
                sha256: "d".repeat(64),
            },
            bootstrap_iterations: 20_000,
            workloads: vec![WorkloadEntry {
                kind: WorkloadKind::Matrix,
                name: "matrix".to_owned(),
                run_dir: std::path::PathBuf::from("/tmp/matrix"),
                files: BTreeMap::new(),
            }],
        };
        assert!(manifest.workload(WorkloadKind::Matrix).is_some());
        assert!(manifest.workload(WorkloadKind::SetupAbba).is_none());
    }
}
