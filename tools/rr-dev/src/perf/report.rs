//! Report assembly and the evaluator's process-facing entry point.
//!
//! Everything above this module is pure. This is where the pipeline touches the
//! filesystem, so the whole authority transfer's externally visible contract lives
//! here: which paths are accepted, whether an existing output is overwritten, and
//! which exit status a caller sees.
//!
//! The exit statuses are load-bearing and deliberately three-valued:
//!
//! ```text
//! 0  the gate passed
//! 1  a real performance regression
//! 2  the evidence was inadmissible, so no comparison happened
//! ```
//!
//! Collapsing 1 and 2 would tell an operator that a broken harness and a genuine
//! regression require the same response, which they do not.

use std::path::Path;

use super::{
    evaluator::{
        self, DeterministicMetric, OverallVerdict, ReportingStatistics,
        validate_bootstrap_iterations, validate_tier,
    },
    evidence::{BinaryIdentity, SUPPORTED_SCHEMA_VERSION, WorkloadKind},
    json_in::Value,
    json_out::Json,
    loader::{self, LoadError, WorkloadInput, sha256_file},
    stats::{Classification, FAMILY_WISE_ALPHA, MAX_EXACT_BLOCKS, MIN_EXACT_BLOCKS},
};

/// Validated evidence: metrics and report inputs from one pass.
///
/// The single object both consumers read. Rebuilding `inputs` separately would let a
/// report claim a different set of files than the evaluator validated.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedEvidence {
    /// Release tier from the manifest.
    pub tier: String,
    /// Candidate binary identity.
    pub candidate: BinaryIdentity,
    /// Baseline binary identity.
    pub baseline: BinaryIdentity,
    /// Bootstrap resample count for reporting statistics.
    pub bootstrap_iterations: usize,
    /// Protected metrics in production order.
    pub metrics: Vec<DeterministicMetric>,
    /// Report inputs in manifest order.
    pub inputs: Vec<WorkloadInput>,
}

/// Loads and validates a complete evaluator manifest.
///
/// Order matters and is transcribed: schema, tier, identities, iteration count, then
/// workload cardinality, then per-workload evidence, then the cross-workload
/// coordination check. A caller that reordered these would report a different first
/// error for the same broken evidence.
///
/// # Errors
///
/// Returns the first rule that failed.
pub fn load_manifest(manifest_path: &Path) -> Result<ValidatedEvidence, LoadError> {
    let manifest = loader::load_json(manifest_path)?;
    let context = "manifest";

    manifest.require_int(
        context,
        "schemaVersion",
        i64::try_from(SUPPORTED_SCHEMA_VERSION).unwrap_or(1),
    )?;
    let tier = manifest.str_field(context, "tier")?.to_owned();
    validate_tier(&tier).map_err(|error| evaluation_to_load(&error))?;

    let candidate = identity(&manifest, "candidate")?;
    let baseline = identity(&manifest, "baseline")?;
    if candidate == baseline {
        return Err(rule(
            context,
            "candidate and baseline identities are identical",
        ));
    }

    // The default is applied before range validation, matching `.get(key, 20_000)`.
    let iterations = match manifest.optional("bootstrapIterations") {
        Some(value) => usize::try_from(value.as_int("manifest.bootstrapIterations")?)
            .map_err(|_| rule(context, "bootstrapIterations must be in 20000..100000"))?,
        None => evaluator::MIN_BOOTSTRAP_ITERATIONS,
    };
    validate_bootstrap_iterations(iterations).map_err(|error| evaluation_to_load(&error))?;

    let workloads = manifest.array_field(context, "workloads")?;
    validate_workload_set(workloads, context)?;
    let mut metrics = Vec::new();
    let mut inputs = Vec::new();
    for entry in workloads {
        let kind =
            WorkloadKind::parse(entry.str_field("workload", "kind")?).expect("validated above");
        let name = entry.str_field("workload", "name")?;
        let run_dir = entry.str_field("workload", "runDir")?;
        let files = entry
            .field("workload", "files")?
            .as_object("workload.files")?
            .clone();
        let (produced, input) = if kind == WorkloadKind::Matrix {
            loader::evaluate_matrix_workload(name, run_dir, &files, &candidate, &baseline)?
        } else {
            loader::evaluate_pair_run(name, kind, run_dir, &files, &candidate, &baseline)?
        };
        metrics.extend(produced);
        inputs.push(input);
    }

    // Every workload must have run under the same host-exclusive lock; otherwise the
    // runs were not mutually exclusive and their measurements are not comparable.
    let mut coordination = Vec::new();
    for input in &inputs {
        coordination.push(
            input
                .host_lock
                .coordination_identity()
                .ok_or_else(|| rule(context, "host lock is missing a verified contract"))?,
        );
    }
    if coordination.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(rule(
            context,
            "workloads used different host-exclusive lock protocols/identities",
        ));
    }

    if metrics.is_empty() {
        return Err(rule(context, "no protected metrics were produced"));
    }

    Ok(ValidatedEvidence {
        tier,
        candidate,
        baseline,
        bootstrap_iterations: iterations,
        metrics,
        inputs,
    })
}

/// Validates workload cardinality, kind uniqueness and name uniqueness.
///
/// Split out of [`load_manifest`] only for length; the order in which these three
/// rules fire is still the order the original checks them, because a caller that
/// reordered them would report a different first error for the same broken manifest.
fn validate_workload_set(workloads: &[Value], context: &str) -> Result<(), LoadError> {
    let required = WorkloadKind::required_kinds();
    if workloads.len() != required.len() {
        return Err(rule(
            context,
            "manifest must contain exactly setup, fallback, and matrix workloads",
        ));
    }
    let mut kinds = Vec::new();
    let mut names = Vec::new();
    for entry in workloads {
        let kind_text = entry.str_field("workload", "kind")?;
        let kind = WorkloadKind::parse(kind_text)
            .ok_or_else(|| rule(context, format!("unknown workload kind {kind_text}")))?;
        if kinds.contains(&kind) {
            return Err(rule(
                context,
                "workload kinds must be exactly setup-abba, fallback-abba, and matrix",
            ));
        }
        kinds.push(kind);
        let name = entry.str_field("workload", "name")?.to_owned();
        if name.is_empty() || names.contains(&name) {
            return Err(rule(context, "workload names must be unique"));
        }
        names.push(name);
    }
    for kind in required {
        if !kinds.contains(&kind) {
            return Err(rule(
                context,
                "workload kinds must be exactly setup-abba, fallback-abba, and matrix",
            ));
        }
    }
    Ok(())
}

fn identity(manifest: &Value, label: &str) -> Result<BinaryIdentity, LoadError> {
    let value = manifest.field("manifest", label)?;
    Ok(BinaryIdentity {
        commit: value.str_field(label, "commit")?.to_owned(),
        sha256: value.str_field(label, "sha256")?.to_owned(),
    })
}

fn rule(context: &str, message: impl Into<String>) -> LoadError {
    LoadError::Rule {
        context: context.to_owned(),
        message: message.into(),
    }
}

fn evaluation_to_load(error: &evaluator::EvaluationError) -> LoadError {
    LoadError::Rule {
        context: "manifest".to_owned(),
        message: error.to_string(),
    }
}

/// The evaluator's own provenance, as the report records it.
///
/// The Python evaluator hashes its own source file. The Rust evaluator identifies the
/// running executable instead, which is the closest honest equivalent: it is what
/// actually produced the verdict. This is why `evaluator.path` and `evaluator.sha256`
/// are the two — and only two — fields expected to differ during parity comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorIdentity {
    /// Canonical path of the running evaluator.
    pub path: String,
    /// SHA-256 of the running evaluator.
    pub sha256: String,
}

impl EvaluatorIdentity {
    /// Determines the identity of the running executable.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::Io`] when the executable cannot be read.
    pub fn current() -> Result<Self, LoadError> {
        let exe = std::env::current_exe().map_err(|error| LoadError::Io {
            path: "<current executable>".to_owned(),
            message: error.to_string(),
        })?;
        let canonical = exe.canonicalize().unwrap_or(exe);
        Ok(Self {
            sha256: sha256_file(&canonical)?,
            path: canonical.to_string_lossy().into_owned(),
        })
    }
}

/// Builds the `method` block, which records the frozen methodology in the report.
///
/// Several fields are deliberately redundant - `statistic` duplicates `testStatistic`,
/// `confidence` duplicates `effectInterval`, `iterations` duplicates
/// `bootstrapIterations`. That redundancy exists in the recorded schema and is
/// reproduced rather than tidied, because consumers may read either spelling.
fn method_block(family_size: usize, iterations: usize) -> Json {
    let family = i64::try_from(family_size).unwrap_or(0);
    let iterations = i64::try_from(iterations).unwrap_or(0);
    let interval_text = "deterministic 95% block bootstrap (reporting only)";
    let statistic_text = "mean oriented block log ratio";
    Json::object([
        ("design", Json::string("warmed alternating ABBA blocks")),
        ("testStatistic", Json::string(statistic_text)),
        (
            "nullHypothesis",
            Json::string("candidate and baseline labels are exchangeable within each ABBA block"),
        ),
        (
            "test",
            Json::string("exact one-sided paired sign-flip permutation"),
        ),
        (
            "multipleTesting",
            Json::string(
                "separate global Holm corrections for the regression and improvement \
                 hypothesis families across every protected metric",
            ),
        ),
        ("familyWiseAlpha", Json::Float(FAMILY_WISE_ALPHA)),
        (
            "minimumCompleteBlocksPerMetric",
            Json::Int(i64::try_from(MIN_EXACT_BLOCKS).unwrap_or(0)),
        ),
        (
            "maximumCompleteBlocksPerMetric",
            Json::Int(i64::try_from(MAX_EXACT_BLOCKS).unwrap_or(0)),
        ),
        ("hypothesisFamilySize", Json::Int(family)),
        (
            "hypothesisFamilies",
            Json::object([
                ("regression", Json::Int(family)),
                ("improvement", Json::Int(family)),
            ]),
        ),
        ("effectEstimate", Json::string("median block ratio")),
        ("effectInterval", Json::string(interval_text)),
        ("bootstrapIterations", Json::Int(iterations)),
        ("statistic", Json::string(statistic_text)),
        ("confidence", Json::string(interval_text)),
        ("iterations", Json::Int(iterations)),
        (
            "regressionRule",
            Json::string(
                "FAIL only when the global Holm-adjusted one-sided regression p-value \
                 is at most 0.05",
            ),
        ),
        (
            "improvementRule",
            Json::string(
                "classify improvement only when its global Holm-adjusted one-sided \
                 p-value is at most 0.05; KEEP also requires at least 1% median benefit",
            ),
        ),
    ])
}

/// Renders the complete report, byte-compatible with the Python evaluator.
///
/// # Errors
///
/// Returns a statistical failure from correction, classification or the reporting
/// bootstrap.
pub fn build_report(
    evidence: &ValidatedEvidence,
    manifest_path: &Path,
    manifest_sha256: &str,
    evaluator: &EvaluatorIdentity,
) -> Result<(Json, OverallVerdict), LoadError> {
    let mut metrics = evidence.metrics.clone();
    evaluator::apply_global_holm(&mut metrics).map_err(|error| evaluation_to_load(&error))?;
    let outcome =
        evaluator::global_outcome(&metrics).map_err(|error| evaluation_to_load(&error))?;

    let mut protected = Vec::with_capacity(metrics.len());
    for metric in &metrics {
        let reporting =
            ReportingStatistics::compute(&metric.id, &metric.blocks, evidence.bootstrap_iterations)
                .map_err(LoadError::Stats)?;
        protected.push(metric_json(metric, &reporting));
    }

    let method = method_block(metrics.len(), evidence.bootstrap_iterations);

    let report = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("status", Json::string("COMPLETE")),
        ("tier", Json::string(evidence.tier.clone())),
        ("candidate", identity_json(&evidence.candidate)),
        ("baseline", identity_json(&evidence.baseline)),
        ("method", method),
        (
            "inputs",
            Json::Array(evidence.inputs.iter().map(input_json).collect()),
        ),
        ("protectedMetrics", Json::Array(protected)),
        (
            "regressions",
            Json::Array(outcome.regressions.iter().cloned().map(Json::Str).collect()),
        ),
        (
            "improvements",
            Json::Array(
                outcome
                    .improvements
                    .iter()
                    .cloned()
                    .map(Json::Str)
                    .collect(),
            ),
        ),
        (
            "overallPerformanceVerdict",
            Json::string(outcome.verdict.as_str()),
        ),
        (
            "manifest",
            Json::object([
                (
                    "path",
                    Json::string(manifest_path.to_string_lossy().into_owned()),
                ),
                ("sha256", Json::string(manifest_sha256.to_owned())),
            ]),
        ),
        (
            "evaluator",
            Json::object([
                ("path", Json::string(evaluator.path.clone())),
                ("sha256", Json::string(evaluator.sha256.clone())),
            ]),
        ),
    ]);

    Ok((report, outcome.verdict))
}

fn identity_json(identity: &BinaryIdentity) -> Json {
    Json::object([
        ("commit", Json::string(identity.commit.clone())),
        ("sha256", Json::string(identity.sha256.clone())),
    ])
}

fn input_json(input: &WorkloadInput) -> Json {
    let files = input
        .files
        .iter()
        .map(|(name, digest)| (name.clone(), Json::string(digest.clone())));
    Json::object([
        ("name", Json::string(input.name.clone())),
        ("kind", Json::string(input.kind.as_str())),
        ("runDir", Json::string(input.run_dir.clone())),
        ("files", Json::object(files)),
        ("status", Json::string(input.status.clone())),
        (
            "dataQualityVerdict",
            Json::string(input.data_quality_verdict),
        ),
        (
            "collectorPerformanceVerdict",
            Json::string(input.collector_performance_verdict.clone()),
        ),
        ("hostExclusiveLock", host_lock_json(&input.host_lock)),
    ])
}

fn host_lock_json(lock: &loader::HostLock) -> Json {
    let mut members: Vec<(&str, Json)> = vec![
        ("protocolVersion", Json::Int(lock.protocol_version)),
        ("path", Json::string(lock.path.clone())),
        ("deviceInode", Json::string(lock.device_inode.clone())),
        ("mode", Json::string(lock.mode.clone())),
        ("keeperPid", Json::Int(lock.keeper_pid)),
        (
            "keeperStarttime",
            Json::string(lock.keeper_starttime.clone()),
        ),
        ("keeperExe", Json::string(lock.keeper_exe.clone())),
        ("parentPid", Json::Int(lock.parent_pid)),
        (
            "parentStarttime",
            Json::string(lock.parent_starttime.clone()),
        ),
        (
            "keeperHelper",
            Json::object([
                ("path", Json::string(lock.keeper_helper.path.clone())),
                ("sha256", Json::string(lock.keeper_helper.sha256.clone())),
            ]),
        ),
        ("required", Json::Bool(true)),
    ];
    if let Some(contract) = &lock.contract {
        members.push((
            "contract",
            Json::object([
                ("path", Json::string(contract.path.clone())),
                ("sha256", Json::string(contract.sha256.clone())),
            ]),
        ));
    }
    Json::object(members)
}

fn metric_json(metric: &DeterministicMetric, reporting: &ReportingStatistics) -> Json {
    let classification = metric
        .classification
        .expect("correction runs before serialisation");
    Json::object([
        ("id", Json::string(metric.id.clone())),
        ("workload", Json::string(metric.workload.clone())),
        ("measure", Json::string(metric.measure.clone())),
        ("unit", Json::string(metric.unit.clone())),
        ("direction", Json::string(metric.direction.as_str())),
        (
            "blocks",
            Json::Array(metric.blocks.iter().copied().map(Json::Float).collect()),
        ),
        (
            "blockCount",
            Json::Int(i64::try_from(metric.blocks.len()).unwrap_or(0)),
        ),
        (
            "medianCandidateVsBaseline",
            Json::Float(metric.median_ratio),
        ),
        (
            "bootstrap95",
            Json::Array(vec![
                Json::Float(reporting.bootstrap95[0]),
                Json::Float(reporting.bootstrap95[1]),
            ]),
        ),
        (
            "meanLogCandidateBenefit",
            Json::Float(metric.mean_log_benefit),
        ),
        ("rawPValue", Json::Float(metric.raw_p_value)),
        (
            "holmAdjustedPValue",
            metric.adjusted_p_value.map_or(Json::Null, Json::Float),
        ),
        (
            "significant",
            Json::Bool(classification == Classification::Regression),
        ),
        (
            "improvementRawPValue",
            Json::Float(metric.improvement_raw_p_value),
        ),
        (
            "improvementHolmAdjustedPValue",
            metric
                .improvement_adjusted_p_value
                .map_or(Json::Null, Json::Float),
        ),
        (
            "improvementSignificant",
            Json::Bool(
                metric
                    .improvement_adjusted_p_value
                    .is_some_and(|value| value <= FAMILY_WISE_ALPHA),
            ),
        ),
        ("classification", Json::string(classification.as_str())),
        ("pass", Json::Bool(classification.passes())),
    ])
}

/// Renders the invalid-evidence report the Python evaluator writes on failure.
#[must_use]
pub fn invalid_report(
    manifest_path: &Path,
    manifest_sha256: Option<&str>,
    errors: &[String],
    evaluator: &EvaluatorIdentity,
) -> Json {
    Json::object([
        ("schemaVersion", Json::Int(1)),
        ("status", Json::string("INVALID")),
        (
            "manifest",
            Json::object([
                (
                    "path",
                    Json::string(manifest_path.to_string_lossy().into_owned()),
                ),
                (
                    "sha256",
                    manifest_sha256.map_or(Json::Null, |digest| Json::string(digest.to_owned())),
                ),
            ]),
        ),
        (
            "errors",
            Json::Array(errors.iter().cloned().map(Json::Str).collect()),
        ),
        (
            "overallPerformanceVerdict",
            Json::string(OverallVerdict::Invalid.as_str()),
        ),
        (
            "evaluator",
            Json::object([
                ("path", Json::string(evaluator.path.clone())),
                ("sha256", Json::string(evaluator.sha256.clone())),
            ]),
        ),
    ])
}

/// Why the command refused its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// A path argument was not absolute.
    NotAbsolute {
        /// Which argument.
        argument: &'static str,
        /// What was given.
        given: String,
    },
    /// The output path already exists.
    OutputExists {
        /// The offending path.
        path: String,
    },
    /// The output's parent directory does not exist.
    OutputParentMissing {
        /// The offending directory.
        path: String,
    },
    /// The report could not be written.
    Write {
        /// The offending path.
        path: String,
        /// The operating-system message.
        message: String,
    },
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute { argument, given } => {
                write!(formatter, "--{argument} must be absolute: {given}")
            }
            Self::OutputExists { path } => write!(formatter, "output must not exist: {path}"),
            Self::OutputParentMissing { path } => {
                write!(formatter, "output parent does not exist: {path}")
            }
            Self::Write { path, message } => {
                write!(formatter, "cannot write {path}: {message}")
            }
        }
    }
}

impl std::error::Error for CliError {}

/// Validates the argument contract before any evidence is read.
///
/// Reproduces the Python entry point exactly: both paths absolute, the output must
/// not already exist and must not be a symlink, and the output's parent must be a
/// directory. These are argument errors rather than evidence errors, so they are
/// reported without producing a report file at all.
///
/// # Errors
///
/// Returns the specific argument violation.
pub fn validate_paths(manifest: &Path, output: &Path) -> Result<(), CliError> {
    if !manifest.is_absolute() {
        return Err(CliError::NotAbsolute {
            argument: "manifest",
            given: manifest.to_string_lossy().into_owned(),
        });
    }
    if !output.is_absolute() {
        return Err(CliError::NotAbsolute {
            argument: "output",
            given: output.to_string_lossy().into_owned(),
        });
    }
    if output.exists() || std::fs::symlink_metadata(output).is_ok() {
        return Err(CliError::OutputExists {
            path: output.to_string_lossy().into_owned(),
        });
    }
    let parent = output.parent().unwrap_or(Path::new("/"));
    if !parent.is_dir() {
        return Err(CliError::OutputParentMissing {
            path: parent.to_string_lossy().into_owned(),
        });
    }
    Ok(())
}

/// Runs the evaluator end to end and writes the report.
///
/// Returns the verdict whose [`OverallVerdict::exit_code`] the caller should use. A
/// report is written in both the successful and the inadmissible case, matching the
/// original: a rejected gate still leaves an artifact explaining why.
///
/// # Errors
///
/// Returns [`CliError`] for an argument or write failure. Evidence failures are not
/// errors here; they produce an `INVALID` report and the corresponding verdict.
pub fn evaluate_to_file(
    manifest_path: &Path,
    output_path: &Path,
) -> Result<OverallVerdict, CliError> {
    validate_paths(manifest_path, output_path)?;
    let evaluator = EvaluatorIdentity::current().map_err(|error| CliError::Write {
        path: "<current executable>".to_owned(),
        message: error.to_string(),
    })?;

    let manifest_sha = sha256_file(manifest_path).ok();
    let (document, verdict) = match manifest_sha.as_deref() {
        Some(digest) => match load_manifest(manifest_path)
            .and_then(|evidence| build_report(&evidence, manifest_path, digest, &evaluator))
        {
            Ok((document, verdict)) => (document, verdict),
            Err(error) => (
                invalid_report(
                    manifest_path,
                    manifest_sha.as_deref(),
                    &[error.to_string()],
                    &evaluator,
                ),
                OverallVerdict::Invalid,
            ),
        },
        None => (
            invalid_report(
                manifest_path,
                None,
                &[format!(
                    "cannot read {}: unreadable",
                    manifest_path.display()
                )],
                &evaluator,
            ),
            OverallVerdict::Invalid,
        ),
    };

    write_new(output_path, &document.to_python_json())?;
    Ok(verdict)
}

/// Writes a file that must not already exist.
fn write_new(path: &Path, contents: &str) -> Result<(), CliError> {
    use std::io::Write as _;
    let mut handle = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CliError::Write {
            path: path.to_string_lossy().into_owned(),
            message: error.to_string(),
        })?;
    handle
        .write_all(contents.as_bytes())
        .map_err(|error| CliError::Write {
            path: path.to_string_lossy().into_owned(),
            message: error.to_string(),
        })
}

/// Renders a report with the two implementation-identity fields normalised.
///
/// Test-only: the recorded parity run is complete and its result is archived in
/// `benchmarks/evidence/evaluator-authority-transfer-acceptance.json`. The function
/// stays so the normalisation rule remains executable and testable rather than
/// existing only as prose in that artifact.
#[cfg(test)]
///
/// The frozen parity normalisation set is exactly `evaluator.path` and
/// `evaluator.sha256`. `evaluator.path` differs even between two Python runs from
/// different checkouts, and `evaluator.sha256` identifies the implementation, so both
/// must differ by construction. Nothing else may be normalised: any other difference
/// is a finding.
#[must_use]
pub fn normalise_for_parity(document: &str) -> String {
    let mut out = String::with_capacity(document.len());
    let mut in_evaluator = false;
    for line in document.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("\"evaluator\": {") {
            in_evaluator = true;
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if in_evaluator {
            if trimmed.starts_with("\"path\":") {
                out.push_str("    \"path\": \"<normalised>\",\n");
                continue;
            }
            if trimmed.starts_with("\"sha256\":") {
                out.push_str("    \"sha256\": \"<normalised>\"\n");
                continue;
            }
            if trimmed.starts_with('}') {
                in_evaluator = false;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths_are_refused_for_both_arguments() {
        let absolute = Path::new("/tmp/rr-dev-parity-out.json");
        assert!(matches!(
            validate_paths(Path::new("relative.json"), absolute),
            Err(CliError::NotAbsolute {
                argument: "manifest",
                ..
            })
        ));
        assert!(matches!(
            validate_paths(Path::new("/tmp/m.json"), Path::new("relative.json")),
            Err(CliError::NotAbsolute {
                argument: "output",
                ..
            })
        ));
    }

    #[test]
    fn an_existing_output_is_refused_rather_than_truncated() {
        // The distinction matters: truncating first and then failing would destroy a
        // previous report while producing nothing usable.
        let temp = std::env::temp_dir().join(format!("rr-dev-exists-{}", std::process::id()));
        std::fs::write(&temp, b"previous report").expect("write fixture");
        let error = validate_paths(Path::new("/tmp/m.json"), &temp).expect_err("must refuse");
        assert!(matches!(error, CliError::OutputExists { .. }));
        assert_eq!(
            std::fs::read_to_string(&temp).expect("still readable"),
            "previous report",
            "the existing file must be untouched"
        );
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn a_missing_output_parent_is_refused() {
        let missing = Path::new("/tmp/rr-dev-no-such-dir-xyz/report.json");
        assert!(matches!(
            validate_paths(Path::new("/tmp/m.json"), missing),
            Err(CliError::OutputParentMissing { .. })
        ));
    }

    #[test]
    fn write_new_refuses_to_overwrite() {
        let temp = std::env::temp_dir().join(format!("rr-dev-writenew-{}", std::process::id()));
        std::fs::write(&temp, b"first").expect("fixture");
        assert!(matches!(
            write_new(&temp, "second"),
            Err(CliError::Write { .. })
        ));
        assert_eq!(std::fs::read_to_string(&temp).expect("readable"), "first");
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn parity_normalisation_touches_only_the_two_frozen_fields() {
        let document = concat!(
            "{\n",
            "  \"evaluator\": {\n",
            "    \"path\": \"/some/where/rr-dev\",\n",
            "    \"sha256\": \"deadbeef\"\n",
            "  },\n",
            "  \"manifest\": {\n",
            "    \"path\": \"/kept/path\",\n",
            "    \"sha256\": \"kept-digest\"\n",
            "  }\n",
            "}\n"
        );
        let normalised = normalise_for_parity(document);
        assert!(normalised.contains("\"path\": \"<normalised>\""));
        assert!(normalised.contains("\"sha256\": \"<normalised>\""));
        assert!(
            normalised.contains("/kept/path"),
            "the manifest path must NOT be normalised: {normalised}"
        );
        assert!(
            normalised.contains("kept-digest"),
            "the manifest digest must NOT be normalised: {normalised}"
        );
    }

    #[test]
    fn an_invalid_report_carries_the_expected_shape() {
        let evaluator = EvaluatorIdentity {
            path: "/rr-dev".to_owned(),
            sha256: "a".repeat(64),
        };
        let rendered = invalid_report(
            Path::new("/tmp/m.json"),
            Some("b".repeat(64).as_str()),
            &["something failed".to_owned()],
            &evaluator,
        )
        .to_python_json();
        assert!(rendered.contains("\"status\": \"INVALID\""));
        assert!(rendered.contains("\"overallPerformanceVerdict\": \"INVALID\""));
        assert!(rendered.contains("\"errors\": [\n    \"something failed\"\n  ]"));
        assert!(rendered.ends_with("}\n"));
    }

    #[test]
    fn an_unreadable_manifest_records_a_null_digest() {
        let evaluator = EvaluatorIdentity {
            path: "/rr-dev".to_owned(),
            sha256: "a".repeat(64),
        };
        let rendered = invalid_report(
            Path::new("/tmp/missing.json"),
            None,
            &["cannot read".to_owned()],
            &evaluator,
        )
        .to_python_json();
        assert!(
            rendered.contains("\"sha256\": null"),
            "an unhashable manifest records null, matching the original: {rendered}"
        );
    }

    #[test]
    fn the_evaluator_identifies_the_running_executable() {
        let identity = EvaluatorIdentity::current().expect("the test binary is readable");
        assert!(identity.path.starts_with('/'), "{}", identity.path);
        assert_eq!(identity.sha256.len(), 64);
        assert!(identity.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
