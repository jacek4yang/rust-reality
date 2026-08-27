//! The evidence loader: files on disk to validated, typed evidence.
//!
//! Transcribed from Part II of `tools/inventory/evaluator-specification.md`, which was
//! itself read out of the Python evaluator. This is parity work: where the legacy rules
//! are awkward they are reproduced, not tidied.
//!
//! # One validation pass feeds both consumers
//!
//! [`ValidatedEvidence`] carries the protected metrics *and* the report `inputs`
//! entries, produced together by the same pass. That is structural rather than
//! stylistic: if `inputs` were rebuilt afterwards from the manifest, a report could
//! claim a set of files that differs from the set actually validated, and nothing would
//! detect it.
//!
//! # Six legacy semantics that must not be unified
//!
//! Each of these looks like an opportunity to share code and is not:
//!
//! 1. `summary.failures` is the integer `0` in paired evidence and an empty **array**
//!    in matrix evidence.
//! 2. The paired success marker is verified against `environment.json`; the matrix
//!    marker against `run-contract.json`.
//! 3. Matrix blocks are consecutive `sampleIndex` pairs. The interleave governs raw
//!    execution order only; pairing is index arithmetic.
//! 4. Raw sample order is compared as an exact sequence, never as a set and never
//!    after sorting.
//! 5. Setup p99 reads a precomputed field; fallback p99 pools every
//!    `perRequestSeconds` value across the cell and then takes a nearest-rank quantile.
//! 6. Metric identifiers sanitise the cell key, so `bidi:1:1` becomes `bidi_1_1`.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use super::{
    bootstrap::sha256,
    contract::{self, CellKey, MatrixRole},
    evaluator::DeterministicMetric,
    evidence::{EvidenceError, WorkloadKind, is_sha256_hex, positive_number},
    json_in::{self, FieldError, Value},
    stats::{self, Direction, MAX_EXACT_BLOCKS, MIN_EXACT_BLOCKS},
};

/// The host-lock protocol version the evaluator accepts.
const HOST_LOCK_PROTOCOL_VERSION: i64 = 1;

/// Why evidence was refused during loading.
#[derive(Debug, Clone, PartialEq)]
pub enum LoadError {
    /// A file could not be read.
    Io {
        /// The path that failed.
        path: String,
        /// The operating-system message.
        message: String,
    },
    /// A document did not parse as JSON.
    Syntax {
        /// The path that failed.
        path: String,
        /// The parser message.
        message: String,
    },
    /// A document parsed but its root was not an object.
    NotAnObject {
        /// The path that failed.
        path: String,
    },
    /// A required field was absent or the wrong shape.
    Field(FieldError),
    /// A rule specific to evidence admissibility failed.
    Rule {
        /// Which workload or check reported it.
        context: String,
        /// What went wrong.
        message: String,
    },
    /// An underlying admissibility failure.
    Evidence(EvidenceError),
    /// An underlying contract failure.
    Contract(contract::ContractError),
    /// An underlying statistical failure.
    Stats(stats::StatsError),
}

impl From<FieldError> for LoadError {
    fn from(error: FieldError) -> Self {
        Self::Field(error)
    }
}

impl From<EvidenceError> for LoadError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

impl From<contract::ContractError> for LoadError {
    fn from(error: contract::ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<stats::StatsError> for LoadError {
    fn from(error: stats::StatsError) -> Self {
        Self::Stats(error)
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, message } => write!(formatter, "cannot read {path}: {message}"),
            Self::Syntax { path, message } => {
                write!(formatter, "cannot read JSON {path}: {message}")
            }
            Self::NotAnObject { path } => {
                write!(formatter, "JSON root is not an object: {path}")
            }
            Self::Field(error) => write!(formatter, "{error}"),
            Self::Rule { context, message } => write!(formatter, "{context}: {message}"),
            Self::Evidence(error) => write!(formatter, "{error}"),
            Self::Contract(error) => write!(formatter, "{error}"),
            Self::Stats(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {}

fn rule(context: &str, message: impl Into<String>) -> LoadError {
    LoadError::Rule {
        context: context.to_owned(),
        message: message.into(),
    }
}

/// Reads and parses a JSON document whose root must be an object.
///
/// # Errors
///
/// Returns [`LoadError::Io`], [`LoadError::Syntax`] or [`LoadError::NotAnObject`].
pub fn load_json(path: &Path) -> Result<Value, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|error| LoadError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let value = json_in::parse(&text).map_err(|message| LoadError::Syntax {
        path: path.display().to_string(),
        message,
    })?;
    if !matches!(value, Value::Object(_)) {
        return Err(LoadError::NotAnObject {
            path: path.display().to_string(),
        });
    }
    Ok(value)
}

/// Reads a JSON Lines file, skipping blank lines.
///
/// # Errors
///
/// Returns [`LoadError::Io`] or [`LoadError::Syntax`].
pub fn load_jsonl(path: &Path) -> Result<Vec<Value>, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|error| LoadError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    json_in::parse_lines(&text).map_err(|message| LoadError::Syntax {
        path: path.display().to_string(),
        message,
    })
}

/// Computes the SHA-256 of a file as lowercase hex.
///
/// # Errors
///
/// Returns [`LoadError::Io`] when the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<String, LoadError> {
    let bytes = std::fs::read(path).map_err(|error| LoadError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    Ok(sha256(&bytes).iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    }))
}

/// Verifies a workload's declared files and returns the observed digests.
///
/// Reproduces `verify_files`, including the containment guard: a declared file must
/// resolve to a direct child of `runDir`, so a manifest cannot reach outside the
/// evidence directory through a crafted name.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn verify_files(
    run_dir_text: &str,
    files: &BTreeMap<String, Value>,
    kind: WorkloadKind,
) -> Result<(PathBuf, BTreeMap<String, String>), LoadError> {
    let context = kind.as_str();
    if !run_dir_text.starts_with('/') {
        return Err(rule(context, "runDir must be absolute"));
    }
    let run_dir = PathBuf::from(run_dir_text);
    let metadata =
        std::fs::symlink_metadata(&run_dir).map_err(|_| rule(context, "invalid runDir"))?;
    if !metadata.is_dir() {
        return Err(rule(context, "invalid runDir"));
    }

    let expected: Vec<&str> = kind.required_files().to_vec();
    let declared: Vec<&str> = files.keys().map(String::as_str).collect();
    let mut sorted_expected = expected.clone();
    sorted_expected.sort_unstable();
    let mut sorted_declared = declared;
    sorted_declared.sort_unstable();
    if sorted_declared != sorted_expected {
        return Err(rule(
            context,
            format!("files must be exactly {sorted_expected:?}"),
        ));
    }

    let canonical_run_dir = run_dir
        .canonicalize()
        .map_err(|_| rule(context, "invalid runDir"))?;
    let mut observed = BTreeMap::new();
    for relative in sorted_expected {
        let path = format!("{context}.files.{relative}");
        let expected_sha = files
            .get(relative)
            .ok_or_else(|| rule(context, format!("invalid expected SHA for {relative}")))?
            .as_str(&path)?;
        if !is_sha256_hex(expected_sha) {
            return Err(rule(
                context,
                format!("invalid expected SHA for {relative}"),
            ));
        }
        let file = run_dir.join(relative);
        let file_meta = std::fs::symlink_metadata(&file)
            .map_err(|_| rule(context, format!("invalid {relative}")))?;
        if !file_meta.is_file() {
            return Err(rule(context, format!("invalid {relative}")));
        }
        let resolved = file
            .canonicalize()
            .map_err(|_| rule(context, format!("invalid {relative}")))?;
        if resolved.parent() != Some(canonical_run_dir.as_path()) {
            return Err(rule(context, "path escaped runDir"));
        }
        let actual = sha256_file(&file)?;
        if actual != expected_sha {
            return Err(rule(context, format!("SHA mismatch for {relative}")));
        }
        observed.insert(relative.to_owned(), actual);
    }
    Ok((run_dir, observed))
}

/// A verified host-exclusive-lock identity, normalised as the report records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLock {
    /// Protocol version, always 1 for this schema.
    pub protocol_version: i64,
    /// Absolute path of the lock file.
    pub path: String,
    /// `device:inode` of the lock file at run time.
    pub device_inode: String,
    /// Lock mode, always `dedicatedKeeper`.
    pub mode: String,
    /// Keeper process identifier.
    pub keeper_pid: i64,
    /// Keeper process start time, as a decimal string.
    pub keeper_starttime: String,
    /// Absolute path of the keeper executable.
    pub keeper_exe: String,
    /// Parent process identifier.
    pub parent_pid: i64,
    /// Parent process start time, as a decimal string.
    pub parent_starttime: String,
    /// Keeper helper script identity.
    pub keeper_helper: ArtifactIdentity,
    /// Benchmark contract identity, attached after lock verification.
    pub contract: Option<ArtifactIdentity>,
}

/// A path plus digest identity for an external artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIdentity {
    /// Absolute path recorded at run time.
    pub path: String,
    /// SHA-256 recorded at run time.
    pub sha256: String,
}

impl HostLock {
    /// The seven-field projection every workload must agree on.
    ///
    /// Reproduces `coordination_identity`. Two workloads that ran under different
    /// locks were not mutually exclusive, so their measurements are not comparable.
    #[must_use]
    pub fn coordination_identity(&self) -> Option<[String; 7]> {
        let contract = self.contract.as_ref()?;
        Some([
            self.protocol_version.to_string(),
            self.path.clone(),
            self.device_inode.clone(),
            self.mode.clone(),
            self.keeper_exe.clone(),
            self.keeper_helper.sha256.clone(),
            contract.sha256.clone(),
        ])
    }
}

/// Whether an external artifact is resolved live or from the evidence archive.
///
/// Kept explicit so a fresh benchmark can never pass because an archived object
/// happens to exist. See ADR 0009.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractSource {
    /// Verify the artifact at the path recorded by the evidence.
    Live,
    /// Verify a content-addressed object from the evidence archive.
    Archived,
}

/// Verifies a `path` plus `sha256` identity against the live filesystem.
///
/// # Errors
///
/// Returns the specific rule that failed.
fn verify_artifact_identity(
    value: &Value,
    context: &str,
    label: &str,
) -> Result<ArtifactIdentity, LoadError> {
    let path_text = value.str_field(context, "path")?;
    let digest = value.str_field(context, "sha256")?;
    if !path_text.starts_with('/') || !is_sha256_hex(digest) {
        return Err(rule(context, format!("{label} identity missing")));
    }
    let path = Path::new(path_text);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| rule(context, format!("{label} path is invalid")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(rule(context, format!("{label} path is invalid")));
    }
    let resolved = path
        .canonicalize()
        .map_err(|_| rule(context, format!("{label} path is invalid")))?;
    if resolved.to_string_lossy() != path_text {
        return Err(rule(context, format!("{label} path is invalid")));
    }
    if sha256_file(path)? != digest {
        return Err(rule(context, format!("{label} SHA-256 no longer matches")));
    }
    Ok(ArtifactIdentity {
        path: path_text.to_owned(),
        sha256: digest.to_owned(),
    })
}

/// Verifies host-lock metadata against the live filesystem.
///
/// Reproduces `verify_host_lock_metadata`, including the `device:inode` comparison.
/// ADR 0009 records why that check cannot be made durable; it is preserved here
/// because current-schema parity requires it.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn verify_host_lock_metadata(value: &Value, context: &str) -> Result<HostLock, LoadError> {
    value.require_int(context, "protocolVersion", HOST_LOCK_PROTOCOL_VERSION)?;
    value.require_bool(context, "required", true)?;
    value.require_str(context, "mode", "dedicatedKeeper")?;

    let path_text = value.str_field(context, "path")?;
    if !path_text.starts_with('/') {
        return Err(rule(context, "host lock path is not absolute"));
    }
    let path = Path::new(path_text);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| rule(context, "host lock path is not a canonical regular file"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(rule(
            context,
            "host lock path is not a canonical regular file",
        ));
    }
    if path
        .canonicalize()
        .is_ok_and(|resolved| resolved.to_string_lossy() == path_text)
        .eq(&false)
    {
        return Err(rule(
            context,
            "host lock path is not a canonical regular file",
        ));
    }

    let device_inode = value.str_field(context, "deviceInode")?;
    if !valid_device_inode(device_inode) {
        return Err(rule(context, "host lock device/inode is invalid"));
    }
    let observed = observed_device_inode(path)
        .ok_or_else(|| rule(context, "host lock device/inode is invalid"))?;
    if observed != device_inode {
        return Err(rule(
            context,
            "host lock device/inode no longer matches its path",
        ));
    }

    let keeper_pid = value.int_field(context, "keeperPid")?;
    let parent_pid = value.int_field(context, "parentPid")?;
    for (label, pid) in [("keeperPid", keeper_pid), ("parentPid", parent_pid)] {
        if pid <= 1 {
            return Err(rule(context, format!("{label} is invalid")));
        }
    }
    let keeper_starttime = decimal_string(value, context, "keeperStarttime")?;
    let parent_starttime = decimal_string(value, context, "parentStarttime")?;

    let keeper_exe = value.str_field(context, "keeperExe")?;
    if !keeper_exe.starts_with('/') {
        return Err(rule(context, "keeper executable path is invalid"));
    }
    let exe = Path::new(keeper_exe);
    if !exe.is_file()
        || !exe
            .canonicalize()
            .is_ok_and(|resolved| resolved.to_string_lossy() == keeper_exe)
    {
        return Err(rule(context, "keeper executable path is not canonical"));
    }

    let helper = verify_artifact_identity(
        value.field(context, "keeperHelper")?,
        &format!("{context}.keeperHelper"),
        "keeper helper",
    )?;

    Ok(HostLock {
        protocol_version: HOST_LOCK_PROTOCOL_VERSION,
        path: path_text.to_owned(),
        device_inode: device_inode.to_owned(),
        mode: "dedicatedKeeper".to_owned(),
        keeper_pid,
        keeper_starttime,
        keeper_exe: keeper_exe.to_owned(),
        parent_pid,
        parent_starttime,
        keeper_helper: helper,
        contract: None,
    })
}

fn decimal_string(value: &Value, context: &str, key: &str) -> Result<String, LoadError> {
    let text = value.str_field(context, key)?;
    let valid = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && text.parse::<u64>().is_ok_and(|number| number > 0);
    if valid {
        Ok(text.to_owned())
    } else {
        Err(rule(context, format!("{key} is invalid")))
    }
}

fn valid_device_inode(text: &str) -> bool {
    let Some((device, inode)) = text.split_once(':') else {
        return false;
    };
    let positive = |part: &str| {
        !part.is_empty() && !part.starts_with('0') && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    positive(device) && positive(inode)
}

#[cfg(unix)]
fn observed_device_inode(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).ok()?;
    Some(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn observed_device_inode(_path: &Path) -> Option<String> {
    None
}

/// Verifies a collector success marker.
///
/// Reproduces `verify_success_marker`. The `evidence_path` argument differs by
/// workload kind and is the reason the two callers are not unified: a paired run
/// attests `environment.json` while the matrix attests `run-contract.json`.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn verify_success_marker(
    marker: &Value,
    evidence_path: &Path,
    run_id: &str,
    collector: &str,
    context: &str,
) -> Result<(), LoadError> {
    marker.require_int(context, "schemaVersion", 1)?;
    marker.require_str(context, "status", "COMPLETE")?;
    if marker.int_field(context, "exitCode")? != 0 {
        return Err(rule(context, "collector exit code is not zero"));
    }
    if run_id.is_empty() || marker.str_field(context, "runId")? != run_id {
        return Err(rule(context, "success marker run ID mismatch"));
    }
    if marker.str_field(context, "collector")? != collector {
        return Err(rule(context, "success marker collector mismatch"));
    }
    let evidence = marker.field(context, "evidence")?;
    let resolved = evidence_path
        .canonicalize()
        .map_err(|_| rule(context, "marker evidence path mismatch"))?;
    if evidence.str_field(context, "path")? != resolved.to_string_lossy() {
        return Err(rule(context, "marker evidence path mismatch"));
    }
    if evidence.str_field(context, "sha256")? != sha256_file(evidence_path)? {
        return Err(rule(context, "marker evidence SHA-256 mismatch"));
    }
    Ok(())
}

/// One report `inputs` entry, derived from the same pass that produced the metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadInput {
    /// Workload name from the manifest.
    pub name: String,
    /// Workload kind.
    pub kind: WorkloadKind,
    /// Evidence directory.
    pub run_dir: String,
    /// Observed digests for every declared file.
    pub files: BTreeMap<String, String>,
    /// Collector status.
    pub status: String,
    /// Always `PASS`; the evaluator emits it as a constant.
    pub data_quality_verdict: &'static str,
    /// The verdict the collector declined to make.
    pub collector_performance_verdict: String,
    /// Verified host-lock identity.
    pub host_lock: HostLock,
}

/// Validated evidence: metrics and report inputs from one pass.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedEvidence {
    /// Protected metrics in evaluation order.
    pub metrics: Vec<DeterministicMetric>,
    /// Report `inputs` entries in manifest order.
    pub inputs: Vec<WorkloadInput>,
}

/// Sanitises a cell key into a metric identifier component.
///
/// Reproduces `re.sub(r"[^A-Za-z0-9._-]+", "_", key)`: each maximal run of
/// disallowed characters collapses to a single underscore, so `bidi:1:1` becomes
/// `bidi_1_1` rather than `bidi__1__1`.
#[must_use]
pub fn sanitise_metric_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut in_run = false;
    for character in key.chars() {
        let allowed = character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-');
        if allowed {
            out.push(character);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out
}

/// Builds one ratio per block from a field, keyed by block, implementation and concurrency.
///
/// Reproduces `ratios_for_rows`.
///
/// # Errors
///
/// Returns a rule error when a cell has no samples, or an admissibility error when a
/// value is not a positive finite number.
pub fn ratios_for_rows(
    rows: &[Value],
    blocks: i64,
    concurrency: i64,
    field: &str,
    context: &str,
) -> Result<Vec<f64>, LoadError> {
    let mut ratios = Vec::new();
    for block in 1..=blocks {
        let mut sides: BTreeMap<&str, Vec<f64>> = BTreeMap::new();
        for row in rows {
            let matches_cell = row.optional("block").and_then(|v| v.as_int("block").ok())
                == Some(block)
                && row
                    .optional("concurrency")
                    .and_then(|v| v.as_int("concurrency").ok())
                    == Some(concurrency);
            if !matches_cell {
                continue;
            }
            let implementation = row
                .optional("implementation")
                .and_then(|v| v.as_str("implementation").ok())
                .ok_or_else(|| rule(context, "row implementation missing"))?;
            let value = positive_number(
                row.optional(field).and_then(|v| v.as_f64(field).ok()),
                &format!("{field} row"),
            )?;
            let slot = if implementation == "baseline" {
                "baseline"
            } else if implementation == "candidate" {
                "candidate"
            } else {
                continue;
            };
            sides.entry(slot).or_default().push(value);
        }
        let mut medians = BTreeMap::new();
        for side in ["baseline", "candidate"] {
            let values = sides.get(side).filter(|values| !values.is_empty());
            let Some(values) = values else {
                return Err(rule(
                    context,
                    format!("block {block} {side} {field}: no samples"),
                ));
            };
            medians.insert(side, stats::median(values)?);
        }
        ratios.push(medians["candidate"] / medians["baseline"]);
    }
    Ok(ratios)
}

/// Builds the server-CPU metric from a summary block table.
///
/// Reproduces `cpu_metrics`, including the cross-check that the recorded
/// `candidateVsBaseline` agrees with the recomputed ratio to a relative tolerance of
/// `1e-9`. That check exists because the collector and the evaluator compute the same
/// ratio independently, and a disagreement means one of them is wrong.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn cpu_metric(
    summary: &Value,
    field: &str,
    blocks: i64,
    workload: &str,
    unit: &str,
) -> Result<DeterministicMetric, LoadError> {
    let cpu = summary
        .optional(field)
        .ok_or_else(|| rule(workload, format!("missing {field}")))?;
    let rows = cpu.array_field(workload, "blocks")?;
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) != blocks {
        return Err(rule(workload, "incomplete CPU blocks"));
    }
    let mut ratios = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let path = format!("{workload}.{field}.blocks[{index}]");
        let baseline = positive_number(
            row.optional("baseline").and_then(|v| v.as_f64(&path).ok()),
            &format!("{workload} CPU baseline"),
        )?;
        let candidate = positive_number(
            row.optional("candidate").and_then(|v| v.as_f64(&path).ok()),
            &format!("{workload} CPU candidate"),
        )?;
        let ratio = candidate / baseline;
        let recorded = positive_number(
            row.optional("candidateVsBaseline")
                .and_then(|v| v.as_f64(&path).ok()),
            &format!("{workload} CPU recorded ratio"),
        )?;
        if !is_close(ratio, recorded, 1e-9) {
            return Err(rule(
                workload,
                format!("CPU ratio mismatch in block {}", index + 1),
            ));
        }
        ratios.push(ratio);
    }
    Ok(DeterministicMetric::evaluate(
        format!("{workload}:server-cpu"),
        workload,
        "serverCpu",
        unit,
        Direction::LowerIsBetter,
        &ratios,
    )?)
}

/// Reproduces `math.isclose(a, b, rel_tol=tol)` with a zero absolute tolerance.
#[expect(
    clippy::float_cmp,
    reason = "the exact-equality fast path mirrors Python's math.isclose, which \
              returns True immediately when the two values are identical"
)]
#[must_use]
pub fn is_close(left: f64, right: f64, relative: f64) -> bool {
    if left == right {
        return true;
    }
    if !left.is_finite() || !right.is_finite() {
        return false;
    }
    (left - right).abs() <= relative * left.abs().max(right.abs())
}

/// Validates one matrix cell and returns its two metrics.
///
/// The block rule is the one worth reading carefully: blocks are consecutive
/// `sampleIndex` pairs, `{0,1}`, `{2,3}` and so on. The interleave order is validated
/// separately and governs *execution* sequence only. Pairing by interleave chunks
/// instead would produce plausible ratios over the wrong groupings.
///
/// # Errors
///
/// Returns the specific rule that failed.
#[expect(
    clippy::too_many_lines,
    reason = "one cell's validation is a single legacy dataflow; splitting it would \
              hide the consecutive-index pairing rule this function exists to make visible"
)]
pub fn matrix_cell_metrics(
    key: &str,
    cell: &Value,
    rows: &[Value],
    workload: &str,
) -> Result<Vec<DeterministicMetric>, LoadError> {
    let context = format!("matrix cell {key}");
    let count = usize::try_from(cell.int_field(&context, "samplesPerImplementation")?)
        .map_err(|_| rule(&context, "sample count is invalid"))?;
    let blocks = contract::validate_sample_count(key, count)?;

    let interleave_values = cell.array_field(&context, "interleaveOrder")?;
    let mut interleave = Vec::with_capacity(interleave_values.len());
    for entry in interleave_values {
        let text = entry.as_str(&format!("{context}.interleaveOrder"))?;
        interleave.push(
            MatrixRole::parse(text)
                .ok_or_else(|| rule(&context, "interleave implementations invalid"))?,
        );
    }
    contract::validate_interleave(key, &interleave, count)?;

    let scenario = cell.str_field(&context, "scenario")?;
    let direction = cell.str_field(&context, "direction")?;
    let payload_mib = cell.int_field(&context, "payloadMiB")?;
    let concurrency = cell.int_field(&context, "concurrency")?;
    let payload_bytes = payload_mib * 1024 * 1024;

    // Selection preserves file order, which the exact-order check below depends on.
    let selected: Vec<&Value> = rows
        .iter()
        .filter(|row| {
            row.optional("scenario").and_then(|v| v.as_str("s").ok()) == Some(scenario)
                && row.optional("direction").and_then(|v| v.as_str("d").ok()) == Some(direction)
                && row
                    .optional("payloadBytes")
                    .and_then(|v| v.as_int("p").ok())
                    == Some(payload_bytes)
                && row.optional("concurrency").and_then(|v| v.as_int("c").ok()) == Some(concurrency)
        })
        .collect();

    // Expected order: walk the interleave, handing each arm the next index it has not used.
    let mut next_index: BTreeMap<MatrixRole, i64> = BTreeMap::new();
    let mut expected_order = Vec::with_capacity(interleave.len());
    for role in &interleave {
        let index = next_index.entry(*role).or_insert(0);
        expected_order.push((*role, *index));
        *index += 1;
    }
    let mut actual_order = Vec::with_capacity(selected.len());
    for row in &selected {
        let implementation = row
            .optional("implementation")
            .and_then(|v| v.as_str("i").ok())
            .and_then(MatrixRole::parse)
            .ok_or_else(|| rule(&context, "raw sample implementation invalid"))?;
        let index = row
            .optional("sampleIndex")
            .and_then(|v| v.as_int("s").ok())
            .ok_or_else(|| rule(&context, "raw sample index missing"))?;
        actual_order.push((implementation, index));
    }
    if actual_order != expected_order {
        return Err(rule(
            &context,
            "raw sample order disagrees with interleaveOrder",
        ));
    }

    // Per paired arm: exact cardinality, exact index coverage, and per-row validity.
    let mut per_arm: BTreeMap<MatrixRole, Vec<&Value>> = BTreeMap::new();
    for role in [MatrixRole::Baseline, MatrixRole::Final] {
        let arm: Vec<&Value> = selected
            .iter()
            .copied()
            .filter(|row| {
                row.optional("implementation")
                    .and_then(|v| v.as_str("i").ok())
                    .and_then(MatrixRole::parse)
                    == Some(role)
            })
            .collect();
        if arm.len() != count {
            return Err(rule(
                &context,
                format!("{} sample count mismatch", role.as_str()),
            ));
        }
        let mut indexes: Vec<i64> = arm
            .iter()
            .filter_map(|row| row.optional("sampleIndex").and_then(|v| v.as_int("s").ok()))
            .collect();
        indexes.sort_unstable();
        let expected: Vec<i64> = (0..i64::try_from(count).unwrap_or(0)).collect();
        if indexes != expected {
            return Err(rule(
                &context,
                format!("{} sample indexes incomplete", role.as_str()),
            ));
        }
        for row in &arm {
            if row.optional("invalid").and_then(|v| v.as_bool("i").ok()) != Some(false)
                || row
                    .optional("bytesVerified")
                    .and_then(|v| v.as_bool("b").ok())
                    != Some(true)
            {
                return Err(rule(&context, "invalid/unverified sample"));
            }
            positive_number(
                row.optional("throughputMiBPerSecond")
                    .and_then(|v| v.as_f64("t").ok()),
                &format!("{context} throughput"),
            )?;
            let latencies = row.array_field(&context, "perRequestSeconds")?;
            if latencies.is_empty() {
                return Err(rule(&context, "latency samples missing"));
            }
            for latency in latencies {
                positive_number(
                    latency.as_f64("perRequestSeconds").ok(),
                    &format!("{context} latency"),
                )?;
            }
        }
        per_arm.insert(role, arm);
    }

    // The Xray arm is validated for completeness but never paired.
    let xray: Vec<&Value> = selected
        .iter()
        .copied()
        .filter(|row| {
            row.optional("implementation")
                .and_then(|v| v.as_str("i").ok())
                .and_then(MatrixRole::parse)
                == Some(MatrixRole::Xray)
        })
        .collect();
    let mut xray_indexes: Vec<i64> = xray
        .iter()
        .filter_map(|row| row.optional("sampleIndex").and_then(|v| v.as_int("s").ok()))
        .collect();
    xray_indexes.sort_unstable();
    if xray.len() != count
        || xray_indexes != (0..i64::try_from(count).unwrap_or(0)).collect::<Vec<i64>>()
    {
        return Err(rule(&context, "Xray comparator samples incomplete"));
    }

    // Blocks are consecutive sampleIndex pairs, not interleave chunks.
    let mut throughput_ratios = Vec::with_capacity(blocks);
    let mut latency_ratios = Vec::with_capacity(blocks);
    for block in 0..blocks {
        let wanted = [
            i64::try_from(2 * block).unwrap_or(0),
            i64::try_from(2 * block + 1).unwrap_or(0),
        ];
        let mut throughput = BTreeMap::new();
        let mut tail = BTreeMap::new();
        for role in [MatrixRole::Baseline, MatrixRole::Final] {
            let arm = &per_arm[&role];
            let block_rows: Vec<&&Value> = arm
                .iter()
                .filter(|row| {
                    row.optional("sampleIndex")
                        .and_then(|v| v.as_int("s").ok())
                        .is_some_and(|index| wanted.contains(&index))
                })
                .collect();
            if block_rows.len() != 2 {
                return Err(rule(&context, format!("block {} incomplete", block + 1)));
            }
            let values: Vec<f64> = block_rows
                .iter()
                .filter_map(|row| {
                    row.optional("throughputMiBPerSecond")
                        .and_then(|v| v.as_f64("t").ok())
                })
                .collect();
            throughput.insert(role, stats::median(&values)?);
            let mut pooled = Vec::new();
            for row in &block_rows {
                for latency in row.array_field(&context, "perRequestSeconds")? {
                    pooled.push(latency.as_f64("perRequestSeconds")?);
                }
            }
            tail.insert(role, stats::nearest_rank(&pooled, 0.99)?);
        }
        throughput_ratios.push(throughput[&MatrixRole::Final] / throughput[&MatrixRole::Baseline]);
        latency_ratios.push(tail[&MatrixRole::Final] / tail[&MatrixRole::Baseline]);
    }

    let safe = sanitise_metric_key(key);
    Ok(vec![
        DeterministicMetric::evaluate(
            format!("{workload}:{safe}:throughput"),
            workload,
            "throughput",
            "MiBPerSecond",
            Direction::HigherIsBetter,
            &throughput_ratios,
        )?,
        DeterministicMetric::evaluate(
            format!("{workload}:{safe}:p99-latency"),
            workload,
            "p99Latency",
            "seconds",
            Direction::LowerIsBetter,
            &latency_ratios,
        )?,
    ])
}

/// Collects the cell keys present in raw matrix samples, excluding integrity rows.
///
/// # Errors
///
/// Returns a rule error when a row lacks the fields needed to form a key.
pub fn raw_cell_keys(rows: &[Value]) -> Result<Vec<CellKey>, LoadError> {
    let mut keys = Vec::new();
    for row in rows {
        let scenario = row
            .optional("scenario")
            .and_then(|v| v.as_str("scenario").ok())
            .ok_or_else(|| rule("matrix", "raw row is missing scenario"))?;
        if scenario == contract::INTEGRITY_SCENARIO {
            continue;
        }
        // `payloadBytes` defaults to zero in the original, matching `.get(field, 0)`.
        let payload = row
            .optional("payloadBytes")
            .and_then(|v| v.as_int("payloadBytes").ok())
            .unwrap_or(0);
        let concurrency = row
            .optional("concurrency")
            .and_then(|v| v.as_int("concurrency").ok())
            .ok_or_else(|| rule("matrix", "raw row is missing concurrency"))?;
        let key = CellKey::from_bytes(
            scenario.to_owned(),
            u64::try_from(payload).unwrap_or(0),
            u32::try_from(concurrency).unwrap_or(0),
        );
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Block-count validation shared by both paired kinds.
///
/// # Errors
///
/// Returns a rule error outside the exact gate's range.
pub fn validate_block_count(blocks: i64, context: &str) -> Result<(), LoadError> {
    let within = i64::try_from(MIN_EXACT_BLOCKS).unwrap_or(0) <= blocks
        && blocks <= i64::try_from(MAX_EXACT_BLOCKS).unwrap_or(i64::MAX);
    if within {
        return Ok(());
    }
    Err(rule(
        context,
        format!("formal gate requires {MIN_EXACT_BLOCKS}..{MAX_EXACT_BLOCKS} complete ABBA blocks"),
    ))
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "parity tests compare against recorded evidence exactly; an epsilon \
              would defeat their purpose"
)]
mod tests {
    use super::*;

    fn doc(text: &str) -> Value {
        json_in::parse(text).expect("fixture must parse")
    }

    #[test]
    fn metric_key_sanitisation_matches_the_legacy_regex() {
        // A maximal run of disallowed characters collapses to ONE underscore, which is
        // what `[^A-Za-z0-9._-]+` with a `+` quantifier does.
        assert_eq!(sanitise_metric_key("bidi:1:1"), "bidi_1_1");
        assert_eq!(
            sanitise_metric_key("direct-upload:32:1"),
            "direct-upload_32_1"
        );
        assert_eq!(sanitise_metric_key("a::b"), "a_b", "a run collapses to one");
        assert_eq!(
            sanitise_metric_key("keep.dots_and-dashes"),
            "keep.dots_and-dashes"
        );
        assert_eq!(sanitise_metric_key("sp ace"), "sp_ace");
    }

    #[test]
    fn the_recorded_matrix_metric_ids_are_reproduced() {
        // From the recorded v1.8.0 report.
        assert_eq!(
            format!("matrix-c1:{}:throughput", sanitise_metric_key("bidi:1:1")),
            "matrix-c1:bidi_1_1:throughput"
        );
        assert_eq!(
            format!(
                "matrix-c1:{}:p99-latency",
                sanitise_metric_key("direct-upload:32:1")
            ),
            "matrix-c1:direct-upload_32_1:p99-latency"
        );
    }

    #[test]
    fn is_close_matches_the_python_relative_tolerance() {
        assert!(is_close(1.0, 1.0, 1e-9));
        assert!(is_close(1.0, 1.0 + 1e-10, 1e-9));
        assert!(!is_close(1.0, 1.0 + 1e-8, 1e-9));
        assert!(!is_close(f64::NAN, f64::NAN, 1e-9));
        assert!(is_close(0.0, 0.0, 1e-9));
    }

    #[test]
    fn device_inode_format_is_validated_strictly() {
        assert!(valid_device_inode("43:509895"));
        assert!(!valid_device_inode("0:1"), "a leading zero is refused");
        assert!(!valid_device_inode("43:0"), "inode zero is refused");
        assert!(!valid_device_inode("43"), "both parts are required");
        assert!(!valid_device_inode("a:b"));
        assert!(!valid_device_inode(""));
    }

    #[test]
    fn ratios_for_rows_pairs_by_block_implementation_and_concurrency() {
        let rows = vec![
            doc(r#"{"block":1,"implementation":"baseline","concurrency":1,"t":100.0}"#),
            doc(r#"{"block":1,"implementation":"candidate","concurrency":1,"t":110.0}"#),
            // A different concurrency must not contaminate the c1 cell.
            doc(r#"{"block":1,"implementation":"baseline","concurrency":32,"t":400.0}"#),
            doc(r#"{"block":1,"implementation":"candidate","concurrency":32,"t":200.0}"#),
        ];
        assert_eq!(
            ratios_for_rows(&rows, 1, 1, "t", "ctx").expect("valid"),
            vec![1.1]
        );
        assert_eq!(
            ratios_for_rows(&rows, 1, 32, "t", "ctx").expect("valid"),
            vec![0.5]
        );
    }

    #[test]
    fn a_missing_side_in_any_block_fails_closed() {
        let rows = vec![doc(
            r#"{"block":1,"implementation":"candidate","concurrency":1,"t":110.0}"#,
        )];
        let error = ratios_for_rows(&rows, 1, 1, "t", "ctx").expect_err("must fail");
        assert!(matches!(error, LoadError::Rule { .. }), "{error}");
    }

    #[test]
    fn a_non_positive_measurement_is_refused_before_any_ratio() {
        let rows = vec![
            doc(r#"{"block":1,"implementation":"baseline","concurrency":1,"t":0.0}"#),
            doc(r#"{"block":1,"implementation":"candidate","concurrency":1,"t":110.0}"#),
        ];
        assert!(matches!(
            ratios_for_rows(&rows, 1, 1, "t", "ctx"),
            Err(LoadError::Evidence(_))
        ));
    }

    #[test]
    fn integrity_rows_are_excluded_from_cell_coverage() {
        let rows = vec![
            doc(r#"{"scenario":"bidi","payloadBytes":1048576,"concurrency":1}"#),
            doc(r#"{"scenario":"integrity","payloadBytes":1048576,"concurrency":1}"#),
        ];
        let keys = raw_cell_keys(&rows).expect("valid");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].to_string(), "bidi:1:1");
    }

    #[test]
    fn block_count_bounds_match_the_exact_gate() {
        assert!(validate_block_count(12, "k").is_ok());
        assert!(validate_block_count(16, "k").is_ok());
        assert!(validate_block_count(11, "k").is_err());
        assert!(validate_block_count(17, "k").is_err());
    }

    #[test]
    fn the_cpu_metric_rejects_a_disagreeing_recorded_ratio() {
        use std::fmt::Write as _;

        // The collector and evaluator compute this ratio independently; disagreement
        // means one of them is wrong, so it must not be silently preferred.
        let mut blocks = String::from("[");
        for index in 0..12 {
            if index > 0 {
                blocks.push(',');
            }
            blocks.push_str(r#"{"baseline":2.0,"candidate":1.0,"candidateVsBaseline":0.5}"#);
        }
        blocks.push(']');
        let good = doc(&format!(r#"{{"serverCpuPerGiB":{{"blocks":{blocks}}}}}"#));
        let metric = cpu_metric(&good, "serverCpuPerGiB", 12, "fallback", "secondsPerGiB")
            .expect("consistent ratios must be accepted");
        assert_eq!(metric.id, "fallback:server-cpu");
        assert_eq!(metric.direction, Direction::LowerIsBetter);

        // Twelve blocks, one of which disagrees. Using a single block would let the
        // block-count check reject it first and mask the cross-check entirely - a
        // masking that mutation testing caught.
        let mut mixed = String::from("[");
        for index in 0..12 {
            if index > 0 {
                mixed.push(',');
            }
            let recorded = if index == 7 { "0.9" } else { "0.5" };
            let _ = write!(
                mixed,
                r#"{{"baseline":2.0,"candidate":1.0,"candidateVsBaseline":{recorded}}}"#
            );
        }
        mixed.push(']');
        let bad = doc(&format!(r#"{{"serverCpuPerGiB":{{"blocks":{mixed}}}}}"#));
        let error = cpu_metric(&bad, "serverCpuPerGiB", 12, "fallback", "secondsPerGiB")
            .expect_err("a disagreeing recorded ratio must be refused");
        assert!(
            matches!(error, LoadError::Rule { ref message, .. } if message.contains("block 8")),
            "the failing block must be named: {error}"
        );
    }

    #[test]
    fn the_cpu_metric_requires_exactly_the_declared_block_count() {
        let one = doc(
            r#"{"serverCpuPerGiB":{"blocks":[{"baseline":2.0,"candidate":1.0,"candidateVsBaseline":0.5}]}}"#,
        );
        assert!(
            cpu_metric(&one, "serverCpuPerGiB", 12, "fallback", "secondsPerGiB").is_err(),
            "one block cannot satisfy a twelve-block declaration"
        );
    }

    #[test]
    fn host_lock_coordination_identity_needs_a_contract() {
        let lock = HostLock {
            protocol_version: 1,
            path: "/tmp/x.lock".to_owned(),
            device_inode: "43:1".to_owned(),
            mode: "dedicatedKeeper".to_owned(),
            keeper_pid: 2,
            keeper_starttime: "10".to_owned(),
            keeper_exe: "/usr/bin/python3".to_owned(),
            parent_pid: 3,
            parent_starttime: "9".to_owned(),
            keeper_helper: ArtifactIdentity {
                path: "/h.py".to_owned(),
                sha256: "a".repeat(64),
            },
            contract: None,
        };
        assert!(
            lock.coordination_identity().is_none(),
            "a lock without a verified contract has no coordination identity"
        );
        let with_contract = HostLock {
            contract: Some(ArtifactIdentity {
                path: "/c.sh".to_owned(),
                sha256: "b".repeat(64),
            }),
            ..lock
        };
        let identity = with_contract
            .coordination_identity()
            .expect("a verified contract yields an identity");
        assert_eq!(identity.len(), 7, "the projection is exactly seven fields");
        assert_eq!(identity[5], "a".repeat(64), "keeper helper digest");
        assert_eq!(identity[6], "b".repeat(64), "contract digest");
    }

    /// Locates a file beside the checkout, where evidence archives live.
    fn evidence(relative: &str) -> Option<std::path::PathBuf> {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|ancestor| ancestor.join(relative))
            .find(|candidate| candidate.is_file())
    }

    #[test]
    fn the_real_recorded_matrix_evidence_reproduces_its_24_metrics() {
        // The first proof that the loader implementation matches the specification:
        // run the actual v1.8.0 matrix evidence through the real code path and require
        // the recorded metric identities and values, not merely a plausible count.
        let Some(summary_path) =
            evidence("artifacts/v180-release-gate/gates/matrix-formal-r01/summary.json")
        else {
            eprintln!("recorded matrix evidence unavailable; skipping");
            return;
        };
        let samples_path = summary_path
            .parent()
            .expect("summary has a parent")
            .join("samples.jsonl");

        let summary = load_json(&summary_path).expect("summary must load");
        let rows = load_jsonl(&samples_path).expect("samples must load");
        let cells = summary
            .as_object("summary")
            .expect("summary is an object")
            .get("cells")
            .expect("cells are present")
            .as_object("summary.cells")
            .expect("cells is an object");

        // Coverage must hold in both directions before any metric is produced.
        let summary_keys: Vec<CellKey> = cells
            .keys()
            .map(|key| CellKey::parse(key).expect("recorded cell keys parse"))
            .collect();
        let raw_keys = raw_cell_keys(&rows).expect("raw keys");
        contract::validate_coverage(&summary_keys, &raw_keys)
            .expect("recorded summary cells must exactly cover raw samples");

        let mut metrics = Vec::new();
        for (key, cell) in cells {
            metrics.extend(
                matrix_cell_metrics(key, cell, &rows, "matrix-c1")
                    .unwrap_or_else(|error| panic!("cell {key}: {error}")),
            );
        }

        assert_eq!(
            metrics.len(),
            24,
            "twelve protected cells yield twenty-four matrix metrics"
        );

        // Spot-check two recorded metrics by identity and by value. These are the
        // smallest and largest raw p-values in the recorded family, so they exercise
        // both orientations and the full deterministic path.
        let p99 = metrics
            .iter()
            .find(|metric| metric.id == "matrix-c1:direct-upload_32_1:p99-latency")
            .expect("the recorded p99 metric identity must be reproduced");
        assert_eq!(p99.direction, Direction::LowerIsBetter);
        assert_eq!(p99.blocks.len(), 12);
        assert_eq!(p99.median_ratio, 1.028_454_451_654_484_5);
        assert_eq!(p99.mean_log_benefit, -0.058_513_158_852_144_67);
        assert_eq!(p99.raw_p_value, 0.052_734_375);
        assert_eq!(p99.improvement_raw_p_value, 0.947_509_765_625);

        let throughput = metrics
            .iter()
            .find(|metric| metric.id == "matrix-c1:framed-upload_32_1:throughput")
            .expect("the recorded throughput metric identity must be reproduced");
        assert_eq!(throughput.direction, Direction::HigherIsBetter);
        assert_eq!(throughput.median_ratio, 1.006_459_443_017_899_5);
        assert_eq!(throughput.raw_p_value, 0.966_552_734_375);
        assert_eq!(throughput.improvement_raw_p_value, 0.033_691_406_25);

        // Every metric must carry one of the two expected suffixes and no duplicates.
        let mut ids: Vec<&str> = metrics.iter().map(|metric| metric.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "metric identities must be unique");
        for id in &ids {
            assert!(
                id.ends_with(":throughput") || id.ends_with(":p99-latency"),
                "unexpected metric identity {id}"
            );
            assert!(id.starts_with("matrix-c1:"), "unexpected workload in {id}");
        }
    }

    #[test]
    fn raw_sample_order_is_compared_as_a_sequence_not_a_set() {
        // Reordering rows preserves the multiset but breaks the recorded execution
        // sequence. Sorting before comparison would accept this, which mutation
        // testing showed the real-evidence test alone does not catch.
        let Some(summary_path) =
            evidence("artifacts/v180-release-gate/gates/matrix-formal-r01/summary.json")
        else {
            eprintln!("recorded matrix evidence unavailable; skipping");
            return;
        };
        let samples_path = summary_path
            .parent()
            .expect("summary has a parent")
            .join("samples.jsonl");
        let summary = load_json(&summary_path).expect("summary loads");
        let rows = load_jsonl(&samples_path).expect("samples load");
        let cells = summary
            .as_object("summary")
            .expect("object")
            .get("cells")
            .expect("cells")
            .as_object("cells")
            .expect("object");
        let (key, cell) = cells.iter().next().expect("at least one cell");

        // Baseline: the untouched order is accepted.
        matrix_cell_metrics(key, cell, &rows, "matrix-c1").expect("recorded order is valid");

        // Reverse every row. Same elements, different sequence.
        let mut reversed = rows.clone();
        reversed.reverse();
        let error = matrix_cell_metrics(key, cell, &reversed, "matrix-c1")
            .expect_err("a permuted execution order must be refused");
        assert!(
            matches!(error, LoadError::Rule { ref message, .. }
                     if message.contains("raw sample order")),
            "the order rule must be what rejects it: {error}"
        );
    }

    #[test]
    fn a_declared_file_outside_the_run_directory_is_refused() {
        // The containment guard: a manifest must not be able to reach outside the
        // evidence directory through a crafted relative name.
        let temp = std::env::temp_dir().join(format!("rr-dev-escape-{}", std::process::id()));
        let run_dir = temp.join("run");
        std::fs::create_dir_all(&run_dir).expect("temp run dir");
        let outside = temp.join("outside.json");
        std::fs::write(&outside, b"{}").expect("write outside file");
        // A symlink named like a required file, pointing out of the run directory.
        let planted = run_dir.join("summary.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &planted).expect("symlink");

        let digest = sha256_file(&outside).expect("hash");
        let mut files = BTreeMap::new();
        for name in WorkloadKind::Matrix.required_files() {
            files.insert((*name).to_owned(), Value::Str(digest.clone()));
        }
        let result = verify_files(&run_dir.to_string_lossy(), &files, WorkloadKind::Matrix);
        assert!(
            result.is_err(),
            "a symlink escaping the run directory must be refused"
        );

        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn contract_source_modes_are_distinct_values() {
        // ADR 0009: there is no fallback from live to archived, so the two modes must
        // be separate values a caller has to choose between.
        assert_ne!(ContractSource::Live, ContractSource::Archived);
    }
}
