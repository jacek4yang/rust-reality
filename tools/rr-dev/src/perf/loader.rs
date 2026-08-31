//! The evidence loader: files on disk to validated, typed evidence.
//!
//! Transcribed from the frozen evaluator specification
//! (`docs/en/operations/frozen-evaluator-specification.md`), which was itself read
//! out of the Python evaluator. This is parity work: where the legacy rules are
//! awkward they are reproduced, not tidied.
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
    evidence::{
        BinaryBuildIds, BinaryIdentity, EvidenceError, WorkloadKind, is_build_id_hex,
        is_sha256_hex, positive_number,
    },
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
#[cfg(test)]
pub fn load_json(path: &Path) -> Result<Value, LoadError> {
    let bytes = std::fs::read(path).map_err(|error| LoadError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    parse_json_bytes(path, &bytes)
}

/// Parses a JSON object from bytes already read by the caller.
///
/// Keeping parsing separate from I/O lets the evidence loader hash and parse the
/// same immutable snapshot instead of reopening a path after verification.
///
/// # Errors
///
/// Returns [`LoadError::Syntax`] or [`LoadError::NotAnObject`].
pub fn parse_json_bytes(path: &Path, bytes: &[u8]) -> Result<Value, LoadError> {
    let text = std::str::from_utf8(bytes).map_err(|error| LoadError::Syntax {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let value = json_in::parse(text).map_err(|message| LoadError::Syntax {
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
#[cfg(test)]
pub fn load_jsonl(path: &Path) -> Result<Vec<Value>, LoadError> {
    let bytes = std::fs::read(path).map_err(|error| LoadError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    parse_jsonl_bytes(path, &bytes)
}

fn parse_jsonl_bytes(path: &Path, bytes: &[u8]) -> Result<Vec<Value>, LoadError> {
    let text = std::str::from_utf8(bytes).map_err(|error| LoadError::Syntax {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    json_in::parse_lines(text).map_err(|message| LoadError::Syntax {
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
    Ok(sha256_bytes(&bytes))
}

/// Computes lowercase SHA-256 for an in-memory file snapshot.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    sha256(bytes).iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// One workload's declared files, read once and bound to their observed digests.
pub struct VerifiedFiles {
    run_dir: PathBuf,
    hashes: BTreeMap<String, String>,
    contents: BTreeMap<String, Vec<u8>>,
}

impl VerifiedFiles {
    fn json(&self, name: &str) -> Result<Value, LoadError> {
        let bytes = self
            .contents
            .get(name)
            .expect("callers only request files required by the workload kind");
        parse_json_bytes(&self.run_dir.join(name), bytes)
    }

    fn jsonl(&self, name: &str) -> Result<Vec<Value>, LoadError> {
        let bytes = self
            .contents
            .get(name)
            .expect("callers only request files required by the workload kind");
        parse_jsonl_bytes(&self.run_dir.join(name), bytes)
    }
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
) -> Result<VerifiedFiles, LoadError> {
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
    let mut contents = BTreeMap::new();
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
        let bytes = std::fs::read(&resolved).map_err(|error| LoadError::Io {
            path: resolved.display().to_string(),
            message: error.to_string(),
        })?;
        let actual = sha256_bytes(&bytes);
        if actual != expected_sha {
            return Err(rule(context, format!("SHA mismatch for {relative}")));
        }
        observed.insert(relative.to_owned(), actual);
        contents.insert(relative.to_owned(), bytes);
    }
    Ok(VerifiedFiles {
        run_dir,
        hashes: observed,
        contents,
    })
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
    evidence_sha256: &str,
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
    if evidence.str_field(context, "sha256")? != evidence_sha256 {
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
    /// Independently recorded Build IDs, retained for cross-workload consistency.
    pub build_ids: BinaryBuildIds,
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
    let requests_per_connection = match direction {
        "download" | "upload" => 1_u32,
        "bidi" => 2,
        _ => return Err(rule(&context, "direction is invalid")),
    };
    let payload_mib = u64::try_from(cell.int_field(&context, "payloadMiB")?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| rule(&context, "payloadMiB must be positive"))?;
    let concurrency = u32::try_from(cell.int_field(&context, "concurrency")?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| rule(&context, "concurrency must be positive"))?;
    verify_matrix_cell_key(key, scenario, payload_mib, concurrency, &context)?;
    let payload_bytes = i64::try_from(
        payload_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| rule(&context, "payloadMiB is too large"))?,
    )
    .map_err(|_| rule(&context, "payloadMiB is too large"))?;
    let concurrency_i64 = i64::from(concurrency);
    let latency_count = usize::try_from(
        concurrency
            .checked_mul(requests_per_connection)
            .ok_or_else(|| rule(&context, "latency count is too large"))?,
    )
    .unwrap_or(usize::MAX);

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
                && row.optional("concurrency").and_then(|v| v.as_int("c").ok())
                    == Some(concurrency_i64)
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
            validate_matrix_sample(row, &context, latency_count)?;
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
    for row in &xray {
        validate_matrix_sample(row, &context, latency_count)?;
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

fn verify_matrix_cell_key(
    key: &str,
    scenario: &str,
    payload_mib: u64,
    concurrency: u32,
    context: &str,
) -> Result<(), LoadError> {
    let declared = CellKey {
        scenario: scenario.to_owned(),
        payload_mib,
        concurrency,
    };
    if CellKey::parse(key).as_ref() == Some(&declared) {
        Ok(())
    } else {
        Err(rule(context, "summary key disagrees with the cell fields"))
    }
}

/// Validates the measurement fields shared by every matrix arm.
///
/// Xray is not part of the candidate/baseline ratio, but it is part of the formal
/// interoperability run. Treating a failed or partially timed Xray row as complete
/// would let a broken comparator run inherit the protected verdict from the other arms.
fn validate_matrix_sample(
    row: &Value,
    context: &str,
    latency_count: usize,
) -> Result<(), LoadError> {
    if row.optional("invalid").and_then(|v| v.as_bool("i").ok()) != Some(false)
        || row
            .optional("bytesVerified")
            .and_then(|v| v.as_bool("b").ok())
            != Some(true)
    {
        return Err(rule(context, "invalid/unverified sample"));
    }
    positive_number(
        row.optional("throughputMiBPerSecond")
            .and_then(|v| v.as_f64("t").ok()),
        &format!("{context} throughput"),
    )?;
    let latencies = row.array_field(context, "perRequestSeconds")?;
    if latencies.len() != latency_count {
        return Err(rule(context, "per-request latency count mismatch"));
    }
    for latency in latencies {
        positive_number(
            latency.as_f64("perRequestSeconds").ok(),
            &format!("{context} latency"),
        )?;
    }
    Ok(())
}

/// Parses the `concurrencies` field, which the schema records either way.
///
/// Setup evidence records a whitespace-separated string such as `"1 32"`; the schema
/// also permits a JSON array. Both forms are accepted because the original accepts
/// both, and the result must be non-empty, duplicate-free and strictly positive.
///
/// # Errors
///
/// Returns a rule error for any other shape or an invalid value.
pub fn parse_concurrencies(value: &Value, context: &str) -> Result<Vec<i64>, LoadError> {
    let parsed = match value {
        Value::Str(text) => {
            let mut out = Vec::new();
            for token in text.split_whitespace() {
                out.push(
                    token
                        .parse::<i64>()
                        .map_err(|_| rule(context, "invalid concurrencies"))?,
                );
            }
            out
        }
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.push(item.as_int(&format!("{context}.concurrencies"))?);
            }
            out
        }
        _ => return Err(rule(context, "concurrencies missing")),
    };
    let mut unique = parsed.clone();
    unique.sort_unstable();
    unique.dedup();
    if parsed.is_empty() || unique.len() != parsed.len() || parsed.iter().any(|value| *value <= 0) {
        return Err(rule(context, "concurrencies invalid"));
    }
    Ok(parsed)
}

/// Reads an integer field from a raw row without a full accessor path.
fn row_int(row: &Value, key: &str) -> Option<i64> {
    row.optional(key).and_then(|value| value.as_int(key).ok())
}

/// Reads a string field from a raw row.
fn row_str<'row>(row: &'row Value, key: &str) -> Option<&'row str> {
    row.optional(key).and_then(|value| value.as_str(key).ok())
}

/// Validates one paired ABBA workload and returns its metrics and report input.
///
/// Reproduces `evaluate_pair_run`. The two callers differ in three ways that are
/// deliberately not abstracted away: the collector name, the throughput field, and how
/// the p99 metric is derived. Setup reads a precomputed `p99Seconds` per row; fallback
/// pools every `perRequestSeconds` value in the cell and takes a nearest-rank quantile.
///
/// # Errors
///
/// Returns the specific rule that failed.
#[expect(
    clippy::too_many_lines,
    reason = "this is one legacy validation dataflow; splitting it would separate rules \
              that must be read together to see what the gate actually requires"
)]
pub fn evaluate_pair_run(
    name: &str,
    kind: WorkloadKind,
    run_dir_text: &str,
    files: &BTreeMap<String, Value>,
    candidate: &BinaryIdentity,
    baseline: &BinaryIdentity,
) -> Result<(Vec<DeterministicMetric>, WorkloadInput), LoadError> {
    let context = kind.as_str();
    let verified = verify_files(run_dir_text, files, kind)?;

    let summary = verified.json("summary.json")?;
    let environment = verified.json("environment.json")?;
    let completion = verified.json("completion.json")?;
    let order = verified.json("order.json")?;
    let rows = verified.jsonl("raw-samples.jsonl")?;

    // The paired marker attests environment.json; the matrix marker attests
    // run-contract.json. Keeping the call sites separate is what preserves that.
    let collector = match kind {
        WorkloadKind::SetupAbba => "benchmark-setup-rate",
        WorkloadKind::FallbackAbba => "benchmark-fallback-ab",
        WorkloadKind::Matrix => return Err(rule(context, "matrix is not a paired run")),
    };
    let run_id = environment.str_field(context, "runId")?.to_owned();
    verify_success_marker(
        &completion,
        &verified.run_dir.join("environment.json"),
        &verified.hashes["environment.json"],
        &run_id,
        collector,
        context,
    )?;

    summary.require_str(context, "status", "COMPLETE")?;
    summary.require_str(context, "performanceVerdict", "NOT_EVALUATED")?;
    // Paired evidence records failures as the integer zero.
    summary.require_int(context, "failures", 0)?;

    let (host_lock, build_ids) =
        verify_pair_environment(&environment, candidate, baseline, context)?;

    let blocks = environment.int_field(context, "blocks")?;
    validate_block_count(blocks, context)?;
    let samples = environment.int_field(context, "samplesPerSlot")?;
    if samples < 1 {
        return Err(rule(context, "samples invalid"));
    }
    let concurrencies = parse_concurrencies(environment.field(context, "concurrencies")?, context)?;

    let expected_slots = blocks
        .checked_mul(4)
        .ok_or_else(|| rule(context, "slot count overflow"))?;
    summary.require_int(context, "slotCount", expected_slots)?;
    let concurrency_count = i64::try_from(concurrencies.len())
        .map_err(|_| rule(context, "raw sample count overflow"))?;
    let expected_rows = expected_slots
        .checked_mul(concurrency_count)
        .and_then(|value| value.checked_mul(samples))
        .ok_or_else(|| rule(context, "raw sample count overflow"))?;
    summary.require_int(context, "rawSampleCount", expected_rows)?;
    if i64::try_from(rows.len()).unwrap_or(-1) != expected_rows {
        return Err(rule(
            context,
            "raw sample count disagrees with the run plan",
        ));
    }

    // Order manifest, then every raw row must agree with the slot it claims.
    let slots = order.array_field(context, "slots")?;
    let mut expected_slots: BTreeMap<(i64, i64), String> = BTreeMap::new();
    let mut order_slots = Vec::with_capacity(slots.len());
    for slot in slots {
        let block = slot.int_field(context, "block")?;
        let position = slot.int_field(context, "position")?;
        let implementation = slot.str_field(context, "implementation")?.to_owned();
        expected_slots.insert((block, position), implementation.clone());
        order_slots.push((block, position, implementation));
    }
    verify_pair_order(&order_slots, blocks, context)?;

    let mut grouped: BTreeMap<(i64, i64, i64), Vec<&Value>> = BTreeMap::new();
    for row in &rows {
        let block = row_int(row, "block")
            .ok_or_else(|| rule(context, "raw row references an unknown slot"))?;
        let position = row_int(row, "position")
            .ok_or_else(|| rule(context, "raw row references an unknown slot"))?;
        let expected = expected_slots
            .get(&(block, position))
            .ok_or_else(|| rule(context, "raw row references an unknown slot"))?;
        if row_str(row, "implementation") != Some(expected.as_str()) {
            return Err(rule(context, "raw row implementation disagrees with order"));
        }
        let concurrency =
            row_int(row, "concurrency").ok_or_else(|| rule(context, "unexpected concurrency"))?;
        if !concurrencies.contains(&concurrency) {
            return Err(rule(context, "unexpected concurrency"));
        }
        if row_int(row, "failed") != Some(0) {
            return Err(rule(context, "raw row has failures"));
        }
        match kind {
            WorkloadKind::SetupAbba => {
                let expected_connections =
                    environment.int_field(context, "connectionsPerSample")?;
                if expected_connections <= 0 {
                    return Err(rule(context, "connectionsPerSample invalid"));
                }
                if row_int(row, "connections") != Some(expected_connections) {
                    return Err(rule(context, "setup row has a missing connection"));
                }
            }
            WorkloadKind::FallbackAbba => {
                let payload_mib = environment.int_field(context, "payloadMiB")?;
                let expected_bytes = payload_mib * 1024 * 1024;
                if expected_bytes <= 0 {
                    return Err(rule(context, "payloadMiB invalid"));
                }
                if row_int(row, "requests") != Some(concurrency) {
                    return Err(rule(context, "fallback request count mismatch"));
                }
                let observed = row.array_field(context, "bytesObserved")?;
                let full = i64::try_from(observed.len()).unwrap_or(-1) == concurrency
                    && observed
                        .iter()
                        .all(|value| value.as_int("bytesObserved").ok() == Some(expected_bytes));
                if !full {
                    return Err(rule(context, "fallback short read or missing byte count"));
                }
                let per_request = row.array_field(context, "perRequestSeconds")?;
                if i64::try_from(per_request.len()).unwrap_or(-1) != concurrency {
                    return Err(rule(context, "fallback latency count mismatch"));
                }
            }
            WorkloadKind::Matrix => unreachable!("guarded above"),
        }
        grouped
            .entry((block, position, concurrency))
            .or_default()
            .push(row);
    }

    // Every slot must be fully sampled, with exactly the expected sample indexes.
    for (block, position) in expected_slots.keys() {
        for concurrency in &concurrencies {
            let selected = grouped
                .get(&(*block, *position, *concurrency))
                .map_or(&[][..], Vec::as_slice);
            if i64::try_from(selected.len()).unwrap_or(-1) != samples {
                return Err(rule(
                    context,
                    format!("block {block} slot {position} c{concurrency} missing samples"),
                ));
            }
            let mut indexes: Vec<i64> = selected
                .iter()
                .filter_map(|row| row_int(row, "sampleIndex"))
                .collect();
            indexes.sort_unstable();
            if indexes != (0..samples).collect::<Vec<i64>>() {
                return Err(rule(context, "duplicate or missing sample index"));
            }
        }
    }

    let mut metrics = Vec::new();
    for concurrency in &concurrencies {
        let (throughput_field, throughput_unit) = match kind {
            WorkloadKind::SetupAbba => ("connectionsPerSecond", "connectionsPerSecond"),
            _ => ("throughputMiBPerSecond", "MiBPerSecond"),
        };
        metrics.push(DeterministicMetric::evaluate(
            format!("{name}:c{concurrency}:throughput"),
            name,
            throughput_field,
            throughput_unit,
            Direction::HigherIsBetter,
            &ratios_for_rows(&rows, blocks, *concurrency, throughput_field, context)?,
        )?);

        let tail_ratios = match kind {
            WorkloadKind::SetupAbba => {
                ratios_for_rows(&rows, blocks, *concurrency, "p99Seconds", context)?
            }
            _ => pooled_tail_ratios(&rows, blocks, *concurrency, context)?,
        };
        metrics.push(DeterministicMetric::evaluate(
            format!("{name}:c{concurrency}:p99-latency"),
            name,
            "p99Latency",
            "seconds",
            Direction::LowerIsBetter,
            &tail_ratios,
        )?);
    }

    let (cpu_field, cpu_unit) = match kind {
        WorkloadKind::SetupAbba => ("serverCpuPerConnection", "microsecondsPerConnection"),
        _ => ("serverCpuPerGiB", "secondsPerGiB"),
    };
    metrics.push(cpu_metric(&summary, cpu_field, blocks, name, cpu_unit)?);

    let input = WorkloadInput {
        name: name.to_owned(),
        kind,
        run_dir: verified.run_dir.to_string_lossy().into_owned(),
        files: verified.hashes,
        status: summary.str_field(context, "status")?.to_owned(),
        data_quality_verdict: "PASS",
        collector_performance_verdict: summary.str_field(context, "performanceVerdict")?.to_owned(),
        host_lock,
        build_ids,
    };
    Ok((metrics, input))
}

/// Fallback p99: pool every per-request latency in the cell, then nearest-rank.
///
/// Distinct from the setup path on purpose. Setup records a precomputed `p99Seconds`
/// per row and the ratio is taken over block medians of that field; fallback has no
/// such field and the quantile is computed over the pooled raw latencies, so a shared
/// implementation would silently change one of the two.
///
/// # Errors
///
/// Returns a rule error when a cell has no latencies.
pub fn pooled_tail_ratios(
    rows: &[Value],
    blocks: i64,
    concurrency: i64,
    context: &str,
) -> Result<Vec<f64>, LoadError> {
    let mut ratios = Vec::with_capacity(usize::try_from(blocks).unwrap_or(0));
    for block in 1..=blocks {
        let mut tails = BTreeMap::new();
        for side in ["baseline", "candidate"] {
            let mut pooled = Vec::new();
            for row in rows {
                let in_cell = row_int(row, "block") == Some(block)
                    && row_str(row, "implementation") == Some(side)
                    && row_int(row, "concurrency") == Some(concurrency);
                if !in_cell {
                    continue;
                }
                let latencies = row.array_field(context, "perRequestSeconds")?;
                if latencies.is_empty() {
                    return Err(rule(context, "per-request latency missing"));
                }
                for latency in latencies {
                    pooled.push(positive_number(
                        latency.as_f64("perRequestSeconds").ok(),
                        &format!("{context} request latency"),
                    )?);
                }
            }
            if pooled.is_empty() {
                return Err(rule(context, "per-request latency missing"));
            }
            tails.insert(side, stats::nearest_rank(&pooled, 0.99)?);
        }
        ratios.push(tails["candidate"] / tails["baseline"]);
    }
    Ok(ratios)
}

/// Validates a paired order manifest: four slots per block, ABBA or BAAB, alternating.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn verify_pair_order(
    slots: &[(i64, i64, String)],
    blocks: i64,
    context: &str,
) -> Result<(), LoadError> {
    let expected = usize::try_from(blocks * 4).unwrap_or(0);
    if slots.len() != expected {
        return Err(rule(
            context,
            "order manifest does not contain exactly four slots per block",
        ));
    }
    let mut previous: Option<Vec<String>> = None;
    for block in 1..=blocks {
        let mut rows: Vec<&(i64, i64, String)> =
            slots.iter().filter(|slot| slot.0 == block).collect();
        rows.sort_by_key(|slot| slot.1);
        if rows.iter().map(|slot| slot.1).collect::<Vec<i64>>() != vec![1, 2, 3, 4] {
            return Err(rule(
                context,
                format!("block {block}: positions are incomplete"),
            ));
        }
        let sequence: Vec<String> = rows.iter().map(|slot| slot.2.clone()).collect();
        let abba = ["baseline", "candidate", "candidate", "baseline"];
        let baab = ["candidate", "baseline", "baseline", "candidate"];
        if sequence != abba && sequence != baab {
            return Err(rule(context, format!("block {block}: not ABBA/BAAB")));
        }
        if previous.as_ref() == Some(&sequence) {
            return Err(rule(
                context,
                format!("block {block}: direction did not alternate"),
            ));
        }
        previous = Some(sequence);
    }
    Ok(())
}

/// Verifies a paired run's environment identity block and host lock.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn verify_pair_environment(
    environment: &Value,
    candidate: &BinaryIdentity,
    baseline: &BinaryIdentity,
    context: &str,
) -> Result<(HostLock, BinaryBuildIds), LoadError> {
    let repository = environment.field(context, "repository")?;
    if repository.field(context, "dirty")?.as_bool("dirty")? {
        return Err(rule(context, "repository was dirty"));
    }
    if repository.str_field(context, "head")? != candidate.commit {
        return Err(rule(context, "repository HEAD did not match the candidate"));
    }
    let mut observed_build_ids = BTreeMap::new();
    for (label, expected) in [("candidate", candidate), ("baseline", baseline)] {
        let observed = environment.field(context, label)?;
        let path = format!("{context}.{label}");
        if observed.str_field(&path, "sha256")? != expected.sha256 {
            return Err(rule(context, format!("{label} SHA mismatch")));
        }
        if observed.str_field(&path, "commit")? != expected.commit {
            return Err(rule(context, format!("{label} commit mismatch")));
        }
        let build_id = observed.str_field(&path, "buildId")?;
        if !is_build_id_hex(build_id) {
            return Err(rule(context, format!("{label} Build ID missing")));
        }
        observed_build_ids.insert(label, build_id.to_owned());
    }

    let lock_value = environment.field(context, "hostExclusiveLock")?;
    let current = verify_host_lock_metadata(lock_value, context)?;
    let preflight = verify_host_lock_metadata(
        lock_value.field(context, "preflight")?,
        &format!("{context} preflight"),
    )?;
    let postflight = verify_host_lock_metadata(
        lock_value.field(context, "postflight")?,
        &format!("{context} postflight"),
    )?;
    if current != preflight || current != postflight {
        return Err(rule(
            context,
            "host lock identity changed during collection",
        ));
    }

    let harness = environment.field(context, "harness")?;
    let contract = verify_artifact_identity(
        harness.field(context, "contract")?,
        &format!("{context}.harness.contract"),
        "lock contract",
    )?;
    let harness_helper = verify_artifact_identity(
        harness.field(context, "keeperHelper")?,
        &format!("{context}.harness.keeperHelper"),
        "harness keeper helper",
    )?;
    if harness_helper != current.keeper_helper {
        return Err(rule(
            context,
            "harness keeper identity disagrees with lock evidence",
        ));
    }

    let mut result = current;
    result.contract = Some(contract);
    Ok((
        result,
        BinaryBuildIds {
            candidate: observed_build_ids["candidate"].clone(),
            baseline: observed_build_ids["baseline"].clone(),
        },
    ))
}

/// Validates the formal matrix workload and returns its metrics and report input.
///
/// Reproduces `evaluate_matrix`. Note the two encodings that differ from the paired
/// path and are validated with distinct accessors: `summary.failures` is an empty
/// array here, and the success marker attests `run-contract.json` rather than
/// `environment.json`.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn evaluate_matrix_workload(
    name: &str,
    run_dir_text: &str,
    files: &BTreeMap<String, Value>,
    candidate: &BinaryIdentity,
    baseline: &BinaryIdentity,
) -> Result<(Vec<DeterministicMetric>, WorkloadInput), LoadError> {
    let kind = WorkloadKind::Matrix;
    let context = "matrix";
    let verified = verify_files(run_dir_text, files, kind)?;

    let summary = verified.json("summary.json")?;
    let run_contract = verified.json("run-contract.json")?;
    let completion = verified.json("run-completion.json")?;
    let rows = verified.jsonl("samples.jsonl")?;

    let run_id = run_contract.str_field(context, "runId")?.to_owned();
    verify_success_marker(
        &completion,
        &verified.run_dir.join("run-contract.json"),
        &verified.hashes["run-contract.json"],
        &run_id,
        "benchmark-matrix",
        context,
    )?;

    let (host_lock, build_ids) =
        verify_matrix_identity(&summary, &run_contract, candidate, baseline)?;

    verify_matrix_integrity(&summary, &rows)?;

    let cells = summary
        .field(context, "cells")?
        .as_object("matrix.summary.cells")?;
    if cells.is_empty() {
        return Err(rule(context, "no protected cells"));
    }
    verify_matrix_sample_conservation(&summary, cells, &rows)?;

    // Coverage must hold in both directions before any metric is produced.
    let mut summary_keys = Vec::with_capacity(cells.len());
    for key in cells.keys() {
        summary_keys.push(
            CellKey::parse(key)
                .ok_or_else(|| rule(context, format!("matrix cell {key} invalid")))?,
        );
    }
    let raw_keys = raw_cell_keys(&rows)?;
    contract::validate_coverage(&summary_keys, &raw_keys)?;

    let mut metrics = Vec::new();
    for (key, cell) in cells {
        metrics.extend(matrix_cell_metrics(key, cell, &rows, name)?);
    }

    let input = WorkloadInput {
        name: name.to_owned(),
        kind,
        run_dir: verified.run_dir.to_string_lossy().into_owned(),
        files: verified.hashes,
        status: summary.str_field(context, "status")?.to_owned(),
        data_quality_verdict: "PASS",
        collector_performance_verdict: summary.str_field(context, "performanceVerdict")?.to_owned(),
        host_lock,
        build_ids,
    };
    Ok((metrics, input))
}

fn verify_matrix_sample_conservation(
    summary: &Value,
    cells: &BTreeMap<String, Value>,
    rows: &[Value],
) -> Result<(), LoadError> {
    let context = "matrix";
    let totals = summary.field(context, "totals")?;
    totals.require_int(
        "matrix.totals",
        "cells",
        i64::try_from(cells.len()).map_err(|_| rule(context, "cell count overflow"))?,
    )?;
    totals.require_int(
        "matrix.totals",
        "samples",
        i64::try_from(rows.len()).map_err(|_| rule(context, "sample count overflow"))?,
    )?;

    let mut expected_protected_rows = 0_i64;
    for (key, cell) in cells {
        let count = cell.int_field(&format!("matrix cell {key}"), "samplesPerImplementation")?;
        if count <= 0 {
            return Err(rule(
                context,
                format!("matrix cell {key} sample count invalid"),
            ));
        }
        expected_protected_rows = expected_protected_rows
            .checked_add(
                count
                    .checked_mul(3)
                    .ok_or_else(|| rule(context, "sample count overflow"))?,
            )
            .ok_or_else(|| rule(context, "sample count overflow"))?;
        let implementations = cell
            .field(&format!("matrix cell {key}"), "implementations")?
            .as_object(&format!("matrix cell {key}.implementations"))?;
        if implementations.len() != MatrixRole::all().len() {
            return Err(rule(
                context,
                format!("matrix cell {key} arms are incomplete"),
            ));
        }
        for role in MatrixRole::all() {
            let aggregate = implementations
                .get(role.as_str())
                .ok_or_else(|| rule(context, format!("matrix cell {key} arm is missing")))?;
            aggregate.require_int(context, "samples", count)?;
            aggregate.require_int(context, "validSamples", count)?;
            aggregate.require_int(context, "invalidSamples", 0)?;
        }
    }
    let observed_protected_rows = rows
        .iter()
        .filter(|row| row_str(row, "scenario") != Some(contract::INTEGRITY_SCENARIO))
        .count();
    if i64::try_from(observed_protected_rows).unwrap_or(-1) != expected_protected_rows {
        return Err(rule(
            context,
            "raw protected sample count disagrees with the summary cells",
        ));
    }
    Ok(())
}

/// Verifies the matrix run's identity block and contract.
///
/// # Errors
///
/// Returns the specific rule that failed.
pub fn verify_matrix_identity(
    summary: &Value,
    run_contract: &Value,
    candidate: &BinaryIdentity,
    baseline: &BinaryIdentity,
) -> Result<(HostLock, BinaryBuildIds), LoadError> {
    let context = "matrix";
    summary.require_str(context, "status", "COMPLETE")?;
    summary.require_str(context, "performanceVerdict", "NOT_EVALUATED")?;
    // Matrix evidence records failures as an empty ARRAY, not the integer zero.
    summary.require_empty_array(context, "failures")?;
    let totals = summary.field(context, "totals")?;
    totals.require_int("matrix.totals", "invalidSamples", 0)?;

    let identity = summary.field(context, "identity")?;
    if identity.str_field("matrix.identity", "candidateCommit")? != candidate.commit {
        return Err(rule(context, "candidate commit mismatch"));
    }
    if identity.str_field("matrix.identity", "baselineCommit")? != baseline.commit {
        return Err(rule(context, "baseline commit mismatch"));
    }
    if identity.str_field("matrix.identity", "repositoryHead")? != candidate.commit {
        return Err(rule(context, "repository HEAD did not match the candidate"));
    }
    let binaries = identity.field("matrix.identity", "binaries")?;
    // The candidate arm is spelled `final` in matrix evidence.
    if binaries
        .field("matrix.identity.binaries", "final")?
        .str_field("matrix.identity.binaries.final", "sha256")?
        != candidate.sha256
    {
        return Err(rule(context, "candidate SHA mismatch"));
    }
    if binaries
        .field("matrix.identity.binaries", "baseline")?
        .str_field("matrix.identity.binaries.baseline", "sha256")?
        != baseline.sha256
    {
        return Err(rule(context, "baseline SHA mismatch"));
    }
    identity.require_bool("matrix.identity", "binariesPinned", true)?;
    let xray_sha = binaries
        .field("matrix.identity.binaries", "xray")?
        .str_field("matrix.identity.binaries.xray", "sha256")?;
    if !is_sha256_hex(xray_sha) {
        return Err(rule(context, "Xray SHA invalid"));
    }

    run_contract.require_str("matrix.contract", "phase", "complete")?;
    run_contract.require_bool("matrix.contract", "exploratory", false)?;
    if run_contract
        .field("matrix.contract", "script")?
        .str_field("matrix.contract.script", "harnessCommit")?
        != candidate.commit
    {
        return Err(rule(context, "harness commit mismatch"));
    }

    let build_ids = verify_matrix_registrations(
        run_contract.array_field("matrix.contract", "binaries")?,
        candidate,
        baseline,
        xray_sha,
    )?;

    let mut host_lock = verify_host_lock_metadata(
        run_contract.field("matrix.contract", "hostExclusiveLock")?,
        context,
    )?;
    host_lock.contract = Some(verify_artifact_identity(
        run_contract.field("matrix.contract", "contract")?,
        "matrix.contract.contract",
        "lock contract",
    )?);
    Ok((host_lock, build_ids))
}

/// Verifies that the formal matrix registered each binary exactly once and that
/// every registration agrees with the independently recorded summary identity.
fn verify_matrix_registrations(
    registered: &[Value],
    candidate: &BinaryIdentity,
    baseline: &BinaryIdentity,
    xray_sha: &str,
) -> Result<BinaryBuildIds, LoadError> {
    let context = "matrix";
    if registered.len() != 3 {
        return Err(rule(
            context,
            "contract binaries must be exactly candidate, baseline, and xray",
        ));
    }
    let mut registrations = BTreeMap::new();
    for row in registered {
        let label = row.str_field("matrix.contract.binaries", "label")?;
        if !matches!(label, "candidate" | "baseline" | "xray")
            || registrations.insert(label, row).is_some()
        {
            return Err(rule(
                context,
                "contract binary labels must be unique candidate, baseline, and xray",
            ));
        }
    }
    let mut observed_build_ids = BTreeMap::new();
    for (label, expected) in [("candidate", candidate), ("baseline", baseline)] {
        let row = registrations
            .get(label)
            .copied()
            .ok_or_else(|| rule(context, format!("contract {label} SHA mismatch")))?;
        let path = format!("matrix.contract.binaries.{label}");
        if row.str_field(&path, "sha256")? != expected.sha256 {
            return Err(rule(context, format!("contract {label} SHA mismatch")));
        }
        if row.str_field(&path, "sourceCommit")? != expected.commit {
            return Err(rule(context, format!("contract {label} commit mismatch")));
        }
        let build_id = row.str_field(&path, "buildId")?;
        if !is_build_id_hex(build_id) {
            return Err(rule(context, format!("contract {label} Build ID missing")));
        }
        observed_build_ids.insert(label, build_id.to_owned());
    }

    let xray = registrations
        .get("xray")
        .copied()
        .ok_or_else(|| rule(context, "contract Xray identity missing"))?;
    if xray.str_field("matrix.contract.binaries.xray", "sha256")? != xray_sha {
        return Err(rule(context, "contract Xray SHA mismatch"));
    }
    if !is_build_id_hex(xray.str_field("matrix.contract.binaries.xray", "buildId")?) {
        return Err(rule(context, "contract Xray Build ID missing"));
    }
    if xray
        .str_field("matrix.contract.binaries.xray", "identity")?
        .is_empty()
    {
        return Err(rule(context, "contract Xray identity missing"));
    }

    Ok(BinaryBuildIds {
        candidate: observed_build_ids["candidate"].clone(),
        baseline: observed_build_ids["baseline"].clone(),
    })
}

/// Verifies the matrix's end-to-end integrity transfers against both raw and summary data.
///
/// Integrity rows are intentionally excluded from protected metric pairing, but they
/// are not optional evidence: one successful SHA-verified transfer from each arm is
/// what proves that throughput was measured over the intended payload rather than a
/// short or bypassed stream.
fn verify_matrix_integrity(summary: &Value, rows: &[Value]) -> Result<(), LoadError> {
    let context = "matrix integrity";
    let recorded = summary.field("matrix", "integrity")?.as_object(context)?;
    if recorded.len() != MatrixRole::all().len() {
        return Err(rule(context, "summary arms are incomplete"));
    }

    let mut raw = BTreeMap::new();
    for row in rows {
        if row
            .optional("scenario")
            .and_then(|value| value.as_str("scenario").ok())
            != Some(contract::INTEGRITY_SCENARIO)
        {
            continue;
        }
        let label = row
            .optional("implementation")
            .and_then(|value| value.as_str("implementation").ok())
            .and_then(MatrixRole::parse)
            .ok_or_else(|| rule(context, "raw implementation is invalid"))?;
        if raw.insert(label, row).is_some() {
            return Err(rule(context, "raw arm is duplicated"));
        }
    }
    if raw.len() != MatrixRole::all().len() {
        return Err(rule(context, "raw arms are incomplete"));
    }

    let mut common_payload = None;
    for role in MatrixRole::all() {
        let label = role.as_str();
        let row = raw
            .get(&role)
            .copied()
            .ok_or_else(|| rule(context, format!("{label} raw row is missing")))?;
        if row_int(row, "sampleIndex") != Some(0)
            || row_int(row, "concurrency") != Some(1)
            || row_str(row, "direction") != Some("download")
        {
            return Err(rule(context, format!("{label} raw shape is invalid")));
        }
        validate_matrix_sample(row, context, 1)?;
        let payload = row_int(row, "payloadBytes")
            .filter(|value| *value > 0)
            .ok_or_else(|| rule(context, format!("{label} payload is invalid")))?;
        if common_payload.is_some_and(|expected| expected != payload) {
            return Err(rule(context, "arms used different payload sizes"));
        }
        common_payload = Some(payload);
        let row_hash = verified_integrity_hash(row.field(context, "sha256")?, context)?;

        let aggregate = recorded
            .get(label)
            .ok_or_else(|| rule(context, format!("{label} summary is missing")))?;
        aggregate.require_bool(context, "invalid", false)?;
        if aggregate.int_field(context, "payloadBytes")? != payload {
            return Err(rule(context, format!("{label} summary payload mismatch")));
        }
        let row_wall = positive_number(
            row.optional("wallSeconds")
                .and_then(|value| value.as_f64("wallSeconds").ok()),
            &format!("{context} {label} raw wall time"),
        )?;
        let summary_wall = positive_number(
            aggregate
                .optional("wallSeconds")
                .and_then(|value| value.as_f64("wallSeconds").ok()),
            &format!("{context} {label} summary wall time"),
        )?;
        if row_wall.to_bits() != summary_wall.to_bits() {
            return Err(rule(context, format!("{label} summary wall time mismatch")));
        }
        if verified_integrity_hash(aggregate.field(context, "sha256")?, context)? != row_hash {
            return Err(rule(context, format!("{label} summary SHA mismatch")));
        }
    }
    Ok(())
}

fn verified_integrity_hash(value: &Value, context: &str) -> Result<String, LoadError> {
    value.require_bool(context, "match", true)?;
    let origin = value.str_field(context, "origin")?;
    let received = value.str_field(context, "received")?;
    if !is_sha256_hex(origin) || received != origin {
        return Err(rule(context, "payload SHA verification is invalid"));
    }
    Ok(origin.to_owned())
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
        let payload = row
            .optional("payloadBytes")
            .and_then(|v| v.as_int("payloadBytes").ok())
            .ok_or_else(|| rule("matrix", "raw row is missing payloadBytes"))?;
        let concurrency = row
            .optional("concurrency")
            .and_then(|v| v.as_int("concurrency").ok())
            .ok_or_else(|| rule("matrix", "raw row is missing concurrency"))?;
        let payload = u64::try_from(payload)
            .ok()
            .filter(|value| *value > 0 && value.is_multiple_of(1024 * 1024))
            .ok_or_else(|| rule("matrix", "raw row payloadBytes is invalid"))?;
        let concurrency = u32::try_from(concurrency)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| rule("matrix", "raw row concurrency is invalid"))?;
        let key = CellKey::from_bytes(scenario.to_owned(), payload, concurrency);
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
    fn every_matrix_arm_requires_one_latency_per_request() {
        let valid = doc(
            r#"{"invalid":false,"bytesVerified":true,"throughputMiBPerSecond":2.0,"perRequestSeconds":[1.0,1.5]}"#,
        );
        validate_matrix_sample(&valid, "cell", 2).expect("two requests were timed");

        let partial = doc(
            r#"{"invalid":false,"bytesVerified":true,"throughputMiBPerSecond":2.0,"perRequestSeconds":[1.0]}"#,
        );
        let error = validate_matrix_sample(&partial, "cell", 2)
            .expect_err("a missing request latency must invalidate the row");
        assert!(
            error.to_string().contains("latency count mismatch"),
            "{error}"
        );

        let failed_xray = doc(
            r#"{"invalid":true,"bytesVerified":false,"throughputMiBPerSecond":2.0,"perRequestSeconds":[1.0,1.5]}"#,
        );
        assert!(
            validate_matrix_sample(&failed_xray, "cell", 2).is_err(),
            "the unpaired Xray arm is still required interoperability evidence"
        );
    }

    #[test]
    fn matrix_summary_key_must_name_its_own_cell_fields() {
        verify_matrix_cell_key("bidi:32:1", "bidi", 32, 1, "cell").expect("matching key");
        assert!(
            verify_matrix_cell_key("bidi:32:1", "bidi", 1, 1, "cell").is_err(),
            "a swapped payload must not put another cell's data under this metric ID"
        );
        assert!(
            verify_matrix_cell_key("bidi:32:1", "fallback", 32, 1, "cell").is_err(),
            "a swapped scenario must not be accepted"
        );
    }

    #[test]
    fn matrix_sample_conservation_rejects_an_unselected_extra_row() {
        let summary = doc(
            r#"{"totals":{"cells":1,"samples":3,"invalidSamples":0},"cells":{"direct-download:1:1":{"samplesPerImplementation":1,"implementations":{"baseline":{"samples":1,"validSamples":1,"invalidSamples":0},"final":{"samples":1,"validSamples":1,"invalidSamples":0},"xray":{"samples":1,"validSamples":1,"invalidSamples":0}}}}}"#,
        );
        let cells = summary
            .field("matrix", "cells")
            .and_then(|value| value.as_object("matrix.cells"))
            .unwrap();
        let row = |direction: &str| {
            doc(&format!(
                r#"{{"scenario":"direct-download","direction":"{direction}"}}"#,
            ))
        };
        let valid = vec![row("download"), row("download"), row("download")];
        verify_matrix_sample_conservation(&summary, cells, &valid)
            .expect("the declared three arms conserve three rows");

        let summary_with_four = doc(
            r#"{"totals":{"cells":1,"samples":4,"invalidSamples":0},"cells":{"direct-download:1:1":{"samplesPerImplementation":1,"implementations":{"baseline":{"samples":1,"validSamples":1,"invalidSamples":0},"final":{"samples":1,"validSamples":1,"invalidSamples":0},"xray":{"samples":1,"validSamples":1,"invalidSamples":0}}}}}"#,
        );
        let cells_with_four = summary_with_four
            .field("matrix", "cells")
            .and_then(|value| value.as_object("matrix.cells"))
            .unwrap();
        let mut extra = valid;
        extra.push(row("upload"));
        assert!(
            verify_matrix_sample_conservation(&summary_with_four, cells_with_four, &extra).is_err(),
            "a row that no cell selects must not disappear from the census"
        );
    }

    #[test]
    fn matrix_integrity_requires_three_matching_sha_verified_transfers() {
        let digest = "a".repeat(64);
        let aggregate = |label: &str, invalid: bool| {
            format!(
                r#""{label}":{{"invalid":{invalid},"payloadBytes":1048576,"wallSeconds":1.0,"sha256":{{"match":true,"origin":"{digest}","received":"{digest}"}}}}"#,
            )
        };
        let summary = doc(&format!(
            r#"{{"integrity":{{{},{},{}}}}}"#,
            aggregate("baseline", false),
            aggregate("final", false),
            aggregate("xray", false),
        ));
        let row = |label: &str, verified: bool| {
            doc(&format!(
                r#"{{"implementation":"{label}","scenario":"integrity","direction":"download","payloadBytes":1048576,"concurrency":1,"sampleIndex":0,"invalid":false,"bytesVerified":{verified},"wallSeconds":1.0,"throughputMiBPerSecond":1.0,"perRequestSeconds":[1.0],"sha256":{{"match":true,"origin":"{digest}","received":"{digest}"}}}}"#,
            ))
        };
        let valid = vec![row("baseline", true), row("final", true), row("xray", true)];
        verify_matrix_integrity(&summary, &valid).expect("all three transfers are complete");

        let corrupt = vec![
            row("baseline", true),
            row("final", true),
            row("xray", false),
        ];
        assert!(
            verify_matrix_integrity(&summary, &corrupt).is_err(),
            "an unverified Xray transfer must invalidate the matrix"
        );
    }

    #[test]
    fn duplicate_matrix_binary_registrations_are_rejected() {
        let candidate = BinaryIdentity {
            commit: "a".repeat(40),
            sha256: "c".repeat(64),
        };
        let baseline = BinaryIdentity {
            commit: "b".repeat(40),
            sha256: "d".repeat(64),
        };
        let summary = doc(&format!(
            r#"{{"status":"COMPLETE","performanceVerdict":"NOT_EVALUATED","failures":[],"totals":{{"invalidSamples":0}},"identity":{{"candidateCommit":"{}","baselineCommit":"{}","repositoryHead":"{}","binariesPinned":true,"binaries":{{"final":{{"sha256":"{}"}},"baseline":{{"sha256":"{}"}},"xray":{{"sha256":"{}"}}}}}}}}"#,
            candidate.commit,
            baseline.commit,
            candidate.commit,
            candidate.sha256,
            baseline.sha256,
            "e".repeat(64),
        ));
        let row = |label: &str| {
            format!(
                r#"{{"label":"{label}","sha256":"{}","sourceCommit":"{}","buildId":"01","identity":"present"}}"#,
                candidate.sha256, candidate.commit,
            )
        };
        let contract = doc(&format!(
            r#"{{"phase":"complete","exploratory":false,"script":{{"harnessCommit":"{}"}},"binaries":[{},{},{}]}}"#,
            candidate.commit,
            row("candidate"),
            row("candidate"),
            row("xray"),
        ));
        let error = verify_matrix_identity(&summary, &contract, &candidate, &baseline)
            .expect_err("duplicate labels must fail before any host-lock check");
        assert!(
            error.to_string().contains("labels must be unique"),
            "{error}"
        );
    }

    #[test]
    fn verified_files_are_parsed_from_the_hashed_snapshot() {
        let temp =
            std::env::temp_dir().join(format!("rr-dev-evidence-snapshot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("temp run dir");
        let bytes = b"{}\n";
        let digest = sha256_bytes(bytes);
        let mut files = BTreeMap::new();
        for name in WorkloadKind::Matrix.required_files() {
            std::fs::write(temp.join(name), bytes).expect("write evidence fixture");
            files.insert((*name).to_owned(), Value::Str(digest.clone()));
        }
        let verified = verify_files(&temp.to_string_lossy(), &files, WorkloadKind::Matrix)
            .expect("fixture hashes match");

        std::fs::write(temp.join("summary.json"), b"not JSON")
            .expect("mutate the path after verification");
        assert!(
            verified.json("summary.json").is_ok(),
            "parsing must use the exact bytes whose digest was recorded"
        );
        assert_eq!(verified.hashes["summary.json"], digest);
        let _ = std::fs::remove_dir_all(&temp);
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
    fn the_real_recorded_paired_evidence_reproduces_its_8_metrics() {
        // Completes the census: five setup metrics plus three fallback metrics, run
        // through the real code path against the recorded v1.8.0 evidence.
        let Some(manifest_path) =
            evidence("artifacts/v180-release-gate/gates/evaluator-manifest-r01.json")
        else {
            eprintln!("recorded manifest unavailable; skipping");
            return;
        };
        let manifest = load_json(&manifest_path).expect("manifest loads");
        let candidate = BinaryIdentity {
            commit: manifest
                .field("$", "candidate")
                .and_then(|v| v.str_field("candidate", "commit"))
                .expect("candidate commit")
                .to_owned(),
            sha256: manifest
                .field("$", "candidate")
                .and_then(|v| v.str_field("candidate", "sha256"))
                .expect("candidate sha")
                .to_owned(),
        };
        let baseline = BinaryIdentity {
            commit: manifest
                .field("$", "baseline")
                .and_then(|v| v.str_field("baseline", "commit"))
                .expect("baseline commit")
                .to_owned(),
            sha256: manifest
                .field("$", "baseline")
                .and_then(|v| v.str_field("baseline", "sha256"))
                .expect("baseline sha")
                .to_owned(),
        };

        let workloads = manifest.array_field("$", "workloads").expect("workloads");
        let mut all_ids = Vec::new();
        let mut counts = BTreeMap::new();
        for entry in workloads {
            let kind_text = entry.str_field("workload", "kind").expect("kind");
            let Some(kind) = WorkloadKind::parse(kind_text) else {
                panic!("unknown kind {kind_text}");
            };
            if kind == WorkloadKind::Matrix {
                continue;
            }
            let name = entry.str_field("workload", "name").expect("name");
            let run_dir = entry.str_field("workload", "runDir").expect("runDir");
            let files = entry
                .field("workload", "files")
                .and_then(|v| v.as_object("files"))
                .expect("files")
                .clone();

            let (metrics, input) =
                evaluate_pair_run(name, kind, run_dir, &files, &candidate, &baseline)
                    .unwrap_or_else(|error| panic!("{name}: {error}"));

            // The report input must come from this same pass.
            assert_eq!(input.name, name);
            assert_eq!(input.kind, kind);
            assert_eq!(input.status, "COMPLETE");
            assert_eq!(input.data_quality_verdict, "PASS");
            assert_eq!(input.collector_performance_verdict, "NOT_EVALUATED");
            assert_eq!(
                input.files.len(),
                kind.required_files().len(),
                "every declared file must be hashed"
            );
            assert!(
                input.host_lock.coordination_identity().is_some(),
                "a verified paired run must yield a coordination identity"
            );

            counts.insert(name.to_owned(), metrics.len());
            all_ids.extend(metrics.into_iter().map(|metric| metric.id));
        }

        assert_eq!(counts.get("setup"), Some(&5), "setup yields five metrics");
        assert_eq!(
            counts.get("fallback"),
            Some(&3),
            "fallback yields three metrics"
        );

        all_ids.sort();
        assert_eq!(
            all_ids,
            vec![
                "fallback:c1:p99-latency".to_owned(),
                "fallback:c1:throughput".to_owned(),
                "fallback:server-cpu".to_owned(),
                "setup:c1:p99-latency".to_owned(),
                "setup:c1:throughput".to_owned(),
                "setup:c32:p99-latency".to_owned(),
                "setup:c32:throughput".to_owned(),
                "setup:server-cpu".to_owned(),
            ],
            "the recorded paired metric identities must be reproduced exactly"
        );
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
}
