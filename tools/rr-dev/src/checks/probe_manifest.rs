//! The active-probe manifest validator, migrated from `active-probe-gate.py`.
//!
//! Only the `--check` mode is migrated here, because that is the one `check.sh`
//! runs in the gate: it validates the manifest schema and proves every declared
//! regression test still exists in the library test list. The evidence-recording
//! `run` mode of the Python script had no CI or gate caller and is not resurrected;
//! recording deterministic-case evidence now belongs to the benchmark/evidence
//! tooling built in a later slice.
//!
//! The case corpus itself is declarative data. It moves to
//! `tools/fixtures/active-probe-cases.json` and stays data; this module reads it.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::{
    perf::json_in::{self, Value},
    process::Tool,
};

/// The manifest path relative to the repository root.
pub const MANIFEST: &str = "tools/fixtures/active-probe-cases.json";

/// A single validated regression case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// Stable case identifier.
    pub id: String,
    /// The fully-qualified library test name.
    pub test: String,
    /// The observation the case pins.
    pub observation: String,
}

/// Why the manifest could not be validated.
#[derive(Debug)]
pub enum Error {
    /// The manifest file could not be read.
    Unreadable {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error text.
        detail: String,
    },
    /// The manifest content violated the schema.
    Schema(String),
    /// The declared tests could not be listed.
    ListFailed(String),
    /// Declared tests are absent from the library test list.
    MissingTests(Vec<String>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, detail } => {
                write!(formatter, "{}: {detail}", path.display())
            }
            Self::Schema(reason) => write!(formatter, "{reason}"),
            Self::ListFailed(reason) => write!(formatter, "could not list tests: {reason}"),
            Self::MissingTests(missing) => {
                write!(formatter, "active-probe tests missing:\n{}", missing.join("\n"))
            }
        }
    }
}

impl std::error::Error for Error {}

/// Loads and schema-validates the manifest, returning its cases.
///
/// # Errors
///
/// Returns [`Error::Unreadable`] or [`Error::Schema`] on any read or schema
/// violation, matching `active-probe-gate.py`'s `load`.
pub fn load(repo: &Path) -> Result<Vec<Case>, Error> {
    let path = repo.join(MANIFEST);
    let manifest_text = std::fs::read_to_string(&path).map_err(|error| Error::Unreadable {
        path: path.clone(),
        detail: error.to_string(),
    })?;
    let value = json_in::parse(&manifest_text).map_err(Error::Schema)?;

    let schema = value.optional("schemaVersion").and_then(|v| v.as_int("schemaVersion").ok());
    if schema != Some(1) {
        return Err(Error::Schema("schemaVersion must be 1".to_owned()));
    }
    let required = array(&value, "requiredCases")?;
    let cases = array(&value, "cases")?;

    let mut parsed = Vec::with_capacity(cases.len());
    let mut ids: Vec<String> = Vec::new();
    for case in cases {
        let id = required_str(case, "id")?;
        let test = required_str(case, "test")?;
        let observation = required_str(case, "observation")?;
        ids.push(id.clone());
        parsed.push(Case { id, test, observation });
    }

    let required_ids: Vec<String> = required
        .iter()
        .filter_map(|item| item.as_str("requiredCases[]").ok().map(str::to_owned))
        .collect();
    let id_set: BTreeSet<&String> = ids.iter().collect();
    let required_set: BTreeSet<&String> = required_ids.iter().collect();
    if id_set.len() != ids.len() || id_set != required_set || ids.len() != required_ids.len() {
        return Err(Error::Schema(
            "cases must cover requiredCases exactly once".to_owned(),
        ));
    }

    for key in ["comparators", "timingPolicy", "packetizationPolicy"] {
        if value.optional(key).is_none() {
            return Err(Error::Schema(format!("missing {key}")));
        }
    }

    Ok(parsed)
}

/// The `--check` gate: validates the manifest and proves every test exists.
///
/// # Errors
///
/// Propagates load errors, then returns [`Error::ListFailed`] if the library
/// test list cannot be produced or [`Error::MissingTests`] if any declared test
/// is absent.
pub fn check(repo: &Path) -> Result<String, Error> {
    let cases = load(repo)?;
    let available = list_library_tests(repo)?;
    let mut missing: Vec<String> = cases
        .iter()
        .filter(|case| !available.contains(&case.test))
        .map(|case| case.test.clone())
        .collect();
    missing.sort_unstable();
    if !missing.is_empty() {
        return Err(Error::MissingTests(missing));
    }
    Ok(format!("active-probe manifest: PASS ({} cases)", cases.len()))
}

/// Lists the library tests via `cargo test --lib ... -- --list`.
fn list_library_tests(repo: &Path) -> Result<BTreeSet<String>, Error> {
    let outcome = Tool::new("cargo")
        .args([
            "test", "--lib", "--all-features", "--locked", "--", "--list",
        ])
        .current_dir(repo)
        .probe()
        .map_err(|error| Error::ListFailed(error.to_string()))?;
    if !outcome.success() {
        return Err(Error::ListFailed(format!(
            "cargo test --list exited with {:?}",
            outcome.code
        )));
    }
    Ok(outcome
        .stdout
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(str::to_owned)
        .collect())
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], Error> {
    match value.optional(key) {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(Error::Schema("case arrays missing".to_owned())),
    }
}

fn required_str(case: &Value, key: &str) -> Result<String, Error> {
    match case.optional(key).and_then(|v| v.as_str(key).ok()) {
        Some(text) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(Error::Schema(
            "each case requires id, test, and observation".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest must sit three levels below the repository root")
            .to_path_buf()
    }

    #[test]
    fn the_checked_in_manifest_loads_and_covers_required_cases() {
        let cases = load(&repo_root()).expect("the fixture manifest must validate");
        assert!(!cases.is_empty(), "the manifest declares cases");
        let ids: BTreeSet<&String> = cases.iter().map(|case| &case.id).collect();
        assert_eq!(ids.len(), cases.len(), "case ids are unique");
    }
}
