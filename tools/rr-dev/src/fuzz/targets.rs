//! The cargo-fuzz target manifest validator, migrated from `fuzz-targets.py`.
//!
//! Reads `fuzz/Cargo.toml`, extracts every `[[bin]]` target, and enforces the same
//! rules the Python did: each target needs a non-empty name and an existing source
//! file, names are unique, no source under `fuzz/fuzz_targets/` may be undeclared,
//! and at least one target must exist. It reproduces the deterministic
//! `index :: count` sharding `security.yml` relies on, so the gate and the sharded
//! smoke job share one definition of which targets exist.
//!
//! Only the `[[bin]]` `name` and `path` keys are read, so this is a purpose-built
//! extractor rather than a general TOML parser.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// A declared fuzz target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    name: String,
    path: String,
}

/// Why the manifest could not be accepted.
#[derive(Debug)]
pub enum Error {
    /// The manifest file could not be read.
    Unreadable {
        /// The path that failed to read.
        path: PathBuf,
        /// The underlying error text.
        detail: String,
    },
    /// The manifest violated one or more target rules.
    Invalid {
        /// The individual rule violations, in discovery order.
        failures: Vec<String>,
    },
    /// The requested shard bounds were invalid or empty.
    Shard(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, detail } => write!(
                formatter,
                "fuzz target validation failed: {}: {detail}",
                path.display()
            ),
            Self::Invalid { failures } => {
                write!(formatter, "fuzz target validation failed: {}", failures.join("; "))
            }
            Self::Shard(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Validates the fuzz manifest under `repo` and returns the declared target names.
///
/// # Errors
///
/// Returns [`Error::Unreadable`] when `fuzz/Cargo.toml` cannot be read and
/// [`Error::Invalid`] when any target rule is violated; all violations are
/// collected before returning.
pub fn all(repo: &Path) -> Result<Vec<String>, Error> {
    let fuzz = repo.join("fuzz");
    let manifest_path = fuzz.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path).map_err(|error| Error::Unreadable {
        path: manifest_path.clone(),
        detail: error.to_string(),
    })?;

    let declared = extract_bin_targets(&manifest);
    let mut failures = Vec::new();
    let mut names: Vec<String> = Vec::new();

    for target in &declared {
        if target.name.is_empty() {
            failures.push("every [[bin]] needs a non-empty string name".to_owned());
            continue;
        }
        if names.contains(&target.name) {
            failures.push(format!("duplicate fuzz target name: {}", target.name));
        }
        names.push(target.name.clone());
        if target.path.is_empty() || !fuzz.join(&target.path).is_file() {
            failures.push(format!(
                "{}: missing fuzz target source: {:?}",
                target.name, target.path
            ));
        }
    }

    let declared_paths: BTreeSet<String> = declared
        .iter()
        .filter(|target| !target.path.is_empty())
        .map(|target| basename(&target.path))
        .collect();
    let mut source_paths: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(fuzz.join("fuzz_targets")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                source_paths.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    source_paths.sort_unstable();
    for source in &source_paths {
        if !declared_paths.contains(source) {
            failures.push(format!("undeclared fuzz target source: fuzz/fuzz_targets/{source}"));
        }
    }

    if names.is_empty() {
        failures.push("fuzz/Cargo.toml declares no [[bin]] targets".to_owned());
    }

    if failures.is_empty() {
        Ok(names)
    } else {
        Err(Error::Invalid { failures })
    }
}

/// Validates the manifest and returns the targets for shard `index` of `count`.
///
/// # Errors
///
/// Propagates [`all`]'s errors, then returns [`Error::Shard`] when the bounds are
/// invalid or the selected shard is empty.
pub fn shard(repo: &Path, index: usize, count: usize) -> Result<Vec<String>, Error> {
    let names = all(repo)?;
    if count < 1 || index >= count {
        return Err(Error::Shard(
            "shard count must be positive and index must be within the count".to_owned(),
        ));
    }
    let selected: Vec<String> = names.into_iter().skip(index).step_by(count).collect();
    if selected.is_empty() {
        return Err(Error::Shard("selected shard is empty".to_owned()));
    }
    Ok(selected)
}

/// Extracts `[[bin]]` `name`/`path` pairs from a Cargo manifest.
fn extract_bin_targets(manifest: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    let mut current: Option<(Option<String>, Option<String>)> = None;
    let flush = |current: &mut Option<(Option<String>, Option<String>)>, out: &mut Vec<Target>| {
        if let Some((name, path)) = current.take() {
            out.push(Target {
                name: name.unwrap_or_default(),
                path: path.unwrap_or_default(),
            });
        }
    };
    for raw in manifest.lines() {
        let line = strip_comment(raw).trim();
        if line == "[[bin]]" {
            flush(&mut current, &mut targets);
            current = Some((None, None));
            continue;
        }
        if line.starts_with('[') {
            flush(&mut current, &mut targets);
            continue;
        }
        if let Some(entry) = current.as_mut() {
            if let Some(value) = key_value(line, "name") {
                entry.0 = Some(value);
            } else if let Some(value) = key_value(line, "path") {
                entry.1 = Some(value);
            }
        }
    }
    flush(&mut current, &mut targets);
    targets
}

/// Removes a trailing `#` comment that is not inside a string literal.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    for (index, byte) in line.bytes().enumerate() {
        match byte {
            b'"' => in_string = !in_string,
            b'#' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Reads a `key = "value"` string assignment, returning the unquoted value.
fn key_value(line: &str, key: &str) -> Option<String> {
    let (found_key, value) = line.split_once('=')?;
    if found_key.trim() != key {
        return None;
    }
    let inner = value.trim().strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_owned())
}

/// The final path component of a `/`-separated relative path.
fn basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest sits three levels below the repository root")
            .to_path_buf()
    }

    #[test]
    fn the_repository_manifest_is_valid_and_nonempty() {
        let names = all(&repo_root()).expect("the checked-in fuzz manifest must validate");
        assert!(!names.is_empty());
        let unique: BTreeSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "target names must be unique");
    }

    #[test]
    fn extraction_reads_name_and_path_pairs() {
        let manifest = "[package]\nname = \"x\"\n\n[[bin]]\nname = \"alpha\"\npath = \"fuzz_targets/alpha.rs\"\ntest = false\n\n[[bin]]\nname = \"beta\"\npath = \"fuzz_targets/beta.rs\"\n";
        let extracted = extract_bin_targets(manifest);
        assert_eq!(
            extracted,
            vec![
                Target { name: "alpha".to_owned(), path: "fuzz_targets/alpha.rs".to_owned() },
                Target { name: "beta".to_owned(), path: "fuzz_targets/beta.rs".to_owned() },
            ]
        );
    }

    #[test]
    fn a_comment_is_not_mistaken_for_a_value() {
        let manifest = "[[bin]]\nname = \"alpha\" # note\npath = \"fuzz_targets/alpha.rs\"\n";
        assert_eq!(extract_bin_targets(manifest)[0].name, "alpha");
    }

    #[test]
    fn sharding_partitions_deterministically_and_disjointly() {
        let repo = repo_root();
        let all_targets = all(&repo).unwrap();
        let mut union: Vec<String> = Vec::new();
        for index in 0..4 {
            union.extend(shard(&repo, index, 4).unwrap());
        }
        union.sort();
        let mut expected = all_targets;
        expected.sort();
        assert_eq!(union, expected, "shards must cover every target exactly once");
    }

    #[test]
    fn an_out_of_range_shard_is_rejected() {
        let repo = repo_root();
        assert!(matches!(shard(&repo, 4, 4), Err(Error::Shard(_))));
    }
}
