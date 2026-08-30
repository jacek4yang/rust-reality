//! Native repository-layout policy.
//!
//! This module validates permanent properties of the current tracked tree. It
//! intentionally does not encode completed migration inventories or historical
//! file lists.

use std::{fmt::Write as _, path::Path};

use crate::process::Tool;

/// Standard project files permitted at the repository root.
const ROOT_FILES: &[&str] = &[
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "Cargo.lock",
    "Cargo.toml",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "deny.toml",
    "rust-toolchain.toml",
    "rustfmt.toml",
];

/// Result of validating the tracked repository tree.
#[derive(Debug, Default)]
pub struct Report {
    /// Policy violations in deterministic path order.
    pub failures: Vec<String>,
    /// Number of tracked paths considered.
    pub files: usize,
}

impl Report {
    /// Whether every active layout rule passed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// Renders a stable human-facing result.
    #[must_use]
    pub fn render(&self) -> String {
        if self.is_clean() {
            return format!(
                "repository layout verified across {} tracked files",
                self.files
            );
        }
        let mut rendered = String::from("repository layout validation failed:\n");
        for failure in &self.failures {
            let _ = writeln!(rendered, "- {failure}");
        }
        rendered
    }
}

/// Reads the current Git index and validates the tracked repository layout.
#[must_use]
pub fn check(repo: &Path) -> Report {
    let outcome = match Tool::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo)
        .run()
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return Report {
                failures: vec![format!("could not enumerate tracked files: {error}")],
                files: 0,
            };
        }
    };

    validate_paths(outcome.stdout.split('\0').filter(|path| !path.is_empty()))
}

fn validate_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Report {
    let mut paths: Vec<&str> = paths.into_iter().collect();
    paths.sort_unstable();

    let mut failures = Vec::new();
    for path in &paths {
        if *path == "scripts" || path.starts_with("scripts/") {
            failures.push(format!("legacy scripts/ path is forbidden: {path}"));
        }
        if !path.contains('/') && !ROOT_FILES.contains(path) {
            failures.push(format!("unauthorized root file: {path}"));
        }
    }

    Report {
        failures,
        files: paths.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_root_files_and_nested_paths_pass() {
        let report = validate_paths([
            "Cargo.toml",
            "CONTRIBUTING.md",
            "README.md",
            "docs/en/index.md",
            "src/main.rs",
        ]);
        assert!(report.is_clean(), "{}", report.render());
        assert_eq!(report.files, 5);
    }

    #[test]
    fn scripts_cannot_return() {
        let report = validate_paths(["Cargo.toml", "scripts/check.sh"]);
        assert_eq!(report.failures.len(), 1);
        assert!(report.failures[0].contains("scripts/"));
    }

    #[test]
    fn arbitrary_root_files_are_rejected() {
        let report = validate_paths(["Cargo.toml", "PLAN.md", "state.json"]);
        assert_eq!(
            report.failures,
            [
                "unauthorized root file: PLAN.md",
                "unauthorized root file: state.json"
            ]
        );
    }
}
