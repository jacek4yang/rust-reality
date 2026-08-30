//! Native repository-layout and onboarding policy.
//!
//! This module validates permanent properties of the tracked tree: every root
//! entry has an explicit owner, documentation and benchmark data stay in their
//! canonical taxonomies, temporary project state and competing agent policy do
//! not return, ADRs remain well-formed and indexed, and onboarding entrypoints
//! form a usable graph. Link resolution and bilingual document pairing remain
//! owned by [`crate::docs`]; both checks compose under `cargo dev check --all`.

use std::{fmt::Write as _, path::Path};

use crate::process::Tool;

mod adr;
mod content;
mod policy;

/// One path reported by `git ls-files --stage`.
#[derive(Debug, Clone)]
struct TrackedEntry {
    path: String,
    mode: String,
    stage: String,
}

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
                "repository architecture verified across {} tracked files",
                self.files
            );
        }
        let mut rendered = String::from("repository architecture validation failed:\n");
        for failure in &self.failures {
            let _ = writeln!(rendered, "- {failure}");
        }
        rendered
    }
}

/// Reads the current Git index and validates the tracked repository architecture.
#[must_use]
pub fn check(repo: &Path) -> Report {
    let entries = match tracked_entries(repo) {
        Ok(entries) => entries,
        Err(error) => {
            return Report {
                failures: vec![error],
                files: 0,
            };
        }
    };
    let paths: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    let mut failures = policy::failures(&paths);
    failures.extend(index_failures(&entries));
    failures.extend(content::failures(repo, &entries));
    failures.extend(adr::failures(repo, &entries));
    failures.sort();
    failures.dedup();
    Report {
        failures,
        files: entries.len(),
    }
}

fn tracked_entries(repo: &Path) -> Result<Vec<TrackedEntry>, String> {
    let outcome = Tool::new("git")
        .args(["ls-files", "--stage", "-z"])
        .current_dir(repo)
        .run()
        .map_err(|error| format!("could not enumerate tracked files: {error}"))?;

    let mut entries = Vec::new();
    for raw in outcome.stdout.split('\0').filter(|entry| !entry.is_empty()) {
        let (metadata, path) = raw
            .split_once('\t')
            .ok_or_else(|| "git returned malformed tracked-file metadata".to_owned())?;
        let mut fields = metadata.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| format!("git omitted the mode for {path}"))?;
        let _object = fields
            .next()
            .ok_or_else(|| format!("git omitted the object id for {path}"))?;
        let stage = fields
            .next()
            .ok_or_else(|| format!("git omitted the index stage for {path}"))?;
        entries.push(TrackedEntry {
            path: path.to_owned(),
            mode: mode.to_owned(),
            stage: stage.to_owned(),
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn index_failures(entries: &[TrackedEntry]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in entries {
        if entry.stage != "0" {
            failures.push(format!(
                "unmerged index stage {} for tracked path: {}",
                entry.stage, entry.path
            ));
        }
        if entry.mode == "120000" {
            failures.push(format!(
                "tracked symlink has no canonical owner: {}",
                entry.path
            ));
        }
        if policy::is_archived_script_evidence(&entry.path) && entry.mode != "100644" {
            failures.push(format!(
                "archived shell/Python evidence must be non-executable: {}",
                entry.path
            ));
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest must sit three levels below the repository root")
            .to_path_buf()
    }

    #[test]
    fn the_real_repository_passes_every_policy() {
        let report = check(&repo_root());
        assert!(report.is_clean(), "{}", report.render());
        assert!(
            report.files > 300,
            "tracked-tree discovery is unexpectedly small"
        );
    }

    #[test]
    fn report_rendering_is_stable() {
        let clean = Report {
            failures: Vec::new(),
            files: 380,
        };
        assert_eq!(
            clean.render(),
            "repository architecture verified across 380 tracked files"
        );
        let failed = Report {
            failures: vec!["bad path".to_owned()],
            files: 1,
        };
        assert!(failed.render().contains("- bad path"));
    }
}
