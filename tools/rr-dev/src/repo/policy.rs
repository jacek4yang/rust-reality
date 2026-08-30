//! Path-only repository ownership policy.

use std::{collections::BTreeSet, path::Path};

/// One deliberately owned entry at repository root.
struct RootEntry {
    name: &'static str,
    role: &'static str,
}

/// The canonical root allowlist, derived from the normalized repository.
///
/// Adding an entry is intentionally one reviewable edit that must state the
/// entry's permanent owner. Git does not track empty directories, so a listed
/// directory is observed through at least one tracked path below it.
const ROOT_ENTRIES: &[RootEntry] = &[
    RootEntry {
        name: ".cargo",
        role: "Cargo aliases and dependency-audit configuration",
    },
    RootEntry {
        name: ".config",
        role: "repository tool configuration",
    },
    RootEntry {
        name: ".editorconfig",
        role: "editor-neutral formatting defaults",
    },
    RootEntry {
        name: ".gitattributes",
        role: "Git path attributes",
    },
    RootEntry {
        name: ".github",
        role: "GitHub CI, Security, and release workflows",
    },
    RootEntry {
        name: ".gitignore",
        role: "untracked build and local-output exclusions",
    },
    RootEntry {
        name: "AGENTS.md",
        role: "normative engineering constitution",
    },
    RootEntry {
        name: "CHANGELOG.md",
        role: "released user-visible changes",
    },
    RootEntry {
        name: "CONTRIBUTING.md",
        role: "human contributor entrypoint",
    },
    RootEntry {
        name: "Cargo.lock",
        role: "production dependency lock",
    },
    RootEntry {
        name: "Cargo.toml",
        role: "production workspace and package manifest",
    },
    RootEntry {
        name: "LICENSE-APACHE",
        role: "Apache-2.0 license text",
    },
    RootEntry {
        name: "LICENSE-MIT",
        role: "MIT license text",
    },
    RootEntry {
        name: "README.md",
        role: "English project entrypoint",
    },
    RootEntry {
        name: "README.zh-CN.md",
        role: "Chinese project entrypoint",
    },
    RootEntry {
        name: "SECURITY.md",
        role: "security reporting and support policy",
    },
    RootEntry {
        name: "benches",
        role: "production Cargo benchmarks",
    },
    RootEntry {
        name: "benchmarks",
        role: "benchmark contracts, baselines, and durable evidence",
    },
    RootEntry {
        name: "crates",
        role: "deliberate production architecture crates",
    },
    RootEntry {
        name: "deny.toml",
        role: "production dependency policy",
    },
    RootEntry {
        name: "deploy",
        role: "service packaging",
    },
    RootEntry {
        name: "docs",
        role: "canonical human documentation and ADRs",
    },
    RootEntry {
        name: "examples",
        role: "Rust examples consuming the public library",
    },
    RootEntry {
        name: "fuzz",
        role: "production attack-surface fuzz workspace",
    },
    RootEntry {
        name: "rust-toolchain.toml",
        role: "pinned Rust toolchain",
    },
    RootEntry {
        name: "rustfmt.toml",
        role: "Rust formatting policy",
    },
    RootEntry {
        name: "src",
        role: "production application source",
    },
    RootEntry {
        name: "tests",
        role: "production integration tests",
    },
    RootEntry {
        name: "tools",
        role: "independent development-tooling workspace",
    },
];

/// Exact path prefixes whose tracked content is forbidden.
const FORBIDDEN_PATH_PREFIXES: &[&str] = &["docs/decisions", "notes", "scripts", "tools/inventory"];

/// File names that always represent transient execution state.
const TRANSIENT_STATE_FILES: &[&str] = &[
    "CURRENT.md",
    "HANDOFF.md",
    "PLAN.md",
    "STATUS.md",
    "TODO.md",
    "agent-state.json",
    "migration-checklist.md",
    "migration-ledger.json",
    "normalization-state.json",
    "progress-ledger.json",
    "project-state.json",
];

/// Vendor-specific competing agent-policy files. `AGENTS.md` is canonical.
const COMPETING_AGENT_POLICY_FILES: &[&str] = &[
    ".cursorrules",
    "AI_RULES.md",
    "CLAUDE.md",
    "CODEX.md",
    "COPILOT-INSTRUCTIONS.md",
    "GEMINI.md",
    "GPT.md",
    "KIRO.md",
];

/// Directory names reserved for model-specific policy or conversation state.
const MODEL_STATE_DIRECTORIES: &[&str] = &[
    ".claude",
    ".codex",
    ".cursor",
    ".kiro",
    "chat-logs",
    "conversation-dumps",
    "model-conversations",
    "prompts",
];

/// Exact entrypoints that make human and stateless-agent onboarding possible.
///
/// Bilingual operator pairs are deliberately not duplicated here; they are
/// enforced by `cargo dev docs check`.
const REQUIRED_PATHS: &[&str] = &[
    ".cargo/config.toml",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "benchmarks/README.md",
    "docs/adr/README.md",
    "docs/en/architecture.md",
    "docs/en/benchmarks.md",
    "docs/en/deployment.md",
    "docs/en/development/development-workflow.md",
    "docs/en/development/fuzzing.md",
    "docs/en/development/repository-layout.md",
    "docs/en/development/testing.md",
    "docs/en/index.md",
    "docs/en/release-process.md",
    "tools/Cargo.toml",
    "tools/rr-dev/Cargo.toml",
];

/// Exact colocated Markdown owners outside `docs/` and the standard root docs.
const COLOCATED_MARKDOWN: &[&str] = &["benchmarks/README.md", "tools/reference/README.md"];

/// The only machine-data homes below `benchmarks/`.
const BENCHMARK_DIRECTORIES: &[&str] = &[
    "benchmarks/baselines",
    "benchmarks/contracts",
    "benchmarks/evidence",
];

pub(super) fn failures(paths: &[&str]) -> Vec<String> {
    let tracked: BTreeSet<&str> = paths.iter().copied().collect();
    let mut failures = Vec::new();

    for path in paths {
        let root = path.split('/').next().unwrap_or(path);
        if canonical_root_role(root).is_none() {
            failures.push(format!("unauthorized root entry: {root} (from {path})"));
        }

        for prefix in FORBIDDEN_PATH_PREFIXES {
            if has_path_prefix(path, prefix) {
                failures.push(format!("forbidden repository path: {path}"));
            }
        }

        let basename = path.rsplit('/').next().unwrap_or(path);
        if TRANSIENT_STATE_FILES
            .iter()
            .any(|name| basename.eq_ignore_ascii_case(name))
        {
            failures.push(format!("transient project-state file: {path}"));
        }
        if COMPETING_AGENT_POLICY_FILES
            .iter()
            .any(|name| basename.eq_ignore_ascii_case(name))
        {
            failures.push(format!(
                "competing agent policy (AGENTS.md is canonical): {path}"
            ));
        }
        if is_model_state_path(path) {
            failures.push(format!("model policy or conversation-state path: {path}"));
        }

        if path.starts_with("docs/") && !has_markdown_extension(path) {
            failures.push(format!("docs must contain Markdown only: {path}"));
        }
        if has_markdown_extension(path) && !is_owned_markdown(path) {
            failures.push(format!(
                "Markdown has no canonical documentation owner: {path}"
            ));
        }

        if let Some(relative) = path.strip_prefix("docs/adr/") {
            if relative.contains('/') {
                failures.push(format!("ADRs must be flat under docs/adr/: {path}"));
            } else if relative != "README.md" && !valid_adr_filename(relative) {
                failures.push(format!(
                    "ADR file name must be NNNN-kebab-case-title.md: {path}"
                ));
            }
        } else if looks_like_adr(basename) {
            failures.push(format!(
                "ADR-like document must live under docs/adr/: {path}"
            ));
        }

        if path.starts_with("benchmarks/")
            && *path != "benchmarks/README.md"
            && !BENCHMARK_DIRECTORIES
                .iter()
                .any(|directory| has_path_prefix(path, directory))
        {
            failures.push(format!(
                "benchmark data must live under contracts/, baselines/, or evidence/: {path}"
            ));
        }

        if is_script_path(path) && !is_archived_script_evidence(path) {
            failures.push(format!("active repository-owned shell/Python file: {path}"));
        }
    }

    for required in REQUIRED_PATHS {
        if !tracked.contains(required) {
            failures.push(format!(
                "missing canonical repository entrypoint: {required}"
            ));
        }
    }
    for directory in BENCHMARK_DIRECTORIES {
        if !paths.iter().any(|path| has_path_prefix(path, directory)) {
            failures.push(format!(
                "missing canonical benchmark category: {directory}/"
            ));
        }
    }

    failures.sort();
    failures.dedup();
    failures
}

fn canonical_root_role(name: &str) -> Option<&'static str> {
    ROOT_ENTRIES
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.role)
}

fn has_path_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn is_model_state_path(path: &str) -> bool {
    if path.split('/').any(|component| {
        MODEL_STATE_DIRECTORIES
            .iter()
            .any(|name| component.eq_ignore_ascii_case(name))
    }) {
        return true;
    }
    let basename = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    [
        "chat.json",
        "chat.jsonl",
        "chat.md",
        "conversation.json",
        "conversation.jsonl",
        "conversation.md",
        "model-transcript.json",
        "model-transcript.jsonl",
        "model-transcript.md",
    ]
    .contains(&basename.as_str())
}

fn is_owned_markdown(path: &str) -> bool {
    if path.starts_with("docs/") || path.starts_with("benchmarks/evidence/") {
        return true;
    }
    if !path.contains('/') {
        return [
            "AGENTS.md",
            "CHANGELOG.md",
            "CONTRIBUTING.md",
            "README.md",
            "README.zh-CN.md",
            "SECURITY.md",
        ]
        .contains(&path);
    }
    COLOCATED_MARKDOWN.contains(&path)
}

fn looks_like_adr(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() > 8
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && has_markdown_extension(name)
}

fn has_markdown_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "md")
}

pub(super) fn valid_adr_filename(name: &str) -> bool {
    if !looks_like_adr(name) {
        return false;
    }
    let title = &name[5..name.len() - 3];
    !title.is_empty()
        && !title.starts_with('-')
        && !title.ends_with('-')
        && !title.contains("--")
        && title
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn is_script_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            ["bash", "py", "pyi", "sh", "zsh"]
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
}

pub(super) fn is_archived_script_evidence(path: &str) -> bool {
    let components: Vec<&str> = path.split('/').collect();
    components.len() == 6
        && components[..4] == ["benchmarks", "evidence", "objects", "sha256"]
        && components[4].len() == 64
        && components[4]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && is_script_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_paths() -> Vec<&'static str> {
        let mut paths = REQUIRED_PATHS.to_vec();
        paths.extend([
            "Cargo.toml",
            "benchmarks/baselines/example.json",
            "benchmarks/contracts/example.json",
            "benchmarks/evidence/example.json",
            "src/main.rs",
        ]);
        paths
    }

    #[test]
    fn every_canonical_root_entry_has_a_stated_role() {
        assert!(
            ROOT_ENTRIES
                .iter()
                .all(|entry| !entry.role.trim().is_empty())
        );
        let mut names: Vec<&str> = ROOT_ENTRIES.iter().map(|entry| entry.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            ROOT_ENTRIES.len(),
            "root entries must be unique"
        );
    }

    #[test]
    fn canonical_paths_and_archived_scripts_pass_path_policy() {
        let mut paths = canonical_paths();
        paths.extend([
            "docs/adr/0014-example-decision.md",
            "docs/zh-CN/index.md",
            "benchmarks/evidence/objects/sha256/817aab781f3db676b574645d90e0d0a2c49143cb37a5cc77517eaa0b739eed14/benchmark-contract.sh",
        ]);
        let failures = failures(&paths);
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn representative_invalid_states_are_rejected() {
        let cases = [
            ("notes/foo.md", "forbidden repository path"),
            ("scripts/foo.sh", "forbidden repository path"),
            ("PLAN.md", "transient project-state file"),
            ("state.json", "unauthorized root entry"),
            ("CLAUDE.md", "competing agent policy"),
            ("src/guide.md", "no canonical documentation owner"),
            (
                "docs/en/0014-wrong-location.md",
                "ADR-like document must live under docs/adr/",
            ),
            (
                "docs/adr/not-numbered.md",
                "ADR file name must be NNNN-kebab-case-title.md",
            ),
            (
                "benchmarks/raw/result.json",
                "benchmark data must live under contracts/",
            ),
            ("docs/HANDOFF.md", "transient project-state file"),
            (
                "tools/fixtures/model-conversations/session.json",
                "model policy or conversation-state path",
            ),
            (
                "tools/check.py",
                "active repository-owned shell/Python file",
            ),
            ("scratch/file.txt", "unauthorized root entry"),
        ];

        for (invalid, expected) in cases {
            let mut paths = canonical_paths();
            paths.push(invalid);
            let violations = failures(&paths);
            assert!(
                violations.iter().any(|failure| failure.contains(expected)),
                "{invalid} did not produce {expected:?}: {violations:?}"
            );
        }
    }
}
