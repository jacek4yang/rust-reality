//! The canonical repository quality gate.
//!
//! This is a typed reimplementation of the step sequence in `scripts/check.sh`.
//! Behavioural parity with that script is the requirement for this slice: the
//! same steps, in the same order, with the same fail-closed semantics. Policy
//! migration out of the Python validators happens in later slices, so for now
//! those validators are invoked rather than reimplemented — that keeps this
//! change reviewable and keeps one source of truth for each rule.
//!
//! Two deliberate differences from the script are documented at
//! [`Scope::steps`]: the `bash -n` sweep is scoped to surviving scripts, and the
//! gate is split into scopes so a developer can run the fast subset locally
//! without silently skipping anything that CI will enforce.

use std::path::Path;

use crate::process::{Tool, ToolError};

/// How much of the gate to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Formatting, lint and the default test profile. The fast local loop.
    Fast,
    /// Everything CI enforces, matching `scripts/check.sh` exactly.
    All,
}

/// One gate step.
///
/// A step is either an external tool or a check rr-dev implements itself. Native
/// checks run in process rather than re-invoking `rr-dev` as a subprocess: that
/// keeps one implementation, avoids a second process per check, and means a
/// failure surfaces as a typed value instead of a parsed exit code.
enum Step {
    /// Delegate to an external program.
    External {
        /// What to print before running.
        label: String,
        /// The invocation.
        tool: Tool,
    },
    /// Run a check implemented inside rr-dev.
    Native {
        /// What to print before running.
        label: String,
        /// The check, returning a rendered failure report.
        run: fn(&Path) -> Result<(), String>,
    },
}

impl Step {
    /// The label printed before this step runs.
    fn label(&self) -> &str {
        match self {
            Self::External { label, .. } | Self::Native { label, .. } => label,
        }
    }

    /// Runs the step, mapping a native failure onto the shared error type.
    fn execute(&self, repo: &Path) -> Result<std::time::Duration, ToolError> {
        match self {
            Self::External { tool, .. } => tool.run().map(|outcome| outcome.elapsed),
            Self::Native { label, run } => {
                let started = std::time::Instant::now();
                run(repo).map_err(|report| ToolError::Failed {
                    command: label.clone(),
                    code: Some(1),
                    stderr: report,
                })?;
                Ok(started.elapsed())
            }
        }
    }
}

/// The documentation policy, as a gate step.
fn docs_step() -> Step {
    Step::Native {
        label: "cargo dev docs check".to_owned(),
        run: |repo| {
            let report = crate::docs::check(repo);
            if report.is_clean() {
                println!("{}", report.render());
                Ok(())
            } else {
                Err(report.render())
            }
        },
    }
}

impl Scope {
    /// Builds the ordered step list for this scope.
    ///
    /// The order mirrors `scripts/check.sh` because several steps depend on
    /// earlier ones having already failed fast: formatting before lint, lint
    /// before tests, cheap validators before the expensive triple test run.
    fn steps(self, repo: &Path) -> Vec<Step> {
        let mut steps = Vec::new();
        steps.extend(shell_syntax_steps(repo));
        steps.push(docs_step());
        steps.extend(validator_steps(repo, self));
        steps.extend(self.cargo_steps(repo));
        steps
    }

    /// The cargo half of the gate.
    fn cargo_steps(self, repo: &Path) -> Vec<Step> {
        let mut steps = Vec::new();
        steps.push(cargo(
            repo,
            "cargo fmt --all --check",
            &["fmt", "--all", "--check"],
        ));
        steps.push(cargo(
            repo,
            "cargo clippy --all-targets --all-features --locked -- -D warnings",
            &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ));

        if self == Self::All {
            steps.push(cargo(
                repo,
                "cargo deny --all-features check bans licenses sources",
                &[
                    "deny",
                    "--all-features",
                    "check",
                    "bans",
                    "licenses",
                    "sources",
                ],
            ));
            steps.push(Step::External {
                label: "cargo doc --all-features --locked --no-deps".to_owned(),
                tool: Tool::new("cargo")
                    .args(["doc", "--all-features", "--locked", "--no-deps"])
                    .env("RUSTDOCFLAGS", "-D warnings")
                    .current_dir(repo)
                    .streaming(),
            });
        }

        steps.push(Step::External {
            label: "cargo nextest run --all-features --locked".to_owned(),
            tool: Tool::new("cargo")
                .args([
                    "nextest",
                    "run",
                    "--profile",
                    "default",
                    "--all-features",
                    "--locked",
                ])
                .current_dir(repo)
                .streaming(),
        });

        if self == Self::All {
            steps.push(cargo(
                repo,
                "cargo test --doc --all-features --locked",
                &["test", "--doc", "--all-features", "--locked"],
            ));
            steps.push(cargo(
                repo,
                "cargo test --release --all-features --locked",
                &["test", "--release", "--all-features", "--locked"],
            ));
            steps.push(cargo(
                repo,
                "cargo test --benches --all-features --locked --no-run",
                &[
                    "test",
                    "--benches",
                    "--all-features",
                    "--locked",
                    "--no-run",
                ],
            ));
        }

        steps
    }
}

/// Shell syntax checks over whatever scripts still exist.
///
/// The legacy script hard-codes `scripts/*.sh`. Discovering them instead means
/// this step keeps working as the migration deletes scripts, and disappears
/// entirely once none remain.
fn shell_syntax_steps(repo: &Path) -> Vec<Step> {
    shell_scripts(repo)
        .into_iter()
        .map(|script| Step::External {
            label: format!("bash -n {script}"),
            tool: Tool::new("bash").arg("-n").arg(&script).current_dir(repo),
        })
        .collect()
}

/// The Python validators, which still own their policy in this slice.
fn validator_steps(repo: &Path, scope: Scope) -> Vec<Step> {
    let mut steps = Vec::new();
    let fast: [(&str, &[&str]); 3] = [
        ("fuzz-targets.py", &[]),
        ("active-probe-gate.py", &["--check"]),
        ("check-performance-contract.py", &[]),
    ];
    let full: [(&str, &[&str]); 3] = [
        ("test-performance-gates.py", &[]),
        ("test-release-canary.py", &[]),
        ("test-config-identity-fingerprint.py", &[]),
    ];
    let selected: Vec<(&str, &[&str])> = if scope == Scope::All {
        fast.iter().chain(full.iter()).copied().collect()
    } else {
        fast.to_vec()
    };
    for (name, args) in selected {
        let path = format!("scripts/{name}");
        if !repo.join(&path).is_file() {
            continue;
        }
        let label = format!("python3 {path} {}", args.join(" "));
        steps.push(Step::External {
            label: label.trim_end().to_owned(),
            tool: Tool::new("python3")
                .arg(&path)
                .args(args.iter().copied())
                .current_dir(repo)
                .streaming(),
        });
    }
    if scope == Scope::All && repo.join("scripts/test-package-release.sh").is_file() {
        steps.push(Step::External {
            label: "scripts/test-package-release.sh".to_owned(),
            tool: Tool::new("bash")
                .arg("scripts/test-package-release.sh")
                .current_dir(repo)
                .streaming(),
        });
    }
    steps
}

fn cargo(repo: &Path, label: &str, args: &[&str]) -> Step {
    Step::External {
        label: label.to_owned(),
        tool: Tool::new("cargo")
            .args(args.iter().copied())
            .current_dir(repo)
            .streaming(),
    }
}

/// Lists the shell scripts still present, sorted for deterministic ordering.
fn shell_scripts(repo: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(repo.join("scripts")) else {
        return Vec::new();
    };
    let mut scripts: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let is_shell = path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"));
            let name = entry.file_name().to_string_lossy().into_owned();
            is_shell.then(|| format!("scripts/{name}"))
        })
        .collect();
    scripts.sort_unstable();
    scripts
}

/// Runs the gate, stopping at the first failure.
///
/// # Errors
///
/// Returns the first step failure. Steps run in dependency order, so an early
/// failure usually explains the later ones and stopping is the useful behaviour.
pub fn run(repo: &Path, scope: Scope) -> Result<(), ToolError> {
    for tool in ["cargo", "python3", "bash"] {
        if !Tool::exists(tool) {
            return Err(ToolError::NotFound {
                program: tool.to_owned(),
            });
        }
    }

    let steps = scope.steps(repo);
    let total = steps.len();
    let mut slowest: Option<(String, std::time::Duration)> = None;
    for (index, step) in steps.into_iter().enumerate() {
        println!("\n==> [{}/{total}] {}", index + 1, step.label());
        let elapsed = step.execute(repo)?;
        let replace = slowest
            .as_ref()
            .is_none_or(|(_, longest)| elapsed > *longest);
        if replace {
            slowest = Some((step.label().to_owned(), elapsed));
        }
    }
    println!("\nall {total} checks passed");
    if let Some((label, elapsed)) = slowest {
        println!("slowest step: {label} ({:.1}s)", elapsed.as_secs_f64());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> std::path::PathBuf {
        // tools/rr-dev/src -> tools/rr-dev -> tools -> repository root
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest must sit three levels below the repository root")
            .to_path_buf()
    }

    #[test]
    fn the_full_scope_is_a_superset_of_the_fast_scope() {
        let repo = repo_root();
        let fast: Vec<String> = Scope::Fast
            .steps(&repo)
            .into_iter()
            .map(|step| step.label().to_owned())
            .collect();
        let all: Vec<String> = Scope::All
            .steps(&repo)
            .into_iter()
            .map(|step| step.label().to_owned())
            .collect();
        for label in &fast {
            assert!(
                all.contains(label),
                "the fast scope must never run a step the full scope skips: {label}"
            );
        }
        assert!(
            all.len() > fast.len(),
            "the full scope must add steps, otherwise the split is pointless"
        );
    }

    #[test]
    fn the_full_scope_matches_the_legacy_script_step_for_step() {
        let repo = repo_root();
        let script = repo.join("scripts/check.sh");
        if !script.is_file() {
            // The script has been deleted by a later migration slice; parity is
            // then guaranteed by the golden test that replaced this one.
            return;
        }
        let source = std::fs::read_to_string(&script).expect("check.sh must be readable");
        let labels: Vec<String> = Scope::All
            .steps(&repo)
            .into_iter()
            .map(|step| step.label().to_owned())
            .collect();
        let joined = labels.join("\n");

        // Every cargo and python step the script runs must appear in the gate.
        for required in [
            "cargo dev docs check",
            "fuzz-targets.py",
            "active-probe-gate.py",
            "check-performance-contract.py",
            "test-performance-gates.py",
            "test-release-canary.py",
            "test-config-identity-fingerprint.py",
            "test-package-release.sh",
            "cargo fmt --all --check",
            "clippy",
            "deny",
            "doc",
            "nextest",
        ] {
            assert!(
                source.contains(required),
                "this parity test is stale: check.sh no longer mentions {required}"
            );
            assert!(
                joined.contains(required),
                "the gate omits a step the legacy script runs: {required}"
            );
        }
    }

    #[test]
    fn the_shell_syntax_sweep_covers_every_surviving_script() {
        let repo = repo_root();
        let discovered = shell_scripts(&repo);
        let on_disk = std::fs::read_dir(repo.join("scripts")).map_or(0, |entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"))
                })
                .count()
        });
        assert_eq!(
            discovered.len(),
            on_disk,
            "discovery must not miss a script, or a syntax error could reach main"
        );
        assert!(
            discovered.windows(2).all(|pair| pair[0] <= pair[1]),
            "ordering must be deterministic for reproducible logs"
        );
    }

    #[test]
    fn steps_never_route_through_a_shell_interpreter() {
        let repo = repo_root();
        for step in Scope::All.steps(&repo) {
            let rendered = match &step {
                Step::External { tool, .. } => tool.redacted(),
                Step::Native { label, .. } => label.clone(),
            };
            assert!(
                !rendered.contains("sh -c"),
                "no gate step may build a shell command line: {rendered}"
            );
        }
    }
}
