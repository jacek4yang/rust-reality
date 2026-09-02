//! Deterministic short libFuzzer smoke runs — the typed form of `fuzz-smoke.sh`.
//!
//! Each selected target runs for a fixed wall-clock budget against its checked-in
//! seed corpus plus a scratch corpus in a temporary directory, so the run is
//! reproducible and checked-in seeds are never mutated. Budgets come from the same
//! environment variables the script honoured, with the same bounds and the same
//! `FUZZ_SMOKE_SECONDS` capping behaviour.
//!
//! `cargo fuzz` and the nightly toolchain remain external mechanism; this module
//! owns target selection, budget policy, corpus layout and failure aggregation.

use std::path::{Path, PathBuf};

use crate::{fuzz::targets, process::Tool};

/// Parsed and validated smoke budgets.
struct Budgets {
    seconds: u64,
    case_timeout: u64,
    max_len: u64,
    toolchain: String,
    output_dir: Option<String>,
}

/// Reads and validates budgets from the environment, matching the script's bounds.
fn budgets() -> Result<Budgets, String> {
    let seconds = env_positive("FUZZ_SMOKE_SECONDS", 20)?;
    let max_seconds = env_positive("FUZZ_SMOKE_MAX_SECONDS", 30)?;
    let case_timeout = env_positive("FUZZ_CASE_TIMEOUT_SECONDS", 5)?;
    let max_len = env_positive("FUZZ_MAX_LEN", 131_072)?;
    let toolchain = std::env::var("FUZZ_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_owned());

    if case_timeout > 30 {
        return Err("fuzz-smoke: FUZZ_CASE_TIMEOUT_SECONDS must be 1..30".to_owned());
    }
    if max_len > 1_048_576 {
        return Err("fuzz-smoke: FUZZ_MAX_LEN must be 1..1048576".to_owned());
    }
    let seconds = if seconds > max_seconds {
        eprintln!("fuzz-smoke: capping FUZZ_SMOKE_SECONDS at {max_seconds}");
        max_seconds
    } else {
        seconds
    };

    Ok(Budgets {
        seconds,
        case_timeout,
        max_len,
        toolchain,
        output_dir: std::env::var("FUZZ_OUTPUT_DIR").ok(),
    })
}

/// Runs a smoke pass over `requested` targets, or all targets when empty.
///
/// # Errors
///
/// Returns a message on invalid budgets, an unknown requested target, or a target
/// whose libFuzzer run fails; all target failures are aggregated into one error.
pub fn smoke(repo: &Path, requested: &[String]) -> Result<String, String> {
    let budgets = budgets()?;
    let known = targets::all(repo).map_err(|error| error.to_string())?;
    let selected: Vec<String> = if requested.is_empty() {
        known.clone()
    } else {
        for target in requested {
            if !known.contains(target) {
                return Err(format!("fuzz-smoke: unknown target: {target}"));
            }
        }
        requested.to_vec()
    };

    let scratch = crate::release::package::tempdir("rust-reality-fuzz-smoke")?;
    let output_dir = resolve_output_dir(repo, scratch.path(), budgets.output_dir.as_deref());
    std::fs::create_dir_all(&output_dir)
        .map_err(|error| format!("could not create fuzz output dir: {error}"))?;

    let mut failures: Vec<String> = Vec::new();
    for target in &selected {
        println!("==> fuzz-smoke: {target} ({}s)", budgets.seconds);
        if let Err(reason) = run_target(repo, scratch.path(), &output_dir, target, &budgets) {
            eprintln!("fuzz-smoke: {target} FAILED: {reason}");
            failures.push(target.clone());
        }
    }

    if failures.is_empty() {
        Ok(format!("fuzz smoke: PASS ({} targets)", selected.len()))
    } else {
        Err(format!(
            "fuzz-smoke failed targets: {}",
            failures.join(", ")
        ))
    }
}

/// Runs one target's libFuzzer smoke pass.
fn run_target(
    repo: &Path,
    scratch: &Path,
    output_dir: &Path,
    target: &str,
    budgets: &Budgets,
) -> Result<(), String> {
    // libFuzzer writes new units to the first corpus directory; the scratch
    // directory comes first so checked-in seeds and any local grown corpus stay
    // untouched and the run remains reproducible.
    let target_scratch = scratch.join(target);
    std::fs::create_dir_all(&target_scratch)
        .map_err(|error| format!("could not create scratch corpus: {error}"))?;

    let mut corpus_args: Vec<String> = vec![target_scratch.to_string_lossy().into_owned()];
    for candidate in [
        format!("fuzz/seeds/{target}"),
        format!("fuzz/corpus/{target}"),
    ] {
        if repo.join(&candidate).is_dir() {
            corpus_args.push(candidate);
        }
    }
    let dict = format!("fuzz/dictionaries/{target}.dict");
    let mut libfuzzer_args: Vec<String> = vec![
        format!("-max_total_time={}", budgets.seconds),
        format!("-timeout={}", budgets.case_timeout),
        format!("-max_len={}", budgets.max_len),
        "-rss_limit_mb=2048".to_owned(),
        "-print_final_stats=1".to_owned(),
        format!("-artifact_prefix={}/{target}-", output_dir.display()),
    ];
    if repo.join(&dict).is_file() {
        libfuzzer_args.push(format!("-dict={dict}"));
    }

    let outcome = Tool::new("cargo")
        .arg(format!("+{}", budgets.toolchain))
        .args(["fuzz", "run", target, "--"])
        .args(libfuzzer_args)
        .args(corpus_args)
        .current_dir(repo)
        .streaming()
        .probe()
        .map_err(|error| error.to_string())?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!("libFuzzer exited with {:?}", outcome.code))
    }
}

/// Resolves the artifact output directory, honouring a relative `FUZZ_OUTPUT_DIR`.
fn resolve_output_dir(repo: &Path, scratch: &Path, configured: Option<&str>) -> PathBuf {
    match configured {
        Some(dir) if Path::new(dir).is_absolute() => PathBuf::from(dir),
        Some(dir) => repo.join(dir),
        None => scratch.join("output"),
    }
}

/// Reads a positive-integer environment variable, or its default when unset.
fn env_positive(key: &str, default: u64) -> Result<u64, String> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .parse::<u64>()
            .ok()
            .filter(|value| *value >= 1)
            .ok_or_else(|| format!("fuzz-smoke: {key} must be a positive integer")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_output_dir_is_anchored_at_the_repo() {
        let repo = Path::new("/repo");
        let scratch = Path::new("/tmp/scratch");
        assert_eq!(
            resolve_output_dir(repo, scratch, Some("fuzz-output")),
            PathBuf::from("/repo/fuzz-output")
        );
        assert_eq!(
            resolve_output_dir(repo, scratch, Some("/abs/out")),
            PathBuf::from("/abs/out")
        );
        assert_eq!(
            resolve_output_dir(repo, scratch, None),
            PathBuf::from("/tmp/scratch/output")
        );
    }
}
