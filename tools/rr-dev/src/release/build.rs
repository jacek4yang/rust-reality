//! Per-tier release build — the typed form of `build-release.sh`.
//!
//! Builds (and, unless `--build-only`, tests) a tier's workspace with the tier's
//! `target-cpu`/`target-feature` `RUSTFLAGS`, into the tier's dedicated target
//! directory. Cross targets require `--build-only` because they cannot execute on
//! the build host, with one deliberate exception: the `x86_64` musl target produces
//! fully static binaries that run directly on the same `x86_64` kernel, so it is
//! treated as runnable.

use std::path::Path;

use crate::{process::Tool, release::matrix::Tier};

/// Builds a tier under `repo`.
///
/// When `build_only` is false the workspace is tested first, then built. Returns
/// the built binary path and its SHA-256 line as printed by the script.
///
/// # Errors
///
/// Returns a message on an unknown tier, a cross tier invoked without
/// `--build-only`, a missing musl C compiler, or any cargo failure.
pub fn build(repo: &Path, tier_id: &str, build_only: bool) -> Result<String, String> {
    let tier = Tier::resolve(tier_id)?;
    let host = host_target()?;
    let cross = tier.target != host;
    let musl_runnable =
        host == "x86_64-unknown-linux-gnu" && tier.target == "x86_64-unknown-linux-musl";
    if cross && !musl_runnable && !build_only {
        return Err(format!(
            "cross tier {} ({} on {host}) requires --build-only",
            tier.id, tier.target
        ));
    }

    let mut rustflags = format!("-C target-cpu={}", tier.target_cpu);
    if !tier.target_features.is_empty() {
        use std::fmt::Write as _;
        let _ = write!(rustflags, " -C target-feature={}", tier.target_features);
    }
    let target_dir = repo.join(tier.target_dir);
    let commit = git_head(repo, &["rev-parse", "--verify", "HEAD"])?;
    let epoch = git_head(repo, &["show", "-s", "--format=%ct", "HEAD"])?;

    let mut musl_cc = None;
    if tier.target == "x86_64-unknown-linux-musl" {
        musl_cc = Some(resolve_musl_cc(&host, tier.target)?);
    }

    let target_args: Vec<&str> = if cross {
        vec!["--target", tier.target]
    } else {
        Vec::new()
    };

    if !build_only {
        run_cargo(
            repo,
            &target_dir,
            &rustflags,
            &commit,
            &epoch,
            musl_cc.as_deref(),
            "test",
            &target_args,
        )?;
    }
    run_cargo(
        repo,
        &target_dir,
        &rustflags,
        &commit,
        &epoch,
        musl_cc.as_deref(),
        "build",
        &target_args,
    )?;

    let binary = if cross {
        target_dir.join(tier.target).join("release/rust-reality")
    } else {
        target_dir.join("release/rust-reality")
    };
    let digest = sha256_line(&binary)?;
    Ok(format!("{}: {digest}", tier.id))
}

#[allow(clippy::too_many_arguments)]
fn run_cargo(
    repo: &Path,
    target_dir: &Path,
    rustflags: &str,
    commit: &str,
    epoch: &str,
    musl_cc: Option<&str>,
    subcommand: &str,
    target_args: &[&str],
) -> Result<(), String> {
    let mut tool = Tool::new("cargo")
        .arg(subcommand)
        .args(["--workspace", "--release", "--locked"])
        .args(target_args.iter().copied())
        .current_dir(repo)
        .env(
            "CARGO_TARGET_DIR",
            target_dir.to_string_lossy().into_owned(),
        )
        .env("RUSTFLAGS", rustflags)
        .env("RUST_REALITY_GIT_COMMIT", commit)
        .env("SOURCE_DATE_EPOCH", epoch)
        .streaming();
    if let Some(cc) = musl_cc {
        // musl-gcc only for C dependencies (ring); Rust's musl target owns the
        // final self-contained link.
        tool = tool.env("CC_x86_64_unknown_linux_musl", cc);
    }
    tool.run().map(|_| ()).map_err(|error| error.to_string())
}

/// Resolves the musl C compiler, matching the script's fallback order.
fn resolve_musl_cc(host: &str, target: &str) -> Result<String, String> {
    if let Ok(explicit) = std::env::var("CC_x86_64_unknown_linux_musl")
        && !explicit.is_empty()
    {
        return Ok(explicit);
    }
    if Tool::exists("musl-gcc") {
        return Ok("musl-gcc".to_owned());
    }
    if host == target && Tool::exists("cc") {
        return Ok("cc".to_owned());
    }
    Err("x86_64 musl release requires musl-gcc (install musl-tools)".to_owned())
}

fn host_target() -> Result<String, String> {
    let out = Tool::new("rustc")
        .arg("-vV")
        .probe()
        .map_err(|error| format!("rustc -vV failed: {error}"))?;
    out.stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc -vV did not report a host target".to_owned())
}

fn git_head(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Tool::new("git")
        .args(["-C"])
        .arg(repo.to_string_lossy().into_owned())
        .args(args.iter().copied())
        .probe()
        .map_err(|error| format!("git failed: {error}"))?;
    if !out.success() {
        return Err(format!("git {args:?} failed"));
    }
    Ok(out.trimmed_stdout().to_owned())
}

fn sha256_line(binary: &Path) -> Result<String, String> {
    let out = Tool::new("sha256sum")
        .arg(binary.to_string_lossy().into_owned())
        .probe()
        .map_err(|error| format!("sha256sum failed: {error}"))?;
    if !out.success() {
        return Err(format!("sha256sum failed for {}", binary.display()));
    }
    Ok(out.trimmed_stdout().to_owned())
}
