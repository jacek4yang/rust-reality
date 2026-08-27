//! Release tag identity gate — the typed form of `verify-release-tag.sh`.
//!
//! Proves, before any artifact is built, that the release tag is stable `SemVer`,
//! equals the Cargo package version, is an annotated tag, points at the current
//! `HEAD`, and is reachable from the mainline ref. These are load-bearing release
//! safety invariants: a release must have exact commit and tag identity.

use std::path::Path;

use crate::{perf::json_in, process::Tool, release::semver};

/// Verifies the tag identity for `tag`, comparing reachability against `main_ref`.
///
/// # Errors
///
/// Returns a message describing the first violated identity invariant, matching
/// the shell script's diagnostics.
pub fn verify(repo: &Path, tag: &str, main_ref: &str) -> Result<String, String> {
    if !semver::is_stable_release_tag(tag) {
        return Err(format!(
            "release tag must be stable SemVer in vMAJOR.MINOR.PATCH form: {tag}"
        ));
    }
    let tag_version = tag.trim_start_matches('v');
    let package_version = cargo_package_version(repo)?;
    if tag_version != package_version {
        return Err(format!(
            "release tag {tag} does not match Cargo package version {package_version}"
        ));
    }

    let object_type = git(repo, &["cat-file", "-t", &format!("refs/tags/{tag}")])
        .map_err(|_| format!("release tag object does not exist: {tag}"))?;
    if object_type.trim() != "tag" {
        return Err(format!(
            "release tag {tag} must be annotated, but refs/tags/{tag} is a {} object",
            object_type.trim()
        ));
    }

    let tag_commit = git(repo, &["rev-parse", "--verify", &format!("{tag}^{{commit}}")])?;
    let head_commit = git(repo, &["rev-parse", "--verify", "HEAD"])?;
    let tag_commit = tag_commit.trim();
    let head_commit = head_commit.trim();
    if tag_commit != head_commit {
        return Err(format!(
            "release tag {tag} points to {tag_commit}, but the checkout is {head_commit}"
        ));
    }

    let ancestor = Tool::new("git")
        .args(["-C"])
        .arg(repo.to_string_lossy().into_owned())
        .args(["merge-base", "--is-ancestor", tag_commit, main_ref])
        .probe()
        .map_err(|error| format!("git merge-base failed: {error}"))?;
    if !ancestor.success() {
        return Err(format!(
            "release commit {tag_commit} is not reachable from {main_ref}"
        ));
    }

    Ok(format!("release identity verified: {tag} at {tag_commit}"))
}

/// Reads the single `rust-reality` package version from `cargo metadata`.
fn cargo_package_version(repo: &Path) -> Result<String, String> {
    let out = Tool::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(repo)
        .probe()
        .map_err(|error| format!("cargo metadata failed: {error}"))?;
    if !out.success() {
        return Err("cargo metadata failed".to_owned());
    }
    let value = json_in::parse(&out.stdout)?;
    let packages = value
        .optional("packages")
        .and_then(|packages| packages.as_array("packages").ok())
        .ok_or_else(|| "cargo metadata has no packages array".to_owned())?;
    let versions: Vec<String> = packages
        .iter()
        .filter(|package| {
            package
                .optional("name")
                .and_then(|name| name.as_str("name").ok())
                == Some("rust-reality")
        })
        .filter_map(|package| {
            package
                .optional("version")
                .and_then(|version| version.as_str("version").ok())
                .map(str::to_owned)
        })
        .collect();
    if versions.len() != 1 {
        return Err("cargo metadata must contain exactly one rust-reality package".to_owned());
    }
    Ok(versions.into_iter().next().unwrap_or_default())
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Tool::new("git")
        .args(["-C"])
        .arg(repo.to_string_lossy().into_owned())
        .args(args.iter().copied())
        .probe()
        .map_err(|error| format!("git failed: {error}"))?;
    if !out.success() {
        return Err(format!("git {:?} exited with {:?}", args, out.code));
    }
    Ok(out.stdout)
}
