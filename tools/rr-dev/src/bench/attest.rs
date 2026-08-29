//! Attesting the inputs a formal measurement depended on.
//!
//! A benchmark number is only evidence if you can say what produced it. Each
//! harness therefore pinned its inputs before measuring and re-checked them
//! afterwards: the repository commit and cleanliness, each binary's SHA-256 and
//! GNU build ID, the claim that the candidate ELF actually embeds the commit it
//! says it does, the baseline's identity sidecar, and — per slot — that the
//! process being measured is really running the registered executable.
//!
//! ## Two definitions of "dirty"
//!
//! The family does not agree on what a dirty repository is, and the difference is
//! load-bearing rather than accidental:
//!
//! * The paired setup-rate and fallback suites use
//!   `git status --porcelain=v1 --untracked-files=normal`, so an **untracked**
//!   file fails the run.
//! * The comparator suite uses `git diff --quiet` plus
//!   `git diff --cached --quiet`, which ignores untracked files entirely.
//!
//! Collapsing these to one rule would change which runs are accepted, so
//! [`Dirtiness`] keeps both.

use std::path::Path;

use crate::{hash, perf::json_in, process::Tool};

/// Which working-tree changes count as dirty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dirtiness {
    /// `git status --porcelain=v1 --untracked-files=normal`: untracked counts.
    IncludingUntracked,
    /// `git diff --quiet` and `git diff --cached --quiet`: tracked and staged only.
    TrackedAndStagedOnly,
}

/// The repository facts a run records and re-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryState {
    /// The resolved 40-hex `HEAD` commit.
    pub head: String,
    /// Whether the working tree is dirty under the chosen rule.
    pub dirty: bool,
}

/// Reads `HEAD` and working-tree cleanliness under `rule`.
///
/// # Errors
///
/// Returns a message when git is unavailable or `HEAD` is not a valid commit.
pub fn repository_state(repo: &Path, rule: Dirtiness) -> Result<RepositoryState, String> {
    let outcome = Tool::new("git")
        .args([
            "-C",
            &repo.display().to_string(),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ])
        .probe()
        .map_err(|error| format!("git rev-parse failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "repository HEAD is not a valid commit: {}",
            outcome.stderr.trim_end()
        ));
    }
    let head = outcome.trimmed_stdout().to_owned();
    if !(head.len() == 40 && head.chars().all(|c| c.is_ascii_hexdigit())) {
        return Err(format!("repository HEAD is not a 40-hex commit: {head}"));
    }
    let dirty = match rule {
        Dirtiness::IncludingUntracked => {
            let outcome = Tool::new("git")
                .args([
                    "-C",
                    &repo.display().to_string(),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=normal",
                ])
                .probe()
                .map_err(|error| format!("git status failed: {error}"))?;
            if !outcome.success() {
                return Err(format!("git status failed: {}", outcome.stderr.trim_end()));
            }
            !outcome.trimmed_stdout().is_empty()
        }
        Dirtiness::TrackedAndStagedOnly => {
            !(git_diff_quiet(repo, false)? && git_diff_quiet(repo, true)?)
        }
    };
    Ok(RepositoryState { head, dirty })
}

/// Whether `git diff [--cached] --quiet --ignore-submodules=none --` reports clean.
fn git_diff_quiet(repo: &Path, cached: bool) -> Result<bool, String> {
    let repo = repo.display().to_string();
    let mut args = vec!["-C", &repo, "diff"];
    if cached {
        args.push("--cached");
    }
    args.extend(["--quiet", "--ignore-submodules=none", "--"]);
    let outcome = Tool::new("git")
        .args(args)
        .probe()
        .map_err(|error| format!("git diff failed: {error}"))?;
    Ok(outcome.success())
}

/// Reads a binary's GNU build ID.
///
/// The harnesses required one on every binary under test: two builds of the same
/// source can differ, and the build ID is what distinguishes them in the report
/// when the paths are identical.
///
/// # Errors
///
/// Returns a message when `readelf` is unavailable or prints no build ID.
pub fn build_id(binary: &Path) -> Result<String, String> {
    let outcome = Tool::new("readelf")
        .args(["-n", &binary.display().to_string()])
        .probe()
        .map_err(|error| format!("readelf failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "readelf exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    outcome
        .trimmed_stdout()
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix("Build ID:")?;
            let id = rest.split_whitespace().next()?;
            (!id.is_empty()).then(|| id.to_owned())
        })
        .ok_or_else(|| format!("{} has no GNU build ID", binary.display()))
}

/// Whether the binary's bytes contain `commit` literally.
///
/// `grep -aFq -- "$commit" "$candidate_bin"` in the originals. A candidate that
/// claims a commit it does not embed is not the build it says it is.
///
/// # Errors
///
/// Returns a message when the binary cannot be read or `commit` is empty.
pub fn embeds_commit(binary: &Path, commit: &str) -> Result<bool, String> {
    if commit.is_empty() {
        return Err("cannot search a binary for an empty commit".to_owned());
    }
    let bytes = std::fs::read(binary)
        .map_err(|error| format!("could not read {}: {error}", binary.display()))?;
    let needle = commit.as_bytes();
    Ok(bytes.windows(needle.len()).any(|window| window == needle))
}

/// Verifies a baseline identity sidecar binds the requested commit and binary.
///
/// The sidecar is how a prebuilt baseline ELF — one whose source is no longer
/// checked out — stays attributable. It must name the same binary digest and
/// assert that its own `sha256sums` were verified when it was made. The commit is
/// checked only when the caller supplies one to check against, because a prebuilt
/// baseline cannot be asked for its own commit: the sidecar is the source of that
/// fact, not a second opinion on it.
///
/// # Errors
///
/// Returns a message when the sidecar is unreadable, malformed, or does not bind
/// both the commit and the digest.
pub fn verify_identity_sidecar(
    sidecar: &Path,
    expected_commit: Option<&str>,
    expected_sha256: &str,
) -> Result<(), String> {
    let kind = sidecar
        .symlink_metadata()
        .map_err(|error| format!("could not stat {}: {error}", sidecar.display()))?;
    if !kind.is_file() {
        return Err(format!(
            "the baseline identity must be a regular non-symlink file: {}",
            sidecar.display()
        ));
    }
    let raw = std::fs::read_to_string(sidecar)
        .map_err(|error| format!("could not read {}: {error}", sidecar.display()))?;
    let value = json_in::parse(&raw)
        .map_err(|error| format!("baseline identity is invalid JSON: {error}"))?;
    let source_commit = value
        .field("identity", "sourceCommit")
        .and_then(|field| field.as_str("identity.sourceCommit"))
        .map_err(|error| format!("baseline identity: {error}"))?;
    let binary_sha256 = value
        .field("identity", "binarySha256")
        .and_then(|field| field.as_str("identity.binarySha256"))
        .map_err(|error| format!("baseline identity: {error}"))?;
    let verified = matches!(
        value.field("identity", "sha256sumsVerified"),
        Ok(json_in::Value::Bool(true))
    );
    if let Some(expected_commit) = expected_commit
        && !source_commit.eq_ignore_ascii_case(expected_commit)
    {
        return Err(format!(
            "baseline identity names commit {source_commit}, expected {expected_commit}"
        ));
    }
    if !binary_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err(format!(
            "baseline identity names binary {binary_sha256}, expected {expected_sha256}"
        ));
    }
    if !verified {
        return Err("baseline identity does not assert sha256sumsVerified".to_owned());
    }
    Ok(())
}

/// The SHA-256 of the executable a running process is actually running.
///
/// Reading `/proc/<pid>/exe` follows the kernel's own link to the mapped image, so
/// this catches a slot that launched something other than the registered binary —
/// a stale build on `PATH`, or a rebuild that landed mid-run.
///
/// # Errors
///
/// Returns a message when the process is gone or its image cannot be read.
pub fn running_executable_sha256(pid: u32) -> Result<String, String> {
    let path = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    hash::sha256_file(&path)
        .map_err(|error| format!("could not hash the image of PID {pid}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rr-bench-attest-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, contents).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_identity_sidecar_must_bind_both_the_commit_and_the_digest() {
        let scratch = Scratch::new("identity");
        let commit = "a".repeat(40);
        let sha = "b".repeat(64);
        let good = scratch.write(
            "identity.json",
            &format!(
                "{{\"sourceCommit\":\"{}\",\"binarySha256\":\"{}\",\"sha256sumsVerified\":true}}",
                commit.to_uppercase(),
                sha.to_uppercase()
            ),
        );
        // Case-insensitive on both hex fields, as the jq `ascii_downcase` was.
        verify_identity_sidecar(&good, Some(&commit), &sha)
            .expect("an uppercase sidecar still binds");

        assert!(verify_identity_sidecar(&good, Some(&"c".repeat(40)), &sha).is_err());
        assert!(verify_identity_sidecar(&good, Some(&commit), &"d".repeat(64)).is_err());
        // With no commit to check against, the digest binding still applies.
        verify_identity_sidecar(&good, None, &sha).expect("the digest still binds");
        assert!(verify_identity_sidecar(&good, None, &"d".repeat(64)).is_err());

        let unverified = scratch.write(
            "unverified.json",
            &format!(
                "{{\"sourceCommit\":\"{commit}\",\"binarySha256\":\"{sha}\",\
                 \"sha256sumsVerified\":false}}"
            ),
        );
        let error = verify_identity_sidecar(&unverified, Some(&commit), &sha).unwrap_err();
        assert!(error.contains("sha256sumsVerified"), "{error}");

        let missing = scratch.write("missing.json", "{}");
        assert!(verify_identity_sidecar(&missing, Some(&commit), &sha).is_err());
    }

    #[test]
    fn a_binary_is_searched_for_the_commit_it_claims() {
        let scratch = Scratch::new("embeds");
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let binary = scratch.write("bin", &format!("\u{0}\u{1}binary{commit}bytes\u{0}"));
        assert!(embeds_commit(&binary, commit).unwrap());
        assert!(!embeds_commit(&binary, &"f".repeat(40)).unwrap());
        assert!(embeds_commit(&binary, "").is_err());
    }

    /// This repository is a git worktree, so both rules must resolve HEAD here.
    #[test]
    fn the_repository_state_resolves_head_under_both_rules() {
        let Ok(repo) = std::env::current_dir() else {
            return;
        };
        let Ok(loose) = repository_state(&repo, Dirtiness::TrackedAndStagedOnly) else {
            // Not a git checkout (for example a vendored source tarball); nothing
            // to assert about git here.
            return;
        };
        let strict = repository_state(&repo, Dirtiness::IncludingUntracked).unwrap();
        assert_eq!(loose.head, strict.head);
        assert_eq!(loose.head.len(), 40);
        // The strict rule can only ever be at least as dirty as the loose one.
        assert!(
            strict.dirty || !loose.dirty,
            "untracked-sensitive dirtiness must subsume tracked-only dirtiness"
        );
    }

    /// The test binary itself is a process whose image can be hashed.
    #[test]
    fn the_running_image_of_this_process_can_be_hashed() {
        let digest = running_executable_sha256(std::process::id()).unwrap();
        assert_eq!(digest.len(), 64);
        let from_path = hash::sha256_file(&std::env::current_exe().unwrap()).unwrap();
        assert_eq!(digest, from_path, "/proc/self/exe is this test binary");
        assert!(running_executable_sha256(u32::MAX).is_err());
    }

    /// Every ELF this toolchain produces carries a build ID, including the test
    /// binary, so this exercises the real `readelf` path when it is available.
    #[test]
    fn a_real_binary_has_a_build_id() {
        if !Tool::exists("readelf") {
            return;
        }
        let this = std::env::current_exe().unwrap();
        let id = build_id(&this).expect("the test binary has a GNU build ID");
        assert!(
            !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()),
            "build id must be hex, got {id}"
        );
    }
}
