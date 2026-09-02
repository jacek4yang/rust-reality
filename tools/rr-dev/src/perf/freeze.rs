//! Identity-bound release artifact freezing.
//!
//! `perf hotspot`, `perf environment` and the evaluator all *consume* a binary
//! that already carries its source commit, its SHA-256 and its ELF Build ID.
//! Nothing produced one, so every comparison began with an ad-hoc sequence of
//! `cargo build`, `sha256sum`, `readelf` and a hand-written note — and the one
//! step that is easy to forget, `RUST_REALITY_GIT_COMMIT`, is the step whose
//! omission is only discovered later, by a capture that refuses to start.
//!
//! This command closes that gap. It builds one named commit with the commit
//! embedded, archives the result read-only, and fails immediately if the binary
//! does not report the commit that was asked for. The complete build log stays
//! in the evidence directory as raw authority, `freeze.json` is the machine
//! authority, and the returned summary is a compact projection of both.

use std::path::{Path, PathBuf};

use crate::bench::{
    attest,
    evidence::RunDirectory,
    identity::{self, Kind},
};
use crate::hash;
use crate::perf::{evidence::is_commit_hex, json_out::Json};
use crate::process::Tool;

/// The binary the release profile produces and every perf command consumes.
const BINARY_NAME: &str = "rust-reality";

/// Everything one freeze needs.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Repository root to build.
    pub repo: PathBuf,
    /// The 40-hex source commit to build and embed.
    pub commit: String,
    /// New absolute evidence directory. Must not already exist.
    pub out_dir: PathBuf,
}

/// One frozen artifact's complete identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Source commit requested, embedded, and confirmed by the binary itself.
    pub commit: String,
    /// SHA-256 of the archived binary.
    pub sha256: String,
    /// ELF Build ID of the archived binary.
    pub build_id: String,
    /// Size of the archived binary in bytes.
    pub bytes: i64,
    /// Absolute path of the archived binary.
    pub archived: PathBuf,
}

fn validate(plan: &Plan) -> Result<(), String> {
    if !is_commit_hex(&plan.commit) {
        return Err("--commit must be 40 lowercase hexadecimal characters".to_owned());
    }
    if !plan.out_dir.is_absolute() {
        return Err("--out-dir must be absolute".to_owned());
    }
    Ok(())
}

/// Runs one `git` query in the repository and returns its trimmed stdout.
fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let outcome = Tool::new("git")
        .args(args.iter().copied())
        .current_dir(repo)
        .probe()
        .map_err(|error| format!("git {} failed: {error}", args.join(" ")))?;
    if !outcome.success() {
        return Err(format!(
            "git {} exited {:?}: {}",
            args.join(" "),
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    Ok(outcome.trimmed_stdout().to_owned())
}

/// Refuses to freeze anything but the exact requested commit, cleanly checked out.
///
/// The tool deliberately does not check the commit out itself. Moving `HEAD` on
/// a developer's behalf is a destructive operation against possibly valuable
/// working state, and an artifact built from a tree that merely *claims* a
/// commit is precisely the evidence failure this command exists to prevent.
fn verify_worktree(plan: &Plan) -> Result<(), String> {
    let head = git(&plan.repo, &["rev-parse", "HEAD"])?;
    if head != plan.commit {
        return Err(format!(
            "worktree is at {head}, not the requested {}; check the commit out first",
            plan.commit
        ));
    }
    let dirty = git(&plan.repo, &["status", "--porcelain"])?;
    if !dirty.is_empty() {
        return Err(format!(
            "worktree is not clean, so the artifact would not match {}:\n{dirty}",
            plan.commit
        ));
    }
    Ok(())
}

/// Builds the release profile with the commit embedded.
///
/// Cargo tracks the `option_env!` dependency, so changing only the commit does
/// force a rebuild of the crate that embeds it; the identity check afterwards
/// does not rely on that behaviour.
fn build(plan: &Plan, run_dir: &RunDirectory) -> Result<(), String> {
    let outcome = Tool::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(&plan.repo)
        .env("RUST_REALITY_GIT_COMMIT", plan.commit.clone())
        .probe()
        .map_err(|error| format!("cargo build failed to start: {error}"))?;
    run_dir.write_new("build.stdout", &outcome.stdout)?;
    run_dir.write_new("build.stderr", &outcome.stderr)?;
    if !outcome.success() {
        return Err(format!(
            "cargo build --release exited {:?}; see {}",
            outcome.code,
            run_dir.join("build.stderr").display()
        ));
    }
    Ok(())
}

/// Archives `source` read-only and re-verifies its identity after the copy.
fn archive(
    source: &Path,
    run_dir: &RunDirectory,
    sha256: &str,
    commit: &str,
) -> Result<Identity, String> {
    use std::os::unix::fs::PermissionsExt;

    let build_id = attest::build_id(source)?;
    let binary_dir = run_dir.join("binary");
    std::fs::create_dir(&binary_dir)
        .map_err(|error| format!("could not create {}: {error}", binary_dir.display()))?;
    let archived = binary_dir.join(BINARY_NAME);
    std::fs::copy(source, &archived)
        .map_err(|error| format!("could not archive {}: {error}", source.display()))?;
    let mut permissions = std::fs::metadata(&archived)
        .map_err(|error| format!("could not stat {}: {error}", archived.display()))?
        .permissions();
    permissions.set_mode(permissions.mode() & !0o222);
    std::fs::set_permissions(&archived, permissions)
        .map_err(|error| format!("could not make {} read-only: {error}", archived.display()))?;
    if hash::sha256_file(&archived)? != sha256 || attest::build_id(&archived)? != build_id {
        return Err("archived binary identity changed during copy".to_owned());
    }
    let length = std::fs::metadata(&archived)
        .map_err(|error| format!("could not stat {}: {error}", archived.display()))?
        .len();
    let bytes = i64::try_from(length)
        .map_err(|_| format!("archived binary size {length} does not fit an i64"))?;
    Ok(Identity {
        commit: commit.to_owned(),
        sha256: sha256.to_owned(),
        build_id,
        bytes,
        archived,
    })
}

fn document(identity: &Identity, repo: &Path) -> Json {
    Json::object([
        ("schemaVersion", Json::Int(1)),
        ("collector", Json::string("perf-freeze")),
        ("sourceCommit", Json::string(identity.commit.clone())),
        ("repo", Json::string(repo.display().to_string())),
        (
            "binary",
            Json::object([
                (
                    "path",
                    Json::string(identity.archived.display().to_string()),
                ),
                ("sha256", Json::string(identity.sha256.clone())),
                ("buildId", Json::string(identity.build_id.clone())),
                ("bytes", Json::Int(identity.bytes)),
            ]),
        ),
    ])
}

/// Builds, archives and identity-binds one release artifact.
///
/// # Errors
///
/// Returns an error when the commit is malformed, the worktree does not match
/// it exactly, the build fails, or the built binary does not report the
/// requested commit.
pub fn run(plan: &Plan) -> Result<String, String> {
    validate(plan)?;
    if !Tool::exists("cargo") || !Tool::exists("git") || !Tool::exists("readelf") {
        return Err("required tools unavailable: cargo, git and readelf".to_owned());
    }
    verify_worktree(plan)?;

    let run_dir = RunDirectory::create(&plan.out_dir)?;
    build(plan, &run_dir)?;

    let built = plan.repo.join("target/release").join(BINARY_NAME);
    // `register` runs the binary's own benchmark identity, so a build that did
    // not pick the commit up fails here rather than inside a later capture.
    let binary = identity::register(BINARY_NAME, &built, "", Kind::Rust)?;
    let observed = identity::embedded_commit(&binary.identity)?;
    if observed != plan.commit {
        return Err(format!(
            "built binary reports commit {observed}, not the requested {}",
            plan.commit
        ));
    }

    let identity = archive(&binary.path, &run_dir, &binary.sha256, &plan.commit)?;
    run_dir.write_new(
        "freeze.json",
        &document(&identity, &plan.repo).to_python_json(),
    )?;
    run_dir.write_new(
        "SHA256SUMS",
        &format!("{}  binary/{BINARY_NAME}\n", identity.sha256),
    )?;

    Ok(summary(&identity, run_dir.path()))
}

/// The compact projection printed to the terminal.
///
/// Everything here is also in `freeze.json`; this exists so a reader does not
/// have to open the file to learn whether the freeze is usable.
fn summary(identity: &Identity, run_dir: &Path) -> String {
    format!(
        "frozen {} {}\n  commit  {}\n  sha256  {}\n  buildId {}\n  bytes   {}\n  binary  {}",
        BINARY_NAME,
        run_dir.display(),
        identity.commit,
        identity.sha256,
        identity.build_id,
        identity.bytes,
        identity.archived.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            repo: PathBuf::from("/repo"),
            commit: "b2a820d41437988a885d6ecfca2f71b5689e2910".to_owned(),
            out_dir: PathBuf::from("/tmp/rr-freeze"),
        }
    }

    #[test]
    fn accepts_a_well_formed_plan() {
        assert!(validate(&plan()).is_ok());
    }

    #[test]
    fn rejects_a_short_or_uppercase_commit() {
        let mut short = plan();
        short.commit = "b2a820d".to_owned();
        assert!(validate(&short).is_err());
        let mut upper = plan();
        upper.commit = "B2A820D41437988A885D6ECFCA2F71B5689E2910".to_owned();
        assert!(validate(&upper).is_err());
    }

    #[test]
    fn rejects_a_relative_output_directory() {
        let mut relative = plan();
        relative.out_dir = PathBuf::from("evidence");
        assert!(validate(&relative).is_err());
    }

    #[test]
    fn the_document_records_every_identity_field() {
        let identity = Identity {
            commit: "b2a820d41437988a885d6ecfca2f71b5689e2910".to_owned(),
            sha256: "260f8b7413c056590a88251b5f6f1aa8bb2c4176c8052c90c44e6d945aaa1f7b".to_owned(),
            build_id: "d0bf5f2f8a99c934a852db78d60551cba009f19d".to_owned(),
            bytes: 8_259_208,
            archived: PathBuf::from("/tmp/rr-freeze/binary/rust-reality"),
        };
        let rendered = document(&identity, Path::new("/repo")).to_python_json();
        for expected in [
            "b2a820d41437988a885d6ecfca2f71b5689e2910",
            "260f8b7413c056590a88251b5f6f1aa8bb2c4176c8052c90c44e6d945aaa1f7b",
            "d0bf5f2f8a99c934a852db78d60551cba009f19d",
            "8259208",
            "perf-freeze",
        ] {
            assert!(
                rendered.contains(expected),
                "freeze.json must record {expected}: {rendered}"
            );
        }
    }

    #[test]
    fn the_summary_states_the_identity_without_reading_the_document() {
        let identity = Identity {
            commit: "b2a820d41437988a885d6ecfca2f71b5689e2910".to_owned(),
            sha256: "260f8b7413c056590a88251b5f6f1aa8bb2c4176c8052c90c44e6d945aaa1f7b".to_owned(),
            build_id: "d0bf5f2f8a99c934a852db78d60551cba009f19d".to_owned(),
            bytes: 8_259_208,
            archived: PathBuf::from("/tmp/rr-freeze/binary/rust-reality"),
        };
        let rendered = summary(&identity, Path::new("/tmp/rr-freeze"));
        assert!(rendered.contains("b2a820d41437988a885d6ecfca2f71b5689e2910"));
        assert!(rendered.contains("d0bf5f2f8a99c934a852db78d60551cba009f19d"));
        assert!(rendered.lines().count() == 6);
    }
}
