//! Benchmark binary identity capture and registration.
//!
//! The legacy `rr_register_binary` proved, before any measurement ran, that each
//! binary under test is an absolute regular executable, recorded its SHA-256 and
//! GNU build ID, and captured a version identity the report could attribute
//! results to. [`Binary`] reproduces that contract with typed parsing: a
//! `rust-reality` binary must emit its self-benchmark JSON whose
//! `environment.gitCommit` is a 40-hex commit, and an `xray` binary must print a
//! version line on the first line of `xray version`.
//!
//! Nothing here runs a shell: every invocation is typed argv.

use std::path::{Path, PathBuf};

use crate::{hash, process::Tool};

/// One binary registered for a benchmark run.
#[derive(Debug, Clone)]
pub struct Binary {
    /// The label the report records, e.g. `rust-reality` or `xray`.
    pub label: String,
    /// The canonical absolute path of the executable.
    pub path: PathBuf,
    /// The SHA-256 of the binary contents.
    pub sha256: String,
    /// The version identity line/JSON, when the kind produces one.
    pub identity: String,
}

/// The identity kinds a benchmark binary can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A `rust-reality` binary: identity is its benchmark JSON environment.
    Rust,
    /// An `xray` binary: identity is the first line of `xray version`.
    Xray,
    /// A pinned historical ELF whose provenance comes from its sidecar.
    ///
    /// The ABBA harnesses compare against a baseline built long ago, often
    /// before the build stamped its commit — `rust-reality-baseline-717e69b`
    /// reports `gitCommit: "unknown"`. Demanding a self-reported commit from it
    /// would reject exactly the artifact the comparison exists to use. Its
    /// provenance is the identity sidecar plus the GNU build ID, which is what
    /// the legacy harnesses required of it too.
    Prebuilt,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Xray => "xray",
            Self::Prebuilt => "prebuilt",
        }
    }
}

/// Registers `label` -> binary `path`, capturing identity by `kind`.
///
/// `expected_sha256` must be empty or 64 lowercase hex characters; a non-matching
/// value fails closed, which is the contract that keeps evidence honest.
///
/// # Errors
///
/// Returns a message when the path is not an executable regular file, the
/// expected digest is malformed or mismatched, or the binary's identity could not
/// be captured.
pub fn register(
    label: &str,
    path: &Path,
    expected_sha256: &str,
    kind: Kind,
) -> Result<Binary, String> {
    if !expected_sha256.is_empty() && !crate::perf::evidence::is_sha256_hex(expected_sha256) {
        return Err(format!(
            "{label} expected SHA-256 must be 64 lowercase hexadecimal characters"
        ));
    }
    let unresolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("could not resolve the working directory: {error}"))?
            .join(path)
    };
    let path = unresolved.canonicalize().map_err(|error| {
        format!(
            "{label} binary is not a regular executable file: {}: {error}",
            unresolved.display()
        )
    })?;
    if !is_executable_file(&path) {
        return Err(format!(
            "{} binary is not a regular executable file: {}",
            label,
            path.display()
        ));
    }
    let sha256 = hash::sha256_file(&path)?;
    if !expected_sha256.is_empty() && expected_sha256 != sha256 {
        return Err(format!(
            "{label} SHA-256 mismatch: expected {expected_sha256}, got {sha256}"
        ));
    }
    let identity = match kind {
        Kind::Rust => rust_identity(&path)?,
        Kind::Xray => xray_identity(&path)?,
        // A prebuilt baseline is identified by content and by its sidecar; it is
        // never asked to describe itself.
        Kind::Prebuilt => String::new(),
    };
    Ok(Binary {
        label: label.to_owned(),
        path,
        sha256,
        identity,
    })
}

/// Captures a rust-reality binary's benchmark identity: the `environment` object
/// of its self-benchmark JSON.
fn rust_identity(path: &Path) -> Result<String, String> {
    let outcome = Tool::new(path.display().to_string())
        .args(["benchmark", "--duration-ms", "90", "--warmup-ms", "1"])
        .probe()
        .map_err(|error| format!("rust-reality benchmark identity failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "rust-reality benchmark identity exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let value = crate::perf::json_in::parse(outcome.trimmed_stdout())
        .map_err(|error| format!("rust-reality benchmark JSON is invalid: {error}"))?;
    let environment = value
        .field("", "environment")
        .map_err(|error| format!("rust-reality benchmark JSON: {error}"))?;
    let commit = environment
        .field("environment", "gitCommit")
        .and_then(|commit| commit.as_str("environment.gitCommit"))
        .map_err(|error| format!("rust-reality benchmark JSON: {error}"))?;
    if !crate::perf::evidence::is_commit_hex(commit) {
        return Err(format!(
            "rust-reality benchmark JSON has no valid 40-hex environment.gitCommit: {commit}"
        ));
    }
    Ok(serde_compatible_environment(environment))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Renders the captured `environment` object back to compact JSON for the report.
fn serde_compatible_environment(environment: &crate::perf::json_in::Value) -> String {
    use crate::perf::json_in::Value;
    fn render(value: &Value) -> String {
        match value {
            Value::Null => "null".to_owned(),
            Value::Bool(flag) => flag.to_string(),
            Value::Number(text) => text.clone(),
            Value::Str(text) => format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")),
            Value::Array(items) => format!(
                "[{}]",
                items.iter().map(render).collect::<Vec<_>>().join(",")
            ),
            Value::Object(members) => format!(
                "{{{}}}",
                members
                    .iter()
                    .map(|(key, value)| format!("\"{key}\":{}", render(value)))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
    render(environment)
}

/// Captures an xray binary's version identity: the first line of `xray version`.
fn xray_identity(path: &Path) -> Result<String, String> {
    let outcome = Tool::new(path.display().to_string())
        .arg("version")
        .probe()
        .map_err(|error| format!("xray version identity failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "xray version identity exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let first = outcome
        .trimmed_stdout()
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    if first.is_empty() {
        return Err("xray version produced no identity line".to_owned());
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rr-bench-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_malformed_expected_digest_is_rejected_before_anything_else() {
        let dir = scratch("digest");
        let error = register("tool", &dir.join("missing"), "not-hex", Kind::Rust).unwrap_err();
        assert!(error.contains("64 lowercase hexadecimal"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_binary_fails_closed() {
        let dir = scratch("missing");
        let error = register("tool", &dir.join("absent"), "", Kind::Xray).unwrap_err();
        assert!(error.contains("not a regular executable file"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_xray_kind_requires_a_version_line() {
        let dir = scratch("xray");
        let script = dir.join("tool");
        // Print no version line at all: the identity must fail closed.
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        make_executable(&script);
        let error = register("tool", &script, "", Kind::Xray).unwrap_err();
        assert!(error.contains("no identity line"), "{error}");

        std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
        make_executable(&script);
        let error = register("tool", &script, "", Kind::Xray).unwrap_err();
        assert!(error.contains("identity exited"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rust_kind_requires_the_git_commit_field() {
        let dir = scratch("rust");
        let script = dir.join("tool");
        std::fs::write(&script, "#!/bin/sh\nprintf '{}\\n'\n").unwrap();
        make_executable(&script);
        let error = register("tool", &script, "", Kind::Rust).unwrap_err();
        assert!(error.contains("environment"), "{error}");

        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '{\"environment\":{\"gitCommit\":\"short\"}}\\n'\n",
        )
        .unwrap();
        make_executable(&script);
        let error = register("tool", &script, "", Kind::Rust).unwrap_err();
        assert!(error.contains("40-hex"), "{error}");

        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '{{\"environment\":{{\"gitCommit\":\"{}\"}}}}\\n'\n",
                "A".repeat(40)
            ),
        )
        .unwrap();
        make_executable(&script);
        let error = register("tool", &script, "", Kind::Rust).unwrap_err();
        assert!(error.contains("40-hex"), "{error}");

        let commit = "a".repeat(40);
        std::fs::write(
            &script,
            format!("#!/bin/sh\nprintf '{{\"environment\":{{\"gitCommit\":\"{commit}\"}}}}\\n'\n"),
        )
        .unwrap();
        make_executable(&script);
        let binary = register("tool", &script, "", Kind::Rust).expect("valid identity");
        assert_eq!(binary.path, script.canonicalize().unwrap());
        assert_eq!(binary.sha256.len(), 64);
        assert!(binary.identity.contains(&commit));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_executable_regular_file_is_rejected_at_registration() {
        let dir = scratch("not-executable");
        let file = dir.join("tool");
        std::fs::write(&file, "not executable\n").unwrap();
        let error = register("tool", &file, "", Kind::Prebuilt).unwrap_err();
        assert!(error.contains("not a regular executable file"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }
}
