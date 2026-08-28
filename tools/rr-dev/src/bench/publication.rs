//! Hash-bound, write-once benchmark completion publication.
//!
//! A completion marker is authority that a collector finished successfully. It
//! therefore attests an immutable evidence file by canonical path and SHA-256,
//! and publication must fail when the destination already exists. The marker is
//! first written and synced as a sibling temporary file, then atomically linked
//! into place without overwrite.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use crate::perf::{json_out::Json, loader};

/// Publishes a schema-v1 success marker bound to `evidence_path`.
///
/// The marker path must not exist. The evidence path is canonicalized and hashed
/// before the marker is made visible. A same-directory hard link publishes the
/// completed file atomically and fails closed instead of replacing an existing
/// marker.
///
/// # Errors
///
/// Returns a diagnostic when the evidence cannot be identified, the temporary
/// file cannot be written, or the destination already exists.
pub fn publish_success_marker(
    marker_path: &Path,
    evidence_path: &Path,
    run_id: &str,
    collector: &str,
) -> Result<(), String> {
    if run_id.is_empty() || collector.is_empty() {
        return Err("completion run ID and collector must be non-empty".to_owned());
    }
    let evidence = evidence_path.canonicalize().map_err(|error| {
        format!(
            "could not canonicalize {}: {error}",
            evidence_path.display()
        )
    })?;
    let digest = loader::sha256_file(&evidence).map_err(|error| error.to_string())?;
    let document = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("status", Json::string("COMPLETE")),
        ("exitCode", Json::Int(0)),
        ("runId", Json::string(run_id)),
        ("collector", Json::string(collector)),
        (
            "evidence",
            Json::object([
                (
                    "path",
                    Json::string(evidence.to_string_lossy().into_owned()),
                ),
                ("sha256", Json::string(digest)),
            ]),
        ),
    ])
    .to_python_json();

    let temporary = temporary_path(marker_path);
    let result = write_then_link(&temporary, marker_path, document.as_bytes());
    let _ = std::fs::remove_file(&temporary);
    result
}

fn write_then_link(temporary: &Path, destination: &Path, contents: &[u8]) -> Result<(), String> {
    let mut handle = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(|error| format!("could not create {}: {error}", temporary.display()))?;
    handle
        .write_all(contents)
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    handle
        .sync_all()
        .map_err(|error| format!("could not sync {}: {error}", temporary.display()))?;
    drop(handle);
    std::fs::hard_link(temporary, destination).map_err(|error| {
        format!(
            "could not publish completion marker {} without overwrite: {error}",
            destination.display()
        )
    })
}

fn temporary_path(destination: &Path) -> PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut name = destination
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".tmp-{}-{suffix}", std::process::id()));
    destination.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perf::json_in;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rr-publication-{}-{name}", std::process::id()))
    }

    #[test]
    fn publication_is_hash_bound_and_cannot_overwrite() {
        let root = scratch("write-once");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let evidence = root.join("evidence.json");
        let marker = root.join("completion.json");
        std::fs::write(&evidence, b"{\"status\":\"COMPLETE\"}\n").unwrap();

        publish_success_marker(&marker, &evidence, "run-1", "native-test")
            .expect("first publication succeeds");
        let original = std::fs::read(&marker).unwrap();
        assert!(
            publish_success_marker(&marker, &evidence, "run-1", "native-test").is_err(),
            "a second publication must fail closed"
        );
        assert_eq!(std::fs::read(&marker).unwrap(), original);

        let parsed = json_in::parse(std::str::from_utf8(&original).unwrap()).unwrap();
        loader::verify_success_marker(&parsed, &evidence, "run-1", "native-test", "completion")
            .expect("the marker attests the exact evidence");

        std::fs::write(&evidence, b"{\"status\":\"TAMPERED\"}\n").unwrap();
        assert!(
            loader::verify_success_marker(
                &parsed,
                &evidence,
                "run-1",
                "native-test",
                "completion",
            )
            .is_err(),
            "changed evidence must invalidate the marker"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_identity_is_rejected_before_writing() {
        let root = scratch("empty");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let evidence = root.join("evidence");
        let marker = root.join("completion");
        std::fs::write(&evidence, b"evidence").unwrap();
        assert!(publish_success_marker(&marker, &evidence, "", "collector").is_err());
        assert!(!marker.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
