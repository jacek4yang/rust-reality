//! The evidence directory a formal run publishes, and how it becomes authoritative.
//!
//! A benchmark's output directory is not a scratch space. Every file in it is
//! write-once, the directory must not pre-exist, and the run only becomes
//! *authoritative* at the very end, when a completion marker is written that binds
//! the finished metadata by SHA-256. Until that marker exists, an interrupted run
//! leaves evidence that is visibly incomplete rather than evidence that is subtly
//! wrong.
//!
//! ## Two publication shapes
//!
//! The family inherited two, and they are kept distinct because archived runs of
//! each already exist:
//!
//! * [`Publication::Environment`] — `benchmark-fallback-ab.sh` and
//!   `benchmark-setup-rate.sh`. `environment.json` is written early, without the
//!   final host-lock attestation. At the end the completed document is written to
//!   `.environment.complete.json`, renamed over `environment.json`, and only then
//!   bound by `completion.json`. The rename is what makes the swap atomic: a
//!   reader never sees a half-written `environment.json`.
//! * [`Publication::Contract`] — `benchmark-setup-rate-xray.sh`, via
//!   `benchmark-contract.sh`. The metadata lives in `run-contract.json`, rewritten
//!   with `phase: "complete"` at finalisation and bound by `run-completion.json`.
//!
//! Both end in [`crate::bench::publication::publish_success_marker`], which already
//! fails closed on an existing marker and hashes the evidence before publishing.
//!
//! ## Write-once
//!
//! [`RunDirectory::write_new`] uses `create_new`, which is the `open(path, "x")`
//! the Python aggregators used. Re-running an aggregation over a directory that
//! already has a `summary.json` is a bug, and it fails rather than overwriting
//! evidence someone may already have archived.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::bench::publication;

/// Mode for the run directory: the originals created it with `mkdir -m 700`.
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;

/// Which publication contract a suite follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publication {
    /// `environment.json` + `completion.json`, staged through
    /// `.environment.complete.json`.
    Environment,
    /// `run-contract.json` + `run-completion.json`, as `benchmark-contract.sh` does.
    Contract,
}

impl Publication {
    /// The metadata file this contract publishes.
    #[must_use]
    pub const fn metadata_name(self) -> &'static str {
        match self {
            Self::Environment => "environment.json",
            Self::Contract => "run-contract.json",
        }
    }

    /// The completion marker that binds the metadata.
    #[must_use]
    pub const fn marker_name(self) -> &'static str {
        match self {
            Self::Environment => "completion.json",
            Self::Contract => "run-completion.json",
        }
    }

    /// The staging name the environment contract renames from, if any.
    #[must_use]
    pub const fn staging_name(self) -> Option<&'static str> {
        match self {
            Self::Environment => Some(".environment.complete.json"),
            Self::Contract => None,
        }
    }
}

/// An owned, freshly created run output directory.
#[derive(Debug)]
pub struct RunDirectory {
    root: PathBuf,
}

impl RunDirectory {
    /// Creates the run directory, refusing to reuse an existing path.
    ///
    /// The originals asserted `[[ ! -e $out_dir && ! -L $out_dir ]]` before
    /// `mkdir -m 700`. A dangling symlink counts as existing, which is why this
    /// checks `symlink_metadata` rather than `exists`.
    ///
    /// # Errors
    ///
    /// Returns a message when the path already exists or cannot be created.
    pub fn create(root: &Path) -> Result<Self, String> {
        if root.symlink_metadata().is_ok() {
            return Err(format!(
                "OUT_DIR must not already exist or be a symlink: {}",
                root.display()
            ));
        }
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!("could not create {}: {error}", parent.display())
            })?;
        }
        make_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Adopts an existing directory, for tests and for resuming an aggregation.
    #[must_use]
    pub fn adopt(root: PathBuf) -> Self {
        Self { root }
    }

    /// The run directory root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Joins a relative path inside the run directory.
    #[must_use]
    pub fn join(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Creates and returns `slots/<name>` for one measurement slot.
    ///
    /// # Errors
    ///
    /// Returns a message when the directory cannot be created.
    pub fn slot_directory(&self, name: &str) -> Result<PathBuf, String> {
        let path = self.root.join("slots").join(name);
        std::fs::create_dir_all(&path)
            .map_err(|error| format!("could not create {}: {error}", path.display()))?;
        Ok(path)
    }

    /// Writes a file that must not already exist.
    ///
    /// # Errors
    ///
    /// Returns a message when the file exists or cannot be written.
    pub fn write_new(&self, relative: &str, contents: &str) -> Result<PathBuf, String> {
        let path = self.root.join(relative);
        write_new_at(&path, contents)?;
        Ok(path)
    }

    /// Writes JSON Lines, one document per line, to a file that must not exist.
    ///
    /// # Errors
    ///
    /// Returns a message when the file exists or cannot be written.
    pub fn write_jsonl(&self, relative: &str, lines: &[String]) -> Result<PathBuf, String> {
        let mut body = String::new();
        for line in lines {
            body.push_str(line);
            body.push('\n');
        }
        self.write_new(relative, &body)
    }

    /// Publishes the run's metadata and its completion marker.
    ///
    /// For [`Publication::Environment`] the completed metadata is staged, then
    /// renamed over the early copy, then bound. For [`Publication::Contract`] the
    /// metadata is written in place and bound. In both cases the marker is written
    /// last, so its presence means the whole run finished.
    ///
    /// # Errors
    ///
    /// Returns a message when staging, renaming, or binding fails. A marker that
    /// already exists fails closed rather than being replaced.
    pub fn publish(
        &self,
        contract: Publication,
        metadata_json: &str,
        run_id: &str,
        collector: &str,
    ) -> Result<PathBuf, String> {
        let metadata = self.join(contract.metadata_name());
        if let Some(staging_name) = contract.staging_name() {
            let staging = self.join(staging_name);
            let _ = std::fs::remove_file(&staging);
            write_new_at(&staging, metadata_json)?;
            // The original refused to publish unless the staged file was a
            // regular, non-symlink file it had just written itself.
            let staged_kind = staging
                .symlink_metadata()
                .map_err(|error| format!("could not stat {}: {error}", staging.display()))?;
            if !staged_kind.is_file() {
                return Err(format!(
                    "staged metadata is not a regular file: {}",
                    staging.display()
                ));
            }
            std::fs::rename(&staging, &metadata).map_err(|error| {
                format!(
                    "could not publish {} over {}: {error}",
                    staging.display(),
                    metadata.display()
                )
            })?;
        } else {
            // The contract rewrites its metadata in place at finalisation.
            let _ = std::fs::remove_file(&metadata);
            write_new_at(&metadata, metadata_json)?;
        }
        let marker = self.join(contract.marker_name());
        publication::publish_success_marker(&marker, &metadata, run_id, collector)?;
        Ok(marker)
    }
}

/// Writes `contents` to a path that must not already exist.
fn write_new_at(path: &Path, contents: &str) -> Result<(), String> {
    let mut handle = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    handle
        .write_all(contents.as_bytes())
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    handle
        .sync_all()
        .map_err(|error| format!("could not sync {}: {error}", path.display()))
}

#[cfg(unix)]
fn make_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(DIRECTORY_MODE)
        .create(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn make_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perf::{json_in, loader};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rr-bench-evidence-{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn join(&self, relative: &str) -> PathBuf {
            self.0.join(relative)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_run_directory_refuses_to_reuse_an_existing_path() {
        let scratch = Scratch::new("exists");
        let out = scratch.join("run");
        RunDirectory::create(&out).expect("a fresh directory is created");
        let error = RunDirectory::create(&out).unwrap_err();
        assert!(error.contains("must not already exist"), "{error}");
    }

    /// A dangling symlink is not `exists()` but is very much "already there"; the
    /// original's `-L` test caught it and so must this.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_counts_as_existing() {
        let scratch = Scratch::new("symlink");
        let out = scratch.join("run");
        std::os::unix::fs::symlink(scratch.join("nowhere"), &out).unwrap();
        assert!(!out.exists(), "the link target is absent");
        let error = RunDirectory::create(&out).unwrap_err();
        assert!(error.contains("must not already exist"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn the_run_directory_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("mode");
        let out = scratch.join("nested/run");
        let run = RunDirectory::create(&out).unwrap();
        let mode = std::fs::metadata(run.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the originals used mkdir -m 700");
    }

    #[test]
    fn evidence_files_are_write_once() {
        let scratch = Scratch::new("write-once");
        let run = RunDirectory::create(&scratch.join("run")).unwrap();
        run.write_new("summary.json", "{}\n").unwrap();
        let error = run.write_new("summary.json", "{\"tampered\":true}\n").unwrap_err();
        assert!(error.contains("could not create"), "{error}");
        assert_eq!(
            std::fs::read_to_string(run.join("summary.json")).unwrap(),
            "{}\n",
            "the first write must survive"
        );
    }

    #[test]
    fn jsonl_rows_are_newline_terminated() {
        let scratch = Scratch::new("jsonl");
        let run = RunDirectory::create(&scratch.join("run")).unwrap();
        run.write_jsonl(
            "raw-samples.jsonl",
            &["{\"a\":1}".to_owned(), "{\"a\":2}".to_owned()],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(run.join("raw-samples.jsonl")).unwrap(),
            "{\"a\":1}\n{\"a\":2}\n"
        );
    }

    #[test]
    fn slot_directories_follow_the_slots_layout() {
        let scratch = Scratch::new("slots");
        let run = RunDirectory::create(&scratch.join("run")).unwrap();
        let slot = run.slot_directory("block-01-slot-01-baseline").unwrap();
        assert!(slot.is_dir());
        assert_eq!(slot, run.join("slots").join("block-01-slot-01-baseline"));
    }

    /// The environment contract stages, renames, then binds — and the marker must
    /// attest the *renamed* file, not the early copy.
    #[test]
    fn the_environment_contract_swaps_then_binds() {
        let scratch = Scratch::new("environment");
        let run = RunDirectory::create(&scratch.join("run")).unwrap();
        // The early copy, written before the host-lock attestation is complete.
        run.write_new("environment.json", "{\"phase\": \"early\"}\n")
            .unwrap();

        let completed = "{\"phase\": \"complete\"}\n";
        let marker = run
            .publish(Publication::Environment, completed, "run-1", "benchmark-fallback-ab")
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(run.join("environment.json")).unwrap(),
            completed,
            "the completed document must replace the early one"
        );
        assert!(
            !run.join(".environment.complete.json").exists(),
            "the staging file is renamed away, not left behind"
        );

        let parsed = json_in::parse(&std::fs::read_to_string(&marker).unwrap()).unwrap();
        loader::verify_success_marker(
            &parsed,
            &run.join("environment.json"),
            "run-1",
            "benchmark-fallback-ab",
            "completion",
        )
        .expect("the marker attests the published environment");
    }

    #[test]
    fn the_contract_publication_uses_the_run_contract_names() {
        let scratch = Scratch::new("contract");
        let run = RunDirectory::create(&scratch.join("run")).unwrap();
        run.write_new("run-contract.json", "{\"phase\": \"preflight\"}\n")
            .unwrap();
        let marker = run
            .publish(
                Publication::Contract,
                "{\"phase\": \"complete\"}\n",
                "run-2",
                "benchmark-setup-rate-xray",
            )
            .unwrap();
        assert_eq!(marker, run.join("run-completion.json"));
        assert!(
            std::fs::read_to_string(run.join("run-contract.json"))
                .unwrap()
                .contains("complete")
        );
    }

    /// Publishing twice must not silently replace an authoritative marker.
    #[test]
    fn a_second_publication_fails_closed() {
        let scratch = Scratch::new("twice");
        let run = RunDirectory::create(&scratch.join("run")).unwrap();
        run.publish(Publication::Environment, "{}\n", "run-1", "collector")
            .unwrap();
        let error = run
            .publish(Publication::Environment, "{}\n", "run-1", "collector")
            .unwrap_err();
        assert!(error.contains("without overwrite"), "{error}");
    }

    #[test]
    fn each_contract_names_its_own_files() {
        assert_eq!(Publication::Environment.metadata_name(), "environment.json");
        assert_eq!(Publication::Environment.marker_name(), "completion.json");
        assert_eq!(
            Publication::Environment.staging_name(),
            Some(".environment.complete.json")
        );
        assert_eq!(Publication::Contract.metadata_name(), "run-contract.json");
        assert_eq!(Publication::Contract.marker_name(), "run-completion.json");
        assert_eq!(Publication::Contract.staging_name(), None);
    }
}
