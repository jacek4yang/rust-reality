//! Native required checks collected beside, not after, the QEMU cells.
//!
//! Frozen collects the native receipts on their own runner while the four VM
//! cells run. `stability-freeze` writes the same identity every cell freezes
//! (merge already requires byte-identical identities across runners),
//! `stability-check` extends that bundle unchanged, `stability-export-checks`
//! retains only receipt-referenced files and collector records, and
//! `stability-import-checks` binds them into the merged campaign. Import fails
//! closed on any identity difference, repeated check, escaped or private path,
//! changed digest, or failed receipt verification; the offline evaluator is
//! unchanged and still requires every check.

use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    path::{Component, Path, PathBuf},
};

use clap::Args;

use super::{campaign, checks, collect, qualification::CollectionLock, schema};

/// Identity-root executables native checks observe; the merged campaign
/// already holds them under the same identity, so they are never copied.
const SHARED_ROOT_FILES: [&str; 2] = ["xray", "openssl"];
/// Collector records retained for every attempted check directory.
const COLLECTOR_RECORDS: [&str; 5] = [
    "command.json",
    "terminal.json",
    "evidence-before.json",
    "evidence-after.json",
    "receipt.json",
];
const PRIVATE_SUFFIXES: [&str; 4] = ["pem", "key", "p12", "pfx"];
const MAX_FILES: usize = 200_000;

/// Bundle-relative paths to transfer, with their bound digest when one exists.
type TransferSet = BTreeMap<String, Option<String>>;

/// Freeze the campaign identity for native required checks only.
#[derive(Args)]
pub struct FreezePlan {
    /// Fresh bundle directory; never reused.
    #[arg(long)]
    pub output: PathBuf,
    /// Frozen rust-reality release executable (same as the VM cells).
    #[arg(long)]
    pub candidate: PathBuf,
    /// Pinned stock-Xray executable (same as the VM cells).
    #[arg(long)]
    pub xray: PathBuf,
    /// Pinned OpenSSL executable (same as the VM cells).
    #[arg(long)]
    pub openssl: PathBuf,
}

/// Retain native check receipts for transfer to the aggregate.
#[derive(Args)]
pub struct ExportPlan {
    /// Native bundle evidence written by `stability-freeze` and `stability-check`.
    #[arg(long)]
    pub evidence: PathBuf,
    /// Fresh directory receiving evidence.json and referenced receipts only.
    #[arg(long)]
    pub output: PathBuf,
}

/// Bind exported native receipts into the merged campaign evidence.
#[derive(Args)]
pub struct ImportPlan {
    /// Merged campaign evidence to extend.
    #[arg(long)]
    pub evidence: PathBuf,
    /// Exported native evidence.json; its identity must equal the campaign's.
    #[arg(long)]
    pub from: PathBuf,
}

fn read_evidence(path: &Path) -> Result<(Vec<u8>, schema::Evidence), String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?
        .take((schema::MAX_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let evidence = schema::parse(&bytes)?;
    Ok((bytes, evidence))
}

fn root_of(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|error| format!("{}: {error}", path.display()))?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "missing evidence directory".to_owned())
}

fn fingerprint(identity: &schema::Identity) -> Result<String, String> {
    serde_json::to_string(identity).map_err(|error| error.to_string())
}

/// Reject absolute, parent, empty, private and symlinked bundle paths.
fn checked_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("escaped native evidence path {relative:?}"));
    }
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            PRIVATE_SUFFIXES.contains(&extension.to_ascii_lowercase().as_str())
        })
    {
        return Err(format!(
            "private material is not transferable evidence: {relative}"
        ));
    }
    let mut current = root.to_path_buf();
    for part in path.components() {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("missing native evidence {relative}: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("native evidence {relative} traverses a symlink"));
        }
    }
    if !current.is_file() {
        return Err(format!("native evidence {relative} is not a regular file"));
    }
    Ok(current)
}

fn top_level(relative: &str) -> Option<&str> {
    relative.split('/').next()
}

/// Every file a native check binds, plus collector records of each attempted
/// `required-*` directory. Shared identity executables are listed separately.
fn transfer_set(
    root: &Path,
    evidence: &schema::Evidence,
) -> Result<(TransferSet, Vec<schema::Artifact>), String> {
    let mut files = BTreeMap::new();
    let mut shared = Vec::new();
    let mut add = |artifact: &schema::Artifact, files: &mut TransferSet| -> Result<(), String> {
        if SHARED_ROOT_FILES.contains(&artifact.path.as_str()) {
            shared.push(artifact.clone());
            return Ok(());
        }
        if !top_level(&artifact.path).is_some_and(|top| top.starts_with("required-")) {
            return Err(format!(
                "native check artifact {} is outside a required-* directory",
                artifact.path
            ));
        }
        match files.insert(artifact.path.clone(), Some(artifact.sha256.clone())) {
            Some(Some(previous)) if previous != artifact.sha256 => Err(format!(
                "native check artifact {} is bound to two digests",
                artifact.path
            )),
            _ => Ok(()),
        }
    };
    for check in &evidence.checks {
        for artifact in [&check.execution, &check.output]
            .into_iter()
            .chain(&check.observations)
        {
            add(artifact, &mut files)?;
        }
        let terminal = checked_path(root, &check.execution.path)?;
        if let Ok(bytes) = fs::read(&terminal)
            && let Ok(execution) = checks::parse_execution(&bytes)
        {
            add(&execution.stdout, &mut files)?;
            add(&execution.stderr, &mut files)?;
        }
    }
    let mut directories: Vec<_> = fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())?;
    directories.sort_by_key(fs::DirEntry::file_name);
    for entry in directories {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("required-") || !entry.file_type().map_err(|e| e.to_string())?.is_dir()
        {
            continue;
        }
        for record in COLLECTOR_RECORDS {
            if entry.path().join(record).is_file() {
                files.entry(format!("{name}/{record}")).or_insert(None);
            }
        }
    }
    if files.len() > MAX_FILES {
        return Err("native evidence reference bound exceeded".to_owned());
    }
    Ok((files, shared))
}

/// Copy one checked file and prove the destination bytes equal the binding.
fn transfer(from: &Path, to: &Path, relative: &str, expected: Option<&str>) -> Result<(), String> {
    let source = checked_path(from, relative)?;
    let digest = collect::file_digest(&source)?;
    if expected.is_some_and(|expected| expected != digest) {
        return Err(format!(
            "native evidence {relative} changed before transfer"
        ));
    }
    let destination = to.join(relative);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(format!("refusing to overwrite {relative}"));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::copy(&source, &destination).map_err(|error| format!("copy {relative}: {error}"))?;
    if collect::file_digest(&destination)? != digest {
        return Err(format!("native evidence {relative} changed while copying"));
    }
    Ok(())
}

fn write_atomically(path: &Path, value: &schema::Evidence) -> Result<(), String> {
    let pending = path.with_extension("import-next.json");
    fs::write(
        &pending,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::rename(&pending, path).map_err(|error| error.to_string())
}

/// Freeze the identity the VM cells freeze, with no cells and no checks.
///
/// # Errors
/// Rejects a reused directory or any input `freeze` rejects.
pub fn freeze(repo: &Path, plan: &FreezePlan) -> Result<(), String> {
    fs::create_dir(&plan.output).map_err(|error| format!("fresh native bundle: {error}"))?;
    let root = plan
        .output
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let (identity, _, _) = campaign::freeze(
        repo,
        &campaign::Inputs {
            candidate: &plan.candidate,
            xray: &plan.xray,
            openssl: &plan.openssl,
        },
        &root,
    )?;
    let evidence = schema::Evidence {
        schema: "rr-stability-evidence/v1".to_owned(),
        identity,
        checks: Vec::new(),
        cells: Vec::new(),
    };
    super::workload::save(&root.join("evidence.json"), &evidence)
}

/// Retain native check receipts without fixture material or benchmark scratch.
///
/// # Errors
/// Rejects VM cells, escaped/private/symlinked paths and changed digests.
pub fn export(plan: &ExportPlan) -> Result<(), String> {
    let root = root_of(&plan.evidence)?;
    let (bytes, evidence) = read_evidence(&plan.evidence)?;
    if !evidence.cells.is_empty() {
        return Err("native receipt bundles must not carry VM cells".to_owned());
    }
    let (files, _) = transfer_set(&root, &evidence)?;
    fs::create_dir(&plan.output).map_err(|error| format!("fresh export directory: {error}"))?;
    let output = plan
        .output
        .canonicalize()
        .map_err(|error| error.to_string())?;
    for (relative, expected) in &files {
        transfer(&root, &output, relative, expected.as_deref())?;
    }
    fs::write(output.join("evidence.json"), bytes).map_err(|error| error.to_string())
}

/// Bind exported native checks into the merged campaign.
///
/// # Errors
/// Rejects identity drift, VM cells, empty or repeated checks, path escapes,
/// overwrites, changed digests, and any receipt the check verifier rejects.
/// Failed receipts are still bound so the evaluator and diagnostics see them.
pub fn import(plan: &ImportPlan) -> Result<(), String> {
    let path = plan
        .evidence
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let root = path.parent().ok_or("missing evidence directory")?;
    let _lock = CollectionLock::acquire(root)?;
    let (bytes, mut evidence) = read_evidence(&path)?;
    let from = root_of(&plan.from)?;
    let (_, native) = read_evidence(&plan.from)?;
    if fingerprint(&native.identity)? != fingerprint(&evidence.identity)? {
        return Err("native receipt identity differs from the merged campaign".to_owned());
    }
    if !native.cells.is_empty() || native.checks.is_empty() {
        return Err("native receipt bundle must carry checks and no VM cells".to_owned());
    }
    let mut names = std::collections::BTreeSet::new();
    for check in &native.checks {
        if !names.insert(check.name.as_str())
            || evidence.checks.iter().any(|bound| bound.name == check.name)
        {
            return Err(format!("check {} already attempted", check.name));
        }
    }
    let (files, shared) = transfer_set(&from, &native)?;
    // A pre-existing check directory means a second attempt; never merge into it.
    let tops: std::collections::BTreeSet<_> =
        files.keys().filter_map(|path| top_level(path)).collect();
    for top in tops {
        if fs::symlink_metadata(root.join(top)).is_ok() {
            return Err(format!("{top} already exists in the merged campaign"));
        }
    }
    for artifact in &shared {
        super::verify_artifact(root, artifact)?;
    }
    // Verify every source before writing anything, so a rejected import
    // leaves the merged campaign untouched.
    for (relative, expected) in &files {
        let digest = collect::file_digest(&checked_path(&from, relative)?)?;
        if expected
            .as_deref()
            .is_some_and(|expected| expected != digest)
        {
            return Err(format!(
                "native evidence {relative} changed before transfer"
            ));
        }
    }
    for (relative, expected) in &files {
        transfer(&from, root, relative, expected.as_deref())?;
    }
    let mut errors = Vec::new();
    for check in native.checks {
        match super::verify_required_check(root, &check, &evidence.identity) {
            Ok(report) if report.verdict == super::evaluate::Verdict::Pass => {}
            Ok(report) => errors.push(format!(
                "{}: {:?}: {:?}",
                check.name, report.verdict, report.findings
            )),
            Err(error) => errors.push(format!("{}: {error}", check.name)),
        }
        evidence.checks.push(check);
    }
    if fs::read(&path).map_err(|error| error.to_string())? != bytes {
        return Err("aggregate changed concurrently; import not bound".to_owned());
    }
    write_atomically(&path, &evidence)?;
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::workspace::Workspace;
    use serde_json::json;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn save(root: &Path, relative: &str, bytes: &[u8]) -> schema::Artifact {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        super::super::workload::artifact(root, &path).unwrap()
    }

    /// A campaign root holding the six identity files plus shared executables.
    fn campaign(root: &Path) -> schema::Evidence {
        let identity = schema::Identity {
            source_commit: COMMIT.to_owned(),
            source_archive: save(root, "source.tar", b"source"),
            candidate: save(root, "rust-reality", b"candidate"),
            evaluator: save(root, "rr-dev", b"evaluator"),
            contract: save(root, "contract.json", b"{}"),
            environment: save(root, "environment.json", b"{}"),
            workload: save(root, "workload.json", b"{}"),
        };
        save(root, "xray", b"stock");
        save(root, "openssl", b"openssl");
        let evidence = schema::Evidence {
            schema: "rr-stability-evidence/v1".to_owned(),
            identity,
            checks: Vec::new(),
            cells: Vec::new(),
        };
        super::super::workload::save(&root.join("evidence.json"), &evidence).unwrap();
        evidence
    }

    /// A native bundle with one verifiable exact-head CI receipt.
    fn native(root: &Path) -> schema::Evidence {
        let mut evidence = campaign(root);
        let receipt = json!({"headSha":COMMIT,"workflowName":"CI","status":"completed",
            "conclusion":"success","databaseId":123,
            "url":"https://github.com/jacek4yang/rust-reality/actions/runs/123","event":"push"});
        let argv: Vec<String> = ["gh", "run", "view", "123", "--json", checks::CI_FIELDS]
            .map(str::to_owned)
            .to_vec();
        let output = save(
            root,
            "required-exact-head-ci/output.json",
            &serde_json::to_vec(&receipt).unwrap(),
        );
        let stderr = save(root, "required-exact-head-ci/stderr.log", b"");
        save(root, "required-exact-head-ci/command.json", b"[]");
        let terminal = json!({"argv":argv,"started_unix_ms":1,"completed_unix_ms":2,"pid":7,
            "start_ticks":"9","boot_id":"boot","exit_code":0,"primary_error":null,
            "finalization_errors":[],"source_commit":[COMMIT,COMMIT],
            "candidate_sha256":[evidence.identity.candidate.sha256,evidence.identity.candidate.sha256],
            "evaluator_sha256":[evidence.identity.evaluator.sha256,evidence.identity.evaluator.sha256],
            "stdout":output,"stderr":stderr});
        let execution = save(
            root,
            "required-exact-head-ci/terminal.json",
            &serde_json::to_vec(&terminal).unwrap(),
        );
        // Unreferenced scratch, such as fixture keys, is never transferred.
        save(root, "required-exact-head-ci/run/cover.key", b"private");
        save(root, "required-exact-head-ci/run/scratch.bin", b"scratch");
        evidence.checks.push(schema::Check {
            name: "exact-head-ci".to_owned(),
            source_commit: COMMIT.to_owned(),
            candidate_sha256: evidence.identity.candidate.sha256.clone(),
            argv,
            exit_code: Some(0),
            completed: true,
            executed_cases: 1,
            failed_cases: 0,
            execution,
            output,
            observations: vec![super::super::workload::artifact(root, &root.join("xray")).unwrap()],
        });
        super::super::workload::save(&root.join("evidence.json"), &evidence).unwrap();
        evidence
    }

    struct Fixture {
        work: Workspace,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let work = Workspace::create(name).unwrap();
            fs::create_dir(work.join("native")).unwrap();
            fs::create_dir(work.join("merged")).unwrap();
            native(&work.join("native"));
            campaign(&work.join("merged"));
            Self { work }
        }
        fn export(&self) -> Result<(), String> {
            export(&ExportPlan {
                evidence: self.work.join("native/evidence.json"),
                output: self.work.join("export"),
            })
        }
        fn import(&self) -> Result<(), String> {
            import(&ImportPlan {
                evidence: self.work.join("merged/evidence.json"),
                from: self.work.join("export/evidence.json"),
            })
        }
        fn merged(&self) -> schema::Evidence {
            schema::parse(&fs::read(self.work.join("merged/evidence.json")).unwrap()).unwrap()
        }
    }

    #[test]
    fn exported_receipts_bind_into_identical_merged_evidence() {
        let fixture = Fixture::new("native-bundle-roundtrip");
        fixture.export().unwrap();
        let exported = fixture.work.join("export");
        assert!(
            exported
                .join("required-exact-head-ci/terminal.json")
                .is_file()
        );
        assert!(
            exported
                .join("required-exact-head-ci/command.json")
                .is_file()
        );
        assert!(!exported.join("required-exact-head-ci/run").exists());
        assert!(!exported.join("xray").exists());
        fixture.import().unwrap();
        let merged = fixture.merged();
        assert_eq!(merged.checks.len(), 1);
        assert_eq!(merged.checks[0].name, "exact-head-ci");
        for artifact in super::super::artifacts(&merged) {
            super::super::verify_artifact(&fixture.work.join("merged"), artifact).unwrap();
        }
        assert!(!fixture.work.join("merged/evidence.lock").exists());
        // A second import is a second attempt and is refused.
        assert!(fixture.import().unwrap_err().contains("already attempted"));
    }

    #[test]
    fn import_rejects_identity_drift_cells_and_empty_bundles() {
        let fixture = Fixture::new("native-bundle-identity");
        fixture.export().unwrap();
        let path = fixture.work.join("export/evidence.json");
        let original = fs::read(&path).unwrap();
        let mut drifted = schema::parse(&original).unwrap();
        drifted.identity.source_commit = "f".repeat(40);
        super::super::workload::save(&path, &drifted).unwrap();
        assert!(fixture.import().unwrap_err().contains("identity differs"));
        let mut empty = schema::parse(&original).unwrap();
        empty.checks.clear();
        super::super::workload::save(&path, &empty).unwrap();
        assert!(fixture.import().unwrap_err().contains("must carry checks"));
        let unchanged = fs::read(fixture.work.join("merged/evidence.json")).unwrap();
        assert!(schema::parse(&unchanged).unwrap().checks.is_empty());
    }

    #[test]
    fn import_rejects_changed_bytes_and_preexisting_check_directories() {
        let fixture = Fixture::new("native-bundle-digest");
        fixture.export().unwrap();
        fs::write(
            fixture
                .work
                .join("export/required-exact-head-ci/output.json"),
            b"{}",
        )
        .unwrap();
        assert!(
            fixture
                .import()
                .unwrap_err()
                .contains("changed before transfer")
        );
        // Nothing was written, so the merged campaign stays importable.
        assert!(!fixture.work.join("merged/required-exact-head-ci").exists());
        let fixture = Fixture::new("native-bundle-overwrite");
        fixture.export().unwrap();
        fs::create_dir(fixture.work.join("merged/required-exact-head-ci")).unwrap();
        assert!(fixture.import().unwrap_err().contains("already exists"));
        assert!(fixture.merged().checks.is_empty());
    }

    #[test]
    fn import_rejects_a_shared_executable_that_differs_from_the_campaign() {
        let fixture = Fixture::new("native-bundle-shared");
        fixture.export().unwrap();
        fs::write(fixture.work.join("merged/xray"), b"other").unwrap();
        assert!(fixture.import().is_err());
        assert!(fixture.merged().checks.is_empty());
    }

    #[test]
    fn a_failing_receipt_is_bound_but_import_fails() {
        let fixture = Fixture::new("native-bundle-failing");
        let root = fixture.work.join("native");
        let mut evidence = schema::parse(&fs::read(root.join("evidence.json")).unwrap()).unwrap();
        let receipt = json!({"headSha":"f".repeat(40),"workflowName":"CI","status":"completed",
            "conclusion":"success","databaseId":123,
            "url":"https://github.com/jacek4yang/rust-reality/actions/runs/123","event":"push"});
        evidence.checks[0].output = save(
            &root,
            "required-exact-head-ci/other-head.json",
            &serde_json::to_vec(&receipt).unwrap(),
        );
        super::super::workload::save(&root.join("evidence.json"), &evidence).unwrap();
        fixture.export().unwrap();
        assert!(fixture.import().unwrap_err().contains("exact-head-ci"));
        assert_eq!(fixture.merged().checks.len(), 1);
    }

    #[test]
    fn transfer_paths_cannot_escape_follow_symlinks_or_carry_private_material() {
        let work = Workspace::create("native-bundle-paths").unwrap();
        fs::write(work.join("plain"), b"x").unwrap();
        for name in ["../outside", "/absolute", "", "a/../plain"] {
            assert!(checked_path(work.path(), name).is_err(), "{name}");
        }
        for name in ["cover.pem", "fixture.KEY", "trust.p12", "client.pfx"] {
            fs::write(work.join(name), b"x").unwrap();
            assert!(checked_path(work.path(), name).is_err(), "{name}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(work.join("plain"), work.join("linked")).unwrap();
            assert!(checked_path(work.path(), "linked").is_err());
        }
        assert!(checked_path(work.path(), "plain").is_ok());
    }

    #[test]
    fn check_artifacts_outside_required_directories_are_not_transferable() {
        let work = Workspace::create("native-bundle-scope").unwrap();
        let mut evidence = native(work.path());
        evidence.checks[0]
            .observations
            .push(save(work.path(), "payload-1.bin", b"p"));
        assert!(
            transfer_set(work.path(), &evidence)
                .unwrap_err()
                .contains("outside a required-* directory")
        );
    }
}
