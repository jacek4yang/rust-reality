//! Fixed native qualification commands and their durable observation inventory.

use std::{fs, path::Path};

use super::{collect, native_interop, qualification::Case, schema, workload};

pub(super) fn command(
    case: Case,
    directory: &Path,
    identity: &schema::Identity,
) -> Result<Vec<String>, String> {
    let root = directory.parent().ok_or("missing frozen bundle root")?;
    let suite = match case {
        Case::NativeInterop => "no-ccs-interop",
        Case::NativeMechanism => "deployment",
        Case::NativeDescriptorPressure => "descriptor-pressure",
        Case::NativeResources => "soak",
        _ => return Err("not a native qualification case".to_owned()),
    };
    let mut argv = vec![
        identity.evaluator.path.clone(),
        "bench".to_owned(),
        "run".to_owned(),
        "--suite".to_owned(),
        suite.to_owned(),
    ];
    if matches!(case, Case::NativeMechanism) {
        argv.extend(["--deployment-plan", "mechanism"].map(str::to_owned));
    }
    argv.extend([
        "--rust-bin".to_owned(),
        root.join(&identity.candidate.path).display().to_string(),
        "--xray-bin".to_owned(),
        root.join("xray").display().to_string(),
    ]);
    if !matches!(case, Case::NativeMechanism) {
        argv.extend([
            "--openssl-bin".to_owned(),
            root.join("openssl").display().to_string(),
        ]);
    }
    match case {
        Case::NativeDescriptorPressure => argv.extend(
            [
                "--nofile-limit",
                "192",
                "--max-held-connections",
                "96",
                "--storm-connections",
                "12",
            ]
            .map(str::to_owned),
        ),
        Case::NativeResources => {
            let contract: schema::Contract =
                serde_json::from_str(schema::CONTRACT).expect("compiled contract");
            argv.extend([
                "--soak-seconds".to_owned(),
                (contract.native_duration_ms / 1000).to_string(),
                "--soak-min-rounds".to_owned(),
                contract.native_minimum_rounds.to_string(),
            ]);
            argv.extend(
                [
                    "--soak-round-sleep-ms",
                    "5000",
                    "--soak-distributed-interval-seconds",
                    "1800",
                    "--soak-implementation",
                    "rust",
                ]
                .map(str::to_owned),
            );
        }
        _ => {}
    }
    argv.extend([
        "--run-id".to_owned(),
        case.name().to_owned(),
        "--out-dir".to_owned(),
        directory.join("run").display().to_string(),
    ]);
    Ok(argv)
}

pub(super) fn proof(case: Case) -> &'static str {
    match case {
        Case::NativeDescriptorPressure => "gate-summary.json",
        Case::NativeResources => "native-resources.json",
        _ => "summary.json",
    }
}

pub(super) fn verify_inputs(root: &Path, identity: &schema::Identity) -> Result<(), String> {
    let environment =
        native_interop::parse_environment(&super::read_artifact(root, &identity.environment)?)?;
    if !environment.binds_external_images(
        &collect::file_digest(&root.join("xray"))?,
        &collect::file_digest(&root.join("openssl"))?,
    ) {
        return Err("native external executables differ from the frozen environment".to_owned());
    }
    Ok(())
}

pub(super) fn retain(
    root: &Path,
    directory: &Path,
    artifacts: &mut Vec<schema::Artifact>,
) -> Result<(), String> {
    if !directory.exists() {
        return Ok(());
    }
    inventory(root, directory, artifacts, 0)
}

fn inventory(
    root: &Path,
    path: &Path,
    artifacts: &mut Vec<schema::Artifact>,
    depth: usize,
) -> Result<(), String> {
    if depth > 16 || artifacts.len() >= 10_000 {
        return Err("native observation inventory exceeds fixed collection bounds".to_owned());
    }
    let kind = fs::symlink_metadata(path)
        .map_err(|error| error.to_string())?
        .file_type();
    if kind.is_file() {
        artifacts.push(workload::artifact(root, path)?);
    } else if kind.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .map_err(|error| error.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            inventory(root, &entry.path(), artifacts, depth + 1)?;
        }
    } else {
        return Err("native evidence contains a symlink or nonregular object".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_programs_keep_reviewed_pressure_and_workload_coverage() {
        let evidence: schema::Evidence =
            serde_json::from_value(super::super::tests::fixture()).unwrap();
        let directory = Path::new("/bundle/required-native");
        for (case, length) in [
            (Case::NativeInterop, 15),
            (Case::NativeMechanism, 15),
            (Case::NativeDescriptorPressure, 21),
            (Case::NativeResources, 25),
        ] {
            let argv = command(case, directory, &evidence.identity).unwrap();
            assert_eq!(argv.len(), length);
            assert_eq!(argv.last().unwrap(), "/bundle/required-native/run");
            assert!(!argv.iter().any(|arg| arg == "--keep-work"));
        }
        let argv = command(Case::NativeResources, directory, &evidence.identity).unwrap();
        assert_eq!(
            &argv[11..21],
            [
                "--soak-seconds",
                "1800",
                "--soak-min-rounds",
                "3",
                "--soak-round-sleep-ms",
                "5000",
                "--soak-distributed-interval-seconds",
                "1800",
                "--soak-implementation",
                "rust"
            ]
        );
        let mut check = evidence.checks[0].clone();
        check.name = "native-resources".to_owned();
        check.argv = argv;
        check.executed_cases = 1;
        super::super::checks::verify_native_resources_command(&check, &evidence.identity).unwrap();
        for (index, value) in [
            (12, "30"),
            (14, "1"),
            (16, "0"),
            (20, "xray"),
            (6, "relative-binary"),
        ] {
            let original = std::mem::replace(&mut check.argv[index], value.to_owned());
            assert!(
                super::super::checks::verify_native_resources_command(&check, &evidence.identity)
                    .is_err()
            );
            check.argv[index] = original;
        }
    }

    #[cfg(unix)]
    #[test]
    fn inventory_retains_nested_raw_files_and_rejects_symlinks() {
        let workspace = crate::bench::workspace::Workspace::create("native-inventory").unwrap();
        let run = workspace.join("run");
        fs::create_dir_all(run.join("rtt")).unwrap();
        fs::write(run.join("rtt/raw.json"), b"raw observations").unwrap();
        let mut artifacts = Vec::new();
        retain(workspace.path(), &run, &mut artifacts).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].path, "run/rtt/raw.json");
        std::os::unix::fs::symlink("rtt/raw.json", run.join("substituted")).unwrap();
        assert!(retain(workspace.path(), &run, &mut Vec::new()).is_err());
    }
}
