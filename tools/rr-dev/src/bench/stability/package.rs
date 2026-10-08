//! Verify a retained package smoke bundle without executing its executable.

use std::{path::Path, time::Duration};

use super::{
    evaluate::{Report, Verdict},
    schema::{Artifact, Check, Identity},
};
use crate::{
    bench::workspace::Workspace,
    hash,
    process::Tool,
    release::{matrix::Tier, receipt, semver, smoke},
};

fn bound<'a>(root: &Path, check: &'a Check, name: &str) -> Result<&'a Artifact, String> {
    let directory = Path::new(&check.output.path)
        .parent()
        .ok_or("missing package receipt directory")?;
    let path = directory.join(name);
    let mut artifacts = check
        .observations
        .iter()
        .filter(|artifact| Path::new(&artifact.path) == path);
    let artifact = artifacts
        .next()
        .ok_or("missing package-bound observation")?;
    if artifacts.next().is_some() {
        return Err("duplicated package observation".to_owned());
    }
    super::verify_artifact(root, artifact)?;
    Ok(artifact)
}

/// Reconstruct package identities, command coverage and archive/executable binding.
///
/// # Errors
/// Rejects incomplete, emulated, changed or substituted package observations.
pub fn verify(root: &Path, check: &Check, identity: &Identity) -> Result<Report, String> {
    let tier = Tier::resolve(match check.name.as_str() {
        "package-gnu" => "linux-x86_64-generic",
        "package-musl" => "linux-x86_64-musl",
        "package-v3" => "linux-x86_64-v3",
        "package-aarch64" => "linux-aarch64-generic",
        _ => return Err("unknown package check".to_owned()),
    })?;
    let value = receipt::parse(&super::read_artifact(root, &check.output)?)?;
    receipt::verify(&value, &identity.source_commit, tier)?;
    if !semver::is_stable_release_tag(&value.tag) || check.executed_cases != 7 {
        return Err("package label or command coverage differs from the fixed smoke".to_owned());
    }
    let read = |name: &str| super::read_artifact(root, bound(root, check, name)?);
    let fragment: receipt::Fragment =
        serde_json::from_slice(&read(&format!("{}.tier.json", tier.id))?)
            .map_err(|error| error.to_string())?;
    receipt::verify_fragment(&fragment, &value, tier)?;
    for image in [&value.archive, &value.binary, &value.harness] {
        if Some(&bound(root, check, &image.path)?.sha256) != image.before.as_ref() {
            return Err("retained package image differs from the executed bytes".to_owned());
        }
    }
    if bound(root, check, "cpuinfo.txt")?.sha256 != value.host_cpuinfo_sha256
        || (check.name == "package-gnu"
            && value.binary.before.as_ref() != Some(&identity.candidate.sha256))
    {
        return Err("package host or GNU candidate identity was substituted".to_owned());
    }
    let harness = bound(root, check, "rr-dev")?;
    let expected = [
        harness.path.as_str(),
        "release",
        "smoke",
        &value.tag,
        tier.id,
        &value.assets_directory,
        "--receipt-dir",
        &value.output_directory,
    ];
    if !check.argv.iter().map(String::as_str).eq(expected) {
        return Err("package execution command was substituted".to_owned());
    }
    let cover: std::net::SocketAddrV4 = value
        .cover_target
        .parse()
        .map_err(|_| "invalid package cover address")?;
    if *cover.ip() != std::net::Ipv4Addr::LOCALHOST
        || cover.port() == 0
        || value.cover_server_name != "localhost"
    {
        return Err("package smoke lacks its owned loopback TLS cover".to_owned());
    }
    smoke::validate_doctor(
        value.commands[6]
            .stdout
            .as_deref()
            .ok_or("missing doctor output")?,
        &value.cover_target,
        &value.cover_server_name,
    )?;
    let scratch = Workspace::create("package-verification")?;
    let extracted = scratch.join("rust-reality");
    Tool::new("tar")
        .args(["-xOzf"])
        .arg(
            root.join(&bound(root, check, &value.archive.path)?.path)
                .display()
                .to_string(),
        )
        .arg("./rust-reality")
        .timeout(Duration::from_secs(30))
        .capture_limit(super::schema::MAX_EVIDENCE_BYTES)
        .log_output_only(&extracted, scratch.join("tar-stderr"))
        .run()
        .map_err(|error| error.to_string())?;
    if Some(hash::sha256_file(&extracted)?) != value.binary.before {
        return Err("executed binary is not the binary in the bound release archive".to_owned());
    }
    Ok(Report {
        verdict: Verdict::Pass,
        findings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn verify_import_round_trip(root: &Path, receipt: &Path, original: &Identity) {
        use super::super::{package_bind, schema};
        let directory = root.join("import");
        std::fs::create_dir(&directory).unwrap();
        let mut identity = original.clone();
        for (name, artifact) in [
            ("source.tar", &mut identity.source_archive),
            ("evaluator", &mut identity.evaluator),
            ("environment.json", &mut identity.environment),
            ("workload.json", &mut identity.workload),
            ("candidate", &mut identity.candidate),
            ("contract.json", &mut identity.contract),
        ] {
            let bytes: &[u8] = match name {
                "candidate" => b"packaged binary fixture",
                "contract.json" => schema::CONTRACT.as_bytes(),
                _ => b"retained test fixture",
            };
            artifact.path = name.to_owned();
            std::fs::write(directory.join(name), bytes).unwrap();
            artifact.sha256 = hash::sha256_hex(bytes);
        }
        let mut aggregate: schema::Evidence =
            serde_json::from_value(super::super::tests::fixture()).unwrap();
        aggregate.identity = identity;
        aggregate.checks.clear();
        aggregate.cells.clear();
        let path = directory.join("evidence.json");
        std::fs::write(&path, serde_json::to_vec(&aggregate).unwrap()).unwrap();
        let plan = package_bind::Plan {
            evidence: path.clone(),
            receipt_dir: receipt.to_path_buf(),
        };
        package_bind::run(&plan).unwrap();
        let after = std::fs::read(&path).unwrap();
        let bound = schema::parse(&after).unwrap();
        assert_eq!(bound.checks.len(), 1);
        assert_eq!(bound.checks[0].name, "package-gnu");
        assert!(package_bind::run(&plan).is_err());
        assert_eq!(std::fs::read(path).unwrap(), after);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn package_proof_rejects_an_archive_containing_another_binary() {
        let work = Workspace::create("package-proof").unwrap();
        let directory = work.join("bundle");
        std::fs::create_dir(&directory).unwrap();
        let save = |name: &str, bytes: &[u8]| {
            std::fs::write(directory.join(name), bytes).unwrap();
            Artifact {
                path: format!("bundle/{name}"),
                sha256: hash::sha256_hex(bytes),
            }
        };
        let evidence: super::super::schema::Evidence =
            serde_json::from_value(super::super::tests::fixture()).unwrap();
        let mut identity = evidence.identity;
        identity.source_commit = "a".repeat(40);
        let mut check = evidence
            .checks
            .into_iter()
            .find(|check| check.name == "package-gnu")
            .unwrap();
        let binary = save("rust-reality", b"packaged binary fixture");
        let harness = save("rr-dev", b"harness fixture");
        let cpu = save("cpuinfo.txt", b"CPU fixture");
        identity.candidate.sha256.clone_from(&binary.sha256);
        check.source_commit.clone_from(&identity.source_commit);
        check
            .candidate_sha256
            .clone_from(&identity.candidate.sha256);
        let tier = Tier::resolve("linux-x86_64-generic").unwrap();
        let name = "rust-reality-v2.0.1-linux-x86_64-generic.tar.gz";
        let archive = directory.join(name);
        let source = work.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("rust-reality"), b"packaged binary fixture").unwrap();
        let pack = || {
            Tool::new("tar")
                .args([
                    "-czf",
                    archive.to_str().unwrap(),
                    "-C",
                    source.to_str().unwrap(),
                    ".",
                ])
                .run()
                .unwrap();
            Artifact {
                path: format!("bundle/{name}"),
                sha256: hash::sha256_file(&archive).unwrap(),
            }
        };
        let archive_binding = pack();
        let mut receipt: Value = serde_json::from_slice(include_bytes!(
            "../../../../../fuzz/seeds/stability_evidence/seed_package.json"
        ))
        .unwrap();
        for (field, artifact) in [
            ("binary", &binary),
            ("harness", &harness),
            ("archive", &archive_binding),
        ] {
            receipt[field]["before"] = json!(artifact.sha256);
            receipt[field]["after"] = json!(artifact.sha256);
        }
        receipt["host_cpuinfo_sha256"] = json!(cpu.sha256);
        let mut fragment = json!({"schemaVersion":3,"package":"rust-reality","version":"2.0.1","tag":"v2.0.1",
            "commit":identity.source_commit,"sourceDateEpoch":1,"compiler":"rustc fixture","cargoFeatures":["default"],
            "tier":tier.id,"cpuTier":tier.cpu_tier,"artifact":name,"sha256":archive_binding.sha256,
            "target":tier.target,"targetCpu":tier.target_cpu,"targetFeatures":tier.feature_list(),"measuredNatively":true,
            "requirements":serde_json::from_str::<Value>(&tier.requirements_json()).unwrap()});
        let fragment_name = format!("{}.tier.json", tier.id);
        let fragment_binding = save(&fragment_name, &serde_json::to_vec(&fragment).unwrap());
        check.output = save("receipt.json", &serde_json::to_vec(&receipt).unwrap());
        check.observations = vec![
            binary,
            harness.clone(),
            cpu,
            archive_binding,
            fragment_binding,
        ];
        check.argv = [
            harness.path.as_str(),
            "release",
            "smoke",
            "v2.0.1",
            tier.id,
            "/fixture/assets",
            "--receipt-dir",
            "/fixture/receipt",
        ]
        .map(str::to_owned)
        .to_vec();
        check.executed_cases = 7;
        verify(work.path(), &check, &identity).unwrap();
        verify_import_round_trip(work.path(), &directory, &identity);

        let mut missing = check.clone();
        missing
            .observations
            .retain(|artifact| artifact.path != "bundle/cpuinfo.txt");
        assert!(verify(work.path(), &missing, &identity).is_err());
        std::fs::write(source.join("rust-reality"), b"another binary").unwrap();
        let archive_binding = pack();
        receipt["archive"]["before"] = json!(archive_binding.sha256);
        receipt["archive"]["after"] = json!(archive_binding.sha256);
        fragment["sha256"] = json!(archive_binding.sha256);
        check.output = save("receipt.json", &serde_json::to_vec(&receipt).unwrap());
        check.observations[3] = archive_binding;
        check.observations[4] = save(&fragment_name, &serde_json::to_vec(&fragment).unwrap());
        assert!(
            verify(work.path(), &check, &identity)
                .unwrap_err()
                .contains("binary in the bound release archive")
        );
    }
}
