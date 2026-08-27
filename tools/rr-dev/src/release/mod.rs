//! The release subsystem — one typed domain replacing the release shell scripts.
//!
//! Structure follows the release lifecycle rather than the old one-file-per-stage
//! layout:
//!
//! ```text
//! matrix     single source of truth for tiers      (release-matrix.sh)
//! verify_tag SemVer + tag/commit identity gate      (verify-release-tag.sh)
//! build      per-tier build/test                    (build-release.sh)
//! package    deterministic tarball + tier fragment  (package-release.sh)
//! smoke      run the packaged binary against a cover (smoke-release-assets.sh)
//! aggregate  fail-closed complete-matrix manifest    (aggregate-release.sh)
//! ```
//!
//! The release safety invariants are preserved exactly: exact commit and tag
//! identity, deterministic artifact naming and bytes, SHA-256 identities, a
//! complete expected matrix with no partial-success declaration, packaged-binary
//! smoke tests, an artifact manifest, and fail-closed aggregation.

pub mod aggregate;
pub mod build;
pub mod matrix;
pub mod package;
pub mod smoke;
pub mod verify_tag;

/// `SemVer` helpers shared across release stages.
pub mod semver {
    /// Whether `tag` is a stable `vMAJOR.MINOR.PATCH` release tag.
    ///
    /// Matches the shell regex `^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`:
    /// no pre-release or build metadata, and no leading zeroes in any component.
    #[must_use]
    pub fn is_stable_release_tag(tag: &str) -> bool {
        let Some(body) = tag.strip_prefix('v') else {
            return false;
        };
        let parts: Vec<&str> = body.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        parts.iter().all(|part| is_numeric_component(part))
    }

    /// A non-negative integer with no leading zero (except the literal `0`).
    fn is_numeric_component(part: &str) -> bool {
        match part {
            "" => false,
            "0" => true,
            _ => part.chars().all(|character| character.is_ascii_digit()) && !part.starts_with('0'),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accepts_stable_tags() {
            for tag in ["v0.0.0", "v1.8.0", "v10.20.30", "v1.0.10"] {
                assert!(is_stable_release_tag(tag), "{tag}");
            }
        }

        #[test]
        fn rejects_nonstable_or_malformed_tags() {
            for tag in [
                "1.8.0",        // no v
                "v1.8",         // two components
                "v1.8.0.1",     // four components
                "v1.8.0-rc.1",  // pre-release
                "v01.8.0",      // leading zero
                "v1.8.0+build", // build metadata
                "vx.y.z",       // non-numeric
                "",
            ] {
                assert!(!is_stable_release_tag(tag), "{tag}");
            }
        }
    }
}


#[cfg(test)]
mod harness {
    //! End-to-end tests porting the decision-critical invariants of the retired
    //! `scripts/test-package-release.sh`: deterministic packaging, the shipped
    //! artifact set, and fail-closed aggregation. A fake binary stands in for a
    //! real tier build so no cross toolchain is needed.

    use std::path::{Path, PathBuf};

    use super::{aggregate, matrix::Tier, package};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest sits three levels below the repository root")
            .to_path_buf()
    }

    fn write_fake_binary(path: &Path) {
        std::fs::write(path, b"#!/usr/bin/env sh\nprintf fake-release\n").expect("write fake binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake binary");
        }
    }

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn scratch(name: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "rr-release-harness-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch");
        Scratch(path)
    }

    fn package_all(repo: &Path, fake_binary: &Path, output: &Path) {
        for tier in Tier::ids() {
            package::package(&package::Options {
                repo,
                tag: "v9.8.7",
                tier,
                output,
                binary_override: Some(fake_binary.to_path_buf()),
                cargo_features: None,
                measured_natively: None,
            })
            .unwrap_or_else(|error| panic!("package {tier} must succeed: {error}"));
        }
    }

    #[test]
    fn packaging_is_deterministic_and_aggregates_to_a_complete_manifest() {
        let repo = repo_root();
        let work = scratch("deterministic");
        let fake = work.0.join("rust-reality");
        write_fake_binary(&fake);
        let first = work.0.join("first");
        let second = work.0.join("second");

        package_all(&repo, &fake, &first);
        package_all(&repo, &fake, &second);

        for tier in Tier::ids() {
            let name = format!("rust-reality-v9.8.7-{tier}.tar.gz");
            let a = std::fs::read(first.join(&name)).expect("first archive");
            let b = std::fs::read(second.join(&name)).expect("second archive");
            assert_eq!(a, b, "archive for {tier} must be reproducible");
        }

        aggregate::aggregate(&first, "v9.8.7").expect("aggregate must succeed");
        let mut present: Vec<String> = std::fs::read_dir(&first)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        present.sort();
        let mut expected: Vec<String> = Tier::ids()
            .iter()
            .map(|tier| format!("rust-reality-v9.8.7-{tier}.tar.gz"))
            .collect();
        expected.push("SHA256SUMS".to_owned());
        expected.push("release-manifest.json".to_owned());
        expected.sort();
        assert_eq!(present, expected, "aggregate ships only tarballs, manifest and sums");

        for tier in Tier::ids() {
            assert!(
                !first.join(format!("{tier}.tier.json")).exists(),
                "fragment for {tier} must be removed after aggregation"
            );
        }

        let manifest = std::fs::read_to_string(first.join("release-manifest.json")).unwrap();
        assert!(manifest.contains("\"schemaVersion\": 3"));
        assert!(manifest.contains("\"version\": \"9.8.7\""));
        assert!(manifest.contains("\"tag\": \"v9.8.7\""));
        assert!(manifest.contains("\"target\": \"x86_64-unknown-linux-gnu\""));
        for tier in Tier::ids() {
            assert!(manifest.contains(&format!("\"tier\": \"{tier}\"")), "manifest lists {tier}");
        }
    }

    #[test]
    fn aggregate_rejects_a_partial_matrix_without_writing_outputs() {
        let repo = repo_root();
        let work = scratch("partial");
        let fake = work.0.join("rust-reality");
        write_fake_binary(&fake);
        let partial = work.0.join("dist");
        std::fs::create_dir_all(&partial).unwrap();

        package::package(&package::Options {
            repo: &repo,
            tag: "v9.8.7",
            tier: "linux-x86_64-generic",
            output: &partial,
            binary_override: Some(fake.clone()),
            cargo_features: None,
            measured_natively: None,
        })
        .expect("single-tier package");

        let error =
            aggregate::aggregate(&partial, "v9.8.7").expect_err("a partial matrix must fail closed");
        assert!(error.contains("missing aggregated release input"), "{error}");
        assert!(!partial.join("release-manifest.json").exists());
        assert!(!partial.join("SHA256SUMS").exists());
    }

    #[test]
    fn aggregate_rejects_an_unlisted_asset() {
        let repo = repo_root();
        let work = scratch("poisoned");
        let fake = work.0.join("rust-reality");
        write_fake_binary(&fake);
        let poisoned = work.0.join("dist");
        std::fs::create_dir_all(&poisoned).unwrap();
        package_all(&repo, &fake, &poisoned);

        std::fs::write(poisoned.join("rust-reality-v9.8.7-linux-x86_64-v4.tar.gz"), b"").unwrap();

        let error = aggregate::aggregate(&poisoned, "v9.8.7")
            .expect_err("an unlisted asset must fail closed");
        assert!(error.contains("unexpected files in aggregate dist directory"), "{error}");
        assert!(!poisoned.join("release-manifest.json").exists());
        assert!(!poisoned.join("SHA256SUMS").exists());
    }

    #[test]
    fn packaging_refuses_to_overwrite_an_existing_asset() {
        let repo = repo_root();
        let work = scratch("collision");
        let fake = work.0.join("rust-reality");
        write_fake_binary(&fake);
        let output = work.0.join("dist");
        std::fs::create_dir_all(&output).unwrap();

        let options = package::Options {
            repo: &repo,
            tag: "v9.8.7",
            tier: "linux-x86_64-generic",
            output: &output,
            binary_override: Some(fake.clone()),
            cargo_features: None,
            measured_natively: None,
        };
        package::package(&options).expect("first package");
        let error =
            package::package(&options).expect_err("a second package must refuse to overwrite");
        assert!(error.contains("release output already contains"), "{error}");
    }
}
