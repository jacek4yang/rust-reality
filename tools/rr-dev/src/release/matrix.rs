//! The canonical release tier matrix — the single source of truth.
//!
//! This replaces `scripts/release-matrix.sh`. Every other release stage (build,
//! package, smoke, aggregate) resolves tier metadata through this module, so tier
//! definitions, CPU requirements, target-directory mapping and the schema-v2
//! `cpuTier` alias all live in exactly one place.
//!
//! Matrix design rationale (measured, see
//! `artifacts/v1.5.0/release-tiers/dispatch-inspection.md`): ring and the
//! `RustCrypto` fallbacks already dispatch AES-NI/AVX2/SHA-NI at runtime, so the CPU
//! tiers change `LLVM` codegen of the proxy's own code rather than the crypto path.//! `target-cpu=native` is never used: release assets must run on any host meeting
//! the documented tier baseline.

/// A release tier and its build/runtime metadata.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    /// Stable tier identifier, e.g. `linux-x86_64-generic`.
    pub id: &'static str,
    /// The Rust target triple.
    pub target: &'static str,
    /// The `-C target-cpu` value.
    pub target_cpu: &'static str,
    /// Extra `-C target-feature` list, comma-separated, empty when none.
    pub target_features: &'static str,
    /// The GitHub Actions runner label.
    pub runs_on: &'static str,
    /// Whether validation runs on native hardware of this architecture.
    pub measured_natively: bool,
    /// The schema-v2 `cpuTier` manifest alias.
    pub cpu_tier: &'static str,
    /// `CARGO_TARGET_DIR` relative to the repository root.
    pub target_dir: &'static str,
}

/// The four release tiers, in canonical order.
///
/// An `aarch64-crypto` tier (+aes,+sha2) was evaluated and dropped: ring does
/// HWCAP runtime dispatch on aarch64 and no aarch64 hardware is available to
/// measure the residual non-default-path gain.
pub const TIERS: [Tier; 4] = [
    Tier {
        id: "linux-x86_64-generic",
        target: "x86_64-unknown-linux-gnu",
        target_cpu: "x86-64",
        target_features: "",
        runs_on: "ubuntu-22.04",
        measured_natively: true,
        cpu_tier: "portable",
        target_dir: "target",
    },
    Tier {
        id: "linux-x86_64-musl",
        target: "x86_64-unknown-linux-musl",
        target_cpu: "x86-64",
        target_features: "",
        runs_on: "ubuntu-22.04",
        measured_natively: true,
        cpu_tier: "portable-musl",
        target_dir: "target/x86_64-musl",
    },
    Tier {
        id: "linux-x86_64-v3",
        target: "x86_64-unknown-linux-gnu",
        target_cpu: "x86-64-v3",
        target_features: "",
        runs_on: "ubuntu-22.04",
        measured_natively: true,
        cpu_tier: "x86-64-v3",
        target_dir: "target/x86-64-v3",
    },
    Tier {
        id: "linux-aarch64-generic",
        target: "aarch64-unknown-linux-gnu",
        target_cpu: "generic",
        target_features: "",
        runs_on: "ubuntu-22.04-arm",
        measured_natively: true,
        cpu_tier: "aarch64-generic",
        target_dir: "target/aarch64-generic",
    },
];

impl Tier {
    /// Resolves a tier by id.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown tier and the known ids, matching
    /// `release_matrix_field`'s failure text.
    pub fn resolve(id: &str) -> Result<&'static Self, String> {
        TIERS.iter().find(|tier| tier.id == id).ok_or_else(|| {
            format!(
                "unknown release tier: {id} (known: {})",
                Self::ids().join(" ")
            )
        })
    }

    /// The CPU/runtime requirements block embedded into the manifest fragment.
    ///
    /// `runtimeDispatch` records that hot paths (record AEAD, `SHA-2`, `ChaCha20`,
    /// memchr) select ISA extensions beyond the static baseline at process start.
    #[must_use]
    pub fn requirements_json(&self) -> String {
        match self.id {
            "linux-x86_64-generic" => "{\n  \"architecture\": \"x86_64\",\n  \"isaLevel\": \"x86-64\",\n  \"requiredCpuFeatures\": [\"sse2\"],\n  \"runtimeDispatch\": true\n}".to_owned(),
            "linux-x86_64-musl" => "{\n  \"architecture\": \"x86_64\",\n  \"isaLevel\": \"x86-64\",\n  \"requiredCpuFeatures\": [\"sse2\"],\n  \"runtimeDispatch\": true,\n  \"libc\": \"musl\",\n  \"linkage\": \"static\",\n  \"dynamicLoaderRequired\": false\n}".to_owned(),
            "linux-x86_64-v3" => "{\n  \"architecture\": \"x86_64\",\n  \"isaLevel\": \"x86-64-v3\",\n  \"requiredCpuFeatures\": [\n    \"avx\", \"avx2\", \"bmi1\", \"bmi2\", \"cx16\", \"f16c\", \"fma\", \"lahf_lm\",\n    \"lzcnt\", \"movbe\", \"popcnt\", \"sse3\", \"sse4_1\", \"sse4_2\", \"ssse3\", \"xsave\"\n  ],\n  \"requiresOsAvxState\": true,\n  \"runtimeDispatch\": true\n}".to_owned(),
            "linux-aarch64-generic" => "{\n  \"architecture\": \"aarch64\",\n  \"isaLevel\": \"armv8-a\",\n  \"requiredCpuFeatures\": [\"neon\"],\n  \"runtimeDispatch\": true\n}".to_owned(),
            other => unreachable!("no requirements metadata for tier: {other}"),
        }
    }

    /// The list of comma-separated target features, empty when none.
    #[must_use]
    pub fn feature_list(&self) -> Vec<String> {
        self.target_features
            .split(',')
            .map(str::trim)
            .filter(|feature| !feature.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Every tier id in canonical order.
    #[must_use]
    pub fn ids() -> Vec<&'static str> {
        TIERS.iter().map(|tier| tier.id).collect()
    }
}

/// Renders the GitHub Actions matrix JSON, prefixed with `matrix=` for
/// `$GITHUB_OUTPUT`, exactly as `release-matrix.sh --github-matrix` did.
#[must_use]
pub fn github_matrix() -> String {
    use std::fmt::Write as _;
    let mut include = String::new();
    for (index, tier) in TIERS.iter().enumerate() {
        if index > 0 {
            include.push(',');
        }
        let _ = write!(
            include,
            "{{\"tier\":\"{}\",\"target\":\"{}\",\"runs-on\":\"{}\",\"measured-natively\":\"{}\"}}",
            tier.id, tier.target, tier.runs_on, tier.measured_natively
        );
    }
    format!("matrix={{\"include\":[{include}]}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tier_resolves_and_has_a_requirements_block() {
        for tier in &TIERS {
            let resolved = Tier::resolve(tier.id).expect("declared tier must resolve");
            assert_eq!(resolved.id, tier.id);
            let requirements = tier.requirements_json();
            assert!(requirements.contains("runtimeDispatch"), "{}", tier.id);
        }
    }

    #[test]
    fn an_unknown_tier_is_rejected_with_the_known_list() {
        let error = Tier::resolve("linux-riscv64-generic").expect_err("unknown tier must fail");
        assert!(
            error.contains("unknown release tier: linux-riscv64-generic"),
            "{error}"
        );
        assert!(error.contains("linux-x86_64-generic"), "{error}");
    }

    #[test]
    fn the_github_matrix_lists_every_tier_once() {
        let rendered = github_matrix();
        assert!(rendered.starts_with("matrix={\"include\":["));
        for tier in &TIERS {
            assert!(
                rendered.contains(&format!("\"tier\":\"{}\"", tier.id)),
                "{rendered}"
            );
        }
        // Well-formed single-line JSON body.
        assert_eq!(rendered.matches("\"tier\":").count(), TIERS.len());
    }

    #[test]
    fn cpu_tier_aliases_are_stable() {
        let aliases: Vec<&str> = TIERS.iter().map(|tier| tier.cpu_tier).collect();
        assert_eq!(
            aliases,
            ["portable", "portable-musl", "x86-64-v3", "aarch64-generic"]
        );
    }
}
