//! Fail-closed release aggregation — the typed form of `aggregate-release.sh`.
//!
//! Merges every per-tier fragment into one `release-manifest.json` plus
//! `SHA256SUMS`. The complete expected matrix is required: a missing or
//! unexpected tier fails the release, so a partial publish is impossible. Each
//! fragment's recorded SHA-256 is re-verified against its archive bytes, and the
//! global provenance keys must agree across every tier. Fragments are removed
//! after a successful merge; the release ships only tarballs, the manifest and
//! `SHA256SUMS`.

use std::{
    collections::BTreeMap,
    path::Path,
};

use crate::{
    perf::{json_in::Value, json_out::Json},
    process::Tool,
    release::{matrix::Tier, semver},
};

/// The global provenance keys that must be identical across every fragment.
const GLOBAL_KEYS: [&str; 7] = [
    "package",
    "version",
    "tag",
    "commit",
    "sourceDateEpoch",
    "compiler",
    "cargoFeatures",
];

/// Aggregates the complete matrix in `dist` for `tag`.
///
/// # Errors
///
/// Returns a message on an invalid tag, a missing or unexpected input, an SHA-256
/// mismatch, disagreeing provenance, or any write/hash failure. No manifest or
/// `SHA256SUMS` is written unless every check passes.
pub fn aggregate(repo_dist: &Path, tag: &str) -> Result<String, String> {
    if !semver::is_stable_release_tag(tag) {
        return Err(format!("invalid release tag: {tag}"));
    }
    let tiers = Tier::ids();

    // Every expected input must be present.
    for tier in &tiers {
        for file in [
            format!("rust-reality-{tag}-{tier}.tar.gz"),
            format!("{tier}.tier.json"),
        ] {
            if !repo_dist.join(&file).is_file() {
                return Err(format!(
                    "missing aggregated release input: {}",
                    repo_dist.join(&file).display()
                ));
            }
        }
    }

    // No unexpected files may be present.
    let mut expected: Vec<String> = Vec::new();
    for tier in &tiers {
        expected.push(format!("rust-reality-{tag}-{tier}.tar.gz"));
        expected.push(format!("{tier}.tier.json"));
    }
    expected.sort();
    let mut present: Vec<String> = std::fs::read_dir(repo_dist)
        .map_err(|error| format!("could not read dist directory: {error}"))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    present.sort();
    let unexpected: Vec<&String> = present
        .iter()
        .filter(|name| !expected.contains(name))
        .collect();
    if !unexpected.is_empty() {
        let listing = unexpected
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!(
            "unexpected files in aggregate dist directory:\n{listing}"
        ));
    }

    // Parse and verify every fragment.
    let mut fragments: Vec<Value> = Vec::with_capacity(tiers.len());
    for tier in &tiers {
        let fragment_path = repo_dist.join(format!("{tier}.tier.json"));
        let text = std::fs::read_to_string(&fragment_path)
            .map_err(|error| format!("{}: {error}", fragment_path.display()))?;
        let fragment = crate::perf::json_in::parse(&text)
            .map_err(|error| format!("{}: {error}", fragment_path.display()))?;
        check_int(&fragment, "schemaVersion", 3, &fragment_path)?;
        check_str(&fragment, "tag", tag, &fragment_path)?;
        check_str(&fragment, "tier", tier, &fragment_path)?;
        let artifact = str_of(&fragment, "artifact")?;
        let expected_name = format!("rust-reality-{tag}-{tier}.tar.gz");
        if artifact != expected_name {
            return Err(format!("{}: artifact {artifact} != {expected_name}", fragment_path.display()));
        }
        let archive = repo_dist.join(&artifact);
        let digest = sha256_of(&archive)?;
        let recorded = str_of(&fragment, "sha256")?;
        if digest != recorded {
            return Err(format!(
                "sha256 mismatch for {artifact}: fragment {recorded} != actual {digest}"
            ));
        }
        fragments.push(fragment);
    }

    // Global provenance keys must agree across all fragments.
    let first = &fragments[0];
    for fragment in &fragments[1..] {
        for key in GLOBAL_KEYS {
            if fragment.optional(key) != first.optional(key) {
                let tier = str_of(fragment, "tier").unwrap_or_default();
                return Err(format!("fragment {tier} disagrees on {key}"));
            }
        }
    }

    let manifest = build_manifest(&fragments)?;
    let manifest_path = repo_dist.join("release-manifest.json");
    std::fs::write(&manifest_path, manifest.to_python_json())
        .map_err(|error| format!("could not write manifest: {error}"))?;

    // Fragments are removed; the release ships only tarballs + manifest + sums.
    for tier in &tiers {
        let fragment_path = repo_dist.join(format!("{tier}.tier.json"));
        std::fs::remove_file(&fragment_path)
            .map_err(|error| format!("could not remove fragment: {error}"))?;
    }

    write_sha256sums(repo_dist, tag, &tiers)?;

    Ok(format!(
        "aggregated {} tiers into {}/release-manifest.json",
        tiers.len(),
        repo_dist.display()
    ))
}

/// Builds the schema-v3 manifest, preserving the generic-asset v1/v2 aliases.
fn build_manifest(fragments: &[Value]) -> Result<Json, String> {
    let by_tier: BTreeMap<String, &Value> = fragments
        .iter()
        .map(|fragment| (str_of(fragment, "tier").unwrap_or_default(), fragment))
        .collect();
    let first = &fragments[0];
    let generic = by_tier
        .get("linux-x86_64-generic")
        .ok_or_else(|| "aggregate is missing the generic tier".to_owned())?;

    let mut artifacts = Vec::with_capacity(fragments.len());
    for tier in Tier::ids() {
        let fragment = by_tier
            .get(tier)
            .ok_or_else(|| format!("aggregate is missing tier {tier}"))?;
        artifacts.push(Json::object([
            ("artifact", value_to_json(fragment.optional("artifact"))),
            ("sha256", value_to_json(fragment.optional("sha256"))),
            ("tier", value_to_json(fragment.optional("tier"))),
            ("cpuTier", value_to_json(fragment.optional("cpuTier"))),
            ("target", value_to_json(fragment.optional("target"))),
            ("targetCpu", value_to_json(fragment.optional("targetCpu"))),
            ("targetFeatures", value_to_json(fragment.optional("targetFeatures"))),
            ("measuredNatively", value_to_json(fragment.optional("measuredNatively"))),
            ("requirements", value_to_json(fragment.optional("requirements"))),
        ]));
    }

    Ok(Json::object([
        ("schemaVersion", Json::Int(3)),
        ("package", value_to_json(first.optional("package"))),
        ("version", value_to_json(first.optional("version"))),
        ("tag", value_to_json(first.optional("tag"))),
        ("commit", value_to_json(first.optional("commit"))),
        ("target", value_to_json(generic.optional("target"))),
        ("sourceDateEpoch", value_to_json(first.optional("sourceDateEpoch"))),
        ("compiler", value_to_json(first.optional("compiler"))),
        ("cargoFeatures", value_to_json(first.optional("cargoFeatures"))),
        ("artifact", value_to_json(generic.optional("artifact"))),
        ("sha256", value_to_json(generic.optional("sha256"))),
        ("artifacts", Json::Array(artifacts)),
    ]))
}

/// Writes `SHA256SUMS` over tarballs then the manifest, and verifies it.
fn write_sha256sums(dist: &Path, tag: &str, tiers: &[&str]) -> Result<(), String> {
    let mut entries: Vec<String> = Vec::with_capacity(tiers.len() + 1);
    for tier in tiers {
        let name = format!("rust-reality-{tag}-{tier}.tar.gz");
        let digest = sha256_of(&dist.join(&name))?;
        entries.push(format!("{digest}  {name}"));
    }
    let manifest_digest = sha256_of(&dist.join("release-manifest.json"))?;
    entries.push(format!("{manifest_digest}  release-manifest.json"));
    let mut lines = entries.join("\n");
    lines.push('\n');
    std::fs::write(dist.join("SHA256SUMS"), &lines)
        .map_err(|error| format!("could not write SHA256SUMS: {error}"))?;

    let check = Tool::new("sha256sum")
        .args(["--check", "SHA256SUMS"])
        .current_dir(dist)
        .probe()
        .map_err(|error| format!("sha256sum --check failed: {error}"))?;
    if !check.success() {
        return Err("SHA256SUMS verification failed".to_owned());
    }
    Ok(())
}

fn value_to_json(value: Option<&Value>) -> Json {
    match value {
        None | Some(Value::Null) => Json::Null,
        Some(Value::Bool(flag)) => Json::Bool(*flag),
        Some(Value::Number(text)) => text
            .parse::<i64>()
            .map(Json::Int)
            .or_else(|_| text.parse::<f64>().map(Json::Float))
            .unwrap_or(Json::Null),
        Some(Value::Str(text)) => Json::Str(text.clone()),
        Some(Value::Array(items)) => {
            Json::Array(items.iter().map(|item| value_to_json(Some(item))).collect())
        }
        Some(Value::Object(members)) => Json::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(Some(value))))
                .collect(),
        ),
    }
}

fn str_of(value: &Value, key: &str) -> Result<String, String> {
    value
        .optional(key)
        .and_then(|inner| inner.as_str(key).ok())
        .map(str::to_owned)
        .ok_or_else(|| format!("fragment field {key} must be a string"))
}

fn check_int(value: &Value, key: &str, expected: i64, path: &Path) -> Result<(), String> {
    let observed = value
        .optional(key)
        .and_then(|inner| inner.as_int(key).ok());
    if observed == Some(expected) {
        Ok(())
    } else {
        Err(format!("{}: {key} must be {expected}", path.display()))
    }
}

fn check_str(value: &Value, key: &str, expected: &str, path: &Path) -> Result<(), String> {
    if str_of(value, key)? == expected {
        Ok(())
    } else {
        Err(format!("{}: {key} must be {expected}", path.display()))
    }
}

fn sha256_of(path: &Path) -> Result<String, String> {
    let out = Tool::new("sha256sum")
        .arg(path.to_string_lossy().into_owned())
        .probe()
        .map_err(|error| format!("sha256sum failed: {error}"))?;
    if !out.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    out.trimmed_stdout()
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum produced no digest".to_owned())
}
