//! Deterministic per-tier packaging — the typed form of `package-release.sh`.
//!
//! Produces two artifacts for a tier: a reproducible `.tar.gz` (sorted entries,
//! commit mtime, numeric owner 0) and a schema-v3 `<tier>.tier.json` fragment
//! carrying the artifact's SHA-256 and the tier's CPU requirements. The archive
//! layout, the deterministic `tar` flags and the fragment schema are preserved
//! exactly; the SHA-256 identity and refusal to overwrite an existing asset are
//! load-bearing release safety invariants.
//!
//! External mechanism stays external: `git` for commit identity, `rustc` for the
//! compiler string, `tar`/`gzip` for the archive, `sha256sum` for the digest.

use std::path::{Path, PathBuf};

use crate::{
    perf::json_out::Json,
    process::Tool,
    release::{matrix::Tier, semver},
};

/// A packaged tier: the paths and digest of what was produced.
#[derive(Debug)]
pub struct Packaged {
    /// The archive path.
    pub archive: PathBuf,
    /// The archive SHA-256, lowercase hex.
    pub sha256: String,
    /// The fragment path.
    pub fragment: PathBuf,
}

/// Options controlling how the binary and provenance are resolved.
pub struct Options<'a> {
    /// Repository root.
    pub repo: &'a Path,
    /// Release tag, e.g. `v1.8.0`.
    pub tag: &'a str,
    /// Tier id.
    pub tier: &'a str,
    /// Output directory (created if absent).
    pub output: &'a Path,
    /// Explicit binary override, used by the fake-binary regression test.
    pub binary_override: Option<PathBuf>,
    /// Cargo features string recorded in the fragment; defaults to `default`.
    pub cargo_features: Option<String>,
    /// `measuredNatively` override; defaults to the tier's matrix value.
    pub measured_natively: Option<bool>,
}

/// Packages one tier.
///
/// # Errors
///
/// Returns a message on an invalid tag, unknown tier, missing binary, an output
/// collision, or any external-tool failure.
pub fn package(options: &Options) -> Result<Packaged, String> {
    if !semver::is_stable_release_tag(options.tag) {
        return Err(format!("invalid release tag: {}", options.tag));
    }
    let tier = Tier::resolve(options.tier)?;
    let version = options.tag.trim_start_matches('v');

    let binary = resolve_binary(options, tier)?;
    std::fs::create_dir_all(options.output)
        .map_err(|error| format!("could not create output directory: {error}"))?;

    let archive_name = format!("rust-reality-{}-{}.tar.gz", options.tag, tier.id);
    let fragment_name = format!("{}.tier.json", tier.id);
    for existing in [&archive_name, &fragment_name] {
        if options.output.join(existing).exists() {
            return Err(format!(
                "release output already contains {existing}: {}",
                options.output.display()
            ));
        }
    }

    let commit = git_head_commit(options.repo)?;
    let source_date_epoch = git_head_epoch(options.repo)?;
    let compiler = rustc_version()?;

    let staging = tempdir("rust-reality-package")?;
    stage_tree(options.repo, &binary, staging.path())?;

    let archive_path = options.output.join(&archive_name);
    build_archive(staging.path(), &archive_path, source_date_epoch)?;
    let sha256 = sha256_of(&archive_path)?;

    let fragment = build_fragment(&FragmentInput {
        version,
        tag: options.tag,
        commit: &commit,
        source_date_epoch,
        compiler: &compiler,
        cargo_features: options.cargo_features.as_deref().unwrap_or("default"),
        tier,
        archive_name: &archive_name,
        sha256: &sha256,
        measured_natively: options.measured_natively.unwrap_or(tier.measured_natively),
    });
    let fragment_path = options.output.join(&fragment_name);
    std::fs::write(&fragment_path, fragment.to_python_json())
        .map_err(|error| format!("could not write fragment: {error}"))?;

    Ok(Packaged {
        archive: archive_path,
        sha256,
        fragment: fragment_path,
    })
}

fn resolve_binary(options: &Options, tier: &Tier) -> Result<PathBuf, String> {
    if let Some(explicit) = &options.binary_override {
        if is_executable(explicit) {
            return Ok(explicit.clone());
        }
        return Err(format!(
            "release binary does not exist or is not executable: {}",
            explicit.display()
        ));
    }
    let target_dir = options.repo.join(tier.target_dir);
    let direct = target_dir.join("release/rust-reality");
    let cross = target_dir.join(tier.target).join("release/rust-reality");
    for candidate in [&direct, &cross] {
        if is_executable(candidate) {
            return Ok(candidate.clone());
        }
    }
    Err(format!(
        "no built binary for tier {} under {}",
        tier.id,
        target_dir.display()
    ))
}

/// Materialises the archive tree exactly as `package-release.sh` installs it.
fn stage_tree(repo: &Path, binary: &Path, staging: &Path) -> Result<(), String> {
    install(binary, &staging.join("rust-reality"), 0o755)?;
    for name in [
        "README.md",
        "README.zh-CN.md",
        "SECURITY.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
        "CHANGELOG.md",
    ] {
        install(&repo.join(name), &staging.join(name), 0o644)?;
    }
    std::fs::create_dir_all(staging.join("deploy"))
        .and_then(|()| std::fs::create_dir_all(staging.join("docs/decisions")))
        .and_then(|()| std::fs::create_dir_all(staging.join("docs/zh-CN")))
        .map_err(|error| format!("could not create staging subdirectories: {error}"))?;
    install(
        &repo.join("deploy/rust-reality.service"),
        &staging.join("deploy/rust-reality.service"),
        0o644,
    )?;
    copy_markdown(&repo.join("docs"), &staging.join("docs"))?;
    copy_markdown(&repo.join("docs/decisions"), &staging.join("docs/decisions"))?;
    install(
        &repo.join("docs/zh-CN/security.md"),
        &staging.join("docs/zh-CN/security.md"),
        0o644,
    )?;
    Ok(())
}

fn copy_markdown(from: &Path, to: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(from)
        .map_err(|error| format!("could not read {}: {error}", from.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "md") {
            let name = entry.file_name();
            install(&path, &to.join(name), 0o644)?;
        }
    }
    Ok(())
}

/// Copies `source` to `destination` with the requested mode, like `install -m`.
fn install(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    std::fs::copy(source, destination)
        .map_err(|error| format!("could not install {}: {error}", source.display()))?;
    set_mode(destination, mode)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("could not set mode on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Builds the deterministic gzip archive.
///
/// `tar --sort=name --mtime=@epoch --owner=0 --group=0 --numeric-owner` writes an
/// uncompressed archive to a scratch file, then `gzip -n -9` compresses it to the
/// final path. Routing the tar stream through a file rather than captured stdout
/// keeps the pipeline byte-exact: the process layer captures output as UTF-8 text,
/// which would corrupt a binary tar stream.
fn build_archive(staging: &Path, archive: &Path, epoch: i64) -> Result<(), String> {
    let scratch = tempdir("rust-reality-tar")?;
    let raw = scratch.path().join("archive.tar");
    let tar = Tool::new("tar")
        .args([
            "--sort=name",
            &format!("--mtime=@{epoch}"),
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-C",
        ])
        .arg(staging.to_string_lossy().into_owned())
        .arg("-cf")
        .arg(raw.to_string_lossy().into_owned())
        .arg(".")
        .probe()
        .map_err(|error| format!("tar failed: {error}"))?;
    if !tar.success() {
        return Err(format!("tar exited with {:?}: {}", tar.code, tar.stderr));
    }
    // gzip -n -9 in place, producing archive.tar.gz next to the scratch tar.
    let gz = Tool::new("gzip")
        .args(["-n", "-9"])
        .arg(raw.to_string_lossy().into_owned())
        .probe()
        .map_err(|error| format!("gzip failed: {error}"))?;
    if !gz.success() {
        return Err(format!("gzip exited with {:?}: {}", gz.code, gz.stderr));
    }
    let produced = scratch.path().join("archive.tar.gz");
    std::fs::rename(&produced, archive)
        .or_else(|_| std::fs::copy(&produced, archive).map(|_| ()))
        .map_err(|error| format!("could not place archive: {error}"))
}

struct FragmentInput<'a> {
    version: &'a str,
    tag: &'a str,
    commit: &'a str,
    source_date_epoch: i64,
    compiler: &'a str,
    cargo_features: &'a str,
    tier: &'a Tier,
    archive_name: &'a str,
    sha256: &'a str,
    measured_natively: bool,
}

fn build_fragment(input: &FragmentInput) -> Json {
    let features: Vec<Json> = input.tier.feature_list().into_iter().map(Json::string).collect();
    let cargo_features: Vec<Json> = input
        .cargo_features
        .split(',')
        .map(str::trim)
        .filter(|feature| !feature.is_empty())
        .map(Json::string)
        .collect();
    let requirements = crate::perf::json_in::parse(&input.tier.requirements_json())
        .map_or(Json::Null, json_in_to_out);
    Json::object([
        ("schemaVersion", Json::Int(3)),
        ("package", Json::string("rust-reality")),
        ("version", Json::string(input.version)),
        ("tag", Json::string(input.tag)),
        ("commit", Json::string(input.commit)),
        ("sourceDateEpoch", Json::Int(input.source_date_epoch)),
        ("compiler", Json::string(input.compiler)),
        ("cargoFeatures", Json::Array(cargo_features)),
        ("tier", Json::string(input.tier.id)),
        ("cpuTier", Json::string(input.tier.cpu_tier)),
        ("artifact", Json::string(input.archive_name)),
        ("sha256", Json::string(input.sha256)),
        ("target", Json::string(input.tier.target)),
        ("targetCpu", Json::string(input.tier.target_cpu)),
        ("targetFeatures", Json::Array(features)),
        ("measuredNatively", Json::Bool(input.measured_natively)),
        ("requirements", requirements),
    ])
}

/// Converts a parsed input JSON value into an output-tree value.
fn json_in_to_out(value: crate::perf::json_in::Value) -> Json {
    use crate::perf::json_in::Value;
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(flag),
        Value::Number(text) => text
            .parse::<i64>()
            .map(Json::Int)
            .or_else(|_| text.parse::<f64>().map(Json::Float))
            .unwrap_or(Json::Null),
        Value::Str(text) => Json::Str(text),
        Value::Array(items) => Json::Array(items.into_iter().map(json_in_to_out).collect()),
        Value::Object(members) => Json::Object(
            members
                .into_iter()
                .map(|(key, value)| (key, json_in_to_out(value)))
                .collect(),
        ),
    }
}

fn git_head_commit(repo: &Path) -> Result<String, String> {
    let out = Tool::new("git")
        .args(["-C"])
        .arg(repo.to_string_lossy().into_owned())
        .args(["rev-parse", "--verify", "HEAD"])
        .probe()
        .map_err(|error| format!("git rev-parse failed: {error}"))?;
    if !out.success() {
        return Err("could not resolve HEAD commit".to_owned());
    }
    Ok(out.trimmed_stdout().to_owned())
}

fn git_head_epoch(repo: &Path) -> Result<i64, String> {
    let out = Tool::new("git")
        .args(["-C"])
        .arg(repo.to_string_lossy().into_owned())
        .args(["show", "-s", "--format=%ct", "HEAD"])
        .probe()
        .map_err(|error| format!("git show failed: {error}"))?;
    out.trimmed_stdout()
        .parse()
        .map_err(|_| "could not read commit epoch".to_owned())
}

fn rustc_version() -> Result<String, String> {
    let out = Tool::new("rustc")
        .arg("--version")
        .probe()
        .map_err(|error| format!("rustc --version failed: {error}"))?;
    Ok(out.trimmed_stdout().to_owned())
}

/// Computes the SHA-256 of a file via `sha256sum`.
fn sha256_of(path: &Path) -> Result<String, String> {
    let out = Tool::new("sha256sum")
        .arg(path.to_string_lossy().into_owned())
        .probe()
        .map_err(|error| format!("sha256sum failed: {error}"))?;
    if !out.success() {
        return Err(format!("sha256sum exited with {:?}", out.code));
    }
    out.trimmed_stdout()
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum produced no digest".to_owned())
}

/// A temporary directory removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// The directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Creates a uniquely-named temporary directory under the system temp root.
pub fn tempdir(prefix: &str) -> Result<TempDir, String> {
    let base = std::env::temp_dir();
    let unique = format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    );
    let path = base.join(unique);
    std::fs::create_dir_all(&path)
        .map_err(|error| format!("could not create temp dir: {error}"))?;
    Ok(TempDir { path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fragment_carries_schema_three_and_the_tier_requirements() {
        let tier = Tier::resolve("linux-x86_64-musl").unwrap();
        let fragment = build_fragment(&FragmentInput {
            version: "9.8.7",
            tag: "v9.8.7",
            commit: &"a".repeat(40),
            source_date_epoch: 100,
            compiler: "rustc 1.96.0",
            cargo_features: "default",
            tier,
            archive_name: "rust-reality-v9.8.7-linux-x86_64-musl.tar.gz",
            sha256: &"b".repeat(64),
            measured_natively: true,
        });
        let rendered = fragment.to_python_json();
        assert!(rendered.contains("\"schemaVersion\": 3"));
        assert!(rendered.contains("\"cpuTier\": \"portable-musl\""));
        assert!(rendered.contains("\"libc\": \"musl\""));
        assert!(rendered.contains("\"linkage\": \"static\""));
        assert!(rendered.contains("\"measuredNatively\": true"));
    }
}
