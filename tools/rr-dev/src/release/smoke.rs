//! Packaged-binary smoke test — the typed form of `smoke-release-assets.sh`.
//!
//! Executing the packaged binary is the authoritative CPU+OS feature gate: a host
//! that cannot run a tier must fail the release rather than publish an untested
//! optimized artifact. This verifies the asset SHA-256, extracts the tarball, and
//! drives the binary through `--version`, `--help`, `schema`, `config generate`,
//! `check` and `self-test`, asserting the self-test reports a single compatible
//! REALITY destination pointing at the cover.
//!
//! The release workflow smokes against a real local TLS 1.3 peer. When no cover is
//! supplied via the environment overrides, a loopback `openssl s_server` cover is
//! started; those overrides also let the fake-binary regression test point at an
//! arbitrary target. An optional runner wrapper (e.g. qemu) validates functionality
//! only and is never native performance evidence.

use std::{io::Read, path::Path};

use crate::{
    perf::json_in,
    process::Tool,
    release::{matrix::Tier, package::tempdir, semver},
};

/// Smoke-tests the packaged asset for `tier` in `asset_dir` at `tag`.
///
/// # Errors
///
/// Returns a message on an invalid tag, unknown tier, a missing or corrupt asset,
/// a failed binary invocation, or a self-test that does not report exactly one
/// compatible destination matching the cover.
pub fn smoke(repo: &Path, tag: &str, tier_id: &str, asset_dir: &Path) -> Result<String, String> {
    if !semver::is_stable_release_tag(tag) {
        return Err(format!("invalid release tag: {tag}"));
    }
    let tier = Tier::resolve(tier_id)?;
    let version = tag.trim_start_matches('v');
    let archive = format!("rust-reality-{tag}-{}.tar.gz", tier.id);
    let archive_path = asset_dir.join(&archive);
    if !archive_path.is_file() {
        return Err(format!("missing release asset: {}", archive_path.display()));
    }
    let _ = repo; // repository root reserved for future cover-material sourcing.

    // Verify recorded sums if present.
    if asset_dir.join("SHA256SUMS").is_file() {
        let check = Tool::new("sha256sum")
            .args(["--check", "--ignore-missing", "SHA256SUMS"])
            .current_dir(asset_dir)
            .probe()
            .map_err(|error| format!("sha256sum --check failed: {error}"))?;
        if !check.success() {
            return Err("SHA256SUMS verification failed".to_owned());
        }
    }

    let runner = std::env::var("RUST_REALITY_SMOKE_RUNNER").unwrap_or_default();
    let runner_parts: Vec<String> = runner.split_whitespace().map(str::to_owned).collect();
    let emulated = !runner_parts.is_empty();

    let work = tempdir("rust-reality-release-smoke")?;
    let (cover_target, cover_server_name, _cover) = resolve_cover(work.path())?;

    let extract = work.path().join(tier.id);
    std::fs::create_dir_all(&extract)
        .map_err(|error| format!("could not create extract dir: {error}"))?;
    let untar = Tool::new("tar")
        .args(["-xzf"])
        .arg(archive_path.to_string_lossy().into_owned())
        .arg("-C")
        .arg(extract.to_string_lossy().into_owned())
        .probe()
        .map_err(|error| format!("tar extraction failed: {error}"))?;
    if !untar.success() {
        return Err(format!("tar extraction exited with {:?}", untar.code));
    }
    let binary = extract.join("rust-reality");
    if !binary.is_file() {
        return Err(format!("{} archive has no rust-reality", tier.id));
    }

    let run = |args: &[&str]| -> Result<String, String> {
        let mut tool = if emulated {
            let mut base = Tool::new(&runner_parts[0]);
            base = base.args(runner_parts[1..].iter().cloned());
            base.arg(binary.to_string_lossy().into_owned())
        } else {
            Tool::new(binary.to_string_lossy().into_owned())
        };
        tool = tool.args(args.iter().copied());
        let out = tool.probe().map_err(|error| error.to_string())?;
        if !out.success() {
            return Err(format!(
                "{} {:?} exited with {:?}",
                binary.display(),
                args,
                out.code
            ));
        }
        Ok(out.stdout)
    };

    // --version must match exactly.
    let version_line = run(&["--version"])?;
    let expected_version = format!("rust-reality {version}");
    if !version_line.lines().any(|line| line == expected_version) {
        return Err(format!(
            "version mismatch: expected {expected_version:?}, got {version_line:?}"
        ));
    }
    run(&["--help"])?;
    let schema = run(&["schema"])?;
    json_in::parse(&schema).map_err(|error| format!("schema is not valid JSON: {error}"))?;

    let config_dir = extract.join("config");
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| format!("could not create config dir: {error}"))?;
    let config = run(&[
        "config",
        "generate",
        "standalone",
        "--listen",
        "127.0.0.1",
        "--port",
        "19443",
        "--target",
        &cover_target,
        "--server-name",
        &cover_server_name,
    ])?;
    let config_path = config_dir.join("standalone.json");
    std::fs::write(&config_path, &config)
        .map_err(|error| format!("could not write config: {error}"))?;

    run(&["check", "--config", &config_path.to_string_lossy()])?;
    let self_test = run(&["self-test", "--config", &config_path.to_string_lossy()])?;
    validate_self_test(&self_test, &cover_target, &cover_server_name)?;

    Ok(format!("{} packaged binary smoke: PASS", tier.id))
}

/// Validates the self-test report shape and cover identity.
fn validate_self_test(report: &str, target: &str, server_name: &str) -> Result<(), String> {
    let value =
        json_in::parse(report).map_err(|error| format!("self-test is not JSON: {error}"))?;
    if value
        .optional("configuration")
        .and_then(|v| v.as_str("configuration").ok())
        != Some("ok")
    {
        return Err("self-test configuration is not ok".to_owned());
    }
    if value
        .optional("routing")
        .and_then(|v| v.as_str("routing").ok())
        != Some("ok")
    {
        return Err("self-test routing is not ok".to_owned());
    }
    let destinations = value
        .optional("realityDestinations")
        .and_then(|v| v.as_array("realityDestinations").ok())
        .ok_or_else(|| "self-test has no realityDestinations".to_owned())?;
    if destinations.len() != 1 {
        return Err(format!(
            "expected exactly one destination, got {}",
            destinations.len()
        ));
    }
    let destination = &destinations[0];
    if destination
        .optional("compatible")
        .and_then(|v| v.as_bool("compatible").ok())
        != Some(true)
    {
        return Err("destination is not compatible".to_owned());
    }
    if destination
        .optional("target")
        .and_then(|v| v.as_str("target").ok())
        != Some(target)
    {
        return Err(format!("destination target mismatch, expected {target}"));
    }
    if destination
        .optional("serverName")
        .and_then(|v| v.as_str("serverName").ok())
        != Some(server_name)
    {
        return Err(format!(
            "destination serverName mismatch, expected {server_name}"
        ));
    }
    Ok(())
}

/// A running loopback cover process, terminated on drop.
pub struct Cover {
    child: Option<std::process::Child>,
}

impl Drop for Cover {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Resolves the cover target: either the environment override or a fresh loopback
/// `openssl s_server` TLS 1.3 endpoint bound to an ephemeral port.
fn resolve_cover(work: &Path) -> Result<(String, String, Option<Cover>), String> {
    let target = std::env::var("RUST_REALITY_SMOKE_COVER_TARGET").unwrap_or_default();
    let server_name = std::env::var("RUST_REALITY_SMOKE_SERVER_NAME").unwrap_or_default();
    if !target.is_empty() || !server_name.is_empty() {
        if target.is_empty() || server_name.is_empty() {
            return Err(
                "RUST_REALITY_SMOKE_COVER_TARGET and RUST_REALITY_SMOKE_SERVER_NAME must be set together"
                    .to_owned(),
            );
        }
        return Ok((target, server_name, None));
    }
    start_loopback_cover(work)
}

/// Starts a loopback TLS 1.3 cover with `openssl`.
fn start_loopback_cover(work: &Path) -> Result<(String, String, Option<Cover>), String> {
    let cert = work.join("cover.crt");
    let key = work.join("cover.key");
    let cert_gen = Tool::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
        ])
        .arg(key.to_string_lossy().into_owned())
        .arg("-out")
        .arg(cert.to_string_lossy().into_owned())
        .probe()
        .map_err(|error| format!("openssl cert generation failed: {error}"))?;
    if !cert_gen.success() {
        return Err(format!(
            "openssl cert generation exited with {:?}",
            cert_gen.code
        ));
    }

    let port = free_loopback_port()?;
    // openssl s_server on a fixed loopback port, TLS 1.3, accepting connections
    // until killed. -naccept is omitted so the smoke self-test can probe it.
    let child = std::process::Command::new("openssl")
        .args(["s_server", "-tls1_3", "-quiet", "-accept"])
        .arg(port.to_string())
        .arg("-cert")
        .arg(&cert)
        .arg("-key")
        .arg(&key)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("could not start openssl s_server: {error}"))?;

    // Wait briefly for the listener to accept connections.
    wait_for_port(port)?;
    Ok((
        format!("127.0.0.1:{port}"),
        "localhost".to_owned(),
        Some(Cover { child: Some(child) }),
    ))
}

/// Picks a free loopback TCP port by binding to port 0 and releasing it.
fn free_loopback_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("could not reserve a loopback port: {error}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|error| format!("could not read reserved port: {error}"))
}

/// Polls until the loopback port accepts a TCP connection or times out.
fn wait_for_port(port: u16) -> Result<(), String> {
    let address = format!("127.0.0.1:{port}");
    for _ in 0..100 {
        if let Ok(mut stream) = std::net::TcpStream::connect(&address) {
            // Immediately drop; we only needed to confirm the listener is up.
            let mut scratch = [0_u8; 0];
            let _ = stream.read(&mut scratch);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("loopback TLS cover did not become ready".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_self_test_report_is_accepted() {
        let report = r#"{"configuration":"ok","routing":"ok","realityDestinations":[{"compatible":true,"target":"127.0.0.1:9","serverName":"localhost"}]}"#;
        assert!(validate_self_test(report, "127.0.0.1:9", "localhost").is_ok());
    }

    #[test]
    fn a_wrong_destination_count_is_rejected() {
        let report = r#"{"configuration":"ok","routing":"ok","realityDestinations":[]}"#;
        assert!(validate_self_test(report, "127.0.0.1:9", "localhost").is_err());
    }

    #[test]
    fn an_incompatible_destination_is_rejected() {
        let report = r#"{"configuration":"ok","routing":"ok","realityDestinations":[{"compatible":false,"target":"127.0.0.1:9","serverName":"localhost"}]}"#;
        assert!(validate_self_test(report, "127.0.0.1:9", "localhost").is_err());
    }
}
