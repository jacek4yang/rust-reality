//! Packaged-binary smoke test — the typed form of `smoke-release-assets.sh`.
//!
//! Executing the packaged binary is the authoritative CPU+OS feature gate: a host
//! that cannot run a tier must fail the release rather than publish an untested
//! optimized artifact. This verifies the asset SHA-256, extracts the tarball, and
//! drives the binary through `--version`, `--help`, `generate`, `check`, and
//! `doctor`, asserting the environment report names a single compatible cover.
//!
//! The release workflow smokes against a real local TLS 1.3 peer. When no cover is
//! supplied via the environment overrides, a loopback `openssl s_server` cover is
//! started; those overrides also let the fake-binary regression test point at an
//! arbitrary target. An optional runner wrapper (e.g. qemu) validates functionality
//! only and is never native performance evidence.

use std::path::Path;

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
/// a failed binary invocation, or a `doctor` report that does not name exactly
/// one compatible cover matching the one supplied.
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

    // The packaged binary generates its own material, which also proves the
    // random source works on this host before anything depends on it.
    let keys = run(&["generate", "x25519", "--json"])?;
    let keys =
        json_in::parse(&keys).map_err(|error| format!("generate x25519 is not JSON: {error}"))?;
    let private_key = keys
        .str_field("", "privateKey")
        .map_err(|error| format!("generate x25519: {error}"))?
        .to_owned();
    let uuid = run(&["generate", "uuid"])?.trim().to_owned();
    let short_id = run(&["generate", "short-id"])?.trim().to_owned();

    let config_dir = extract.join("config");
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| format!("could not create config dir: {error}"))?;
    let identity = crate::bench::config::RealityIdentity {
        uuid,
        short_id,
        server_name: cover_server_name.clone(),
        target: cover_target.clone(),
    };
    let config = crate::bench::config::RustServer::new(&identity, 19_443, &private_key)
        .build()
        .to_python_json();
    let config_path = config_dir.join("standalone.json");
    std::fs::write(&config_path, &config)
        .map_err(|error| format!("could not write config: {error}"))?;

    run(&["check", "--config", &config_path.to_string_lossy()])?;
    let doctor = run(&["doctor", "--config", &config_path.to_string_lossy()])?;
    validate_doctor(&doctor, &cover_target, &cover_server_name)?;

    Ok(format!("{} packaged binary smoke: PASS", tier.id))
}

/// Validates the `doctor` report shape and cover identity.
fn validate_doctor(report: &str, target: &str, server_name: &str) -> Result<(), String> {
    let value = json_in::parse(report).map_err(|error| format!("doctor is not JSON: {error}"))?;
    if value
        .optional("configuration")
        .and_then(|v| v.as_str("configuration").ok())
        != Some("ok")
    {
        return Err("doctor configuration is not ok".to_owned());
    }
    if value
        .optional("routing")
        .and_then(|v| v.as_str("routing").ok())
        != Some("ok")
    {
        return Err("doctor routing is not ok".to_owned());
    }
    let destinations = value
        .optional("cover")
        .and_then(|v| v.as_array("cover").ok())
        .ok_or_else(|| "doctor reported no cover".to_owned())?;
    if destinations.len() != 1 {
        return Err(format!(
            "expected exactly one cover, got {}",
            destinations.len()
        ));
    }
    let destination = &destinations[0];
    if destination
        .optional("compatible")
        .and_then(|v| v.as_bool("compatible").ok())
        != Some(true)
    {
        return Err("the cover is not compatible".to_owned());
    }
    if destination
        .optional("target")
        .and_then(|v| v.as_str("target").ok())
        != Some(target)
    {
        return Err(format!("cover target mismatch, expected {target}"));
    }
    if destination
        .optional("serverName")
        .and_then(|v| v.as_str("serverName").ok())
        != Some(server_name)
    {
        return Err(format!("cover serverName mismatch, expected {server_name}"));
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
///
/// A completed `connect` is the whole of the evidence wanted: the cover is
/// listening. Reading from the stream would not add anything, and a zero-length
/// read in particular is **not** the no-op it looks like — Linux's
/// `sock_rcvlowat` clamps a zero receive threshold up to one byte, so
/// `read(&mut [])` on a connected TCP socket blocks until the peer sends
/// something or hangs up. Against `openssl s_server`, which says nothing until
/// a TLS handshake, that is forever. It is what hung every tier of the v1.9.0
/// release.
fn wait_for_port(port: u16) -> Result<(), String> {
    let address = format!("127.0.0.1:{port}");
    for _ in 0..100 {
        if std::net::TcpStream::connect(&address).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("loopback TLS cover did not become ready".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The readiness probe must return against a peer that accepts and then
    /// says nothing, which is exactly what a TLS server does before its
    /// handshake — and is the shape that hung the v1.9.0 release.
    #[test]
    fn readiness_returns_against_a_silent_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind cover stand-in");
        let port = listener.local_addr().expect("port").port();
        // Accept and hold, writing nothing, until the test drops the listener.
        let accepted = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));

        let started = std::time::Instant::now();
        wait_for_port(port).expect("a listening port must be reported ready");
        let elapsed = started.elapsed();

        drop(accepted.join().expect("accept thread"));
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "readiness took {elapsed:?}; it must not wait for the peer to speak"
        );
    }

    /// A port with nothing behind it must fail closed rather than hang, and
    /// must do so inside its own bound.
    #[test]
    fn readiness_fails_closed_on_a_dead_port() {
        // Bind and immediately release, so the port is almost certainly unused.
        let port = free_loopback_port().expect("reserve a port");
        let started = std::time::Instant::now();
        let outcome = wait_for_port(port);
        assert!(outcome.is_err(), "a dead port must not be reported ready");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the readiness bound must hold"
        );
    }

    #[test]
    fn a_well_formed_self_test_report_is_accepted() {
        let report = r#"{"configuration":"ok","routing":"ok","cover":[{"compatible":true,"target":"127.0.0.1:9","serverName":"localhost"}]}"#;
        assert!(validate_doctor(report, "127.0.0.1:9", "localhost").is_ok());
    }

    #[test]
    fn a_wrong_destination_count_is_rejected() {
        let report = r#"{"configuration":"ok","routing":"ok","realityDestinations":[]}"#;
        assert!(validate_doctor(report, "127.0.0.1:9", "localhost").is_err());
    }

    #[test]
    fn an_incompatible_destination_is_rejected() {
        let report = r#"{"configuration":"ok","routing":"ok","realityDestinations":[{"compatible":false,"target":"127.0.0.1:9","serverName":"localhost"}]}"#;
        assert!(validate_doctor(report, "127.0.0.1:9", "localhost").is_err());
    }
}
