//! Interoperability gates: does an unmodified Xray actually talk to us?
//!
//! This is not a benchmark. It asks a yes/no question that a performance number
//! cannot answer: an unmodified Xray client, configured exactly as a user would
//! configure it, must complete a VLESS + REALITY + Vision session against
//! rust-reality and get its bytes back unaltered.
//!
//! The gate once also compared both implementations' ML-DSA-65 verification
//! keys derived from one seed. That check went with the command behind it:
//! ML-DSA had no configuration field and no consumer in the protocol stack, so
//! `rust-reality mldsa65` and the dependency implementing it were removed. A
//! differential over a scheme this project does not use was measuring
//! agreement about nothing.

use std::path::Path;

use crate::{hash, perf::json_out::Json, process::Tool};

/// What the interoperability gate reports.
#[derive(Debug, Clone)]
pub struct InteropReport {
    /// The Xray version line the gate ran against.
    pub xray_version: String,
    /// Bytes retrieved through the tunnel.
    pub local_bytes: u64,
    /// The digest of what came back.
    pub local_sha256: String,
    /// The Internet reachability line, or `skipped`.
    pub internet: String,
}

impl InteropReport {
    /// Renders `report.json`.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("pass", Json::Bool(true)),
            ("xrayVersion", Json::string(self.xray_version.clone())),
            (
                "localBytes",
                Json::Int(i64::try_from(self.local_bytes).unwrap_or(i64::MAX)),
            ),
            ("localSha256", Json::string(self.local_sha256.clone())),
            ("internet", Json::string(self.internet.clone())),
        ])
    }
}

/// The digest of an agreed verification key, as the report records it.
#[must_use]
pub fn verify_digest(key: &str) -> String {
    hash::sha256_hex(key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_records_what_the_gate_proved() {
        let report = InteropReport {
            xray_version: "Xray 26.7.28".to_owned(),
            local_bytes: 1_048_576,
            local_sha256: "a".repeat(64),
            internet: "http=200 connect=0.01".to_owned(),
        };
        let rendered = report.to_json().to_python_json();
        assert!(rendered.contains("\"pass\": true"));
        assert!(rendered.contains("\"localBytes\": 1048576"));
        assert!(rendered.contains("Xray 26.7.28"));
        assert!(rendered.contains("http=200"));
    }

    #[test]
    fn a_verification_key_digest_is_stable() {
        let first = verify_digest("THE-KEY");
        assert_eq!(first.len(), 64);
        assert_eq!(first, verify_digest("THE-KEY"));
        assert_ne!(first, verify_digest("OTHER-KEY"));
    }
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Everything the Xray interoperability gate needs.
#[derive(Debug, Clone)]
pub struct InteropSuite {
    /// Repository root, for the Go origin.
    pub repo: std::path::PathBuf,
    /// The rust-reality binary under test.
    pub rust_bin: std::path::PathBuf,
    /// The unmodified Xray that must interoperate with it.
    pub xray_bin: std::path::PathBuf,
    /// Output directory; must not already exist.
    pub out_dir: std::path::PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// The REALITY cover target.
    pub cover_target: String,
    /// The REALITY cover SNI.
    pub cover_sni: String,
    /// A URL fetched through the tunnel to prove real reachability.
    pub internet_url: Option<String>,
}

/// Validates the gate's parameters.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(suite: &InteropSuite) -> Result<(), String> {
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if suite.cover_target.is_empty() || suite.cover_sni.is_empty() {
        return Err("a REALITY cover target and SNI are required".to_owned());
    }
    Ok(())
}

/// Runs the Xray interoperability gate.
///
/// # Errors
///
/// Returns the first failure. A transfer that comes back with the wrong digest,
/// or an ML-DSA key disagreement, is a gate failure rather than a slow result.
pub fn run(suite: &InteropSuite) -> Result<InteropReport, String> {
    use crate::bench::{
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        origin_go,
        workspace::Workspace,
    };

    validate(suite)?;
    for program in ["curl"] {
        if !Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    let rust = identity::register("rust-reality", &suite.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("test-xray-interop")?;

    let port_base = crate::bench::workspace::reserve_block(3)?;
    let (origin_port, server_port, socks_port) = (port_base, port_base + 1, port_base + 2);

    // One MiB of the repeating 0..=255 pattern, which is what the gate compares.
    let payload = origin_go::write_pattern_payload(workspace.path(), 1)?;
    let expected_sha = hash::sha256_file(&payload)?;
    let origin_binary = origin_go::executable()?;
    let _origin = origin_go::start(
        &origin_binary,
        &workspace,
        &origin_go::OriginPlan {
            label: "origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;

    let (_server, _client) =
        start_tunnel(suite, &workspace, &rust, &xray, server_port, socks_port)?;

    let downloaded = workspace.join("download.bin");
    fetch_payload(socks_port, origin_port, &downloaded)?;
    let observed_sha = hash::sha256_file(&downloaded)?;
    if observed_sha != expected_sha {
        return Err("local Xray interoperability payload hash mismatch".to_owned());
    }
    let local_bytes = std::fs::metadata(&downloaded)
        .map_err(|error| format!("could not stat the download: {error}"))?
        .len();

    let internet = match &suite.internet_url {
        None => "skipped".to_owned(),
        Some(url) => fetch_internet(socks_port, url)?,
    };
    let report = InteropReport {
        xray_version: xray.identity.clone(),
        local_bytes,
        local_sha256: observed_sha,
        internet,
    };
    let document = report.to_json().to_python_json();
    run.write_new("report.json", &document)?;
    run.publish(
        Publication::Environment,
        &document,
        &suite.run_id,
        "test-xray-interop",
    )?;
    Ok(report)
}

/// Starts the rust-reality server and the unmodified Xray client in front of it.
fn start_tunnel(
    suite: &InteropSuite,
    workspace: &crate::bench::workspace::Workspace,
    rust: &crate::bench::identity::Binary,
    xray: &crate::bench::identity::Binary,
    server_port: u16,
    socks_port: u16,
) -> Result<(crate::bench::process::Child, crate::bench::process::Child), String> {
    use crate::bench::{config::RealityIdentity, process::Child, suites};
    let generated = suites::generate_rust_identity(
        workspace,
        &rust.path,
        server_port,
        &suite.cover_target,
        &suite.cover_sni,
        Some(&workspace.join("generate.log")),
    )?;
    let server_path = workspace.join("server.json");
    std::fs::write(&server_path, &generated.server_json)
        .map_err(|error| format!("could not write {}: {error}", server_path.display()))?;
    let mut server = Child::spawn(
        "rust-server",
        &rust.path,
        &[
            "run".to_owned(),
            "--config".to_owned(),
            server_path.display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join("rust.log"),
    )
    .map_err(|error| error.to_string())?;

    let identity = RealityIdentity {
        uuid: generated.uuid.clone(),
        short_id: generated.short_id.clone(),
        server_name: suite.cover_sni.clone(),
        target: suite.cover_target.clone(),
    };
    let client_path = workspace.join("xray.json");
    std::fs::write(
        &client_path,
        crate::bench::config::xray_client(
            &identity,
            server_port,
            socks_port,
            &generated.public_key,
        )
        .to_python_json(),
    )
    .map_err(|error| format!("could not write {}: {error}", client_path.display()))?;
    let mut client = Child::spawn(
        "xray-client",
        &xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_path.display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join("xray.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, std::time::Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, std::time::Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    Ok((server, client))
}

/// Downloads the payload through the tunnel into `destination`.
///
/// # Errors
///
/// Returns the curl failure.
pub fn fetch_payload(socks_port: u16, origin_port: u16, destination: &Path) -> Result<(), String> {
    let outcome = clean_curl()
        .args([
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{socks_port}"),
            "--max-time".to_owned(),
            "30".to_owned(),
            "--output".to_owned(),
            destination.display().to_string(),
            format!("http://127.0.0.1:{origin_port}/payload-1.bin"),
        ])
        .probe()
        .map_err(|error| format!("could not run curl: {error}"))?;
    if outcome.success() {
        return Ok(());
    }
    Err(format!(
        "local Xray interoperability test failed: curl exited {:?}: {}",
        outcome.code,
        outcome.stderr.trim_end()
    ))
}

/// Fetches a real URL through the tunnel and returns curl's timing line.
fn fetch_internet(socks_port: u16, url: &str) -> Result<String, String> {
    let outcome = clean_curl()
        .args([
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{socks_port}"),
            "--max-time".to_owned(),
            "30".to_owned(),
            "--output".to_owned(),
            "/dev/null".to_owned(),
            "--write-out".to_owned(),
            "http=%{http_code} connect=%{time_connect} start=%{time_starttransfer} total=%{time_total}"
                .to_owned(),
            url.to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not run curl: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "Internet reachability through the tunnel failed: curl exited {:?}",
            outcome.code
        ));
    }
    Ok(outcome.trimmed_stdout().to_owned())
}

/// A curl with every proxy variable stripped.
fn clean_curl() -> Tool {
    let mut curl = Tool::new("curl");
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        curl = curl.env(name, "");
    }
    curl
}
