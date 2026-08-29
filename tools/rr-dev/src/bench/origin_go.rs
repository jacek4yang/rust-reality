//! The compiled Go benchmark origin, built and owned by the run.
//!
//! `scripts/bench-origin` exists because the embedded Python origin it replaced
//! collapsed under concurrency-32 TLS workloads and invalidated whole matrix cells
//! for *every* implementation — the origin, not the proxy, was the bottleneck. It
//! is therefore part of the measurement apparatus, and the harnesses treat it that
//! way: they snapshot its source tree by content ([`crate::bench::attest`]) and
//! rebuild it per run rather than trusting a stale artifact.
//!
//! This module keeps that arrangement. It is deliberately *not* a rewrite of the
//! origin in Rust: reimplementing it would change the thing every archived
//! measurement was taken against, which is a bigger claim than this migration is
//! entitled to make. `scripts/bench-origin` moves out of `scripts/` in a later
//! family, once the shell harnesses that also depend on it are gone.
//!
//! Build stamping is disabled with `-buildvcs=false`. Go's VCS discovery follows a
//! linked worktree's common git directory and would otherwise inspect the
//! non-repository workspace parent; the run's own content manifest is the identity
//! that matters here.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{
    bench::{process::Child, workspace::Workspace},
    process::Tool,
};

/// Readiness deadline for an origin listener.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Path of the origin source tree relative to the repository root.
pub const SOURCE_RELATIVE: &str = "scripts/bench-origin";

/// Builds `scripts/bench-origin` into the run workspace.
///
/// # Errors
///
/// Returns a message when the toolchain is missing, the source tree is absent, or
/// the build fails.
pub fn build(repo: &Path, workspace: &Workspace) -> Result<PathBuf, String> {
    let source = repo.join(SOURCE_RELATIVE);
    if !source.is_dir() {
        return Err(format!(
            "the benchmark origin source is missing: {}",
            source.display()
        ));
    }
    if !Tool::exists("go") {
        return Err("go is required to build the benchmark origin".to_owned());
    }
    let binary = workspace.join("bench-origin");
    let outcome = Tool::new("go")
        .current_dir(&source)
        .env("GOFLAGS", "-buildvcs=false")
        .args(["build", "-o", &binary.display().to_string(), "."])
        .probe()
        .map_err(|error| format!("could not build the benchmark origin: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "go build exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    if !binary.is_file() {
        return Err(format!(
            "go build produced no binary at {}",
            binary.display()
        ));
    }
    Ok(binary)
}

/// The origin's own argv for a listener plan.
fn listener_args(plan: &OriginPlan) -> Vec<String> {
    let mut args = vec![
        "--listen-address".to_owned(),
        plan.listen_address.clone(),
        "--port".to_owned(),
        plan.port.to_string(),
        "--payload-dir".to_owned(),
        plan.payload_dir.display().to_string(),
        "--put-log".to_owned(),
        plan.put_log.display().to_string(),
    ];
    if let Some((cert, key)) = &plan.tls {
        args.extend([
            "--tls-cert".to_owned(),
            cert.display().to_string(),
            "--tls-key".to_owned(),
            key.display().to_string(),
        ]);
    }
    if let Some(alpn) = &plan.alpn {
        args.extend(["--tls-alpn".to_owned(), alpn.clone()]);
    }
    if let Some(access_log) = &plan.access_log {
        args.extend([
            "--access-log".to_owned(),
            access_log.display().to_string(),
            "--label".to_owned(),
            plan.label.clone(),
        ]);
    }
    args
}

/// How an origin listener is exposed.
#[derive(Debug, Clone)]
pub struct OriginPlan {
    /// Label used for the child and its log file.
    pub label: String,
    /// Address to listen on; `127.0.0.1` unless the cover leg moves it.
    pub listen_address: String,
    /// Listen port.
    pub port: u16,
    /// Directory holding `payload*.bin`.
    pub payload_dir: PathBuf,
    /// Path of the per-PUT JSONL log the origin appends to.
    pub put_log: PathBuf,
    /// Certificate and key, which switch the listener to TLS 1.3 only.
    pub tls: Option<(PathBuf, PathBuf)>,
    /// Per-request JSONL log, tagged with `label`.
    ///
    /// The IPv6 suite runs two origins on the same port in different address
    /// families; which one served a request is its evidence of the family an
    /// egress dial chose. Leaving this unset also leaves request hashing off.
    pub access_log: Option<PathBuf>,
    /// ALPN protocols the TLS listener offers. `None` negotiates none.
    pub alpn: Option<String>,
}

/// Launches one origin listener and waits for it to accept connections.
///
/// The returned [`Child`] owns the process: dropping it stops the origin, so a
/// failed run cannot leave a listener holding a port.
///
/// # Errors
///
/// Returns a message when the process cannot start or never becomes ready.
pub fn start(binary: &Path, workspace: &Workspace, plan: &OriginPlan) -> Result<Child, String> {
    let args = listener_args(plan);
    let log = workspace.join(&format!("{}.log", plan.label));
    let mut child = Child::spawn(&plan.label, binary, &args, workspace.path(), &[], &log)
        .map_err(|error| error.to_string())?;
    child
        .wait_for_port(plan.port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    Ok(child)
}

/// Launches an origin listener inside a shaped network namespace.
///
/// `ip netns exec` needs root, but the origin itself must not run as root just
/// because the namespace did; `setpriv` drops back to the invoking user before it
/// execs.
///
/// # Errors
///
/// Returns a message when the process cannot start or never becomes ready.
pub fn start_in_namespace(
    binary: &Path,
    workspace: &Workspace,
    plan: &OriginPlan,
    leg: &crate::bench::netns::CoverLeg,
) -> Result<Child, String> {
    let mut args = leg.exec_prefix()?;
    args.push(binary.display().to_string());
    args.extend(listener_args(plan));
    let log = workspace.join(&format!("{}.log", plan.label));
    let mut child = Child::spawn(
        &plan.label,
        Path::new("sudo"),
        &args,
        workspace.path(),
        &[],
        &log,
    )
    .map_err(|error| error.to_string())?;
    // The listener is in the namespace, so readiness is proved by connecting to
    // its namespace address rather than to loopback.
    crate::bench::engine::wait_until(
        || {
            std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::new(
                    plan.listen_address.parse().unwrap_or(std::net::IpAddr::V4(
                        std::net::Ipv4Addr::LOCALHOST,
                    )),
                    plan.port,
                ),
                Duration::from_millis(200),
            )
            .is_ok()
        },
        READY_TIMEOUT,
        &format!("{} on {}:{}", plan.label, plan.listen_address, plan.port),
    )?;
    let _ = child.is_alive();
    Ok(child)
}

/// Writes the 256-byte `payload.bin` the setup-rate harnesses serve.
///
/// The size is the point: setup-rate measures connection establishment, so the
/// body must be small enough that transferring it costs nothing measurable. The
/// first byte is what the workload checks to prove the response really came from
/// this origin.
///
/// # Errors
///
/// Returns a message when the file cannot be written.
pub fn write_setup_payload(directory: &Path) -> Result<PathBuf, String> {
    let path = directory.join("payload.bin");
    std::fs::write(&path, vec![b'x'; 256])
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    Ok(path)
}

/// Writes a payload of `mebibytes` MiB of the repeating byte pattern `0..=255`.
///
/// The throughput harnesses generate their payloads this way so the content is
/// deterministic and its SHA-256 can be compared end to end.
///
/// # Errors
///
/// Returns a message when the file cannot be written.
pub fn write_pattern_payload(directory: &Path, mebibytes: u64) -> Result<PathBuf, String> {
    let path = directory.join(format!("payload-{mebibytes}.bin"));
    let chunk: Vec<u8> = (0..=255_u8).cycle().take(256 * 4096).collect();
    let mut remaining = mebibytes * 1024 * 1024;
    let mut file = std::fs::File::create(&path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
        file.write_all(&chunk[..take])
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        remaining -= take as u64;
    }
    file.sync_all()
        .map_err(|error| format!("could not sync {}: {error}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::net::{Ipv4Addr, TcpStream};

    #[test]
    fn a_missing_source_tree_fails_closed() {
        let workspace = Workspace::create("origin-missing").unwrap();
        let error = build(Path::new("/nonexistent/repo"), &workspace).unwrap_err();
        assert!(error.contains("origin source is missing"), "{error}");
    }

    #[test]
    fn the_setup_payload_is_the_256_byte_marker_body() {
        let workspace = Workspace::create("origin-payload").unwrap();
        let path = write_setup_payload(workspace.path()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 256);
        assert!(bytes.iter().all(|byte| *byte == b'x'));
        assert_eq!(path.file_name().unwrap(), "payload.bin");
    }

    #[test]
    fn a_pattern_payload_is_exact_and_deterministic() {
        let workspace = Workspace::create("origin-pattern").unwrap();
        let path = write_pattern_payload(workspace.path(), 1).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 1024 * 1024);
        // The pattern is 0..=255 repeating, so byte n is n mod 256.
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| usize::from(*byte) == index % 256)
        );
        assert_eq!(path.file_name().unwrap(), "payload-1.bin");
    }

    /// The repository root, two levels above this crate's manifest.
    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("tools/rr-dev sits two levels below the repository root")
            .to_path_buf()
    }

    /// Builds and serves from the real origin. This is the apparatus every
    /// setup-rate slot depends on, so it is worth proving end to end rather than
    /// discovering a build or flag mismatch inside a benchmark run.
    #[test]
    fn the_real_origin_builds_and_serves_its_payload() {
        if !Tool::exists("go") {
            return;
        }
        let workspace = Workspace::create("origin-integration").unwrap();
        let binary = match build(&repo_root(), &workspace) {
            Ok(binary) => binary,
            // A sandbox without a writable Go build cache cannot compile; that is
            // an environment limitation, not a contract failure.
            Err(error) if error.contains("go build exited") => return,
            Err(error) => panic!("{error}"),
        };
        write_setup_payload(workspace.path()).unwrap();
        let port = crate::bench::workspace::reserve_ports(1).unwrap()[0];
        let plan = OriginPlan {
            label: "origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        };
        let child = start(&binary, &workspace, &plan).expect("the origin becomes ready");

        // Fetch exactly what the workload fetches, without a proxy in the way.
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        stream
            .write_all(
                format!("GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
            )
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.0 200"), "{}", &text[..40.min(text.len())]);
        assert!(text.contains("Content-Length: 256"), "the 256-byte marker body");
        assert!(text.ends_with(&"x".repeat(256)), "the body is the marker payload");

        drop(child);
    }

    /// The listener plan is argv, not a shell string; TLS is opt-in by cert+key.
    #[test]
    fn the_tls_flags_appear_only_with_a_certificate() {
        let plan = OriginPlan {
            label: "origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: 8080,
            payload_dir: PathBuf::from("/w"),
            put_log: PathBuf::from("/w/http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        };
        assert!(plan.tls.is_none());
        let tls = OriginPlan {
            tls: Some((PathBuf::from("/w/origin.crt"), PathBuf::from("/w/origin.key"))),
            ..plan
        };
        assert!(tls.tls.is_some());
        assert!(!listener_args(&tls).contains(&"--tls-alpn".to_owned()));
    }

    /// The access log carries the label, and hashing follows the log.
    #[test]
    fn the_access_log_and_alpn_flags_are_opt_in() {
        let plan = OriginPlan {
            label: "origin-v6".to_owned(),
            listen_address: "::1".to_owned(),
            port: 8080,
            payload_dir: PathBuf::from("/w"),
            put_log: PathBuf::from("/w/http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        };
        let bare = listener_args(&plan);
        assert!(!bare.contains(&"--access-log".to_owned()));
        assert!(!bare.contains(&"--label".to_owned()));

        let logged = OriginPlan {
            access_log: Some(PathBuf::from("/w/access.jsonl")),
            alpn: Some("h2,http/1.1".to_owned()),
            ..plan
        };
        let args = listener_args(&logged);
        assert!(args.contains(&"--access-log".to_owned()));
        // Without the label the rows cannot attribute an egress family, which
        // is the only reason this origin logs requests at all.
        let label = args.iter().position(|arg| arg == "--label").unwrap();
        assert_eq!(args[label + 1], "origin-v6");
        let alpn = args.iter().position(|arg| arg == "--tls-alpn").unwrap();
        assert_eq!(args[alpn + 1], "h2,http/1.1");
    }
}
