//! The native benchmark origin process, owned by the run.
//!
//! The origin must remain a separate process: if the high-concurrency HTTP/TLS
//! measurement apparatus wedges, the suite must be able to terminate it without
//! affecting its own control plane. The hidden `bench origin` child is embedded in
//! the same attested `rr-dev` executable as the harness, and [`Child`] owns its
//! lifetime. Its wire contract lives in [`crate::bench::origin_server`].

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bench::{process::Child, workspace::Workspace};

/// Readiness deadline for an origin listener.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolves the current `rr-dev` executable for the origin child.
///
/// # Errors
///
/// Returns a message when the operating system cannot resolve the executable.
pub fn executable() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map_err(|error| format!("could not resolve the rr-dev executable: {error}"))
}

/// The origin's own argv for a listener plan.
pub(crate) fn listener_args(plan: &OriginPlan) -> Vec<String> {
    let mut args = vec![
        "bench".to_owned(),
        "origin".to_owned(),
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
    let address = format_socket_address(&plan.listen_address, plan.port)?;
    child
        .wait_for_address(address, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    Ok(child)
}

/// Parses a numeric listener address into the socket the readiness probe uses.
fn format_socket_address(address: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let ip = address
        .parse::<std::net::IpAddr>()
        .map_err(|error| format!("origin listen address {address:?} is not numeric: {error}"))?;
    Ok(std::net::SocketAddr::new(ip, port))
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
                    plan.listen_address
                        .parse()
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
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
        assert_eq!(&listener_args(&plan)[..2], ["bench", "origin"]);
        assert!(plan.tls.is_none());
        let tls = OriginPlan {
            tls: Some((
                PathBuf::from("/w/origin.crt"),
                PathBuf::from("/w/origin.key"),
            )),
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
