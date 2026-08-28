//! Loopback HTTP origin for benchmark suites that do not need WAN egress.
//!
//! `benchmark-xray.sh` and siblings serve a deterministic payload from a
//! loopback `python3 -m http.server` so the measurement stays on one host.
//! This module owns that origin as an RAII child: write the payload, launch
//! the server, wait for readiness, and tear it down with the rest of the run.
//!
//! Prefer this over a custom Rust HTTP server: the legacy evidence path used
//! the stdlib server, and the measurement contracts the payload integrity and
//! byte counts, not the origin implementation.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::bench::process::Child;

/// A loopback HTTP origin serving one payload file, owned by RAII.
#[derive(Debug)]
pub struct HttpOrigin {
    /// The child process running the HTTP server.
    pub child: Child,
    /// The loopback port the server listens on.
    pub port: u16,
    /// Absolute path of the payload file being served.
    pub payload: PathBuf,
    /// Expected payload size in bytes.
    pub expected_bytes: u64,
}

impl HttpOrigin {
    /// The URL a SOCKS client should download.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/{}",
            self.port,
            self.payload
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("payload.bin")
        )
    }
}

/// Writes a deterministic `size` byte payload at `path`.
///
/// The pattern matches the legacy script: a 1 MiB repeating `0..=255` chunk
/// written until the requested size is reached. Exact length is the integrity
/// contract the transfer checks against.
///
/// # Errors
///
/// Returns a message when the file cannot be written.
pub fn write_payload(path: &Path, size: u64) -> Result<(), String> {
    let chunk: Vec<u8> = (0u8..=255).cycle().take(256 * 4096).collect();
    let mut remaining = size;
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("could not create payload {}: {error}", path.display()))?;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
        file.write_all(&chunk[..take])
            .map_err(|error| format!("could not write payload {}: {error}", path.display()))?;
        remaining -= take as u64;
    }
    Ok(())
}

/// Launches a loopback HTTP origin serving `directory` on `port`.
///
/// Uses `python3 -m http.server` with typed argv (no shell), matching the
/// legacy harness. The returned [`HttpOrigin`] terminates the server on drop.
///
/// # Errors
///
/// Returns a message when the server cannot start or the port never becomes ready.
pub fn launch(
    directory: &Path,
    payload_name: &str,
    expected_bytes: u64,
    port: u16,
    log: &Path,
) -> Result<HttpOrigin, String> {
    let payload = directory.join(payload_name);
    if !payload.is_file() {
        return Err(format!("payload is missing: {}", payload.display()));
    }
    let python = which("python3").ok_or_else(|| "python3 is unavailable".to_owned())?;
    let mut child = Child::spawn(
        "http-origin",
        &python,
        &[
            "-m".to_owned(),
            "http.server".to_owned(),
            port.to_string(),
            "--bind".to_owned(),
            "127.0.0.1".to_owned(),
            "--directory".to_owned(),
            directory.display().to_string(),
        ],
        directory,
        &[],
        log,
    )
    .map_err(|error| error.to_string())?;
    child
        .wait_for_port(port, std::time::Duration::from_secs(10))
        .map_err(|error| error.to_string())?;
    Ok(HttpOrigin {
        child,
        port,
        payload,
        expected_bytes,
    })
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_has_the_exact_requested_size() {
        let dir = std::env::temp_dir().join(format!("rr-origin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        write_payload(&path, 12_345).expect("write");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 12_345);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_loopback_origin_serves_the_payload_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("rr-origin-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let payload = dir.join("payload.bin");
        write_payload(&payload, 4096).expect("write");
        let ports = crate::bench::workspace::reserve_ports(1).expect("port");
        let log = dir.join("http.log");
        let origin = launch(&dir, "payload.bin", 4096, ports[0], &log).expect("launch");
        let url = origin.url();
        let outcome = crate::process::Tool::new("curl")
            .args([
                "--fail",
                "--silent",
                "--max-time",
                "5",
                "--output",
                "/dev/null",
                "--write-out",
                "%{size_download}",
                &url,
            ])
            .probe()
            .expect("curl");
        assert!(outcome.success(), "{}", outcome.stderr);
        assert_eq!(outcome.trimmed_stdout(), "4096");
        let pid = origin.child.pid();
        drop(origin);
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            crate::bench::process::proc_starttime(pid).is_none(),
            "the origin must not survive drop"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
