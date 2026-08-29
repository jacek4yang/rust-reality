//! TLS 1.3 HTTPS origin for Vision-direct style suites.
//!
//! Extends [`crate::bench::origin`] with a self-signed certificate and a
//! TLS-only `ThreadingHTTPServer` so inner traffic is TLS and Vision can reach
//! Direct. Kept as a separate module so the HTTP origin stays minimal.

use std::path::{Path, PathBuf};

use crate::bench::{origin::HttpOrigin, process::Child};

/// Generates a one-day self-signed localhost certificate with openssl.
///
/// # Errors
///
/// Returns a message when openssl is missing or fails.
pub fn generate_self_signed(directory: &Path) -> Result<(PathBuf, PathBuf), String> {
    let key = directory.join("origin.key");
    let cert = directory.join("origin.crt");
    let openssl = which("openssl").ok_or_else(|| "openssl is unavailable".to_owned())?;
    let outcome = crate::process::Tool::new(openssl.display().to_string())
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &key.display().to_string(),
            "-out",
            &cert.display().to_string(),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ])
        .probe()
        .map_err(|error| error.to_string())?;
    if !outcome.success() {
        return Err(format!(
            "openssl exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    Ok((cert, key))
}

/// Launches a TLS 1.3-only HTTPS origin serving `directory` on `port`.
///
/// # Errors
///
/// Returns a message when the server cannot start or the port never becomes ready.
pub fn launch_https(
    directory: &Path,
    payload_name: &str,
    expected_bytes: u64,
    port: u16,
    cert: &Path,
    key: &Path,
    log: &Path,
) -> Result<HttpOrigin, String> {
    let payload = directory.join(payload_name);
    if !payload.is_file() {
        return Err(format!("payload is missing: {}", payload.display()));
    }
    let helper = directory.join("https_origin.py");
    std::fs::write(
        &helper,
        concat!(
            "import functools, http.server, ssl, sys\n",
            "port = int(sys.argv[1]); directory = sys.argv[2]; cert = sys.argv[3]; key = sys.argv[4]\n",
            "handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)\n",
            "server = http.server.ThreadingHTTPServer((\"127.0.0.1\", port), handler)\n",
            "context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n",
            "context.minimum_version = ssl.TLSVersion.TLSv1_3\n",
            "context.maximum_version = ssl.TLSVersion.TLSv1_3\n",
            "context.load_cert_chain(cert, key)\n",
            "server.socket = context.wrap_socket(server.socket, server_side=True)\n",
            "server.serve_forever()\n",
        ),
    )
    .map_err(|error| format!("could not write https helper: {error}"))?;
    let python = which("python3").ok_or_else(|| "python3 is unavailable".to_owned())?;
    let mut child = Child::spawn(
        "https-origin",
        &python,
        &[
            helper.display().to_string(),
            port.to_string(),
            directory.display().to_string(),
            cert.display().to_string(),
            key.display().to_string(),
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

/// Resolves a bare program name against `PATH`.
///
/// A path that already names a directory component is returned unchanged, so
/// callers can pass either an operator-supplied path or a bare command.
pub fn which(program: &str) -> Option<PathBuf> {
    if program.contains(std::path::MAIN_SEPARATOR) {
        return Some(PathBuf::from(program));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_signed_certificate_is_generated() {
        let dir = std::env::temp_dir().join(format!("rr-tls-origin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = generate_self_signed(&dir).expect("openssl");
        assert!(cert.is_file());
        assert!(key.is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
