//! The no-CCS interoperability gate.
//!
//! TLS 1.3 lets a server skip the middlebox-compatibility `ChangeCipherSpec`, and
//! a compliant peer must cope. REALITY relays its cover target's handshake, so a
//! cover that omits the CCS is a real interoperability hazard rather than a
//! theoretical one: if rust-reality assumed the record were always present, this
//! is where it would break, and it would break only against the minority of real
//! servers that omit it.
//!
//! The gate builds exactly that peer with `openssl s_server -tls1_3
//! -no_middlebox`, points a REALITY server at it, and drives a full session
//! through an unmodified Xray client.
//!
//! ## Two details that are easy to get wrong
//!
//! The trust root is injected into the rust-reality child alone, through its
//! environment, and never exported. A sibling process inheriting a private test
//! CA would be a real weakening of the host's trust configuration for the
//! lifetime of the run.
//!
//! And the CCS assertion reads only *server-direction* lines. OpenSSL's trace
//! shows both directions; the client's own CCS is expected and irrelevant, so an
//! assertion that ignored direction would fail every run for the wrong reason.

use std::path::Path;

use crate::{hash, perf::json_out::Json, process::Tool};

/// The OpenSSL version this gate is validated against.
///
/// Pinned rather than accepting whatever is on `PATH`: `-no_middlebox` and the
/// trace format are both version-sensitive, and a silent upgrade would change
/// what the gate proves without changing what it says.
pub const REQUIRED_OPENSSL_PREFIX: &str = "OpenSSL 3.5.6 ";

/// Checks an OpenSSL trace for the handshake shape the gate requires.
///
/// The server must have sent a `ServerHello`, proving the handshake actually
/// happened, and must **not** have sent a `ChangeCipherSpec`, proving
/// `-no_middlebox` did what it claims. Only server-direction (`>>>`) lines are
/// considered: the client's CCS is expected and says nothing about the server.
///
/// # Errors
///
/// Returns a message naming which expectation failed.
pub fn assert_no_server_ccs(trace: &str) -> Result<(), String> {
    let server_lines: Vec<&str> = trace
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with(">>> "))
        .collect();
    if !server_lines.iter().any(|line| line.contains("ServerHello")) {
        return Err("OpenSSL trace has no server-direction ServerHello".to_owned());
    }
    if server_lines
        .iter()
        .any(|line| line.contains("ChangeCipherSpec"))
    {
        return Err("OpenSSL -no_middlebox emitted a server-direction ChangeCipherSpec".to_owned());
    }
    Ok(())
}

/// Confirms the OpenSSL build is the one this gate was validated against.
///
/// # Errors
///
/// Returns a message naming the version found.
pub fn check_openssl_version(identity: &str) -> Result<String, String> {
    let version = identity.lines().next().unwrap_or_default().to_owned();
    if version.starts_with(REQUIRED_OPENSSL_PREFIX) {
        return Ok(version);
    }
    Err(format!(
        "OPENSSL_BIN must be the validated {REQUIRED_OPENSSL_PREFIX}build, got: {version}"
    ))
}

/// The certificate material the cover server presents.
#[derive(Debug, Clone)]
pub struct CoverCertificate {
    /// The ephemeral CA certificate, trusted only by the rust-reality child.
    pub ca_certificate: std::path::PathBuf,
    /// The leaf certificate.
    pub certificate: std::path::PathBuf,
    /// The leaf private key.
    pub key: std::path::PathBuf,
    /// The leaf's `subjectAltName` extension text, as recorded evidence.
    pub subject_alt_name: String,
}

/// Builds an ephemeral CA and a SAN-bearing leaf for `localhost`.
///
/// Both SANs matter: REALITY dials the cover by name, and some paths verify by
/// address, so a leaf missing either would fail for a reason unrelated to the CCS
/// question the gate exists to answer.
///
/// # Errors
///
/// Returns the first OpenSSL failure, or a message when a required SAN is absent.
pub fn build_cover_certificate(
    openssl_bin: &Path,
    directory: &Path,
    run_id: &str,
) -> Result<CoverCertificate, String> {
    let path = |name: &str| directory.join(name).display().to_string();
    let run = |args: Vec<String>| openssl(openssl_bin, &args);

    run(owned(&[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
        "-subj", &format!("/CN=rust-reality no-CCS test CA {run_id}"),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", &path("ca.key"), "-out", &path("ca.crt"),
    ]))?;

    run(owned(&[
        "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-subj", "/CN=localhost",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", &path("server.key"), "-out", &path("server.csr"),
    ]))?;

    run(owned(&[
        "x509", "-req", "-sha256", "-days", "1",
        "-in", &path("server.csr"),
        "-CA", &path("ca.crt"), "-CAkey", &path("ca.key"),
        "-CAcreateserial", "-copy_extensions", "copy",
        "-out", &path("server.crt"),
    ]))?;

    run(owned(&[
        "verify", "-CAfile", &path("ca.crt"),
        "-verify_hostname", "localhost", &path("server.crt"),
    ]))?;

    let subject_alt_name = run(owned(&[
        "x509", "-in", &path("server.crt"), "-noout", "-ext", "subjectAltName",
    ]))?;
    check_subject_alt_name(&subject_alt_name)?;

    Ok(CoverCertificate {
        ca_certificate: directory.join("ca.crt"),
        certificate: directory.join("server.crt"),
        key: directory.join("server.key"),
        subject_alt_name,
    })
}

/// Borrows a slice of string slices into owned arguments.
fn owned(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

/// Runs one `openssl` invocation, returning its stdout.
fn openssl(openssl_bin: &Path, args: &[String]) -> Result<String, String> {
    let outcome = Tool::new(openssl_bin.display().to_string())
        .args(args.to_vec())
        .probe()
        .map_err(|error| format!("openssl {} failed: {error}", args.join(" ")))?;
    if !outcome.success() {
        return Err(format!(
            "openssl {} exited {:?}: {}",
            args.join(" "),
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    Ok(outcome.trimmed_stdout().to_owned())
}

/// Requires both the DNS and the IP SAN on the cover leaf.
///
/// # Errors
///
/// Returns a message naming the missing entry.
pub fn check_subject_alt_name(text: &str) -> Result<(), String> {
    if !text.contains("DNS:localhost") {
        return Err("server certificate is missing DNS:localhost SAN".to_owned());
    }
    if !text.contains("IP Address:127.0.0.1") {
        return Err("server certificate is missing IP:127.0.0.1 SAN".to_owned());
    }
    Ok(())
}

/// The `openssl s_server` argv the gate runs as its cover target.
///
/// `-no_middlebox` is the whole point; `-trace -msg -state` is what makes the
/// absence of a server CCS observable rather than merely asserted.
#[must_use]
pub fn cover_server_args(port: u16, certificate: &CoverCertificate) -> Vec<String> {
    vec![
        "s_server".to_owned(),
        "-accept".to_owned(),
        format!("127.0.0.1:{port}"),
        "-www".to_owned(),
        "-ign_eof".to_owned(),
        "-cert".to_owned(),
        certificate.certificate.display().to_string(),
        "-key".to_owned(),
        certificate.key.display().to_string(),
        "-CAfile".to_owned(),
        certificate.ca_certificate.display().to_string(),
        "-tls1_3".to_owned(),
        "-no_middlebox".to_owned(),
        "-alpn".to_owned(),
        "h2,http/1.1".to_owned(),
        "-trace".to_owned(),
        "-msg".to_owned(),
        "-state".to_owned(),
    ]
}

/// The gate's `summary.json`.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "these are exactly the fields the recorded summary carries"
)]
pub fn summary_json(
    run_id: &str,
    rust: &crate::bench::identity::Binary,
    xray: &crate::bench::identity::Binary,
    openssl_path: &Path,
    openssl_identity: &str,
    ports: [u16; 4],
    payload_sha256: &str,
    mldsa_sha256: &str,
) -> Json {
    let binary = |bin: &crate::bench::identity::Binary| {
        Json::object([
            ("path", Json::string(bin.path.display().to_string())),
            ("sha256", Json::string(bin.sha256.clone())),
            ("immutableDuringRun", Json::Bool(true)),
        ])
    };
    Json::object([
        ("schemaVersion", Json::Int(1)),
        ("runId", Json::string(run_id)),
        ("rustReality", binary(rust)),
        ("xray", binary(xray)),
        (
            "openssl",
            Json::object([
                ("path", Json::string(openssl_path.display().to_string())),
                (
                    "version",
                    Json::string(openssl_identity.lines().next().unwrap_or_default()),
                ),
                ("tls", Json::string("1.3")),
                ("middlebox", Json::Bool(false)),
                (
                    "alpn",
                    Json::Array(vec![Json::string("h2"), Json::string("http/1.1")]),
                ),
            ]),
        ),
        (
            "topology",
            Json::object([
                ("address", Json::string("127.0.0.1")),
                (
                    "ports",
                    Json::object([
                        ("cover", Json::Int(i64::from(ports[0]))),
                        ("reality", Json::Int(i64::from(ports[1]))),
                        ("socks", Json::Int(i64::from(ports[2]))),
                        ("origin", Json::Int(i64::from(ports[3]))),
                    ]),
                ),
            ]),
        ),
        (
            "certificate",
            Json::object([
                ("authority", Json::string("ephemeral self-signed CA")),
                (
                    "leafSan",
                    Json::Array(vec![
                        Json::string("DNS:localhost"),
                        Json::string("IP:127.0.0.1"),
                    ]),
                ),
                (
                    "trustInjection",
                    Json::string("rust-reality child SSL_CERT_FILE only"),
                ),
            ]),
        ),
        (
            "assertions",
            Json::object([
                ("serverHello", Json::Bool(true)),
                ("serverChangeCipherSpec", Json::Bool(false)),
                ("payloadBytes", Json::Int(1_048_576)),
                ("payloadSha256", Json::string(payload_sha256)),
                ("mldsa65VerifySha256", Json::string(mldsa_sha256)),
            ]),
        ),
        ("trace", Json::string("openssl-trace.log")),
        ("ok", Json::Bool(true)),
    ])
}

/// Re-hashes a binary and confirms it did not change during the run.
///
/// # Errors
///
/// Returns a message naming the binary that changed.
pub fn assert_unchanged(binary: &crate::bench::identity::Binary) -> Result<(), String> {
    let observed = hash::sha256_file(&binary.path)?;
    if observed == binary.sha256 {
        return Ok(());
    }
    Err(format!("{} changed during the run", binary.label))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `-no_middlebox` trace: the server sends a `ServerHello` and no CCS,
    /// while the *client* still sends one, which the assertion must ignore.
    const NO_MIDDLEBOX_TRACE: &str = "\
        >>> TLS 1.3, Handshake [length 0059], ServerHello\n\
        <<< TLS 1.2, ChangeCipherSpec [length 0001]\n\
        >>> TLS 1.3, Handshake [length 0019], EncryptedExtensions\n\
        >>> TLS 1.3, Handshake [length 0034], Finished\n";

    /// The same handshake with middlebox compatibility left on.
    const MIDDLEBOX_TRACE: &str = "\
        >>> TLS 1.3, Handshake [length 0059], ServerHello\n\
        >>> TLS 1.2, ChangeCipherSpec [length 0001]\n\
        >>> TLS 1.3, Handshake [length 0034], Finished\n";

    /// The client's own CCS is expected and says nothing about the server, so an
    /// assertion that ignored direction would fail every run for the wrong reason.
    #[test]
    fn only_server_direction_lines_count() {
        assert_no_server_ccs(NO_MIDDLEBOX_TRACE).expect("a client CCS is irrelevant");
        let error = assert_no_server_ccs(MIDDLEBOX_TRACE).unwrap_err();
        assert!(error.contains("server-direction ChangeCipherSpec"), "{error}");
    }

    /// A trace with no `ServerHello` means the handshake never happened, so an
    /// absent CCS proves nothing.
    #[test]
    fn a_handshake_that_never_happened_is_not_a_pass() {
        let error = assert_no_server_ccs("<<< TLS 1.3, Handshake, ClientHello\n").unwrap_err();
        assert!(error.contains("no server-direction ServerHello"), "{error}");
        assert!(assert_no_server_ccs("").is_err());
    }

    /// Leading whitespace is normal in OpenSSL traces.
    #[test]
    fn indented_trace_lines_are_recognised() {
        let indented = "    >>> TLS 1.3, Handshake [length 0059], ServerHello\n";
        assert_no_server_ccs(indented).expect("indentation must not hide a line");
    }

    #[test]
    fn the_openssl_version_is_pinned() {
        let identity = "OpenSSL 3.5.6 7 Apr 2026\nbuilt on: ...\n";
        assert_eq!(
            check_openssl_version(identity).unwrap(),
            "OpenSSL 3.5.6 7 Apr 2026"
        );
        let error = check_openssl_version("OpenSSL 3.4.0 1 Jan 2025\n").unwrap_err();
        assert!(error.contains("3.5.6"), "{error}");
        assert!(check_openssl_version("").is_err());
    }

    /// Both SANs matter: REALITY dials the cover by name and some paths verify by
    /// address, so a missing one fails for a reason unrelated to the CCS question.
    #[test]
    fn both_subject_alt_names_are_required() {
        check_subject_alt_name("DNS:localhost, IP Address:127.0.0.1").unwrap();
        assert!(
            check_subject_alt_name("IP Address:127.0.0.1")
                .unwrap_err()
                .contains("DNS:localhost")
        );
        assert!(
            check_subject_alt_name("DNS:localhost")
                .unwrap_err()
                .contains("IP:127.0.0.1")
        );
    }

    #[test]
    fn the_cover_server_disables_middlebox_compatibility_and_traces() {
        let certificate = CoverCertificate {
            ca_certificate: std::path::PathBuf::from("/w/ca.crt"),
            certificate: std::path::PathBuf::from("/w/server.crt"),
            key: std::path::PathBuf::from("/w/server.key"),
            subject_alt_name: "DNS:localhost, IP Address:127.0.0.1".to_owned(),
        };
        let args = cover_server_args(8443, &certificate);
        assert!(args.contains(&"-no_middlebox".to_owned()));
        assert!(args.contains(&"-tls1_3".to_owned()));
        // Without the trace flags the absence of a CCS could only be asserted,
        // never observed.
        assert!(args.contains(&"-trace".to_owned()));
        assert!(args.contains(&"-msg".to_owned()));
        assert!(args.contains(&"127.0.0.1:8443".to_owned()));
        assert!(args.contains(&"h2,http/1.1".to_owned()));
    }

    #[test]
    fn the_summary_records_both_assertions() {
        let binary = |label: &str| crate::bench::identity::Binary {
            label: label.to_owned(),
            path: std::path::PathBuf::from(format!("/bin/{label}")),
            sha256: "a".repeat(64),
            identity: "identity".to_owned(),
        };
        let rendered = summary_json(
            "run-1",
            &binary("rust-reality"),
            &binary("xray"),
            Path::new("/usr/bin/openssl"),
            "OpenSSL 3.5.6 7 Apr 2026\nbuilt on: x\n",
            [1, 2, 3, 4],
            &"b".repeat(64),
            &"c".repeat(64),
        )
        .to_python_json();
        assert!(rendered.contains("\"serverChangeCipherSpec\": false"));
        assert!(rendered.contains("\"serverHello\": true"));
        assert!(rendered.contains("\"middlebox\": false"));
        assert!(rendered.contains("\"payloadBytes\": 1048576"));
        assert!(rendered.contains("rust-reality child SSL_CERT_FILE only"));
        assert!(rendered.contains("\"version\": \"OpenSSL 3.5.6 7 Apr 2026\""));
    }
}
