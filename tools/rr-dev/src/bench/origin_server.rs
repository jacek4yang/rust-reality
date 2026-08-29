//! The native benchmark origin: a loopback HTTP/1.1 and TLS 1.3 payload server.
//!
//! The legacy `scripts/bench-origin` Go program replaced a Python
//! `ThreadingHTTPServer` that collapsed under concurrency-32 TLS workloads. The
//! origin is measurement apparatus: when it saturates, every implementation's
//! cell is invalid, so it must be at least as strong as the workloads push
//! through it. This module reimplements the same wire contract with std threads
//! and no dependencies, so the repository keeps one language and one toolchain.
//!
//! The boundary with its callers stays a real process ([`crate::bench::origin`]):
//! a crashed or wedged listener must take down nothing but itself, and the
//! harnesses already own its lifetime through RAII children.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
/// Streaming copy buffer; the Go origin's size, kept for parity.
const COPY_BUFFER_BYTES: usize = 256 * 1024;

/// Counters the `GET /__stats` endpoint reports.
struct Stats {
    gets: AtomicI64,
    puts: AtomicI64,
    get_bytes: AtomicU64,
    put_bytes: AtomicU64,
    errors: AtomicI64,
    connections: AtomicI64,
    user_ns: AtomicI64,
    sys_ns: AtomicI64,
}

impl Stats {
    fn new() -> Self {
        Self {
            gets: AtomicI64::new(0),
            puts: AtomicI64::new(0),
            get_bytes: AtomicU64::new(0),
            put_bytes: AtomicU64::new(0),
            errors: AtomicI64::new(0),
            connections: AtomicI64::new(0),
            user_ns: AtomicI64::new(0),
            sys_ns: AtomicI64::new(0),
        }
    }
}

/// Everything one listener instance shares across its threads.
struct Shared {
    stats: Stats,
    put_log: Option<Mutex<std::fs::File>>,
    access_log: Option<Mutex<std::fs::File>>,
    label: String,
    payload_dir: std::path::PathBuf,
}

/// One append to the per-request access log, when it is enabled.
fn record_access(shared: &Shared, method: &str, path: &str, bytes: u64, digest: &str) {
    let Some(log) = &shared.access_log else {
        return;
    };
    let Ok(mut file) = log.lock() else {
        return;
    };
    let line = format!(
        "{{\"server\":{},\"method\":\"{}\",\"path\":\"{}\",\"bytes\":{},\"sha256\":\"{}\"}}\n",
        serde_string(&shared.label),
        method,
        serde_string(path),
        bytes,
        digest
    );
    let _ = file.write_all(line.as_bytes());
}

/// Renders one string as a JSON string literal.
fn serde_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Appends one PUT row to the put log.
fn record_put(shared: &Shared, path: &str, bytes: u64) {
    let Some(log) = &shared.put_log else {
        return;
    };
    let Ok(mut file) = log.lock() else {
        return;
    };
    let line = format!(
        "{{\"path\":{},\"bytes\":{}}}\n",
        serde_string(path),
        bytes
    );
    let _ = file.write_all(line.as_bytes());
}

/// Parses `/proc/self/stat` utime and stime into nanoseconds.
fn cpu_times() -> (i64, i64) {
    const USER_HZ: i64 = 100;
    let Ok(data) = std::fs::read_to_string("/proc/self/stat") else {
        return (0, 0);
    };
    let Some(end) = data.rfind(')') else {
        return (0, 0);
    };
    let fields: Vec<&str> = data[end + 1..].split_whitespace().collect();
    // fields[0] is state; utime is /proc field 14 (index 11), stime field 15.
    if fields.len() <= 12 {
        return (0, 0);
    }
    let parse = |text: &str| text.parse::<i64>().unwrap_or(0) * 1_000_000_000 / USER_HZ;
    (parse(fields[11]), parse(fields[12]))
}

/// Reads one HTTP request head (request line plus headers) from the stream.
///
/// Returns `None` on a closed or malformed stream: that peer contributed
/// nothing measurable.
fn read_request<R: Read>(
    stream: &mut BufReader<R>,
) -> Option<(String, HashMap<String, String>)> {
    let mut line = String::new();
    stream.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    parts.next()?;
    let mut headers = HashMap::new();
    loop {
        let mut header = String::new();
        stream.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    Some((format!("{method} {path}"), headers))
}

/// Writes a complete HTTP/1.1 response head.
fn respond_head<W: Write>(
    stream: &mut W,
    status: &str,
    content_length: Option<u64>,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {status}\r\nServer: rr-dev-origin\r\n");
    if let Some(length) = content_length {
        let _ = write!(head, "Content-Length: {length}\r\n");
    }
    for (name, value) in extra {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

/// Serves `GET /__stats`.
fn serve_stats<W: Write>(stream: &mut W, shared: &Shared) {
    let (user_ns, sys_ns) = cpu_times();
    shared.stats.user_ns.store(user_ns, Ordering::Relaxed);
    shared.stats.sys_ns.store(sys_ns, Ordering::Relaxed);
    let body = format!(
        "{{\"gets\":{},\"puts\":{},\"getBytes\":{},\"putBytes\":{},\"errors\":{},\
         \"connections\":{},\"cpuUserNs\":{},\"cpuSysNs\":{}}}\n",
        shared.stats.gets.load(Ordering::Relaxed),
        shared.stats.puts.load(Ordering::Relaxed),
        shared.stats.get_bytes.load(Ordering::Relaxed),
        shared.stats.put_bytes.load(Ordering::Relaxed),
        shared.stats.errors.load(Ordering::Relaxed),
        shared.stats.connections.load(Ordering::Relaxed),
        user_ns,
        sys_ns,
    );
    let ok = respond_head(
        stream,
        "200 OK",
        Some(body.len() as u64),
        &[("Content-Type", "application/json")],
    )
    .and_then(|()| stream.write_all(body.as_bytes()));
    if ok.is_err() {
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Serves one GET as an octet-stream payload from `payload_dir`.
fn serve_payload<W: Write>(stream: &mut W, shared: &Shared, path: &str) {
    let name = path.rsplit('/').find(|part| !part.is_empty()).unwrap_or("");
    let payload = shared.payload_dir.join(name);
    let contents = std::fs::read(&payload).ok();
    let Some(contents) = contents else {
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
        let _ = respond_head(stream, "404 Not Found", Some(9), &[]);
        let _ = stream.write_all(b"Not Found");
        return;
    };
    let digest = if shared.access_log.is_some() {
        crate::hash::sha256_hex(&contents)
    } else {
        String::new()
    };
    let ok = respond_head(
        stream,
        "200 OK",
        Some(contents.len() as u64),
        &[("Content-Type", "application/octet-stream")],
    )
    .and_then(|()| stream.write_all(&contents));
    shared.stats.gets.fetch_add(1, Ordering::Relaxed);
    shared
        .stats
        .get_bytes
        .fetch_add(contents.len() as u64, Ordering::Relaxed);
    if ok.is_err() {
        // A client that hangs up mid-transfer invalidates its own transfer; the
        // origin stays alive and keeps serving.
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
    record_access(shared, "GET", path, contents.len() as u64, &digest);
}

/// Consumes exactly `length` body bytes, then appends the PUT row.
fn serve_upload<W: Write, R: Read>(stream: &mut W, shared: &Shared, path: &str, length: u64, reader: &mut BufReader<R>) {
    let mut remaining = length;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut received: u64 = 0;
    let digest = if shared.access_log.is_some() {
        Some(crate::hash::sha256(b""))
    } else {
        None
    };
    let mut state = digest.map(|initial| (initial, Vec::new()));
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        match reader.read(&mut buffer[..want]) {
            Ok(0) => break,
            Ok(taken) => {
                if let Some((hash_state, _)) = state.as_mut() {
                    // Hashing the full body would need a second copy; the access
                    // log's PUT rows only report sizes, matching the Go origin.
                    let _ = hash_state;
                }
                if state.is_some() {
                    if let Some((_, collected)) = state.as_mut() {
                        collected.extend_from_slice(&buffer[..taken]);
                    }
                }
                received += taken as u64;
                remaining -= taken as u64;
            }
            Err(_) => {
                shared.stats.errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    let digest_hex = state.map_or_else(String::new, |(_, collected)| crate::hash::sha256_hex(&collected));
    let ok = respond_head(stream, "200 OK", Some(0), &[]);
    shared.stats.puts.fetch_add(1, Ordering::Relaxed);
    shared
        .stats
        .put_bytes
        .fetch_add(received, Ordering::Relaxed);
    if ok.is_err() {
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
    record_access(shared, "PUT", path, received, &digest_hex);
    record_put(shared, path, received);
}

/// Rejects a request the origin does not implement.
fn respond_not_found<W: Write>(stream: &mut W, shared: &Shared) {
    shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    let _ = respond_head(stream, "404 Not Found", Some(9), &[]);
    let _ = stream.write_all(b"Not Found");
}

/// Runs one listener until its process is terminated.
///
/// # Errors
///
/// Returns a message when the bind fails or the address is not numeric.
pub fn run(
    listen_address: &str,
    port: u16,
    payload_dir: &std::path::Path,
    put_log: Option<&std::path::Path>,
    access_log: Option<&std::path::Path>,
    label: &str,
) -> Result<(), String> {
    let address: std::net::IpAddr = listen_address
        .parse()
        .map_err(|error| format!("--listen-address must be numeric: {error}"))?;
    let listener = TcpListener::bind((address, port))
        .map_err(|error| format!("could not bind {address}:{port}: {error}"))?;
    let actual = listener
        .local_addr()
        .map_err(|error| format!("could not read the bound address: {error}"))?;
    println!("READY {actual}");
    let _ = std::io::stdout().flush();
    serve(listener, payload_dir, put_log, access_log, label);
    Ok(())
}

/// Serves an already-bound listener (plain HTTP) until the process is terminated.
pub fn serve(
    listener: TcpListener,
    payload_dir: &std::path::Path,
    put_log: Option<&std::path::Path>,
    access_log: Option<&std::path::Path>,
    label: &str,
) {
    let _ = serve_with_tls(listener, payload_dir, put_log, access_log, label, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_origin(
        directory: &std::path::Path,
        put_log: &std::path::Path,
    ) -> (std::thread::JoinHandle<()>, u16) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = directory.to_path_buf();
        let put_log = put_log.to_path_buf();
        let handle = std::thread::spawn(move || {
            serve(listener, &directory, Some(&put_log), None, "test-origin");
        });
        (handle, port)
    }

    #[test]
    fn serves_payloads_stats_and_uploads() {
        let root = std::env::temp_dir().join(format!("rr-origin-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let body: Vec<u8> = (0..=255_u8).cycle().take(300_000).collect();
        std::fs::write(root.join("payload.bin"), &body).unwrap();
        let put_log = root.join("put.jsonl");
        let (handle, port) = start_origin(&root, &put_log);

        let url = format!("http://127.0.0.1:{port}/payload.bin");
        let outcome = std::process::Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--output",
                root.join("downloaded.bin").display().to_string().as_str(),
                &url,
            ])
            .output()
            .unwrap();
        assert!(outcome.status.success(), "curl failed: {:?}", outcome);
        let downloaded = std::fs::read(root.join("downloaded.bin")).unwrap();
        assert_eq!(downloaded.len(), body.len());
        assert_eq!(
            crate::hash::sha256_hex(&downloaded),
            crate::hash::sha256_hex(&body)
        );

        // A PUT requires Content-Length and lands in the put log.
        let url = format!("http://127.0.0.1:{port}/upload/1");
        std::fs::write(root.join("up.bin"), b"hello").unwrap();
        let outcome = std::process::Command::new("curl")
            .args([
                "--silent",
                "--output",
                "/dev/null",
                "--upload-file",
                root.join("up.bin").display().to_string().as_str(),
                &url,
            ])
            .output()
            .unwrap();
        assert!(outcome.status.success(), "curl upload failed: {:?}", outcome);
        let put_rows = std::fs::read_to_string(&put_log).unwrap();
        assert!(put_rows.contains("\"bytes\":5"), "{put_rows}");

        // The stats endpoint reports the counters the guards read.
        let outcome = std::process::Command::new("curl")
            .args([
                "--fail",
                "--silent",
                &format!("http://127.0.0.1:{port}/__stats"),
            ])
            .output()
            .unwrap();
        let stats = String::from_utf8_lossy(&outcome.stdout);
        assert!(stats.contains("\"gets\":1"), "{stats}");
        assert!(stats.contains("\"puts\":1"), "{stats}");
        assert!(stats.contains("\"errors\":0"), "{stats}");

        // A missing payload is a 404 and an origin error.
        let outcome = std::process::Command::new("curl")
            .args([
                "--silent",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                &format!("http://127.0.0.1:{port}/absent.bin"),
            ])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&outcome.stdout), "404");
        let outcome = std::process::Command::new("curl")
            .args([
                "--fail",
                "--silent",
                &format!("http://127.0.0.1:{port}/__stats"),
            ])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&outcome.stdout).contains("\"errors\":1"),
            "the 404 must register as an origin error"
        );

        // The serve loop runs until the process terminates; the test process
        // itself is about to exit, so the thread is left to the reaper.
        std::mem::forget(handle);
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// TLS 1.3-only listener configuration.
///
/// The legacy origin pinned `MinVersion` and `MaxVersion` to TLS 1.3; a REALITY
/// cover must present exactly the negotiation the production target would, and
/// nothing older.
pub struct TlsOptions {
    /// PEM certificate chain.
    pub certificate_pem: Vec<u8>,
    /// PEM private key.
    pub key_pem: Vec<u8>,
    /// ALPN protocols offered, in preference order. Empty negotiates none.
    pub alpn: Vec<String>,
}

/// A connection the origin reads and writes through.
enum Transport {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Transport {
    fn stream(&mut self) -> &mut TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Tls(tls) => &mut tls.sock,
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(tls) => tls.read(buffer),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(data),
            Self::Tls(tls) => tls.write(data),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(tls) => tls.flush(),
        }
    }
}

/// Builds the TLS 1.3 acceptor from the PEM material.
///
/// # Errors
///
/// Returns a message when the certificate or key cannot be parsed.
pub fn tls_acceptor(options: &TlsOptions) -> Result<rustls::ServerConfig, String> {
    let mut certificates = std::io::BufReader::new(&options.certificate_pem[..]);
    let certificates: Vec<_> = rustls_pemfile::certs(&mut certificates)
        .collect::<Result<_, _>>()
        .map_err(|error| format!("origin certificate is not valid PEM: {error}"))?;
    if certificates.is_empty() {
        return Err("origin certificate file holds no certificate".to_owned());
    }
    let mut keys = std::io::BufReader::new(&options.key_pem[..]);
    let key = rustls_pemfile::private_key(&mut keys)
        .map_err(|error| format!("origin key is not valid PEM: {error}"))?
        .ok_or_else(|| "origin key file holds no private key".to_owned())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("TLS 1.3-only origin configuration is invalid: {error}"))?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| format!("origin certificate and key do not match: {error}"))?;
    if !options.alpn.is_empty() {
        config.alpn_protocols = options
            .alpn
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
    }
    Ok(config)
}

/// Serves one already-bound listener, optionally under TLS 1.3, until terminated.
///
/// Split from [`run`] so the TLS and plain paths share one loop and tests can
/// drive the exact wire contract in process.
///
/// # Errors
///
/// Returns a message when the TLS material cannot be parsed.
pub fn serve_with_tls(
    listener: TcpListener,
    payload_dir: &std::path::Path,
    put_log: Option<&std::path::Path>,
    access_log: Option<&std::path::Path>,
    label: &str,
    tls: Option<&TlsOptions>,
) -> Result<(), String> {
    let acceptor = match tls {
        Some(options) => Some(Arc::new(tls_acceptor(options)?)),
        None => None,
    };
    let put_log = put_log.and_then(|path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(Mutex::new)
    });
    let access_log = access_log.and_then(|path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
            .map(Mutex::new)
    });
    let shared = Arc::new(Shared {
        stats: Stats::new(),
        put_log,
        access_log,
        label: label.to_owned(),
        payload_dir: payload_dir.to_path_buf(),
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let shared = Arc::clone(&shared);
        let acceptor = acceptor.clone();
        std::thread::spawn(move || {
            let transport = match &acceptor {
                Some(config) => {
                    let config = Arc::clone(config);
                    let connection = match rustls::ServerConnection::new(config) {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    Transport::Tls(Box::new(rustls::StreamOwned::new(connection, stream)))
                }
                None => Transport::Plain(stream),
            };
            handle_transport(transport, shared);
        });
    }
    Ok(())
}

/// Serves one connection over either transport.
fn handle_transport(mut transport: Transport, shared: Arc<Shared>) {
    shared.stats.connections.fetch_add(1, Ordering::Relaxed);
    let _ = transport.stream().set_nodelay(true);
    let raw = match transport.stream().try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    };
    // The buffered reader wraps the same bytes the writer targets; the
    // ownership split below keeps the request body reads and the response
    // writes on the two halves of one connection.
    let mut reader = BufReader::with_capacity(COPY_BUFFER_BYTES, SplitReader(transport));
    let mut writer = SplitWriter(raw);
    while let Some((request, headers)) = read_request(&mut reader) {
        let (method, path) = request
            .split_once(' ')
            .map_or(("", ""), |(method, path)| (method, path));
        match (method, path.split('?').next().unwrap_or(path)) {
            ("GET", "/__stats") => serve_stats(&mut writer, &shared),
            ("GET", _) => serve_payload(&mut writer, &shared, path),
            ("PUT", _) => {
                let length = headers
                    .get("content-length")
                    .and_then(|value| value.parse::<u64>().ok());
                match length {
                    Some(length) => {
                        serve_upload(&mut writer, &shared, path, length, &mut reader)
                    }
                    None => {
                        let _ = respond_head(&mut writer, "411 Length Required", Some(0), &[]);
                    }
                }
            }
            _ => respond_not_found(&mut writer, &shared),
        }
    }
}

/// The read half of a split transport.
struct SplitReader(Transport);

impl Read for SplitReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

/// The write half of a split transport, over the cloned socket.
struct SplitWriter(TcpStream);

impl Write for SplitWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
