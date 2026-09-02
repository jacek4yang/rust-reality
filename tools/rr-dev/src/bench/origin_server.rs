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
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
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
    active_connections: AtomicUsize,
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
            active_connections: AtomicUsize::new(0),
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
fn record_access(
    shared: &Shared,
    method: &str,
    path: &str,
    client: IpAddr,
    bytes: u64,
    digest: &str,
) {
    let Some(log) = &shared.access_log else {
        return;
    };
    let Ok(mut file) = log.lock() else {
        return;
    };
    let line = format!(
        "{{\"server\":{},\"method\":{},\"path\":{},\"client\":{},\"bytes\":{},\"sha256\":{}}}\n",
        serde_string(&shared.label),
        serde_string(method),
        serde_string(path),
        serde_string(&client.to_string()),
        bytes,
        serde_string(digest),
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
    let line = format!("{{\"path\":{},\"bytes\":{}}}\n", serde_string(path), bytes);
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
struct Request {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
}

impl Request {
    fn keep_alive(&self) -> bool {
        let connection = self
            .headers
            .get("connection")
            .map(|value| value.to_ascii_lowercase());
        match self.version.as_str() {
            "HTTP/1.1" => connection.as_deref() != Some("close"),
            "HTTP/1.0" => connection.as_deref() == Some("keep-alive"),
            _ => false,
        }
    }
}

fn read_request<R: Read>(stream: &mut BufReader<R>) -> Option<Request> {
    let mut line = String::new();
    stream.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let version = parts.next()?.to_owned();
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
    Some(Request {
        method,
        path,
        version,
        headers,
    })
}

/// Writes a complete HTTP/1.1 response head.
fn respond_head<W: Write>(
    stream: &mut W,
    version: &str,
    status: &str,
    content_length: Option<u64>,
    keep_alive: bool,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let version = if matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        version
    } else {
        "HTTP/1.0"
    };
    let mut head = format!("{version} {status}\r\nServer: rr-dev-origin\r\n");
    if let Some(length) = content_length {
        let _ = write!(head, "Content-Length: {length}\r\n");
    }
    for (name, value) in extra {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if !keep_alive {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

/// Serves `GET /__stats`.
fn serve_stats<W: Write>(stream: &mut W, shared: &Shared, request: &Request) {
    let (user_ns, sys_ns) = cpu_times();
    shared.stats.user_ns.store(user_ns, Ordering::Relaxed);
    shared.stats.sys_ns.store(sys_ns, Ordering::Relaxed);
    let body = format!(
        "{{\"gets\":{},\"puts\":{},\"getBytes\":{},\"putBytes\":{},\"errors\":{},\
         \"goroutines\":{},\"cpuUserNs\":{},\"cpuSysNs\":{},\"allocBytes\":0}}\n",
        shared.stats.gets.load(Ordering::Relaxed),
        shared.stats.puts.load(Ordering::Relaxed),
        shared.stats.get_bytes.load(Ordering::Relaxed),
        shared.stats.put_bytes.load(Ordering::Relaxed),
        shared.stats.errors.load(Ordering::Relaxed),
        shared.stats.active_connections.load(Ordering::Relaxed),
        user_ns,
        sys_ns,
    );
    let ok = respond_head(
        stream,
        &request.version,
        "200 OK",
        Some(body.len() as u64),
        request.keep_alive(),
        &[("Content-Type", "application/json")],
    )
    .and_then(|()| stream.write_all(body.as_bytes()));
    if ok.is_err() {
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Serves one GET as an octet-stream payload from `payload_dir`.
fn serve_payload<W: Write>(stream: &mut W, shared: &Shared, request: &Request, client: IpAddr) {
    let route_path = request.path.split('?').next().unwrap_or(&request.path);
    let name = route_path
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("");
    let payload = shared.payload_dir.join(name);
    let Ok(mut file) = std::fs::File::open(&payload) else {
        let _ = respond_head(
            stream,
            &request.version,
            "404 Not Found",
            Some(9),
            request.keep_alive(),
            &[],
        );
        let _ = stream.write_all(b"Not Found");
        return;
    };
    let Ok(metadata) = file.metadata() else {
        let _ = respond_head(
            stream,
            &request.version,
            "404 Not Found",
            Some(9),
            request.keep_alive(),
            &[],
        );
        let _ = stream.write_all(b"Not Found");
        return;
    };
    if !metadata.is_file() {
        let _ = respond_head(
            stream,
            &request.version,
            "404 Not Found",
            Some(9),
            request.keep_alive(),
            &[],
        );
        let _ = stream.write_all(b"Not Found");
        return;
    }
    let head = respond_head(
        stream,
        &request.version,
        "200 OK",
        Some(metadata.len()),
        request.keep_alive(),
        &[("Content-Type", "application/octet-stream")],
    );
    let mut digest = shared.access_log.is_some().then(crate::hash::Sha256::new);
    let mut written = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut failed = head.is_err();
    while !failed {
        let taken = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(taken) => taken,
            Err(_) => {
                failed = true;
                break;
            }
        };
        let mut offset = 0;
        while offset < taken {
            match stream.write(&buffer[offset..taken]) {
                Ok(0) | Err(_) => {
                    failed = true;
                    break;
                }
                Ok(sent) => {
                    if let Some(state) = digest.as_mut() {
                        state.update(&buffer[offset..offset + sent]);
                    }
                    offset += sent;
                    written += sent as u64;
                }
            }
        }
    }
    shared.stats.gets.fetch_add(1, Ordering::Relaxed);
    shared.stats.get_bytes.fetch_add(written, Ordering::Relaxed);
    if failed {
        // A client that hangs up mid-transfer invalidates its own transfer; the
        // origin stays alive and keeps serving.
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
    let digest = digest.map_or_else(String::new, crate::hash::Sha256::finish_hex);
    record_access(shared, "GET", &request.path, client, written, &digest);
}

/// Rejects a request the origin does not implement.
fn respond_not_found<W: Write>(stream: &mut W, request: &Request) {
    let _ = respond_head(
        stream,
        &request.version,
        "404 Not Found",
        Some(9),
        request.keep_alive(),
        &[],
    );
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
    serve(&listener, payload_dir, put_log, access_log, label);
    Ok(())
}

/// Serves an already-bound listener (plain HTTP) until the process is terminated.
pub fn serve(
    listener: &TcpListener,
    payload_dir: &std::path::Path,
    put_log: Option<&std::path::Path>,
    access_log: Option<&std::path::Path>,
    label: &str,
) {
    let _ = serve_with_tls(listener, payload_dir, put_log, access_log, label, None);
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
    fn socket(&mut self) -> &mut TcpStream {
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
    listener: &TcpListener,
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
        let client = stream
            .peer_addr()
            .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |address| {
                address.ip()
            });
        let shared = Arc::clone(&shared);
        let acceptor = acceptor.clone();
        std::thread::spawn(move || {
            let transport = match &acceptor {
                Some(config) => {
                    let config = Arc::clone(config);
                    let Ok(connection) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    Transport::Tls(Box::new(rustls::StreamOwned::new(connection, stream)))
                }
                None => Transport::Plain(stream),
            };
            handle_transport(transport, &shared, client);
        });
    }
    Ok(())
}

/// Serves one connection over either transport.
fn handle_transport(mut transport: Transport, shared: &Shared, client: IpAddr) {
    shared
        .stats
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    let _ = transport.socket().set_nodelay(true);
    let mut reader = BufReader::with_capacity(COPY_BUFFER_BYTES, transport);
    while let Some(request) = read_request(&mut reader) {
        let keep_alive = request.keep_alive();
        let route_path = request.path.split('?').next().unwrap_or(&request.path);
        match (request.method.as_str(), route_path) {
            ("GET", "/__stats") => serve_stats(reader.get_mut(), shared, &request),
            ("GET", _) => serve_payload(reader.get_mut(), shared, &request, client),
            ("PUT", _) => {
                let length = request
                    .headers
                    .get("content-length")
                    .and_then(|value| value.parse::<u64>().ok());
                match length {
                    Some(length) => {
                        serve_upload_connection(&mut reader, shared, &request, client, length);
                    }
                    None => {
                        let _ = respond_head(
                            reader.get_mut(),
                            &request.version,
                            "411 Length Required",
                            Some(0),
                            keep_alive,
                            &[],
                        );
                    }
                }
            }
            _ => respond_not_found(reader.get_mut(), &request),
        }
        let _ = reader.get_mut().flush();
        if !keep_alive {
            break;
        }
    }
    shared
        .stats
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
}

/// Reads a PUT body through the buffered connection before borrowing its
/// underlying transport to write the response.
fn serve_upload_connection(
    reader: &mut BufReader<Transport>,
    shared: &Shared,
    request: &Request,
    client: IpAddr,
    length: u64,
) {
    let mut remaining = length;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut received = 0_u64;
    let mut digest = shared.access_log.is_some().then(crate::hash::Sha256::new);
    let mut failed = false;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        match reader.read(&mut buffer[..want]) {
            Ok(0) => break,
            Ok(taken) => {
                if let Some(state) = digest.as_mut() {
                    state.update(&buffer[..taken]);
                }
                received += taken as u64;
                remaining -= taken as u64;
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    failed |= received != length;
    if failed {
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
    let digest_hex = digest.map_or_else(String::new, crate::hash::Sha256::finish_hex);
    shared.stats.puts.fetch_add(1, Ordering::Relaxed);
    shared
        .stats
        .put_bytes
        .fetch_add(received, Ordering::Relaxed);
    record_access(shared, "PUT", &request.path, client, received, &digest_hex);
    record_put(shared, &request.path, received);
    if respond_head(
        reader.get_mut(),
        &request.version,
        "200 OK",
        Some(0),
        request.keep_alive(),
        &[],
    )
    .is_err()
    {
        shared.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
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
            serve(&listener, &directory, Some(&put_log), None, "test-origin");
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
        assert!(outcome.status.success(), "curl failed: {outcome:?}");
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
        assert!(outcome.status.success(), "curl upload failed: {outcome:?}");
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

        // A missing payload is a client-visible 404, not an origin saturation
        // error. The guard must count apparatus failures, not bad URLs.
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
            String::from_utf8_lossy(&outcome.stdout).contains("\"errors\":0"),
            "a normal 404 must not invalidate the origin"
        );

        // The serve loop runs until the process terminates; the test process
        // itself is about to exit, so the thread is left to the reaper.
        std::mem::forget(handle);
        let _ = std::fs::remove_dir_all(&root);
    }
}
