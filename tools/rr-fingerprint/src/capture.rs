//! Controlled HTTPS origin. The recording reader copies bytes without changing
//! what rustls receives. Private TLS keys are kept separate from evidence.
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn prepare(private: &Path, ca_path: &Path) -> Result<()> {
    fs::create_dir(private)?;
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["rr-capture-root.test".into()])?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca = params.self_signed(&key)?;
    let server_key = rcgen::KeyPair::generate()?;
    let mut server_params = rcgen::CertificateParams::new(vec!["browser-capture.test".into()])?;
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = server_params.signed_by(&server_key, &ca, &key)?;
    fs::write(ca_path, ca.der())?;
    fs::write(private.join("server.der"), leaf.der())?;
    let path = private.join("key.der");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(&server_key.serialize_der())?;
    Ok(())
}

struct Recording {
    socket: TcpStream,
    first_flight: Vec<u8>,
    recording: bool,
}
impl Read for Recording {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.read(b)?;
        if self.recording {
            if self.first_flight.len() + n > rr_fingerprint::MAX_CAPTURE_BYTES {
                return Err(io::Error::other("capture bound exceeded"));
            }
            self.first_flight.extend_from_slice(&b[..n]);
        }
        Ok(n)
    }
}
impl Write for Recording {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.socket.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

pub fn serve(private: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fs::read(private.join("server.der"))?)],
            PrivatePkcs8KeyDer::from(fs::read(private.join("key.der"))?).into(),
        )?;
    let mut config = config;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:8443")?;
    fs::write(out.join("ready"), b"127.0.0.1:8443")?;
    // A fixed upper bound on both connections and threads; WebDriver samples
    // are sequential. Deadlines also bound browser speculative connections.
    let mut threads = Vec::new();
    for index in 0..256 {
        let (socket, _) = listener.accept()?;
        let config = config.clone();
        let out = out.to_path_buf();
        threads.push(std::thread::spawn(move || {
            if let Err(error) = connection(socket, config, &out, index) {
                let _ = fs::write(
                    out.join(format!("connection-{index}.error")),
                    error.to_string(),
                );
            }
        }));
    }
    for thread in threads {
        thread.join().map_err(|_| "origin worker panicked")?;
    }
    Ok(())
}
fn connection(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    out: &Path,
    index: usize,
) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = StreamOwned::new(
        ServerConnection::new(config)?,
        Recording {
            socket,
            first_flight: Vec::new(),
            recording: true,
        },
    );
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    tls.sock.recording = false;
    // Collect only the initial handshake records. Subsequent encrypted records
    // may have arrived in the same TCP read and are not ClientHello evidence.
    let mut end = 0;
    let raw = &tls.sock.first_flight;
    while end + 5 <= raw.len() && raw[end] == 22 {
        let len = usize::from(u16::from_be_bytes([raw[end + 3], raw[end + 4]]));
        end = end.checked_add(5 + len).ok_or("capture length overflow")?;
        if end > raw.len() {
            return Err("truncated captured record".into());
        }
        if rr_fingerprint::decode(&raw[..end]).is_ok() {
            break;
        }
    }
    let hello = rr_fingerprint::decode(raw.get(..end).ok_or("capture length")?)?;
    let wire = &raw[..end];
    let digest = Sha256::digest(wire)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    fs::write(out.join(format!("connection-{index}.tls")), wire)?;
    fs::write(
        out.join(format!("connection-{index}.hello.json")),
        serde_json::to_vec_pretty(&hello)?,
    )?;
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() >= 8192 {
            return Err("HTTP header bound".into());
        }
        tls.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    let request = std::str::from_utf8(&request)?;
    let line = request.lines().next().ok_or("missing request")?;
    let token = line
        .strip_prefix("GET /sample-")
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .ok_or("not a sample request")?;
    if token.is_empty()
        || token.len() > 64
        || !token.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("invalid sample token".into());
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        token.len(),
        token
    );
    tls.write_all(response.as_bytes())?;
    tls.flush()?;
    let receipt = json!({"sample":token,"wireSha256":digest,"tlsVersion":format!("{:?}",tls.conn.protocol_version()),"cipher":format!("{:?}",tls.conn.negotiated_cipher_suite()),"alpn":tls.conn.alpn_protocol(),"responseWritten":true});
    fs::write(
        out.join(format!("connection-{index}.receipt.json")),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_https_transaction_retains_original_clienthello() {
        let root = std::env::temp_dir().join(format!(
            "rr-capture-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let private = root.join("private");
        let ca = root.join("ca.der");
        prepare(&private, &ca).unwrap();
        let out = root.join("evidence");
        fs::create_dir(&out).unwrap();
        let server = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    fs::read(private.join("server.der")).unwrap(),
                )],
                PrivatePkcs8KeyDer::from(fs::read(private.join("key.der")).unwrap()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let evidence = out.clone();
        let worker = std::thread::spawn(move || {
            connection(listener.accept().unwrap().0, Arc::new(server), &evidence, 0)
                .map_err(|e| e.to_string())
        });
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(fs::read(ca).unwrap()))
            .unwrap();
        let client =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut tls = StreamOwned::new(
            rustls::ClientConnection::new(
                Arc::new(client),
                "browser-capture.test".try_into().unwrap(),
            )
            .unwrap(),
            socket,
        );
        tls.write_all(b"GET /sample-deadbeef HTTP/1.1\r\nHost: browser-capture.test\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        tls.read_to_string(&mut response).unwrap();
        assert!(response.ends_with("deadbeef"));
        worker.join().unwrap().unwrap();
        let captured = fs::read(out.join("connection-0.tls")).unwrap();
        let decoded = rr_fingerprint::decode(&captured).unwrap();
        assert!(decoded.supported_versions.unwrap().contains(&0x0304));
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("connection-0.receipt.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["sample"], "deadbeef");
        assert_eq!(receipt["responseWritten"], true);
        fs::remove_dir_all(root).unwrap();
    }
}
