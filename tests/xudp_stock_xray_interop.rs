//! Stock Xray bidirectional UDP/XUDP interoperability and UDP/443 probe.
//!
//! Mandatory gate (AGENTS.md §6 / ADR 0059): unmodified stock Xray Client →
//! rust-reality Server XUDP. Exact-head Native downloads a pinned Xray, exports
//! `XRAY_BIN`, and runs `stock_xray_client_udp_echo_via_rust_reality_entry` with
//! `--ignored --exact`. That test panics if `XRAY_BIN` is missing — it MUST NOT
//! early-return as a green pass.
//!
//! Also covered when green:
//! 1. rust-reality entry ← stock Xray SOCKS(udp) client (flow vision-udp443)
//! 2. QUIC-shaped / genuine HTTP/3 over UDP/443 via XUDP with `allowUdp443`
//!    (no TCP CONNECT) — mandatory Exact-head Native gate lives in
//!    `tests/quic_h3_udp443_e2e.rs` (fail-closed without CAP_NET_BIND_SERVICE).
//!
//! Historical only (NOT a release gate): rust-reality client → stock Xray server
//! remains `#[ignore]`. Not native QUIC transport. See `docs/en/development/xudp.md`.

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rust-reality-xudp-stock-interop-ok";
const QUIC_PROBE: &[u8] = b"\x00\x00\x00\x01quic-h3-udp443-probe-no-tcp";

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn xray_bin() -> Option<PathBuf> {
    std::env::var_os("XRAY_BIN").map(PathBuf::from)
}

/// Resolve the mandatory stock Xray fixture. Panics when unset or not executable
/// so a missing Native pin cannot register as a silent green pass.
fn require_stock_xray_bin() -> PathBuf {
    let path = xray_bin().unwrap_or_else(|| {
        panic!("XRAY_BIN must point to an executable unmodified stock Xray-core binary (Native pin: tools/fixtures/stock-xray.json); missing fixture is FAIL, not skip")
    });
    assert!(
        path.is_file(),
        "XRAY_BIN={} is not a regular file",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "XRAY_BIN={} is not executable (mode {mode:#o})",
            path.display()
        );
    }
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_port(port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("port {port} not ready within {budget:?}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rust-reality"))
}

fn generate(subcommand: &str) -> String {
    let output = Command::new(bin())
        .args(["generate", subcommand])
        .output()
        .expect("generate");
    assert!(
        output.status.success(),
        "generate {subcommand} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .next()
        .expect("one line")
        .trim()
        .to_owned()
}

fn generate_x25519() -> (String, String) {
    let output = Command::new(bin())
        .args(["generate", "x25519"])
        .output()
        .expect("generate x25519");
    assert!(output.status.success(), "x25519 generate failed");
    let text = String::from_utf8(output.stdout).expect("utf8");
    let mut private = None;
    let mut public = None;
    for line in text.lines() {
        if let Some(v) = line.split_once(':').map(|(_, v)| v.trim()) {
            if line.starts_with("private key") {
                private = Some(v.to_owned());
            } else if line.starts_with("public key") {
                public = Some(v.to_owned());
            }
        }
    }
    (
        private.expect("private key line"),
        public.expect("public key line"),
    )
}

fn write(path: &Path, body: &str) {
    fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn spawn_logged(name: &str, mut command: Command, log: &Path) -> KillOnDrop {
    let file = fs::File::create(log).expect("log file");
    command.stdout(Stdio::from(file.try_clone().expect("clone")));
    command.stderr(Stdio::from(file));
    KillOnDrop(
        command
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}")),
    )
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

fn spawn_udp_echo() -> (UdpSocket, u16, thread::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("echo timeout");
    let port = sock.local_addr().expect("addr").port();
    let echo = sock.try_clone().expect("clone");
    let handle = thread::spawn(move || {
        let mut buf = [0_u8; 65535];
        for _ in 0..64 {
            match echo.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let _ = echo.send_to(&buf[..n], from);
                }
                Err(_) => break,
            }
        }
    });
    (sock, port, handle)
}

fn socks5_udp_round_trip(
    socks_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut control =
        TcpStream::connect(("127.0.0.1", socks_port)).map_err(|e| format!("socks connect: {e}"))?;
    control.set_read_timeout(Some(Duration::from_secs(30))).ok();
    control.set_write_timeout(Some(Duration::from_secs(8))).ok();
    control
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("greeting: {e}"))?;
    let mut resp = [0_u8; 2];
    control
        .read_exact(&mut resp)
        .map_err(|e| format!("greeting resp: {e}"))?;
    if resp != [0x05, 0x00] {
        return Err(format!("bad greeting resp {resp:?}"));
    }
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("associate: {e}"))?;
    let mut assoc = [0_u8; 10];
    control
        .read_exact(&mut assoc)
        .map_err(|e| format!("associate resp: {e}"))?;
    if assoc[1] != 0x00 {
        return Err(format!("associate failed status={}", assoc[1]));
    }
    let relay_port = u16::from_be_bytes([assoc[8], assoc[9]]);
    let relay: SocketAddr = format!("127.0.0.1:{relay_port}")
        .parse()
        .map_err(|e| format!("relay addr: {e}"))?;

    let udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp bind: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| format!("udp timeout: {e}"))?;

    let mut datagram = vec![0, 0, 0, 1, 127, 0, 0, 1];
    datagram.extend_from_slice(&dest_port.to_be_bytes());
    datagram.extend_from_slice(payload);
    udp.send_to(&datagram, relay)
        .map_err(|e| format!("udp send: {e}"))?;

    let mut buf = [0_u8; 65535];
    let (n, _) = udp
        .recv_from(&mut buf)
        .map_err(|e| format!("udp recv: {e}"))?;
    if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 1 {
        return Err(format!(
            "bad socks udp reply header: {:?}",
            &buf[..n.min(16)]
        ));
    }
    drop(control);
    Ok(buf[10..n].to_vec())
}

fn start_openssl_cover(root: &Path) -> (u16, KillOnDrop) {
    let openssl = which("openssl").expect("openssl required for cover");
    let cover_port = free_port();
    let key = root.join("cover.key");
    let crt = root.join("cover.crt");
    assert!(
        Command::new(&openssl)
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
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .status()
            .expect("openssl req")
            .success(),
        "openssl req failed"
    );
    let cover = spawn_logged(
        "openssl-cover",
        {
            let mut c = Command::new(&openssl);
            c.args([
                "s_server",
                "-tls1_3",
                "-quiet",
                "-accept",
                &cover_port.to_string(),
                "-cert",
            ])
            .arg(&crt)
            .arg("-key")
            .arg(&key)
            .stdin(Stdio::null());
            c
        },
        &root.join("cover.log"),
    );
    wait_port(cover_port, Duration::from_secs(30));
    (cover_port, cover)
}

#[test]
#[ignore = "requires pinned stock Xray via XRAY_BIN; Exact-head Native runs with --ignored --exact"]
fn stock_xray_client_udp_echo_via_rust_reality_entry() {
    let xray = require_stock_xray_bin();
    let root = std::env::temp_dir().join(format!("rr-xudp-xray-client-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let (cover_port, _cover) = start_openssl_cover(&root);
    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let entry_port = free_port();
    let socks_port = free_port();

    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "xray-client-udp"
  }}],
  "routing": {{ "default": "direct" }}
}}
"#
        ),
    );
    write(
        &root.join("xray-client.json"),
        &format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {socks_port},
    "protocol": "socks",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{
      "vnext": [{{
        "address": "127.0.0.1",
        "port": {entry_port},
        "users": [{{
          "id": "{user_id}",
          "encryption": "none",
          "flow": "xtls-rprx-vision-udp443"
        }}]
      }}]
    }},
    "streamSettings": {{
      "network": "tcp",
      "security": "reality",
      "realitySettings": {{
        "fingerprint": "chrome",
        "serverName": "localhost",
        "publicKey": "{public_key}",
        "shortId": "{short_id}",
        "spiderX": "/"
      }}
    }}
  }}]
}}
"#
        ),
    );

    let _entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_port(entry_port, Duration::from_secs(20));
    let _xray = spawn_logged(
        "xray-client",
        {
            let mut c = Command::new(&xray);
            c.args(["run", "-c"]).arg(root.join("xray-client.json"));
            c
        },
        &root.join("xray-client.log"),
    );
    wait_port(socks_port, Duration::from_secs(20));

    let (_echo_keep, echo_port, echo_thread) = spawn_udp_echo();
    let body = socks5_udp_round_trip(socks_port, echo_port, MARKER).unwrap_or_else(|e| {
        panic!(
            "stock Xray client UDP echo failed: {e}\nxray:\n{}\nentry:\n{}",
            fs::read_to_string(root.join("xray-client.log")).unwrap_or_default(),
            fs::read_to_string(root.join("entry.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    // Honest micro-measurement: additional single-datagram RTTs after warm path.
    let mut rtts_ms = Vec::new();
    for i in 0..8 {
        let payload = format!("rtt-sample-{i}").into_bytes();
        let t0 = Instant::now();
        let got = socks5_udp_round_trip(socks_port, echo_port, &payload)
            .unwrap_or_else(|e| panic!("RTT sample {i} failed: {e}"));
        assert_eq!(got, payload);
        rtts_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    rtts_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = rtts_ms[rtts_ms.len() / 2];
    eprintln!(
        "xudp_udp_rtt_ms samples={rtts_ms:?} median_ms={median:.3} (loopback; not a capacity claim)"
    );
    let _ = echo_thread.join();
}

#[test]
#[ignore = "ADR 0059: rust-reality Client → stock Xray Server is not a compatibility or release gate; retained as historical evidence only"]
fn rust_reality_client_udp_echo_via_stock_xray_server() {
    let Some(xray) = xray_bin() else {
        eprintln!("skip: XRAY_BIN not set");
        return;
    };
    let root = std::env::temp_dir().join(format!("rr-xudp-xray-server-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let (cover_port, _cover) = start_openssl_cover(&root);
    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let xray_port = free_port();
    let socks_port = free_port();

    write(
        &root.join("xray-server.json"),
        &format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1",
    "port": {xray_port},
    "protocol": "vless",
    "settings": {{
      "clients": [{{ "id": "{user_id}", "flow": "xtls-rprx-vision" }}],
      "decryption": "none"
    }},
    "streamSettings": {{
      "network": "tcp",
      "security": "reality",
      "realitySettings": {{
        "show": false,
        "dest": "127.0.0.1:{cover_port}",
        "xver": 0,
        "serverNames": ["localhost"],
        "privateKey": "{private_key}",
        "shortIds": ["{short_id}"]
      }}
    }}
  }}],
  "outbounds": [{{
    "protocol": "freedom",
    "tag": "direct",
    "settings": {{
      "finalRules": [{{ "action": "allow" }}]
    }}
  }}]
}}
"#
        ),
    );
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "127.0.0.1" }}],
  "lines": [{{
    "address": "127.0.0.1",
    "port": {xray_port},
    "id": "{user_id}",
    "publicKey": "{public_key}",
    "shortId": "{short_id}",
    "serverName": "localhost",
    "allowUdp443": true
  }}]
}}
"#
        ),
    );

    let _xray = spawn_logged(
        "xray-server",
        {
            let mut c = Command::new(&xray);
            c.args(["run", "-c"]).arg(root.join("xray-server.json"));
            c
        },
        &root.join("xray-server.log"),
    );
    {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if TcpStream::connect(("127.0.0.1", xray_port)).is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "xray server port {xray_port} not ready; log:\n{}",
                    fs::read_to_string(root.join("xray-server.log")).unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    let _client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_port(socks_port, Duration::from_secs(20));

    let (_echo_keep, echo_port, echo_thread) = spawn_udp_echo();
    let body = socks5_udp_round_trip(socks_port, echo_port, MARKER).unwrap_or_else(|e| {
        panic!(
            "rust-reality client ↔ stock Xray UDP failed: {e}\nxray:\n{}\nclient:\n{}",
            fs::read_to_string(root.join("xray-server.log")).unwrap_or_default(),
            fs::read_to_string(root.join("client.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    let _ = echo_thread.join();
}

#[test]
#[ignore = "superseded by tests/quic_h3_udp443_e2e.rs mandatory Native gate; kept as thin datagram probe"]
fn quic_shaped_udp_443_via_xudp_without_tcp_connect() {
    // Fail closed: never green-pass a missing privileged bind.
    let echo = UdpSocket::bind("127.0.0.1:443").unwrap_or_else(|err| {
        panic!(
            "cannot bind 127.0.0.1:443 ({err}); unprivileged skip is FAIL — see quic_h3_udp443_e2e"
        )
    });
    assert_eq!(echo.local_addr().unwrap().port(), 443);
    let echo_clone = echo.try_clone().unwrap();
    let echo_thread = thread::spawn(move || {
        let mut buf = [0_u8; 65535];
        if let Ok((n, from)) = echo_clone.recv_from(&mut buf) {
            let _ = echo_clone.send_to(&buf[..n], from);
        }
    });

    let root = std::env::temp_dir().join(format!("rr-xudp-quic443-{}", free_port()));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());
    let (cover_port, _cover) = start_openssl_cover(&root);
    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let entry_port = free_port();
    let socks_port = free_port();

    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "quic443"
  }}],
  "routing": {{ "default": "direct" }}
}}
"#
        ),
    );
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "127.0.0.1" }}],
  "lines": [{{
    "address": "127.0.0.1",
    "port": {entry_port},
    "id": "{user_id}",
    "publicKey": "{public_key}",
    "shortId": "{short_id}",
    "serverName": "localhost",
    "allowUdp443": true
  }}]
}}
"#
        ),
    );

    let _entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_port(entry_port, Duration::from_secs(20));
    let _client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_port(socks_port, Duration::from_secs(20));

    // SOCKS5 UDP ASSOCIATE only — no TCP CONNECT is issued for this probe.
    let body = socks5_udp_round_trip(socks_port, 443, QUIC_PROBE).unwrap_or_else(|e| {
        panic!("QUIC-shaped UDP/443 via XUDP failed (no TCP fallback): {e}");
    });
    assert_eq!(body, QUIC_PROBE);
    let _ = echo_thread.join();
}
