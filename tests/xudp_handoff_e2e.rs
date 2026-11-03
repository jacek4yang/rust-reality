//! Handoff UDP end-to-end (ADR 0060 Option B / Issue #314 PR6).
//!
//! Topology:
//!   Client (rust-reality or stock Xray) → REALITY+Vision+XUDP → LINE (entry)
//!     → Handoff transfer → LANDING (TLS+Vision+UDP owner) → Internet UDP.
//!
//! LANDING listens on `127.0.0.2` so echo peers observe source `127.0.0.2`,
//! proving LANDING (not LINE on `127.0.0.1`) owns the UDP socket after transfer.
//!
//! Process-level echo / multi-dest / Block tests run unprivileged.
//! UDP/443 + genuine HTTP/3 and stock Xray cases are `#[ignore]` and wired
//! into Exact-head Native like the NXR XUDP gates.

#[path = "support/socks_tcp.rs"]
mod socks_tcp;

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rr-handoff-xudp-echo-ok";
const LANDING_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const LINE_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;
const DEST_443: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

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

#[path = "support/ports.rs"]
mod ports;
use ports::free_port;

#[path = "support/xudp_reordering.rs"]
mod xudp_reordering;

#[test]
fn handoff_xudp_delayed_replies_preserve_sources() {
    let root = std::env::temp_dir().join(format!("rr-handoff-reordering-{}", free_port()));
    let _guard = DirGuard(root.clone());
    let stack = start_handoff_line_landing(&root, false, "chrome");
    xudp_reordering::delayed_replies_preserve_sources(stack.socks_port, LANDING_IP);
}

fn wait_tcp(ip: Ipv4Addr, port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if TcpStream::connect((ip, port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{ip}:{port} not ready within {budget:?}");
        }
        thread::sleep(Duration::from_millis(40));
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
        "generate {subcommand}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .next()
        .expect("line")
        .trim()
        .to_owned()
}

fn generate_x25519() -> (String, String) {
    let output = Command::new(bin())
        .args(["generate", "x25519"])
        .output()
        .expect("x25519");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
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
    (private.expect("private"), public.expect("public"))
}

fn write(path: &Path, body: &str) {
    fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn spawn_logged(label: &str, mut cmd: Command, log: &Path) -> KillOnDrop {
    let file = fs::File::create(log).expect("log");
    cmd.stdout(Stdio::from(file.try_clone().unwrap()))
        .stderr(Stdio::from(file));
    let child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {label}: {e}"));
    KillOnDrop(child)
}

fn openssl_bin() -> PathBuf {
    std::env::var_os("OPENSSL_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("openssl"))
}

fn start_openssl_cover(root: &Path) -> (u16, KillOnDrop) {
    fs::create_dir_all(root).unwrap_or_else(|e| panic!("mkdir {}: {e}", root.display()));
    let cover_port = free_port();
    let key = root.join("cover.key");
    let crt = root.join("cover.crt");
    let output = Command::new(openssl_bin())
        .args(["req", "-x509", "-newkey", "rsa:2048", "-keyout"])
        .arg(&key)
        .arg("-out")
        .arg(&crt)
        .args([
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .output()
        .expect("openssl req");
    assert!(
        output.status.success(),
        "openssl cert failed status={:?} stderr={} stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let cover = spawn_logged(
        "cover",
        {
            let mut c = Command::new(openssl_bin());
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
    wait_tcp(LINE_IP, cover_port, Duration::from_secs(30));
    (cover_port, cover)
}

#[allow(dead_code, reason = "stack metadata retained for diagnostics")]
struct HandoffStack {
    root: PathBuf,
    socks_port: u16,
    entry_port: u16,
    landing_port: u16,
    _cover: KillOnDrop,
    _landing: KillOnDrop,
    _entry: KillOnDrop,
    _client: Option<KillOnDrop>,
    landing_pid: u32,
    entry_pid: u32,
}

fn start_handoff_line_landing(root: &Path, allow_udp_443: bool, fingerprint: &str) -> HandoffStack {
    fs::create_dir_all(root).unwrap();
    let (cover_port, cover) = start_openssl_cover(root);
    let (reality_private, reality_public) = generate_x25519();
    let (landing_private, landing_public) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();
    let allow_line = if allow_udp_443 {
        r#", "allowUdp443": true"#
    } else {
        ""
    };

    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "{landing_ip}" }}],
  "landing": {{
    "protocol": "handoff",
    "psk": "{psk}",
    "privateKey": "{landing_private}"
  }}
}}
"#,
            landing_ip = LANDING_IP,
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "{line_ip}" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "handoff-xudp"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "handoff",
      "address": "{landing_ip}",
      "port": {landing_port},
      "psk": "{psk}",
      "landingPublicKey": "{landing_public}",
      "warmTcp": false
    }}
  }},
  "routing": {{
    "default": "landing-1",
    "rules": [{{
      "name": "block-private-ten",
      "ip": ["10.0.0.0/8"],
      "outbound": "block"
    }}]
  }}
}}
"#,
            line_ip = LINE_IP,
            landing_ip = LANDING_IP,
        ),
    );
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "{line_ip}" }}],
  "lines": [{{
    "address": "{line_ip}",
    "port": {entry_port},
    "id": "{user_id}",
    "publicKey": "{reality_public}",
    "shortId": "{short_id}",
    "serverName": "localhost",
    "fingerprint": "{fingerprint}"{allow_line}
  }}]
}}
"#,
            line_ip = LINE_IP,
        ),
    );
    write(
        &root.join("identity.env"),
        &format!(
            "USER_ID={user_id}\nPUBLIC_KEY={reality_public}\nSHORT_ID={short_id}\nENTRY_PORT={entry_port}\nLANDING_PUBLIC_KEY={landing_public}\n"
        ),
    );

    let landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp(LANDING_IP, landing_port, Duration::from_secs(20));
    let landing_pid = landing.0.id();

    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(LINE_IP, entry_port, Duration::from_secs(20));
    let entry_pid = entry.0.id();

    let client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_tcp(LINE_IP, socks_port, Duration::from_secs(20));

    HandoffStack {
        root: root.to_path_buf(),
        socks_port,
        entry_port,
        landing_port,
        _cover: cover,
        _landing: landing,
        _entry: entry,
        _client: Some(client),
        landing_pid,
        entry_pid,
    }
}

fn socks5_udp_round_trip(
    socks_port: u16,
    dest: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut control =
        TcpStream::connect((LINE_IP, socks_port)).map_err(|e| format!("socks connect: {e}"))?;
    control.set_read_timeout(Some(Duration::from_secs(8))).ok();
    control.set_write_timeout(Some(Duration::from_secs(8))).ok();
    control
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("method: {e}"))?;
    let mut method = [0_u8; 2];
    control
        .read_exact(&mut method)
        .map_err(|e| format!("method reply: {e}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("method reply {method:?}"));
    }
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("associate: {e}"))?;
    let mut reply = [0_u8; 10];
    control
        .read_exact(&mut reply)
        .map_err(|e| format!("associate reply: {e}"))?;
    if reply[0] != 0x05 || reply[1] != 0x00 || reply[3] != 0x01 {
        return Err(format!("associate failed: {reply:?}"));
    }
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = StdUdpSocket::bind((LINE_IP, 0)).map_err(|e| format!("udp bind: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| format!("udp timeout: {e}"))?;
    let mut datagram = Vec::with_capacity(10 + payload.len());
    datagram.extend_from_slice(&[0, 0, 0, 1]);
    match dest.ip() {
        IpAddr::V4(v4) => datagram.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => return Err("test helper is IPv4-only".into()),
    }
    datagram.extend_from_slice(&dest.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    udp.send_to(&datagram, relay)
        .map_err(|e| format!("udp send: {e}"))?;
    let mut buf = [0_u8; 65535];
    let (n, _) = udp
        .recv_from(&mut buf)
        .map_err(|e| format!("udp recv: {e}"))?;
    if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 1 {
        return Err(format!("bad socks udp reply: {:?}", &buf[..n.min(16)]));
    }
    drop(control);
    Ok(buf[10..n].to_vec())
}

/// One SOCKS5 UDP ASSOCIATE that sends several datagrams to a **domain**
/// destination on the same association (stock Xray XUDP repeats the domain on
/// every Keep frame).
fn socks5_udp_domain_round_trips(
    socks_port: u16,
    host: &str,
    port: u16,
    payloads: &[&[u8]],
) -> Result<Vec<Vec<u8>>, String> {
    let mut control =
        TcpStream::connect((LINE_IP, socks_port)).map_err(|e| format!("socks connect: {e}"))?;
    control.set_read_timeout(Some(Duration::from_secs(8))).ok();
    control.set_write_timeout(Some(Duration::from_secs(8))).ok();
    control
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("method: {e}"))?;
    let mut method = [0_u8; 2];
    control
        .read_exact(&mut method)
        .map_err(|e| format!("method reply: {e}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("method reply {method:?}"));
    }
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("associate: {e}"))?;
    let mut reply = [0_u8; 10];
    control
        .read_exact(&mut reply)
        .map_err(|e| format!("associate reply: {e}"))?;
    if reply[0] != 0x05 || reply[1] != 0x00 || reply[3] != 0x01 {
        return Err(format!("associate failed: {reply:?}"));
    }
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = StdUdpSocket::bind((LINE_IP, 0)).map_err(|e| format!("udp bind: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| format!("udp timeout: {e}"))?;
    let host_len = u8::try_from(host.len()).map_err(|_| "host too long".to_owned())?;
    let mut bodies = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        let mut datagram = Vec::with_capacity(7 + host.len() + payload.len());
        datagram.extend_from_slice(&[0, 0, 0, 3, host_len]);
        datagram.extend_from_slice(host.as_bytes());
        datagram.extend_from_slice(&port.to_be_bytes());
        datagram.extend_from_slice(payload);
        udp.send_to(&datagram, relay)
            .map_err(|e| format!("udp send #{index}: {e}"))?;
        let mut buf = [0_u8; 65535];
        let (n, _) = udp
            .recv_from(&mut buf)
            .map_err(|e| format!("udp recv #{index}: {e}"))?;
        if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 1 {
            return Err(format!(
                "bad socks udp reply #{index}: {:?}",
                &buf[..n.min(16)]
            ));
        }
        bodies.push(buf[10..n].to_vec());
    }
    drop(control);
    Ok(bodies)
}

struct EchoPeer {
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    hits: Arc<AtomicUsize>,
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for EchoPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn bind_udp(addr: SocketAddr) -> StdUdpSocket {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match StdUdpSocket::bind(addr) {
            Ok(sock) => return sock,
            Err(err) if err.kind() == ErrorKind::AddrInUse && Instant::now() < deadline => {
                eprintln!("bind {addr} still in use ({err}); retrying");
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => panic!("echo bind {addr}: {err}"),
        }
    }
}

fn spawn_udp_echo_on(bind: SocketAddr) -> EchoPeer {
    let sock = bind_udp(bind);
    sock.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let port = sock.local_addr().unwrap().port();
    let peers = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let peers_bg = peers.clone();
    let hits_bg = hits.clone();
    let stop_bg = stop.clone();
    let join = thread::spawn(move || {
        let mut buf = [0_u8; 65535];
        while !stop_bg.load(Ordering::SeqCst) {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    hits_bg.fetch_add(1, Ordering::SeqCst);
                    peers_bg.lock().unwrap().push(from);
                    let _ = sock.send_to(&buf[..n], from);
                }
                Err(_) => continue,
            }
        }
    });
    EchoPeer {
        peers,
        hits,
        port,
        stop,
        join: Some(join),
    }
}

fn require_udp443_capability() {
    let _probe = bind_udp(DEST_443);
}

fn assert_landing_is_udp_sender(echo: &EchoPeer, landing_pid: u32, entry_pid: u32) {
    let peers = echo.peers.lock().unwrap().clone();
    assert!(
        !peers.is_empty(),
        "echo received no datagrams; landing_pid={landing_pid} entry_pid={entry_pid}"
    );
    for peer in &peers {
        assert_eq!(
            peer.ip(),
            IpAddr::V4(LANDING_IP),
            "UDP source must be LANDING {LANDING_IP}, got {peer} (LINE is {LINE_IP}); landing_pid={landing_pid} entry_pid={entry_pid}"
        );
        assert_ne!(
            peer.ip(),
            IpAddr::V4(LINE_IP),
            "UDP source must not be LINE {LINE_IP}"
        );
    }
    if let Ok(output) = Command::new("ss").args(["-ulnpH"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        let entry_marker = format!("pid={entry_pid}");
        let entry_udp_to_echo = text
            .lines()
            .any(|l| l.contains(&entry_marker) && l.contains(&format!(":{}", echo.port)));
        assert!(
            !entry_udp_to_echo,
            "LINE pid={entry_pid} must not own UDP toward echo :{};\nss:\n{text}",
            echo.port
        );
        eprintln!(
            "landing_udp_sender_proof peers={peers:?} landing_pid={landing_pid} entry_pid={entry_pid}"
        );
    }
}

#[test]
fn rust_client_handoff_udp_echo_landing_is_sender() {
    browser_udp_echo("chrome");
}

#[test]
fn firefox_handoff_udp_echo_landing_is_sender() {
    browser_udp_echo("firefox");
}

fn browser_udp_echo(fingerprint: &str) {
    let root = std::env::temp_dir().join(format!("rr-handoff-echo-{}", free_port()));
    let _guard = DirGuard(root.clone());
    let stack = start_handoff_line_landing(&root, false, fingerprint);
    let echo = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let dest = SocketAddr::from((LINE_IP, echo.port));
    let body = socks5_udp_round_trip(stack.socks_port, dest, MARKER).unwrap_or_else(|e| {
        panic!(
            "Handoff UDP echo failed: {e}\nentry:\n{}\nlanding:\n{}\nclient:\n{}",
            fs::read_to_string(root.join("entry.log")).unwrap_or_default(),
            fs::read_to_string(root.join("landing.log")).unwrap_or_default(),
            fs::read_to_string(root.join("client.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    assert_landing_is_udp_sender(&echo, stack.landing_pid, stack.entry_pid);
    eprintln!(
        "rust_client_handoff_udp_echo_landing_is_sender PASS (peers={:?}, hits={})",
        *echo.peers.lock().unwrap(),
        echo.hits.load(Ordering::SeqCst)
    );
}

#[test]
fn rust_client_handoff_multi_dest_rewrite_and_block_zero_packets() {
    let root = std::env::temp_dir().join(format!("rr-handoff-multi-{}", free_port()));
    let _guard = DirGuard(root.clone());
    let stack = start_handoff_line_landing(&root, false, "chrome");

    let echo_a = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let echo_b = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let blocked_hits = Arc::new(AtomicUsize::new(0));
    let blocked_bind = SocketAddr::from((Ipv4Addr::new(10, 255, 0, 1), 0));
    let blocked_port = match StdUdpSocket::bind(blocked_bind) {
        Ok(sock) => {
            sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
            let port = sock.local_addr().unwrap().port();
            let hits = blocked_hits.clone();
            thread::spawn(move || {
                let mut buf = [0_u8; 2048];
                let deadline = Instant::now() + Duration::from_secs(20);
                while Instant::now() < deadline {
                    if sock.recv_from(&mut buf).is_ok() {
                        hits.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
            Some(port)
        }
        Err(_) => None,
    };

    let dest_a = SocketAddr::from((LINE_IP, echo_a.port));
    let dest_b = SocketAddr::from((LINE_IP, echo_b.port));
    let body_a = socks5_udp_round_trip(stack.socks_port, dest_a, b"A-via-handoff")
        .expect("first dest via Handoff");
    assert_eq!(body_a, b"A-via-handoff");
    assert_landing_is_udp_sender(&echo_a, stack.landing_pid, stack.entry_pid);

    // Keep rewrite to second authorized dest (default outbound = handoff).
    let body_b = socks5_udp_round_trip(stack.socks_port, dest_b, b"B-via-handoff")
        .expect("Keep rewrite dest B via Handoff");
    assert_eq!(body_b, b"B-via-handoff");
    assert_landing_is_udp_sender(&echo_b, stack.landing_pid, stack.entry_pid);

    if let Some(port) = blocked_port {
        let blocked = SocketAddr::from((Ipv4Addr::new(10, 255, 0, 1), port));
        let err = socks5_udp_round_trip(stack.socks_port, blocked, b"BLOCKED");
        assert!(
            err.is_err(),
            "Block rewrite must fail closed, got {:?}",
            err.ok()
        );
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            blocked_hits.load(Ordering::SeqCst),
            0,
            "Block rewrite must send zero packets to 10.x"
        );
    } else {
        // Without a bindable 10.x listener, still require SOCKS fail-closed to 10.x.
        let blocked = SocketAddr::from((Ipv4Addr::new(10, 255, 0, 2), 9));
        let err = socks5_udp_round_trip(stack.socks_port, blocked, b"BLOCKED");
        assert!(err.is_err(), "Block rewrite must fail closed: {err:?}");
    }
    eprintln!("rust_client_handoff_multi_dest_rewrite_and_block_zero_packets PASS");
}

#[test]
#[ignore = "requires CAP_NET_BIND_SERVICE for UDP/443 echo; Exact-head Native runs with --ignored"]
fn rust_client_handoff_udp443_allow_policy() {
    require_udp443_capability();
    // Negative: without allowUdp443. Keep the probe socket on this thread so
    // Drop releases :443 before the allow phase (no orphaned 30s echo thread).
    {
        let root = std::env::temp_dir().join(format!("rr-handoff-443-deny-{}", free_port()));
        let _guard = DirGuard(root.clone());
        let stack = start_handoff_line_landing(&root, false, "chrome");
        let echo = bind_udp(DEST_443);
        echo.set_read_timeout(Some(Duration::from_millis(300))).ok();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_bg = hits.clone();
        let echo_c = echo.try_clone().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = stop.clone();
        let join = thread::spawn(move || {
            let mut buf = [0_u8; 2048];
            while !stop_bg.load(Ordering::SeqCst) {
                if echo_c.recv_from(&mut buf).is_ok() {
                    hits_bg.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let err = socks5_udp_round_trip(stack.socks_port, DEST_443, MARKER);
        assert!(err.is_err(), "UDP/443 without allowUdp443 must fail");
        thread::sleep(Duration::from_millis(200));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "zero packets without allowUdp443"
        );
        stop.store(true, Ordering::SeqCst);
        drop(echo);
        let _ = join.join();
    }
    // Positive: with allowUdp443.
    {
        let root = std::env::temp_dir().join(format!("rr-handoff-443-allow-{}", free_port()));
        let _guard = DirGuard(root.clone());
        let stack = start_handoff_line_landing(&root, true, "chrome");
        let echo = spawn_udp_echo_on(DEST_443);
        let body = socks5_udp_round_trip(stack.socks_port, DEST_443, MARKER)
            .expect("UDP/443 with allowUdp443 via Handoff");
        assert_eq!(body, MARKER);
        assert_landing_is_udp_sender(&echo, stack.landing_pid, stack.entry_pid);
    }
    eprintln!("rust_client_handoff_udp443_allow_policy PASS");
}

fn require_stock_xray_bin() -> PathBuf {
    let path = std::env::var_os("XRAY_BIN").unwrap_or_else(|| {
        panic!("XRAY_BIN unset; Exact-head Native must export pinned stock Xray")
    });
    let path = PathBuf::from(path);
    assert!(path.is_file(), "XRAY_BIN={} missing", path.display());
    path
}

#[test]
#[ignore = "requires pinned stock Xray via XRAY_BIN; Exact-head Native runs with --ignored --exact"]
fn stock_xray_client_handoff_udp_echo_landing_is_sender() {
    let xray = require_stock_xray_bin();
    let root = std::env::temp_dir().join(format!("rr-handoff-xray-{}", free_port()));
    let _guard = DirGuard(root.clone());
    fs::create_dir_all(&root).expect("mkdir stock-xray-handoff root");
    let (cover_port, _cover) = start_openssl_cover(&root);
    let (reality_private, reality_public) = generate_x25519();
    let (landing_private, landing_public) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();

    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "{landing_ip}" }}],
  "landing": {{
    "protocol": "handoff",
    "psk": "{psk}",
    "privateKey": "{landing_private}"
  }}
}}
"#,
            landing_ip = LANDING_IP,
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ipv4": "{line_ip}" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "xray-handoff-udp"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "handoff",
      "address": "{landing_ip}",
      "port": {landing_port},
      "psk": "{psk}",
      "landingPublicKey": "{landing_public}",
      "warmTcp": false
    }}
  }},
  "routing": {{ "default": "landing-1" }}
}}
"#,
            line_ip = LINE_IP,
            landing_ip = LANDING_IP,
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
        "publicKey": "{reality_public}",
        "shortId": "{short_id}",
        "spiderX": "/"
      }}
    }}
  }}]
}}
"#
        ),
    );

    let landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp(LANDING_IP, landing_port, Duration::from_secs(20));
    let landing_pid = landing.0.id();
    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(LINE_IP, entry_port, Duration::from_secs(20));
    let entry_pid = entry.0.id();
    let _xray = spawn_logged(
        "xray-client",
        {
            let mut c = Command::new(&xray);
            c.args(["run", "-c"]).arg(root.join("xray-client.json"));
            c
        },
        &root.join("xray-client.log"),
    );
    wait_tcp(LINE_IP, socks_port, Duration::from_secs(20));

    let echo = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let dest = SocketAddr::from((LINE_IP, echo.port));
    let body = socks5_udp_round_trip(socks_port, dest, MARKER).unwrap_or_else(|e| {
        panic!(
            "stock Xray → Handoff UDP echo failed: {e}\nxray:\n{}\nentry:\n{}\nlanding:\n{}",
            fs::read_to_string(root.join("xray-client.log")).unwrap_or_default(),
            fs::read_to_string(root.join("entry.log")).unwrap_or_default(),
            fs::read_to_string(root.join("landing.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    assert_landing_is_udp_sender(&echo, landing_pid, entry_pid);

    // Regression: a domain destination repeated on Keep frames must reuse the
    // destination LINE sealed at transfer instead of tearing down the
    // association on LANDING after the first datagram.
    let first: &[u8] = b"rr-handoff-xudp-domain-1";
    let second: &[u8] = b"rr-handoff-xudp-domain-2";
    let third: &[u8] = b"rr-handoff-xudp-domain-3";
    let bodies = socks5_udp_domain_round_trips(
        socks_port,
        "localhost",
        echo.port,
        &[first, second, third],
    )
    .unwrap_or_else(|e| {
        panic!(
            "stock Xray → Handoff UDP domain Keep failed: {e}\nxray:\n{}\nentry:\n{}\nlanding:\n{}",
            fs::read_to_string(root.join("xray-client.log")).unwrap_or_default(),
            fs::read_to_string(root.join("entry.log")).unwrap_or_default(),
            fs::read_to_string(root.join("landing.log")).unwrap_or_default()
        );
    });
    assert_eq!(
        bodies,
        vec![first.to_vec(), second.to_vec(), third.to_vec()]
    );
    assert_landing_is_udp_sender(&echo, landing_pid, entry_pid);
    eprintln!("stock_xray_client_handoff_udp_echo_landing_is_sender PASS");
    let _ = (landing, entry);
}

#[test]
fn browser_profiles_handoff_tcp_preserve_bytes_and_half_close() {
    for fingerprint in ["chrome", "firefox"] {
        let root = std::env::temp_dir().join(format!("rr-handoff-tcp-browser-{}", free_port()));
        let _guard = DirGuard(root.clone());
        let stack = start_handoff_line_landing(&root, false, fingerprint);
        socks_tcp::assert_echo(stack.socks_port);
        socks_tcp::assert_reverse_half_close(stack.socks_port);
    }
}

// ---------------------------------------------------------------------------
// ADR 0069: the reported deployment shape over the native UDP channel.
// ---------------------------------------------------------------------------

/// Minimal protobuf writers for synthetic Xray `geoip.dat` / `geosite.dat`.
fn pb_bytes(output: &mut Vec<u8>, field: u8, value: &[u8]) {
    output.push((field << 3) | 2);
    let mut length = value.len();
    while length >= 0x80 {
        output.push(u8::try_from(length & 0x7f).unwrap() | 0x80);
        length >>= 7;
    }
    output.push(u8::try_from(length).unwrap());
    output.extend_from_slice(value);
}

fn pb_varint(output: &mut Vec<u8>, field: u8, value: u8) {
    output.push(field << 3);
    output.push(value);
}

/// `geosite:google` = `localhost`, `geosite:cn` = `ip6-loopback`: names the
/// LINE host resolver answers from `/etc/hosts` (routing resolves through
/// the operating system), standing in for real allowed and blocked sites.
fn geosite_fixture() -> Vec<u8> {
    let mut list = Vec::new();
    for (code, domain) in [("GOOGLE", "localhost"), ("CN", "ip6-loopback")] {
        let mut entry = Vec::new();
        pb_varint(&mut entry, 1, 3); // Domain type: Full
        pb_bytes(&mut entry, 2, domain.as_bytes());
        let mut site = Vec::new();
        pb_bytes(&mut site, 1, code.as_bytes());
        pb_bytes(&mut site, 2, &entry);
        pb_bytes(&mut list, 1, &site);
    }
    list
}

/// `geoip:private` = 10/8, 172.16/12, 192.168/16 (loopback deliberately
/// excluded so loopback echo peers stand in for public hosts);
/// `geoip:cn` = 127.0.0.9/32.
fn geoip_fixture() -> Vec<u8> {
    let mut list = Vec::new();
    for (code, cidrs) in [
        (
            "PRIVATE",
            &[
                ([10, 0, 0, 0], 8),
                ([172, 16, 0, 0], 12),
                ([192, 168, 0, 0], 16),
            ][..],
        ),
        ("CN", &[([127, 0, 0, 9], 32)][..]),
    ] {
        let mut geo = Vec::new();
        pb_bytes(&mut geo, 1, code.as_bytes());
        for (address, prefix) in cidrs {
            let mut cidr = Vec::new();
            pb_bytes(&mut cidr, 1, address);
            pb_varint(&mut cidr, 2, *prefix);
            pb_bytes(&mut geo, 2, &cidr);
        }
        pb_bytes(&mut list, 1, &geo);
    }
    list
}

/// Authoritative stub resolver for the `*.test` names LINE resolves.
fn spawn_dns_stub(hits: Arc<AtomicUsize>) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let socket = bind_udp(SocketAddr::from((LINE_IP, 0)));
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    let port = socket.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();
    let join = thread::spawn(move || {
        let mut buffer = [0_u8; 1500];
        while !stop_bg.load(Ordering::SeqCst) {
            let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                continue;
            };
            if let Some(answer) = dns_answer(&buffer[..length]) {
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = socket.send_to(&answer, from);
            }
        }
    });
    (port, stop, join)
}

fn dns_question(query: &[u8]) -> Option<(String, u16, usize)> {
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*query.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(query.get(offset..offset + length)?).to_lowercase());
        offset += length;
    }
    let qtype = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    Some((labels.join("."), qtype, offset + 4))
}

fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    let (name, qtype, end) = dns_question(query)?;
    let address: Option<[u8; 4]> = match name.as_str() {
        "allowed.rr-e2e.net" => Some([127, 0, 0, 1]),
        _ => None,
    };
    let mut response = query[..end].to_vec();
    response[2] = 0x84 | (query[2] & 0x01); // QR, AA, RD copied
    response[3] = if address.is_some() { 0x00 } else { 0x03 }; // NOERROR / NXDOMAIN
    let answer = address.filter(|_| qtype == 1);
    response[6..8].copy_from_slice(&u16::from(answer.is_some()).to_be_bytes());
    response[8..12].fill(0);
    if let Some(address) = answer {
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        response.extend_from_slice(&address);
    }
    Some(response)
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

/// RFC 5389 STUN server answering Binding Requests with the observed
/// source as XOR-MAPPED-ADDRESS.
fn spawn_stun(bind: SocketAddr) -> EchoPeer {
    let socket = bind_udp(bind);
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    let port = socket.local_addr().unwrap().port();
    let peers = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (peers_bg, hits_bg, stop_bg) = (peers.clone(), hits.clone(), stop.clone());
    let join = thread::spawn(move || {
        let mut buffer = [0_u8; 1500];
        while !stop_bg.load(Ordering::SeqCst) {
            let Ok((length, from)) = socket.recv_from(&mut buffer) else {
                continue;
            };
            if length < 20 || buffer[..2] != [0x00, 0x01] || buffer[4..8] != STUN_MAGIC {
                continue;
            }
            hits_bg.fetch_add(1, Ordering::SeqCst);
            peers_bg.lock().unwrap().push(from);
            let SocketAddr::V4(from4) = from else {
                continue;
            };
            let mut response = vec![0x01, 0x01, 0x00, 0x0c];
            response.extend_from_slice(&buffer[4..20]);
            let xport = from4.port() ^ 0x2112;
            let mut xaddr = from4.ip().octets();
            for (byte, magic) in xaddr.iter_mut().zip(STUN_MAGIC) {
                *byte ^= magic;
            }
            response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
            response.extend_from_slice(&xport.to_be_bytes());
            response.extend_from_slice(&xaddr);
            let _ = socket.send_to(&response, from);
        }
    });
    EchoPeer {
        peers,
        hits,
        port,
        stop,
        join: Some(join),
    }
}

const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

fn stun_binding_request(transaction: u8) -> Vec<u8> {
    let mut request = vec![0x00, 0x01, 0x00, 0x00];
    request.extend_from_slice(&STUN_MAGIC);
    request.extend_from_slice(&[transaction; 12]);
    request
}

fn stun_mapped_address(response: &[u8]) -> Option<SocketAddr> {
    if response.len() < 32 || response[..2] != [0x01, 0x01] || response[20..22] != [0x00, 0x20] {
        return None;
    }
    let port = u16::from_be_bytes([response[26], response[27]]) ^ 0x2112;
    let mut ip = [0_u8; 4];
    for (index, byte) in ip.iter_mut().enumerate() {
        *byte = response[28 + index] ^ STUN_MAGIC[index];
    }
    Some(SocketAddr::from((ip, port)))
}

/// One SOCKS5 UDP ASSOCIATE kept open for many datagrams.
struct SocksUdp {
    _control: TcpStream,
    udp: StdUdpSocket,
    relay: SocketAddr,
}

enum Target<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

impl SocksUdp {
    fn associate(socks_port: u16) -> Self {
        let mut control = TcpStream::connect((LINE_IP, socks_port)).expect("socks connect");
        control.set_read_timeout(Some(Duration::from_secs(8))).ok();
        control.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, 0x00]);
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut reply = [0_u8; 10];
        control.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..2], &[0x05, 0x00], "associate reply {reply:?}");
        let relay = SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        ));
        let udp = StdUdpSocket::bind((LINE_IP, 0)).unwrap();
        Self {
            _control: control,
            udp,
            relay,
        }
    }

    /// Sends one datagram and waits up to `wait` for one reply.
    fn exchange(&self, target: &Target<'_>, payload: &[u8], wait: Duration) -> Option<Vec<u8>> {
        let mut datagram = vec![0, 0, 0];
        match target {
            Target::Ip(SocketAddr::V4(address)) => {
                datagram.push(1);
                datagram.extend_from_slice(&address.ip().octets());
                datagram.extend_from_slice(&address.port().to_be_bytes());
            }
            Target::Ip(SocketAddr::V6(_)) => panic!("IPv4-only helper"),
            Target::Domain(host, port) => {
                datagram.push(3);
                datagram.push(u8::try_from(host.len()).unwrap());
                datagram.extend_from_slice(host.as_bytes());
                datagram.extend_from_slice(&port.to_be_bytes());
            }
        }
        datagram.extend_from_slice(payload);
        self.udp.send_to(&datagram, self.relay).unwrap();
        self.udp.set_read_timeout(Some(wait)).unwrap();
        let mut buffer = vec![0_u8; 65_535];
        let (length, _) = self.udp.recv_from(&mut buffer).ok()?;
        assert!(length >= 10 && buffer[3] == 1, "SOCKS UDP reply header");
        Some(buffer[10..length].to_vec())
    }
}

fn read_log(root: &Path, name: &str) -> String {
    fs::read_to_string(root.join(name)).unwrap_or_default()
}

/// The reported topology, end to end with stock Xray: LINE runs
/// `geoip:private` / `geosite` rules, `resolveOnDemand` DNS, and a
/// `via-landing` user policy; UDP to several destinations (IP and domain),
/// DNS and STUN traffic, and large datagrams all cross the native UDP
/// channel to LANDING, while every Block decision is enforced on LINE and
/// never reaches LANDING or the destination.
#[test]
#[ignore = "requires pinned stock Xray via XRAY_BIN; Exact-head Native runs with --ignored --exact"]
fn stock_xray_handoff_native_udp_user_routing_shape() {
    let xray = require_stock_xray_bin();
    let root = std::env::temp_dir().join(format!("rr-handoff-native-udp-{}", free_port()));
    let _guard = DirGuard(root.clone());
    fs::create_dir_all(root.join("assets")).expect("mkdir");
    fs::write(root.join("assets/geosite.dat"), geosite_fixture()).unwrap();
    fs::write(root.join("assets/geoip.dat"), geoip_fixture()).unwrap();
    let (cover_port, _cover) = start_openssl_cover(&root);
    let (reality_private, reality_public) = generate_x25519();
    let (landing_private, landing_public) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");
    let psk = generate("psk");
    let entry_port = free_port();
    let landing_port = free_port();
    let socks_port = free_port();
    let dns_hits = Arc::new(AtomicUsize::new(0));
    let (dns_port, dns_stop, dns_join) = spawn_dns_stub(dns_hits.clone());
    {
        let probe = StdUdpSocket::bind((LINE_IP, 0)).unwrap();
        probe
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        probe
            .send_to(&dns_query(7, "allowed.rr-e2e.net"), (LINE_IP, dns_port))
            .unwrap();
        let mut answer = [0_u8; 512];
        let (length, _) = probe.recv_from(&mut answer).expect("stub resolver answers");
        assert!(answer[..length].ends_with(&[127, 0, 0, 1]), "stub answer");
        dns_hits.store(0, Ordering::SeqCst);
    }

    write(
        &root.join("landing.json"),
        &format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "{LANDING_IP}" }}],
  "landing": {{ "protocol": "handoff", "psk": "{psk}", "privateKey": "{landing_private}" }},
  "log": {{ "level": "debug" }}
}}
"#
        ),
    );
    write(
        &root.join("entry.json"),
        &format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": {entry_port}, "ip": "ipv4Only", "ipv4": "{LINE_IP}" }}],
  "reality": {{
    "cover": "localhost:{cover_port}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}", "shortIds": ["{short_id}"], "label": "line-handoff", "policy": "via-landing"
  }}],
  "outbounds": {{
    "landing": {{
      "type": "handoff", "address": "{LANDING_IP}", "port": {landing_port},
      "psk": "{psk}", "landingPublicKey": "{landing_public}", "warmTcp": true
    }}
  }},
  "dns": {{ "servers": ["system"], "timeoutMs": 5000 }},
  "assets": {{
    "geoip": "https://127.0.0.1:9/geoip.dat",
    "geosite": "https://127.0.0.1:9/geosite.dat",
    "cacheDirectory": "{assets}"
  }},
  "routing": {{
    "default": "direct",
    "strategy": "resolveOnDemand",
    "rules": [
      {{ "name": "block-self-443", "ip": ["{LINE_IP}", "{LANDING_IP}"], "port": ["443"], "outbound": "block" }},
      {{ "name": "block-private", "ip": ["geoip:private"], "outbound": "block" }}
    ],
    "policies": {{
      "via-landing": {{
        "default": "landing",
        "rules": [
          {{ "name": "allow-google-services", "domain": ["geosite:google"], "outbound": "landing" }},
          {{ "name": "block-cn-domains", "domain": ["geosite:cn"], "outbound": "block" }},
          {{ "name": "block-cn-ip", "ip": ["geoip:cn"], "outbound": "block" }}
        ]
      }}
    }}
  }},
  "log": {{ "level": "debug" }}
}}
"#,
            assets = root.join("assets").display(),
        ),
    );
    write(
        &root.join("xray-client.json"),
        &format!(
            r#"{{
  "log": {{ "loglevel": "warning" }},
  "inbounds": [{{
    "listen": "127.0.0.1", "port": {socks_port}, "protocol": "mixed",
    "settings": {{ "auth": "noauth", "udp": true }}
  }}],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{ "vnext": [{{ "address": "127.0.0.1", "port": {entry_port},
      "users": [{{ "id": "{user_id}", "encryption": "none", "flow": "xtls-rprx-vision-udp443" }}] }}] }},
    "streamSettings": {{ "network": "tcp", "security": "reality",
      "realitySettings": {{ "fingerprint": "chrome", "serverName": "localhost",
        "publicKey": "{reality_public}", "shortId": "{short_id}", "spiderX": "/" }} }}
  }}]
}}
"#
        ),
    );

    let landing = spawn_logged(
        "landing",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("landing.json"));
            c
        },
        &root.join("landing.log"),
    );
    wait_tcp(LANDING_IP, landing_port, Duration::from_secs(20));
    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_tcp(LINE_IP, entry_port, Duration::from_secs(30));
    let _xray = spawn_logged(
        "xray-client",
        {
            let mut c = Command::new(&xray);
            c.args(["run", "-c"]).arg(root.join("xray-client.json"));
            c
        },
        &root.join("xray-client.log"),
    );
    wait_tcp(LINE_IP, socks_port, Duration::from_secs(20));
    let diagnostics = || {
        format!(
            "\ndns_hits={}\nentry:\n{}\nlanding:\n{}\nxray:\n{}",
            dns_hits.load(Ordering::SeqCst),
            read_log(&root, "entry.log"),
            read_log(&root, "landing.log"),
            read_log(&root, "xray-client.log")
        )
    };
    assert!(
        read_log(&root, "landing.log").contains("/udp"),
        "LANDING must announce its native UDP listener{}",
        diagnostics()
    );

    let echo_a = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let echo_b = spawn_udp_echo_on(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 3), 0)));
    let echo_cn = spawn_udp_echo_on(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 9), 0)));
    let stun = spawn_stun(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 4), 0)));
    let a = SocketAddr::from((LINE_IP, echo_a.port));
    let b = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 3), echo_b.port));
    let stun_addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 4), stun.port));
    let resolver = SocketAddr::from((LINE_IP, dns_port));
    let wait = Duration::from_secs(5);

    // One association, many destinations: the reported failure was that only
    // the first destination ever answered once geo rules were configured.
    let association = SocksUdp::associate(socks_port);
    let mut mapped = Vec::new();
    for round in 0..3_u8 {
        for (label, target) in [
            ("ip-a", Target::Ip(a)),
            ("ip-b", Target::Ip(b)),
            ("domain-allowed", Target::Domain("localhost", echo_a.port)),
        ] {
            let payload = format!("{label}-{round}").into_bytes();
            let body = association.exchange(&target, &payload, wait);
            assert_eq!(
                body.as_deref(),
                Some(payload.as_slice()),
                "{label} round {round}{}",
                diagnostics()
            );
        }
        // DNS as UDP payload through the channel.
        let query = dns_query(0x4200 + u16::from(round), "allowed.rr-e2e.net");
        let answer = association
            .exchange(&Target::Ip(resolver), &query, wait)
            .unwrap_or_else(|| panic!("DNS through the channel{}", diagnostics()));
        assert_eq!(&answer[..2], &query[..2], "DNS id");
        assert!(answer.ends_with(&[127, 0, 0, 1]), "DNS answer {answer:?}");
        // STUN: the mapped address is LANDING's egress, stable across rounds.
        let response = association
            .exchange(&Target::Ip(stun_addr), &stun_binding_request(round), wait)
            .unwrap_or_else(|| panic!("STUN through the channel{}", diagnostics()));
        let address = stun_mapped_address(&response).expect("XOR-MAPPED-ADDRESS");
        assert_eq!(address.ip(), IpAddr::V4(LANDING_IP), "STUN sees LANDING");
        mapped.push(address);
    }
    assert!(
        mapped.windows(2).all(|pair| pair[0] == pair[1]),
        "one stable mapping per association: {mapped:?}"
    );
    // Large datagrams (QUIC Initial size and beyond) on the same association.
    for size in [1_200_usize, 1_252, 1_400, 4_096, 7_000] {
        let payload: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let body = association.exchange(&Target::Ip(a), &payload, wait);
        assert_eq!(
            body.as_deref(),
            Some(payload.as_slice()),
            "{size}-byte datagram{}",
            diagnostics()
        );
    }
    assert_landing_is_udp_sender(&echo_a, landing.0.id(), entry.0.id());
    assert_landing_is_udp_sender(&echo_b, landing.0.id(), entry.0.id());
    drop(association);

    // Blocked destinations: each in its own association (LINE fails the
    // association closed on Block). Nothing may arrive anywhere.
    for (label, target) in [
        (
            "geoip:private",
            Target::Ip(SocketAddr::from(([10, 1, 2, 3], echo_a.port))),
        ),
        ("geosite:cn", Target::Domain("ip6-loopback", echo_a.port)),
        (
            "geoip:cn",
            Target::Ip(SocketAddr::from(([127, 0, 0, 9], echo_cn.port))),
        ),
        (
            "block-self-443",
            Target::Ip(SocketAddr::from((LANDING_IP, 443))),
        ),
    ] {
        let hits_before = echo_a.hits.load(Ordering::SeqCst);
        let blocked = SocksUdp::associate(socks_port);
        let body = blocked.exchange(
            &target,
            format!("blocked {label}").as_bytes(),
            Duration::from_secs(2),
        );
        assert!(
            body.is_none(),
            "{label} must be blocked on LINE{}",
            diagnostics()
        );
        assert_eq!(
            echo_a.hits.load(Ordering::SeqCst),
            hits_before,
            "{label} reached a destination"
        );
    }
    assert_eq!(
        echo_cn.hits.load(Ordering::SeqCst),
        0,
        "geoip:cn destination saw traffic"
    );

    // The service is intact after the blocks.
    let fresh = SocksUdp::associate(socks_port);
    assert_eq!(
        fresh
            .exchange(&Target::Ip(b), b"after-blocks", wait)
            .as_deref(),
        Some(&b"after-blocks"[..]),
        "{}",
        diagnostics()
    );
    drop(fresh);
    // LANDING saw exactly the two allowed associations as native UDP
    // channel sessions (LINE closes each one); the blocked associations
    // never sent it an OPEN.
    let deadline = Instant::now() + Duration::from_secs(10);
    let sessions = loop {
        let ended: Vec<String> = read_log(&root, "landing.log")
            .lines()
            .filter(|line| line.contains("\"event\":\"handoff_udp_session_ended\""))
            .map(str::to_owned)
            .collect();
        if ended.len() >= 2 || Instant::now() >= deadline {
            break ended;
        }
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(
        sessions.len(),
        2,
        "native UDP sessions on LANDING: {sessions:#?}{}",
        diagnostics()
    );
    for session in &sessions {
        assert!(session.contains("\"reason\":\"close\""), "{session}");
        assert!(!session.contains("\"uplink_datagrams\":0,"), "{session}");
    }
    eprintln!("landing native UDP sessions: {sessions:#?}");
    assert_eq!(
        dns_hits.load(Ordering::SeqCst),
        3,
        "every tunneled DNS query reached the resolver exactly once"
    );
    dns_stop.store(true, Ordering::SeqCst);
    let _ = dns_join.join();
    eprintln!(
        "stock_xray_handoff_native_udp_user_routing_shape PASS mapped={:?} echo_a_peers={:?}",
        mapped[0],
        echo_a.peers.lock().unwrap().first()
    );
    let _ = (landing, entry);
}
