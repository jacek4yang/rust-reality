//! NXR UDP end-to-end (ADR 0060 Option A / Issue #314 PR3).
//!
//! Topology:
//!   Client (rust-reality or stock Xray) → REALITY+Vision+XUDP → LINE (entry)
//!     → NXR UDP framed TCP → LANDING → Internet-facing UDP.
//!
//! LANDING listens on `127.0.0.2` so echo peers observe source `127.0.0.2`,
//! proving LANDING (not LINE on `127.0.0.1`) owns the UDP socket.
//!
//! Process-level echo / multi-dest / Block tests run unprivileged.
//! UDP/443 + genuine HTTP/3 and stock Xray cases are `#[ignore]` and wired
//! into Exact-head Native like the Direct XUDP gates.

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rr-nxr-xudp-echo-ok";
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

fn free_port() -> u16 {
    TcpListener::bind((LINE_IP, 0))
        .expect("ephemeral")
        .local_addr()
        .expect("addr")
        .port()
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
struct NxrStack {
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

fn start_nxr_line_landing(root: &Path, allow_udp_443: bool, fingerprint: &str) -> NxrStack {
    fs::create_dir_all(root).unwrap();
    let (cover_port, cover) = start_openssl_cover(root);
    let (private_key, public_key) = generate_x25519();
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
  "landing": {{ "protocol": "nxr", "psk": "{psk}" }}
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
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "nxr-xudp"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "nxr",
      "address": "{landing_ip}",
      "port": {landing_port},
      "psk": "{psk}",
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
    "publicKey": "{public_key}",
    "shortId": "{short_id}",
    "serverName": "localhost",
    "fingerprint": "{fingerprint}"{allow_line}
  }}]
}}
"#,
            line_ip = LINE_IP,
        ),
    );
    // Persist identity for stock Xray client fixtures.
    write(
        &root.join("identity.env"),
        &format!(
            "USER_ID={user_id}\nPUBLIC_KEY={public_key}\nSHORT_ID={short_id}\nENTRY_PORT={entry_port}\n"
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

    NxrStack {
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
            "UDP source must be LANDING {LANDING_IP}, got {peer} (LINE is {LINE_IP});              landing_pid={landing_pid} entry_pid={entry_pid}"
        );
        assert_ne!(
            peer.ip(),
            IpAddr::V4(LINE_IP),
            "UDP source must not be LINE {LINE_IP}"
        );
    }
    // Hard gate is peer-IP equality above. `ss -ulnp` lines often omit the
    // literal "udp" token and associations may already be closed after SOCKS
    // control EOF — treat process socket census as bonus diagnostics only.
    if let Ok(output) = Command::new("ss").args(["-ulnpH"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        let entry_marker = format!("pid={entry_pid}");
        let entry_udp_to_echo = text
            .lines()
            .any(|l| l.contains(&entry_marker) && l.contains(&format!(":{}", echo.port)));
        assert!(
            !entry_udp_to_echo,
            "LINE pid={entry_pid} must not own UDP toward echo :{};
ss:
{text}",
            echo.port
        );
        eprintln!(
            "landing_udp_sender_proof peers={peers:?} landing_pid={landing_pid} entry_pid={entry_pid}"
        );
    }
}

#[test]
fn rust_client_nxr_udp_echo_landing_is_sender() {
    browser_udp_echo("chrome");
}

#[test]
fn firefox_nxr_udp_echo_landing_is_sender() {
    browser_udp_echo("firefox");
}

fn browser_udp_echo(fingerprint: &str) {
    let root = std::env::temp_dir().join(format!("rr-nxr-echo-{}", free_port()));
    let _guard = DirGuard(root.clone());
    let stack = start_nxr_line_landing(&root, false, fingerprint);
    let echo = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let dest = SocketAddr::from((LINE_IP, echo.port));
    let body = socks5_udp_round_trip(stack.socks_port, dest, MARKER).unwrap_or_else(|e| {
        panic!(
            "NXR UDP echo failed: {e}\nentry:\n{}\nlanding:\n{}\nclient:\n{}",
            fs::read_to_string(root.join("entry.log")).unwrap_or_default(),
            fs::read_to_string(root.join("landing.log")).unwrap_or_default(),
            fs::read_to_string(root.join("client.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    assert_landing_is_udp_sender(&echo, stack.landing_pid, stack.entry_pid);
    eprintln!(
        "rust_client_nxr_udp_echo_landing_is_sender PASS (peers={:?}, hits={})",
        *echo.peers.lock().unwrap(),
        echo.hits.load(Ordering::SeqCst)
    );
}

#[test]
fn rust_client_nxr_multi_dest_rewrite_and_block_zero_packets() {
    let root = std::env::temp_dir().join(format!("rr-nxr-multi-{}", free_port()));
    let _guard = DirGuard(root.clone());
    let stack = start_nxr_line_landing(&root, false, "chrome");

    let echo_a = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let echo_b = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    // Separate blocked-destination echo on 10.x when the OS allows binding it.
    let blocked_hits = Arc::new(AtomicUsize::new(0));
    let blocked_bind = SocketAddr::from((Ipv4Addr::new(10, 255, 0, 1), 0));
    let blocked_port = match StdUdpSocket::bind(blocked_bind) {
        Ok(sock) => {
            sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
            let port = sock.local_addr().unwrap().port();
            let hits = blocked_hits.clone();
            thread::spawn(move || {
                let mut buf = [0_u8; 2048];
                let deadline = Instant::now() + Duration::from_secs(8);
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
    let got_a = socks5_udp_round_trip(stack.socks_port, dest_a, b"dest-a").expect("dest-a");
    assert_eq!(got_a, b"dest-a");
    let got_b = socks5_udp_round_trip(stack.socks_port, dest_b, b"dest-b").expect("dest-b");
    assert_eq!(got_b, b"dest-b");
    assert_landing_is_udp_sender(&echo_a, stack.landing_pid, stack.entry_pid);
    assert_landing_is_udp_sender(&echo_b, stack.landing_pid, stack.entry_pid);

    if let Some(port) = blocked_port {
        let blocked = SocketAddr::from((Ipv4Addr::new(10, 255, 0, 1), port));
        let err = socks5_udp_round_trip(stack.socks_port, blocked, b"blocked-should-fail");
        assert!(
            err.is_err(),
            "Block rewrite must fail closed, got {:?}",
            err.ok()
        );
        thread::sleep(Duration::from_millis(400));
        assert_eq!(
            blocked_hits.load(Ordering::SeqCst),
            0,
            "forbidden Block destination must receive zero UDP datagrams"
        );
    } else {
        // Fallback: route toward 10.1.2.3 (blocked) even if we cannot bind there.
        let blocked = SocketAddr::from((Ipv4Addr::new(10, 1, 2, 3), 9));
        let err = socks5_udp_round_trip(stack.socks_port, blocked, b"blocked-should-fail");
        assert!(err.is_err(), "Block rewrite must fail closed: {err:?}");
    }

    eprintln!("rust_client_nxr_multi_dest_rewrite_and_block_zero_packets PASS");
}

#[test]
fn rust_client_nxr_association_teardown_recovers() {
    let root = std::env::temp_dir().join(format!("rr-nxr-teardown-{}", free_port()));
    let _guard = DirGuard(root.clone());
    let stack = start_nxr_line_landing(&root, false, "chrome");
    let echo = spawn_udp_echo_on(SocketAddr::from((LINE_IP, 0)));
    let dest = SocketAddr::from((LINE_IP, echo.port));
    for i in 0..3 {
        let payload = format!("teardown-{i}");
        let got = socks5_udp_round_trip(stack.socks_port, dest, payload.as_bytes())
            .unwrap_or_else(|e| panic!("round {i}: {e}"));
        assert_eq!(got, payload.as_bytes());
    }
    eprintln!("rust_client_nxr_association_teardown_recovers PASS (3 sequential associations)");
}

fn require_udp443_capability() {
    let _probe = bind_udp(DEST_443);
}

#[test]
#[ignore = "requires CAP_NET_BIND_SERVICE for 127.0.0.1:443; Exact-head Native runs with --ignored"]
fn rust_client_nxr_udp443_allow_policy() {
    require_udp443_capability();
    // Negative: without allowUdp443.
    {
        let root = std::env::temp_dir().join(format!("rr-nxr-443-deny-{}", free_port()));
        let _guard = DirGuard(root.clone());
        let stack = start_nxr_line_landing(&root, false, "chrome");
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
        let root = std::env::temp_dir().join(format!("rr-nxr-443-allow-{}", free_port()));
        let _guard = DirGuard(root.clone());
        let stack = start_nxr_line_landing(&root, true, "chrome");
        let echo = spawn_udp_echo_on(DEST_443);
        let body = socks5_udp_round_trip(stack.socks_port, DEST_443, MARKER)
            .expect("UDP/443 with allowUdp443 via NXR");
        assert_eq!(body, MARKER);
        assert_landing_is_udp_sender(&echo, stack.landing_pid, stack.entry_pid);
    }
    eprintln!("rust_client_nxr_udp443_allow_policy PASS");
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
fn stock_xray_client_nxr_udp_echo_landing_is_sender() {
    let xray = require_stock_xray_bin();
    let root = std::env::temp_dir().join(format!("rr-nxr-xray-{}", free_port()));
    let _guard = DirGuard(root.clone());
    fs::create_dir_all(&root).expect("mkdir stock-xray-nxr root");
    // Start LINE+LANDING without rust client; stock Xray is the client.
    let (cover_port, _cover) = start_openssl_cover(&root);
    let (private_key, public_key) = generate_x25519();
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
  "landing": {{ "protocol": "nxr", "psk": "{psk}" }}
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
    "privateKey": "{private_key}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{
    "id": "{user_id}",
    "shortIds": ["{short_id}"],
    "label": "xray-nxr-udp"
  }}],
  "outbounds": {{
    "landing-1": {{
      "type": "nxr",
      "address": "{landing_ip}",
      "port": {landing_port},
      "psk": "{psk}",
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
            "stock Xray → NXR UDP echo failed: {e}\nxray:\n{}\nentry:\n{}\nlanding:\n{}",
            fs::read_to_string(root.join("xray-client.log")).unwrap_or_default(),
            fs::read_to_string(root.join("entry.log")).unwrap_or_default(),
            fs::read_to_string(root.join("landing.log")).unwrap_or_default()
        );
    });
    assert_eq!(body, MARKER);
    assert_landing_is_udp_sender(&echo, landing_pid, entry_pid);
    eprintln!("stock_xray_client_nxr_udp_echo_landing_is_sender PASS");
    let _ = (landing, entry);
}
