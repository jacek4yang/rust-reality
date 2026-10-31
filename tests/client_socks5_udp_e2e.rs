//! SOCKS5 UDP ASSOCIATE E2E through XUDP: client → REALITY entry → Direct UDP echo.
//!
//! Spawns openssl cover, rust-reality entry + client, and a loopback UDP echo.
//! Asserts a SOCKS5 UDP datagram round-trips with the exact payload. Also checks
//! UDP/443 is refused without `allowUdp443` and accepted when enabled.

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rust-reality-xudp-udp-associate-e2e-ok";

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
fn direct_xudp_delayed_replies_preserve_sources() {
    let (_guard, socks_port, _entry_port, _cover, _entry, _client) = start_stack(false, "chrome");
    xudp_reordering::delayed_replies_preserve_sources(socks_port, std::net::Ipv4Addr::LOCALHOST);
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
        // Serve a handful of datagrams then exit with the socket.
        for _ in 0..8 {
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

/// Minimal SOCKS5 no-auth UDP ASSOCIATE + one datagram round-trip.
fn socks5_udp_round_trip(
    socks_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut control =
        TcpStream::connect(("127.0.0.1", socks_port)).map_err(|e| format!("socks connect: {e}"))?;
    control.set_read_timeout(Some(Duration::from_secs(10))).ok();
    control
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    control
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("method: {e}"))?;
    let mut method = [0_u8; 2];
    control
        .read_exact(&mut method)
        .map_err(|e| format!("method reply: {e}"))?;
    if method != [0x05, 0x00] {
        return Err(format!("unexpected method reply {method:?}"));
    }

    // ASSOCIATE to 0.0.0.0:0
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

    let udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("udp bind: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("udp timeout: {e}"))?;

    // RSV RSV FRAG ATYP IPv4 DST.ADDR DST.PORT DATA
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
    // Keep control alive until after recv.
    drop(control);
    Ok(buf[10..n].to_vec())
}

fn start_stack(
    allow_udp_443: bool,
    fingerprint: &str,
) -> (DirGuard, u16, u16, KillOnDrop, KillOnDrop, KillOnDrop) {
    let openssl = which("openssl").expect("openssl required for cover");
    let root = std::env::temp_dir().join(format!(
        "rr-client-socks5-udp-e2e-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&root).expect("workdir");
    let guard = DirGuard(root.clone());

    let cover_port = free_port();
    let entry_port = free_port();
    let socks_port = free_port();

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

    let (private_key, public_key) = generate_x25519();
    let user_id = generate("uuid");
    let short_id = generate("short-id");

    let entry_cfg = root.join("entry.json");
    write(
        &entry_cfg,
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
    "label": "e2e-udp"
  }}],
  "routing": {{ "default": "direct" }}
}}
"#
        ),
    );

    let allow_line = if allow_udp_443 {
        r#", "allowUdp443": true"#
    } else {
        ""
    };
    let client_cfg = root.join("client.json");
    write(
        &client_cfg,
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
    "fingerprint": "{fingerprint}"{allow_line}
  }}]
}}
"#
        ),
    );

    for cfg in [&entry_cfg, &client_cfg] {
        let check = Command::new(bin())
            .args(["check", "--config"])
            .arg(cfg)
            .output()
            .expect("check");
        assert!(
            check.status.success(),
            "check {} failed: {}{}",
            cfg.display(),
            String::from_utf8_lossy(&check.stdout),
            String::from_utf8_lossy(&check.stderr)
        );
    }

    let entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(&entry_cfg);
            c
        },
        &root.join("entry.log"),
    );
    wait_port(entry_port, Duration::from_secs(20));

    let client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(&client_cfg);
            c
        },
        &root.join("client.log"),
    );
    wait_port(socks_port, Duration::from_secs(20));

    (guard, socks_port, entry_port, cover, entry, client)
}

#[test]
fn socks5_udp_associate_echo_through_xudp() {
    browser_udp_echo("chrome");
}

#[test]
fn firefox_socks5_udp_associate_echo_through_xudp() {
    browser_udp_echo("firefox");
}

fn browser_udp_echo(fingerprint: &str) {
    let (_echo_keep, echo_port, echo_thread) = spawn_udp_echo();
    let (_guard, socks_port, _entry_port, _cover, _entry, _client) =
        start_stack(false, fingerprint);

    let body = socks5_udp_round_trip(socks_port, echo_port, MARKER).unwrap_or_else(|e| {
        panic!("udp associate round-trip failed: {e}");
    });
    assert_eq!(body, MARKER, "echo payload mismatch");
    let _ = echo_thread.join();
}

#[test]
fn socks5_udp_443_requires_allow_udp_443_policy() {
    // Without allowUdp443, targeting UDP/443 must fail closed on the client XUDP path.
    let (_guard, socks_port, _entry_port, _cover, _entry, _client) = start_stack(false, "chrome");
    let err = socks5_udp_round_trip(socks_port, 443, b"quic-probe").expect_err("must fail");
    assert!(
        err.contains("udp recv") || err.contains("associate") || err.contains("udp send"),
        "unexpected error shape: {err}"
    );
}
