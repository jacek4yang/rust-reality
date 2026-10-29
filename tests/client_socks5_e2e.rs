//! Single-LINE SOCKS5 E2E: curl → loopback SOCKS5 client → REALITY entry →
//! isolated HTTP origin.
//!
//! Spawns real processes (openssl cover, python origin, rust-reality entry +
//! client) and asserts the curl body is exactly the origin payload. Ambient
//! proxy variables are stripped so curl honours `--socks5-hostname`.

use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rust-reality-unified-client-socks5-e2e-ok\n";

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            // Port is taken — good enough signal something is listening.
            // Prefer connect probe:
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
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
    let mut file = fs::File::create(path).expect("create");
    file.write_all(body.as_bytes()).expect("write");
}

fn spawn_logged(name: &str, mut command: Command, log: &Path) -> KillOnDrop {
    let log_file = fs::File::create(log).expect("log");
    command.stdout(Stdio::from(log_file.try_clone().expect("clone")));
    command.stderr(Stdio::from(log_file));
    let child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    KillOnDrop(child)
}

#[test]
fn curl_through_single_line_socks5_to_isolated_origin() {
    run_socks5("chrome");
}

#[test]
fn firefox_through_single_line_socks5_to_isolated_origin() {
    run_socks5("firefox");
}

fn run_socks5(fingerprint: &str) {
    let openssl = which("openssl").expect("openssl required for cover");
    let python = which("python3").expect("python3 required for origin");
    let curl = which("curl").expect("curl required");

    let root = std::env::temp_dir().join(format!(
        "rr-client-socks5-e2e-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&root).expect("workdir");
    let _guard = DirGuard(root.clone());

    let cover_port = free_port();
    let entry_port = free_port();
    let origin_port = free_port();
    let socks_port = free_port();

    // --- cover (TLS 1.3) ---
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
    let _cover = spawn_logged(
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
    wait_port(cover_port, Duration::from_secs(10));

    // --- isolated origin ---
    let payload = root.join("payload.txt");
    fs::write(&payload, MARKER).expect("payload");
    let _origin = spawn_logged(
        "http-origin",
        {
            let mut c = Command::new(&python);
            c.args([
                "-m",
                "http.server",
                &origin_port.to_string(),
                "--bind",
                "127.0.0.1",
                "--directory",
            ])
            .arg(&root);
            c
        },
        &root.join("origin.log"),
    );
    wait_port(origin_port, Duration::from_secs(10));

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
    "label": "e2e"
  }}],
  "routing": {{ "default": "direct" }}
}}
"#
        ),
    );

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
    "fingerprint": "{fingerprint}"
  }}]
}}
"#
        ),
    );

    // Validate configs first for clearer failures.
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

    let _entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(&entry_cfg);
            c
        },
        &root.join("entry.log"),
    );
    wait_port(entry_port, Duration::from_secs(15));

    let _client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(&client_cfg);
            c
        },
        &root.join("client.log"),
    );
    wait_port(socks_port, Duration::from_secs(15));

    let url = format!("http://127.0.0.1:{origin_port}/payload.txt");
    let out = root.join("curl.out");
    let mut curl_cmd = Command::new(&curl);
    curl_cmd
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "20",
            "--socks5-hostname",
            &format!("127.0.0.1:{socks_port}"),
            "--output",
        ])
        .arg(&out)
        .arg(&url)
        // Strip ambient proxies so loopback URLs do not bypass SOCKS5.
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env("NO_PROXY", "*")
        .env("no_proxy", "*");
    let status = curl_cmd.status().expect("curl");
    if !status.success() {
        let entry_log = fs::read_to_string(root.join("entry.log")).unwrap_or_default();
        let client_log = fs::read_to_string(root.join("client.log")).unwrap_or_default();
        panic!(
            "curl failed ({status:?})\n--- entry.log ---\n{entry_log}\n--- client.log ---\n{client_log}"
        );
    }
    let body = fs::read(&out).expect("read curl out");
    assert_eq!(
        body,
        MARKER,
        "origin payload mismatch: got {:?}",
        String::from_utf8_lossy(&body)
    );
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
