//! Single-LINE HTTP CONNECT E2E: curl -x → loopback HTTP CONNECT client →
//! REALITY entry → isolated HTTPS origin.
//!
//! Uses HTTPS so curl speaks CONNECT (HTTPS_PROXY style). Plain HTTP through an
//! HTTP proxy would be absolute-form GET, which this inbound deliberately rejects.
//! Ambient proxy variables are stripped so curl honours `-x http://…`.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rust-reality-unified-client-http-connect-e2e-ok\n";

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[path = "support/ports.rs"]
mod ports;
use ports::free_port;

fn wait_port(port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
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

fn make_tls_material(openssl: &Path, root: &Path, name: &str) -> (PathBuf, PathBuf) {
    let key = root.join(format!("{name}.key"));
    let crt = root.join(format!("{name}.crt"));
    assert!(
        Command::new(openssl)
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("openssl req")
            .success(),
        "openssl req failed for {name}"
    );
    (key, crt)
}

#[test]
fn curl_through_single_line_http_connect_to_isolated_origin() {
    run_https_transfer("chrome");
}

#[test]
fn firefox_http_connect_to_isolated_origin() {
    run_https_transfer("firefox");
}

fn run_https_transfer(fingerprint: &str) {
    let openssl = which("openssl").expect("openssl required");
    let curl = which("curl").expect("curl required");

    let root = std::env::temp_dir().join(format!(
        "rr-client-http-connect-e2e-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&root).expect("workdir");
    let _guard = DirGuard(root.clone());

    let cover_port = free_port();
    let entry_port = free_port();
    let origin_port = free_port();
    let http_port = free_port();

    let (cover_key, cover_crt) = make_tls_material(&openssl, &root, "cover");
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
            .arg(&cover_crt)
            .arg("-key")
            .arg(&cover_key)
            .stdin(Stdio::null());
            c
        },
        &root.join("cover.log"),
    );
    wait_port(cover_port, Duration::from_secs(10));

    // Isolated HTTPS origin: openssl -WWW serves files after TLS.
    let payload = root.join("payload.txt");
    let expected = MARKER.repeat(32 * 1024);
    fs::write(&payload, &expected).expect("payload");
    let (origin_key, origin_crt) = make_tls_material(&openssl, &root, "origin");
    let _origin = spawn_logged(
        "https-origin",
        {
            let mut c = Command::new(&openssl);
            c.args([
                "s_server",
                "-tls1_3",
                "-quiet",
                "-accept",
                &origin_port.to_string(),
                "-cert",
            ])
            .arg(&origin_crt)
            .arg("-key")
            .arg(&origin_key)
            .arg("-WWW")
            .current_dir(&root)
            .stdin(Stdio::null());
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
  "listeners": [{{
    "port": {http_port},
    "ipv4": "127.0.0.1",
    "protocol": "http"
  }}],
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
    wait_port(http_port, Duration::from_secs(15));

    // HTTPS forces CONNECT through the HTTP proxy.
    let url = format!("https://localhost:{origin_port}/payload.txt");
    let out = root.join("curl.out");
    let mut curl_cmd = Command::new(&curl);
    curl_cmd
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "20",
            "--noproxy",
            "",
            "--cacert",
            origin_crt.to_str().expect("certificate path"),
            "-x",
            &format!("http://127.0.0.1:{http_port}"),
            "--output",
        ])
        .arg(&out)
        .arg(&url)
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
    let status = curl_cmd.status().expect("curl");
    if !status.success() {
        let entry_log = fs::read_to_string(root.join("entry.log")).unwrap_or_default();
        let client_log = fs::read_to_string(root.join("client.log")).unwrap_or_default();
        panic!(
            "curl failed ({status:?})\n--- entry.log ---\n{entry_log}\n--- client.log ---\n{client_log}"
        );
    }
    let body = fs::read(&out).expect("read curl out");
    assert_eq!(body, expected, "origin payload mismatch");
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
