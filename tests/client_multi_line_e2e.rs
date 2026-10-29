//! Multi-LINE pre-commit failover: primary LINE dials a closed port; alternate
//! authenticates and serves curl through SOCKS5. Confirms selection races before
//! the SOCKS5 success reply and does not require mid-session migration.

use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MARKER: &[u8] = b"rust-reality-unified-client-multi-line-e2e-ok\n";

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn wait_port(port: u16, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("port {port} not ready");
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
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
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
    (private.unwrap(), public.unwrap())
}

fn write(path: &Path, body: &str) {
    fs::File::create(path)
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
}

fn spawn_logged(name: &str, mut command: Command, log: &Path) -> KillOnDrop {
    let log_file = fs::File::create(log).unwrap();
    command.stdout(Stdio::from(log_file.try_clone().unwrap()));
    command.stderr(Stdio::from(log_file));
    KillOnDrop(command.spawn().unwrap_or_else(|e| panic!("{name}: {e}")))
}

#[test]
fn failover_from_dead_primary_to_live_alternate_before_socks5_reply() {
    let openssl = which("openssl").expect("openssl");
    let python = which("python3").expect("python3");
    let curl = which("curl").expect("curl");

    let root = std::env::temp_dir().join(format!(
        "rr-multi-line-e2e-{}-{}",
        std::process::id(),
        free_port()
    ));
    fs::create_dir_all(&root).unwrap();
    let _guard = DirGuard(root.clone());

    let cover_port = free_port();
    let entry_port = free_port();
    let dead_port = free_port(); // never listen — primary LINE target
    let origin_port = free_port();
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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let _cover = spawn_logged(
        "cover",
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

    fs::write(root.join("payload.txt"), MARKER).unwrap();
    let _origin = spawn_logged(
        "origin",
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
  "users": [{{ "id": "{user_id}", "shortIds": ["{short_id}"], "label": "e2e" }}],
  "routing": {{ "default": "direct" }}
}}"#
        ),
    );

    // Primary → dead_port (connection refused); alternate → live entry.
    // Short hedge so failover is prompt after primary dial fails.
    write(
        &root.join("client.json"),
        &format!(
            r#"{{
  "role": "client",
  "listeners": [{{ "port": {socks_port}, "ipv4": "127.0.0.1", "lineGroup": "edge" }}],
  "lines": [
    {{
      "tag": "dead",
      "address": "127.0.0.1",
      "port": {dead_port},
      "id": "{user_id}",
      "publicKey": "{public_key}",
      "shortId": "{short_id}",
      "serverName": "localhost"
    }},
    {{
      "tag": "live",
      "address": "127.0.0.1",
      "port": {entry_port},
      "id": "{user_id}",
      "publicKey": "{public_key}",
      "shortId": "{short_id}",
      "serverName": "localhost",
      "fingerprint": "firefox"
    }}
  ],
  "lineGroups": [{{ "name": "edge", "lines": ["dead", "live"] }}],
  "selection": {{ "hedgeMs": 100, "timeoutMs": 10000 }}
}}"#
        ),
    );

    for name in ["entry.json", "client.json"] {
        let check = Command::new(bin())
            .args(["check", "--config"])
            .arg(root.join(name))
            .output()
            .unwrap();
        assert!(
            check.status.success(),
            "{}: {}",
            name,
            String::from_utf8_lossy(&check.stderr)
        );
    }

    let _entry = spawn_logged(
        "entry",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("entry.json"));
            c
        },
        &root.join("entry.log"),
    );
    wait_port(entry_port, Duration::from_secs(15));

    let _client = spawn_logged(
        "client",
        {
            let mut c = Command::new(bin());
            c.args(["run", "--config"]).arg(root.join("client.json"));
            c
        },
        &root.join("client.log"),
    );
    wait_port(socks_port, Duration::from_secs(15));

    let url = format!("http://127.0.0.1:{origin_port}/payload.txt");
    let out = root.join("curl.out");
    let status = Command::new(&curl)
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
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .args(["--noproxy", ""])
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .status()
        .unwrap();
    if !status.success() {
        panic!(
            "curl failed: {}\n--- client ---\n{}\n--- entry ---\n{}",
            status,
            fs::read_to_string(root.join("client.log")).unwrap_or_default(),
            fs::read_to_string(root.join("entry.log")).unwrap_or_default()
        );
    }
    assert_eq!(fs::read(&out).unwrap(), MARKER);
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    })
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
