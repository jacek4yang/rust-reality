//! End-to-end CLI diagnostics: the `check` command renders the shared
//! compiler-style diagnostic to stderr and fails the command.

use std::{path::PathBuf, process::Command};

fn workspace(name: &str, contents: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "rust-reality-cli-diagnostics-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("workspace must be creatable");
    let path = directory.join("config.json");
    std::fs::write(&path, contents).expect("fixture must be writable");
    path
}

#[test]
fn check_renders_the_shared_diagnostic_on_stderr() {
    let path = workspace(
        "invalid-enum",
        "{\n  \"inbounds\": [],\n  \"outbounds\": [],\n  \"routing\": { \"users\": [] },\n  \"runtime\": { \"profile\": \"server\" }\n}\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rust-reality"))
        .arg("check")
        .arg("--config")
        .arg(&path)
        .output()
        .expect("the binary must run");
    assert!(!output.status.success(), "an invalid config must fail");
    assert!(
        output.stdout.is_empty(),
        "failures report on stderr only: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostics must be UTF-8");
    let (head, tail) = stderr
        .split_once(path.to_str().expect("temp paths are UTF-8"))
        .expect("the diagnostic must name the config file");
    assert_eq!(head, "error: invalid value for `runtime.profile`\n --> ");
    assert_eq!(
        tail,
        concat!(
            ":5:27\n",
            "  |\n",
            "5 |   \"runtime\": { \"profile\": \"server\" }\n",
            "  |                           ^^^^^^^^ expected \"auto\", \"shared\", or \"dedicated\"\n",
            "  |\n",
            "  = actual value: \"server\"\n",
            "  = help: use \"dedicated\" only when this process owns the bounded host or cgroup\n",
        )
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "redirected output must stay plain text: {stderr:?}"
    );
}

#[test]
fn check_reports_removed_fields_by_name() {
    let path = workspace(
        "removed-policy",
        "{\n  \"policy\": {},\n  \"inbounds\": [],\n  \"outbounds\": [],\n  \"routing\": { \"users\": [] }\n}\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rust-reality"))
        .arg("check")
        .arg("--config")
        .arg(&path)
        .output()
        .expect("the binary must run");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics must be UTF-8");
    assert!(
        stderr.starts_with("error: field `policy` was removed in v1.6\n"),
        "removed fields get a targeted error: {stderr}"
    );
    assert!(stderr.contains("advanced.limits.*"), "{stderr}");
}

#[test]
fn check_accepts_a_valid_config() {
    let path = workspace(
        "valid",
        r#"{
  "inbounds": [{
    "protocol": "vless",
    "tag": "public-reality",
    "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
    "port": 443,
    "settings": {
      "clients": [{
        "id": "11111111-1111-4111-8111-111111111111",
        "shortIds": ["0123456789abcdef"],
        "flow": "xtls-rprx-vision"
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "target": "www.example.com:443",
        "serverNames": ["www.example.com"],
        "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
      }
    }
  }],
  "outbounds": [{ "protocol": "direct", "tag": "direct" }],
  "routing": {
    "users": [{
      "name": "direct-users",
      "userIds": ["11111111-1111-4111-8111-111111111111"],
      "defaultOutbound": "direct"
    }]
  }
}
"#,
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rust-reality"))
        .arg("check")
        .arg("--config")
        .arg(&path)
        .output()
        .expect("the binary must run");
    assert!(
        output.status.success(),
        "a valid config must pass: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
