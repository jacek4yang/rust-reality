//! End-to-end CLI diagnostics: `check` renders the shared compiler-style
//! diagnostic to stderr and fails the command.
//!
//! These run the real binary, so they also pin the two promises `check` makes
//! from outside: it reports on stderr only, and it never contacts anything.

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

fn check(path: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rust-reality"))
        .arg("check")
        .arg("--config")
        .arg(path)
        .output()
        .expect("the binary must run")
}

/// A valid standalone entry node: the shortest configuration that runs.
const VALID: &str = r#"{
  "role": "entry",
  "listeners": [{ "port": 443 }],
  "reality": {
    "cover": "www.example.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    { "id": "11111111-1111-4111-8111-111111111111", "shortIds": ["0123456789abcdef"] }
  ],
  "routing": { "default": "direct" }
}
"#;

#[test]
fn check_accepts_a_valid_config() {
    let path = workspace("valid", VALID);

    let output = check(&path);

    assert!(
        output.status.success(),
        "a valid config must pass: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("output must be UTF-8");
    assert!(
        stdout.contains("entry"),
        "the report names the role that was validated: {stdout}"
    );
}

#[test]
fn check_renders_the_shared_diagnostic_on_stderr() {
    let path = workspace(
        "invalid-enum",
        &VALID.replace(
            r#""role": "entry","#,
            "\"role\": \"entry\",\n  \"runtime\": { \"profile\": \"server\" },",
        ),
    );

    let output = check(&path);

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
            ":3:27\n",
            "  |\n",
            "3 |   \"runtime\": { \"profile\": \"server\" },\n",
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

/// The whole point of the reset: a file written for the previous release must
/// fail, immediately and legibly, rather than being partially accepted.
#[test]
fn a_previous_release_configuration_fails_with_a_targeted_error() {
    let path = workspace(
        "v18-config",
        r#"{
  "log": { "level": "info", "output": "stderr" },
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
      }],
      "decryption": "none"
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
    "domainStrategy": "IPIfNonMatch",
    "users": [{
      "name": "direct-users",
      "userIds": ["11111111-1111-4111-8111-111111111111"],
      "defaultOutbound": "direct"
    }]
  },
  "advanced": { "limits": { "resourceGovernor": { "maxConnections": 16384 } } }
}
"#,
    );

    let output = check(&path);

    assert!(
        !output.status.success(),
        "a previous-release configuration must not be accepted"
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostics must be UTF-8");
    assert!(
        stderr.contains("`role`"),
        "the operator learns which field decides the shape: {stderr}"
    );
}

#[test]
fn check_reports_removed_fields_by_name() {
    // A configuration that states its role but keeps a removed section gets a
    // targeted error naming the replacement, not a bare "unknown field".
    let path = workspace(
        "removed-advanced",
        &VALID.replace(
            r#"  "routing": { "default": "direct" }"#,
            "  \"routing\": { \"default\": \"direct\" },\n  \"advanced\": { \"limits\": {} }",
        ),
    );

    let output = check(&path);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("diagnostics must be UTF-8");
    assert!(
        stderr.starts_with("error: field `advanced` was removed in v1.9\n"),
        "removed sections get a targeted error: {stderr}"
    );
    assert!(
        stderr.contains("runtime.limits"),
        "the message names where the surviving limits live: {stderr}"
    );
}

#[test]
fn check_never_contacts_anything() {
    // A cover target that cannot resolve and an asset URL that cannot be
    // reached: `check` is offline, so neither is touched and the file is valid.
    let path = workspace(
        "offline",
        &VALID.replace(
            r#""cover": "www.example.com:443""#,
            r#""cover": "unreachable.invalid:443", "serverNames": ["unreachable.invalid"]"#,
        )
        .replace(
            r#"  "routing": { "default": "direct" }"#,
            "  \"routing\": { \"default\": \"direct\" },\n  \"assets\": { \"geoip\": \"https://unreachable.invalid/geoip.dat\" }",
        ),
    );

    let output = check(&path);

    assert!(
        output.status.success(),
        "check must not resolve or fetch anything: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
