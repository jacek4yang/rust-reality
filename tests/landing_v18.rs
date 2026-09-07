//! Unchanged v1.8 landing inputs must retain identity and fail closed outside
//! the explicitly supported subset. All credentials here are public fixtures.

use rust_reality::config::{canonical, load_bytes, node::landing::LandingProtocol};
use serde_json::{Value, json};
use std::{path::Path, process::Command};

const PSK: &str = "ERERERERERERERERERERERERERERERERERERERERERE";
const PRIVATE: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";

fn fixture() -> Value {
    json!({
        "inbounds": [{"protocol":"handoff", "tag":"landing", "listen":{"mode":"auto","ipv4":"0.0.0.0","ipv6":"::"},"port":443,
            "settings":{"preSharedKey":PSK,"privateKey":PRIVATE,"maxTimeDifferenceSeconds":30,"maxNonceEntries":65536,"nonceRetentionSeconds":120,
                "preAuthIdleTimeoutMs":60000,"authenticationTimeoutMs":3000,"connectTimeoutMs":10000}}],
        "outbounds":[{"protocol":"direct","tag":"egress"}],
        "routing":{"domainStrategy":"AsIs","globalRules":[],"users":[]},
        "log":{"level":"info","output":"stderr"},
        "dns":{"servers":["system"],"timeoutMs":5000,"cache":{"maxEntries":1024,"minTtlSeconds":5,"maxTtlSeconds":3600,"negativeTtlSeconds":60,"staticTtlSeconds":300,"systemReuseMs":0}},
        "assets":{"geoip":"https://example.com/geoip.dat","geosite":"https://example.com/geosite.dat","cacheDirectory":"/var/lib/rust-reality/assets","reloadIntervalSeconds":86400,"requestTimeoutSeconds":120,"maxBytes":134217728},
        "network":{"dial":{"mode":"auto","fallbackDelayMs":250,"routeRefreshSeconds":30,"hardFailurePenaltySeconds":30,"latencyMemorySeconds":300}},
        "runtime":{"profile":"auto","tuning":{"objective":"balanced"}},
        "advanced":{"limits":{
            "resourceGovernor":{"maxConnections":16384,"maxHandshakes":1024,"maxPreAuthIdleConnections":1024,"maxFallbacks":512,"maxCryptoOperations":128,"maxReplayEntries":65536,"maxDnsLookups":64,"replayRetentionMs":120000,"clientHelloTimeoutMs":3000,"handshakeTimeoutMs":10000,"connectTimeoutMs":10000,"fallbackTimeoutMs":120000},
            "directBarrier":{"maxConcurrent":2048,"maxPerSecond":4096},
            "relay":{"bufferBytes":32768,"maxPooledBuffers":4096,"maxSpliceRelays":256,"maxRelayMemoryBytes":536870912,"splice":true,"pipePool":true,"maxPooledPipes":256},
            "warmConnections":{"minReady":4,"maxReady":256,"maxConnecting":64,"refillBatch":16,"idleTimeoutMs":30000,"maxLifetimeMs":300000,"shrinkDelayMs":30000}}}
    })
}

fn load(
    value: &Value,
) -> Result<rust_reality::config::ValidatedConfig, rust_reality::config::LoadError> {
    load_bytes(
        Path::new("landing-v18.json"),
        &serde_json::to_vec(value).unwrap(),
    )
}

#[test]
fn the_serialized_v18_defaults_preserve_the_deployed_contract() {
    let config = load(&fixture()).expect("unchanged v1.8 Handoff landing must load");
    let landing = config.node().as_landing().unwrap();
    assert_eq!(landing.listeners[0].port, 443);
    assert_eq!(landing.listeners[0].bind_addresses().len(), 2);
    assert_eq!(landing.egress(), "direct");
    let LandingProtocol::Handoff(settings) = &landing.landing else {
        panic!("Handoff required");
    };
    assert_eq!(settings.psk.expose(), PSK);
    assert_eq!(settings.private_key.expose(), PRIVATE);
    assert_eq!(settings.nonce_retention_seconds(), 120);
    assert_eq!(settings.timing().authentication_timeout_ms, 3000);
    assert_eq!(settings.timing().connect_timeout_ms, 10000);
    assert_eq!(settings.timing().pre_auth_idle_timeout_ms, 60000);
    assert!(
        landing.runtime.as_ref().unwrap().limits.is_none(),
        "v1.8 defaults did not pin limits"
    );
    assert_eq!(landing.dns.as_ref().unwrap().servers(), ["system"]);
    let rendered = canonical(&config);
    let reloaded = load_bytes(Path::new("canonical.json"), rendered.as_bytes()).unwrap();
    assert_eq!(config.node(), reloaded.node());
    assert_eq!(canonical(&reloaded), rendered);
}

#[test]
fn omitted_v18_defaults_retain_replay_policy_and_explicit_direct_egress() {
    let mut value = fixture();
    value["inbounds"][0]["settings"]
        .as_object_mut()
        .unwrap()
        .remove("nonceRetentionSeconds");
    value["inbounds"][0]["settings"]["egress"] = json!("egress");
    for section in ["advanced", "assets", "network", "runtime", "dns", "log"] {
        value.as_object_mut().unwrap().remove(section);
    }
    let config = load(&value).unwrap();
    let LandingProtocol::Handoff(settings) = &config.node().as_landing().unwrap().landing else {
        panic!("Handoff required");
    };
    assert_eq!(settings.nonce_retention_seconds(), 120);
    assert_eq!(config.node().as_landing().unwrap().egress(), "direct");
}

#[test]
fn no_legacy_resource_pin_is_silently_discarded() {
    let base = fixture();
    for (section, settings) in base["advanced"]["limits"].as_object().unwrap() {
        for (name, value) in settings.as_object().unwrap() {
            let mut changed = base.clone();
            changed["advanced"]["limits"][section][name] = match value {
                Value::Bool(flag) => json!(!flag),
                number => json!(number.as_u64().unwrap() + 1),
            };
            assert!(load(&changed).is_err(), "must reject pin {section}.{name}");
        }
    }
    for name in [
        "fallbackDelayMs",
        "routeRefreshSeconds",
        "hardFailurePenaltySeconds",
        "latencyMemorySeconds",
    ] {
        let mut changed = base.clone();
        changed["network"]["dial"][name] =
            json!(base["network"]["dial"][name].as_u64().unwrap() + 1);
        assert!(
            load(&changed).is_err(),
            "must reject changed dial heuristic {name}"
        );
    }
}

#[test]
fn unsupported_shapes_and_invalid_authority_fail_closed() {
    for (pointer, replacement) in [
        ("/role", json!("landing")),
        ("/role", Value::Null),
        ("/inbounds/0/protocol", json!("vless")),
        ("/inbounds/0/settings/preSharedKey", json!("invalid-key")),
        ("/inbounds/0/settings/privateKey", json!(PSK)),
        ("/inbounds/0/settings/egress", json!("undeclared")),
        ("/inbounds/0/settings/maxNonceEntries", json!(65537)),
        ("/inbounds/0/settings/nonceRetentionSeconds", json!(60)),
        ("/inbounds/0/settings/nonceRetentionSeconds", json!(86401)),
        ("/outbounds/0/protocol", json!("socks5")),
        ("/routing/users", json!([{}])),
        ("/routing/globalRules", json!([{}])),
        ("/runtime/tuning/mode", json!("fixed")),
        ("/advanced/limits/unrecognized", json!({})),
    ] {
        let mut changed = fixture();
        let (parent, name) = pointer.rsplit_once('/').unwrap();
        let parent = if parent.is_empty() {
            &mut changed
        } else {
            changed.pointer_mut(parent).unwrap()
        };
        parent[name] = replacement;
        assert!(load(&changed).is_err(), "must reject {pointer}");
    }
    let mut multiple = fixture();
    let extra = multiple["inbounds"][0].clone();
    multiple["inbounds"].as_array_mut().unwrap().push(extra);
    assert!(load(&multiple).is_err());
}

#[test]
fn duplicate_keys_and_legacy_secrets_never_escape_diagnostics() {
    let bytes = serde_json::to_string_pretty(&fixture()).unwrap();
    for invalid in [
        bytes.replace(
            "\"preSharedKey\":",
            "\"preSharedKey\":\"secret-sentinel\",\"preSharedKey\":",
        ),
        bytes.replace(PRIVATE, "secret-sentinel"),
        bytes.replace("\"port\": 443", "\"port\":443,\"port\":444"),
    ] {
        let error = load_bytes(Path::new("invalid.json"), invalid.as_bytes())
            .expect_err("invalid legacy input")
            .to_string();
        for secret in [PSK, PRIVATE, "secret-sentinel"] {
            assert!(!error.contains(secret), "diagnostics must redact keys");
        }
    }
}

#[test]
fn check_preserves_the_original_file_bytes() {
    let root = std::env::temp_dir().join(format!("rr-v18-compat-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("config.json");
    let bytes = serde_json::to_vec_pretty(&fixture()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rust-reality"))
        .args(["check", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::remove_dir_all(root).unwrap();
}
