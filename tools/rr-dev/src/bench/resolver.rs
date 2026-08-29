//! One implementation's leg for the resolver-facing comparisons.
//!
//! The DNS and routing comparisons both need the same arrangement: a counted
//! loopback resolver, a server configured to use it, and an unmodified Xray SOCKS
//! client in front. What differs is only the server's configuration — a DNS cache
//! policy in one case, a routing rule list in the other — so the leg is shared and
//! the configuration is the input.
//!
//! ## The cover target must be real TLS
//!
//! Both scripts carry the same warning, and it is worth keeping: a REALITY server
//! relays its cover target's handshake, so pointing the cover at a plain-HTTP
//! origin makes every handshake fail. The failure is silent apart from a
//! connection reset, which reads as a broken benchmark rather than a broken
//! configuration. The leg therefore always points the cover at the TLS origin.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use crate::{
    bench::{
        config::{self, RealityIdentity},
        fake_dns::FakeDns,
        process::Child,
        suites,
        workspace::Workspace,
    },
    perf::{json_in, json_out::Json},
};

/// Readiness deadline for a leg's server and client.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The TTL the fake resolver hands out.
///
/// Comfortably above rust-reality's five-second minimum TTL floor, so a warm
/// lookup is a cache hit in both implementations rather than a re-query that
/// happens to be fast.
pub const FAKE_TTL_SECONDS: u32 = 300;

/// Which implementation a leg measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Implementation {
    /// rust-reality.
    Rust,
    /// The pinned Xray comparator.
    Xray,
}

impl Implementation {
    /// The label used in evidence filenames and the report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Xray => "xray",
        }
    }
}

/// A running leg: resolver, server and client, all stopped on drop.
pub struct Leg {
    /// The counted resolver the server was pointed at.
    pub dns: FakeDns,
    /// The SOCKS port the workload drives.
    pub socks_port: u16,
    /// The server's listen port.
    pub server_port: u16,
    _server: Child,
    _client: Child,
}

/// What a leg's server configuration should contain beyond the defaults.
#[derive(Debug, Clone, Default)]
pub struct ServerPolicy {
    /// Explicit first-match domain rules, in order, routed to `direct`.
    pub domain_rules: Vec<String>,
}

/// Everything a leg needs to start.
#[derive(Debug, Clone, Copy)]
pub struct LegInputs<'a> {
    /// Which implementation this leg measures.
    pub implementation: Implementation,
    /// The run workspace holding configs and logs.
    pub workspace: &'a Workspace,
    /// The rust-reality binary.
    pub rust_bin: &'a Path,
    /// The Xray binary: comparator server and both clients.
    pub xray_bin: &'a Path,
    /// The TLS origin that serves as the REALITY cover.
    pub tls_origin_port: u16,
    /// The server's listen port.
    pub server_port: u16,
    /// The SOCKS port the workload drives.
    pub socks_port: u16,
    /// The server policy: DNS always, routing rules when present.
    pub policy: &'a ServerPolicy,
}

/// Starts one implementation's leg.
///
/// # Errors
///
/// Returns the first failure; partial resources are dropped by their guards.
pub fn start_leg(inputs: &LegInputs<'_>) -> Result<Leg, String> {
    let LegInputs {
        implementation,
        workspace,
        xray_bin,
        server_port,
        socks_port,
        ..
    } = *inputs;
    let dns = FakeDns::start(Ipv4Addr::LOCALHOST, FAKE_TTL_SECONDS)?;
    let label = implementation.as_str();

    let (server_config, identity, public_key, program) = prepare_server(inputs, dns.port())?;

    let server_path = workspace.join(&format!("{label}-server.json"));
    std::fs::write(&server_path, &server_config)
        .map_err(|error| format!("could not write {}: {error}", server_path.display()))?;
    let server_args = if implementation == Implementation::Rust {
        vec![
            "serve".to_owned(),
            "--config".to_owned(),
            server_path.display().to_string(),
        ]
    } else {
        vec![
            "run".to_owned(),
            "-config".to_owned(),
            server_path.display().to_string(),
        ]
    };
    let mut server = Child::spawn(
        format!("{label}-server"),
        &program,
        &server_args,
        workspace.path(),
        &[],
        &workspace.join(&format!("{label}-server.log")),
    )
    .map_err(|error| error.to_string())?;

    let client_path = workspace.join(&format!("{label}-client.json"));
    std::fs::write(
        &client_path,
        config::xray_client(&identity, server_port, socks_port, &public_key).to_python_json(),
    )
    .map_err(|error| format!("could not write {}: {error}", client_path.display()))?;
    let mut client = Child::spawn(
        format!("{label}-client"),
        xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_path.display().to_string(),
        ],
        workspace.path(),
        &[],
        &workspace.join(&format!("{label}-client.log")),
    )
    .map_err(|error| error.to_string())?;

    server
        .wait_for_port(server_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    Ok(Leg {
        dns,
        socks_port,
        server_port,
        _server: server,
        _client: client,
    })
}

/// Builds a leg's server config and the identity its client must pin.
///
/// The two implementations differ in where their identity comes from: rust-reality
/// generates one, and the comparator is given a fresh id with the run's keypair.
fn prepare_server(
    inputs: &LegInputs<'_>,
    dns_port: u16,
) -> Result<(String, RealityIdentity, String, std::path::PathBuf), String> {
    let label = inputs.implementation.as_str();
    let target = format!("127.0.0.1:{}", inputs.tls_origin_port);
    match inputs.implementation {
        Implementation::Rust => {
            let generated = suites::generate_rust_identity(
                inputs.workspace,
                inputs.rust_bin,
                inputs.server_port,
                &target,
                "localhost",
                Some(&inputs.workspace.join(&format!("{label}-generate.log"))),
            )?;
            let config = rust_server_config(&generated.server_json, dns_port, inputs.policy)?;
            let identity = RealityIdentity {
                uuid: generated.uuid.clone(),
                short_id: generated.short_id.clone(),
                server_name: "localhost".to_owned(),
                target,
            };
            Ok((
                config,
                identity,
                generated.public_key.clone(),
                inputs.rust_bin.to_path_buf(),
            ))
        }
        Implementation::Xray => {
            let keys = suites::generate_xray_keys(inputs.xray_bin)?;
            let identity = RealityIdentity {
                uuid: crate::bench::ab_suites::random_uuid_v4()?,
                short_id: crate::bench::ab_suites::random_short_id()?,
                server_name: "localhost".to_owned(),
                target,
            };
            let config = xray_server_config(
                &identity,
                inputs.server_port,
                &keys.private,
                dns_port,
                inputs.policy,
            )
            .to_python_json();
            Ok((config, identity, keys.public.clone(), inputs.xray_bin.to_path_buf()))
        }
    }
}

/// Points a generated rust-reality config at the fake resolver.
///
/// The cache bounds are pinned so a warm lookup is a genuine cache hit: the
/// minimum floor keeps a 300-second TTL from being shortened, and the maximum
/// keeps it from being extended past what the fake resolver promised.
///
/// # Errors
///
/// Returns a message when the generated config is not the expected shape.
pub fn rust_server_config(
    generated: &str,
    dns_port: u16,
    policy: &ServerPolicy,
) -> Result<String, String> {
    let value = json_in::parse(generated)
        .map_err(|error| format!("the generated config is invalid JSON: {error}"))?;
    let json_in::Value::Object(mut members) = value else {
        return Err("the generated config is not an object".to_owned());
    };
    let string = |text: &str| json_in::Value::Str(text.to_owned());
    let number = |value: u64| json_in::Value::Number(value.to_string());

    set_path(
        &mut members,
        &["dns", "servers"],
        json_in::Value::Array(vec![string(&format!("127.0.0.1:{dns_port}"))]),
    )?;
    set_path(&mut members, &["dns", "cache", "minTtlSeconds"], number(5))?;
    set_path(&mut members, &["dns", "cache", "maxTtlSeconds"], number(3600))?;

    if !policy.domain_rules.is_empty() {
        let rules: Vec<json_in::Value> = policy
            .domain_rules
            .iter()
            .enumerate()
            .map(|(index, domain)| {
                let mut rule = std::collections::BTreeMap::new();
                rule.insert("name".to_owned(), string(&format!("r{index}")));
                rule.insert("outbound".to_owned(), string("direct"));
                rule.insert(
                    "domain".to_owned(),
                    json_in::Value::Array(vec![string(domain)]),
                );
                json_in::Value::Object(rule)
            })
            .collect();
        set_path(&mut members, &["routing", "domainStrategy"], string("AsIs"))?;
        set_path(
            &mut members,
            &["routing", "globalRules"],
            json_in::Value::Array(rules),
        )?;
    }
    Ok(suites::render_compact(&json_in::Value::Object(members)))
}

/// Sets one leaf of a nested object, creating intermediate objects as needed.
///
/// This is `jq`'s `.a.b = c`, and the distinction from replacing `.a` outright is
/// load-bearing: the generated config's `routing` carries a `users` block that
/// binds the client UUID to an outbound, and its `dns` carries timeouts and
/// negative-cache bounds. Replacing either object drops those — the server then
/// refuses to start, or silently runs with different cache behaviour than the
/// harness intended.
///
/// # Errors
///
/// Returns a message when an intermediate value exists but is not an object.
fn set_path(
    members: &mut std::collections::BTreeMap<String, json_in::Value>,
    path: &[&str],
    value: json_in::Value,
) -> Result<(), String> {
    let Some((leaf, parents)) = path.split_last() else {
        return Err("an empty path cannot be set".to_owned());
    };
    let mut current = members;
    for key in parents {
        let entry = current
            .entry((*key).to_owned())
            .or_insert_with(|| json_in::Value::Object(std::collections::BTreeMap::new()));
        let json_in::Value::Object(next) = entry else {
            return Err(format!("{key} is not an object in the generated config"));
        };
        current = next;
    }
    current.insert((*leaf).to_owned(), value);
    Ok(())
}

/// Builds the Xray server config with the same resolver and rules.
///
/// `domainStrategy: "UseIP"` on the freedom outbound is what makes Xray resolve
/// the destination itself; without it the name would be passed through and the
/// comparison would measure nothing.
#[must_use]
pub fn xray_server_config(
    identity: &RealityIdentity,
    listen_port: u16,
    private_key: &str,
    dns_port: u16,
    policy: &ServerPolicy,
) -> Json {
    let mut fields: Vec<(String, Json)> = vec![
        (
            "log".to_owned(),
            Json::object([("loglevel", Json::string("warning"))]),
        ),
        (
            "dns".to_owned(),
            Json::object([
                (
                    "servers",
                    Json::Array(vec![Json::object([
                        ("address", Json::string("127.0.0.1")),
                        ("port", Json::Int(i64::from(dns_port))),
                    ])]),
                ),
                ("queryStrategy", Json::string("UseIPv4")),
            ]),
        ),
        (
            "inbounds".to_owned(),
            Json::Array(vec![xray_inbound(identity, listen_port, private_key)]),
        ),
        (
            "outbounds".to_owned(),
            Json::Array(vec![Json::object([
                ("tag", Json::string("direct")),
                ("protocol", Json::string("freedom")),
                (
                    "settings",
                    Json::object([
                        ("domainStrategy", Json::string("UseIP")),
                        (
                            "finalRules",
                            Json::Array(vec![Json::object([("action", Json::string("allow"))])]),
                        ),
                    ]),
                ),
            ])]),
        ),
    ];
    if !policy.domain_rules.is_empty() {
        let rules: Vec<Json> = policy
            .domain_rules
            .iter()
            .map(|domain| {
                Json::object([
                    ("type", Json::string("field")),
                    ("domain", Json::Array(vec![Json::string(domain.clone())])),
                    ("outboundTag", Json::string("direct")),
                ])
            })
            .collect();
        fields.push((
            "routing".to_owned(),
            Json::object([
                ("domainStrategy", Json::string("AsIs")),
                ("rules", Json::Array(rules)),
            ]),
        ));
    }
    Json::object(fields)
}

/// The VLESS + REALITY inbound the comparator serves.
fn xray_inbound(identity: &RealityIdentity, listen_port: u16, private_key: &str) -> Json {
    Json::object([
        ("listen", Json::string("127.0.0.1")),
        ("port", Json::Int(i64::from(listen_port))),
        ("protocol", Json::string("vless")),
        (
            "settings",
            Json::object([
                (
                    "clients",
                    Json::Array(vec![Json::object([
                        ("id", Json::string(identity.uuid.clone())),
                        ("flow", Json::string("xtls-rprx-vision")),
                    ])]),
                ),
                ("decryption", Json::string("none")),
            ]),
        ),
        (
            "streamSettings",
            Json::object([
                ("network", Json::string("tcp")),
                ("security", Json::string("reality")),
                (
                    "realitySettings",
                    Json::object([
                        ("show", Json::Bool(false)),
                        ("target", Json::string(identity.target.clone())),
                        ("xver", Json::Int(0)),
                        (
                            "serverNames",
                            Json::Array(vec![Json::string(identity.server_name.clone())]),
                        ),
                        ("privateKey", Json::string(private_key.to_owned())),
                        (
                            "shortIds",
                            Json::Array(vec![Json::string(identity.short_id.clone())]),
                        ),
                    ]),
                ),
            ]),
        ),
    ])
}

/// Starts the native plain and TLS origin listeners a leg needs.
///
/// # Errors
///
/// Returns the first failure; the guards stop whatever started.
pub fn start_origins(
    _repo: &Path,
    workspace: &Workspace,
    plain_port: u16,
    tls_port: u16,
) -> Result<(Child, Child), String> {
    use crate::bench::{origin_go, origin_tls};
    let binary = origin_go::executable()?;
    origin_go::write_setup_payload(workspace.path())?;
    let (cert, key) = origin_tls::generate_self_signed(workspace.path())?;
    let plain = origin_go::start(
        &binary,
        workspace,
        &origin_go::OriginPlan {
            label: "origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: plain_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;
    let secure = origin_go::start(
        &binary,
        workspace,
        &origin_go::OriginPlan {
            label: "origin-https".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: tls_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("https-put.jsonl"),
            tls: Some((cert, key)),
            access_log: None,
            alpn: None,
        },
    )?;
    Ok((plain, secure))
}

/// The domain rule list for a scale point, in first-match order.
///
/// The measured destination is the *last* rule, so every connection walks the
/// whole list; a rule near the front would measure a lucky early match instead of
/// rule-evaluation cost.
#[must_use]
pub fn rule_domains(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("rule-{index}.routingbench"))
        .collect()
}

/// The destination name that forces a full walk of `count` rules.
#[must_use]
pub fn worst_case_target(count: usize) -> String {
    format!("rule-{}.routingbench", count.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generated config carries more than the harness sets: `routing.users`
    /// binds the client UUID to an outbound, and `dns` carries timeouts.
    const GENERATED: &str = r#"{"log":{"level":"warn"},"assets":{"cacheDirectory":"/w"},
        "dns":{"servers":["system"],"timeoutMs":5000,
               "cache":{"maxEntries":1024,"minTtlSeconds":5,"negativeTtlSeconds":60}},
        "routing":{"domainStrategy":"IPIfNonMatch","globalRules":[],
                   "users":[{"name":"direct-users","defaultOutbound":"direct"}]},
        "inbounds":[{"port":443,"streamSettings":{"realitySettings":{}}}]}"#;

    #[test]
    fn the_rust_config_points_at_the_fake_resolver_with_pinned_cache_bounds() {
        let patched = rust_server_config(GENERATED, 5353, &ServerPolicy::default()).unwrap();
        assert!(patched.contains(r#""servers":["127.0.0.1:5353"]"#));
        // The bounds keep a 300s TTL from being shortened or extended, so a warm
        // lookup is a genuine cache hit.
        assert!(patched.contains(r#""minTtlSeconds":5"#));
        assert!(patched.contains(r#""maxTtlSeconds":3600"#));
        // Merging, not replacing: everything else the generator emitted survives.
        assert!(patched.contains(r#""timeoutMs":5000"#));
        assert!(patched.contains(r#""negativeTtlSeconds":60"#));
        assert!(patched.contains(r#""maxEntries":1024"#));
        assert!(
            patched.contains("direct-users"),
            "routing.users binds the client to an outbound and must survive"
        );
        assert!(patched.contains(r#""domainStrategy":"IPIfNonMatch""#));
    }

    #[test]
    fn rules_are_emitted_in_first_match_order_for_both_implementations() {
        let policy = ServerPolicy {
            domain_rules: rule_domains(3),
        };
        let rust = rust_server_config(GENERATED, 5353, &policy).unwrap();
        assert!(rust.contains(r#""domainStrategy":"AsIs""#));
        assert!(rust.contains(r#""name":"r0""#));
        assert!(rust.contains(r#""rule-2.routingbench""#));
        // The user binding survives the routing patch, or the server will not start.
        assert!(rust.contains("direct-users"));

        let identity = RealityIdentity {
            uuid: "u".to_owned(),
            short_id: "s".to_owned(),
            server_name: "localhost".to_owned(),
            target: "127.0.0.1:8443".to_owned(),
        };
        let xray = xray_server_config(&identity, 443, "PRIV", 5353, &policy).to_python_json();
        assert!(xray.contains("\"type\": \"field\""));
        assert!(xray.contains("\"outboundTag\": \"direct\""));
        assert!(xray.contains("rule-2.routingbench"));
        // UseIP is what makes Xray resolve the destination itself.
        assert!(xray.contains("\"domainStrategy\": \"UseIP\""));
        assert!(xray.contains("\"queryStrategy\": \"UseIPv4\""));
    }

    /// The measured name must be the last rule, or the benchmark would time a
    /// lucky early match rather than the cost of walking the list.
    #[test]
    fn the_worst_case_target_is_the_final_rule() {
        assert_eq!(worst_case_target(10), "rule-9.routingbench");
        assert_eq!(worst_case_target(10_000), "rule-9999.routingbench");
        let domains = rule_domains(10);
        assert_eq!(domains.len(), 10);
        assert_eq!(domains.last().unwrap(), &worst_case_target(10));
    }

    #[test]
    fn a_malformed_generated_config_fails_closed() {
        assert!(rust_server_config("not json", 5353, &ServerPolicy::default()).is_err());
        assert!(rust_server_config("[]", 5353, &ServerPolicy::default()).is_err());
    }

    #[test]
    fn implementations_name_themselves() {
        assert_eq!(Implementation::Rust.as_str(), "rust");
        assert_eq!(Implementation::Xray.as_str(), "xray");
    }
}
