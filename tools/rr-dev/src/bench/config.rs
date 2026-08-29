//! VLESS + REALITY configuration generation shared by benchmark suites.
//!
//! Benchmark suites compare rust-reality against Xray over the same VLESS +
//! REALITY + `xtls-rprx-vision` shape on loopback. The rust-reality server config
//! comes from `rust-reality config generate standalone`; the Xray server and
//! client configs are built here as typed JSON, replacing the `jq` templates the
//! shell scripts embedded. Keeping this in one module means every suite renders
//! the comparator identically.

use crate::perf::json_out::Json;

/// The REALITY identity shared between a server and its client.
#[derive(Debug, Clone)]
pub struct RealityIdentity {
    /// The client UUID.
    pub uuid: String,
    /// The REALITY short id.
    pub short_id: String,
    /// The cover server name (SNI).
    pub server_name: String,
    /// The cover target `host:port`.
    pub target: String,
}

/// Builds the Xray VLESS + REALITY server config for a tunnel benchmark.
///
/// Mirrors the `jq` server template in `benchmark-xray.sh` and siblings: a single
/// VLESS inbound with `xtls-rprx-vision` and REALITY stream settings, plus a
/// `freedom` direct outbound. When `allow_private` is set, the freedom outbound
/// carries `finalRules: [{action: "allow"}]` so a loopback origin is reachable —
/// Xray blocks private targets by default.
#[must_use]
pub fn xray_server(
    identity: &RealityIdentity,
    listen_port: u16,
    private_key: &str,
    allow_private: bool,
) -> Json {
    xray_server_with_fallback(identity, listen_port, private_key, allow_private, None)
}

/// The same server, optionally carrying an explicit VLESS `fallbacks` entry.
///
/// rust-reality falls back automatically when REALITY authentication fails; Xray
/// needs to be told where to send such a connection. The matrix's fallback
/// servers therefore differ between the two implementations in configuration
/// only, so that both are measured on the same behaviour.
#[must_use]
pub fn xray_server_with_fallback(
    identity: &RealityIdentity,
    listen_port: u16,
    private_key: &str,
    allow_private: bool,
    fallback_dest: Option<&str>,
) -> Json {
    let outbound = if allow_private {
        Json::object([
            ("tag", Json::string("direct")),
            ("protocol", Json::string("freedom")),
            (
                "settings",
                Json::object([(
                    "finalRules",
                    Json::Array(vec![Json::object([("action", Json::string("allow"))])]),
                )]),
            ),
        ])
    } else {
        Json::object([
            ("tag", Json::string("direct")),
            ("protocol", Json::string("freedom")),
        ])
    };
    Json::object([
        ("log", Json::object([("loglevel", Json::string("warning"))])),
        (
            "inbounds",
            Json::Array(vec![Json::object([
                ("listen", Json::string("127.0.0.1")),
                ("port", Json::Int(i64::from(listen_port))),
                ("protocol", Json::string("vless")),
                (
                    "settings",
                    Json::object(settings_entries(identity, fallback_dest)),
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
            ])]),
        ),
        ("outbounds", Json::Array(vec![outbound])),
    ])
}

/// The VLESS inbound settings, with `fallbacks` only when one is requested.
fn settings_entries(
    identity: &RealityIdentity,
    fallback_dest: Option<&str>,
) -> Vec<(String, Json)> {
    let mut entries = vec![
        (
            "clients".to_owned(),
            Json::Array(vec![Json::object([
                ("id", Json::string(identity.uuid.clone())),
                ("flow", Json::string("xtls-rprx-vision")),
            ])]),
        ),
        ("decryption".to_owned(), Json::string("none")),
    ];
    if let Some(dest) = fallback_dest {
        entries.push((
            "fallbacks".to_owned(),
            Json::Array(vec![Json::object([("dest", Json::string(dest))])]),
        ));
    }
    entries
}

/// Builds the Xray VLESS + REALITY client config with a local SOCKS inbound.
///
/// Mirrors the `make_client` `jq` template: a SOCKS inbound forwarding to a
/// VLESS/REALITY/`xtls-rprx-vision` outbound at `server_port`, pinned to the cover
/// `public_key` and `server_name`.
#[must_use]
pub fn xray_client(
    identity: &RealityIdentity,
    server_port: u16,
    socks_port: u16,
    public_key: &str,
) -> Json {
    Json::object([
        ("log", Json::object([("loglevel", Json::string("warning"))])),
        (
            "inbounds",
            Json::Array(vec![Json::object([
                ("listen", Json::string("127.0.0.1")),
                ("port", Json::Int(i64::from(socks_port))),
                ("protocol", Json::string("socks")),
                (
                    "settings",
                    Json::object([("auth", Json::string("noauth")), ("udp", Json::Bool(false))]),
                ),
            ])]),
        ),
        (
            "outbounds",
            Json::Array(vec![Json::object([
                ("protocol", Json::string("vless")),
                (
                    "settings",
                    Json::object([(
                        "vnext",
                        Json::Array(vec![Json::object([
                            ("address", Json::string("127.0.0.1")),
                            ("port", Json::Int(i64::from(server_port))),
                            (
                                "users",
                                Json::Array(vec![Json::object([
                                    ("id", Json::string(identity.uuid.clone())),
                                    ("encryption", Json::string("none")),
                                    ("flow", Json::string("xtls-rprx-vision")),
                                ])]),
                            ),
                        ])]),
                    )]),
                ),
                (
                    "streamSettings",
                    Json::object([
                        ("network", Json::string("tcp")),
                        ("security", Json::string("reality")),
                        (
                            "realitySettings",
                            Json::object([
                                ("fingerprint", Json::string("chrome")),
                                ("serverName", Json::string(identity.server_name.clone())),
                                ("publicKey", Json::string(public_key.to_owned())),
                                ("shortId", Json::string(identity.short_id.clone())),
                                ("spiderX", Json::string("/")),
                            ]),
                        ),
                    ]),
                ),
            ])]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RealityIdentity {
        RealityIdentity {
            uuid: "11111111-2222-3333-4444-555555555555".to_owned(),
            short_id: "0123abcd".to_owned(),
            server_name: "dl.google.com".to_owned(),
            target: "dl.google.com:443".to_owned(),
        }
    }

    #[test]
    fn the_server_config_pins_vision_and_reality() {
        let rendered = xray_server(&identity(), 8443, "PRIVKEY", false).to_python_json();
        assert!(rendered.contains("\"flow\": \"xtls-rprx-vision\""));
        assert!(rendered.contains("\"security\": \"reality\""));
        assert!(rendered.contains("\"privateKey\": \"PRIVKEY\""));
        assert!(rendered.contains("\"target\": \"dl.google.com:443\""));
        assert!(rendered.contains("\"protocol\": \"freedom\""));
    }

    #[test]
    fn allow_private_emits_final_rules() {
        let rendered = xray_server(&identity(), 8443, "PRIVKEY", true).to_python_json();
        assert!(rendered.contains("\"finalRules\""));
        assert!(rendered.contains("\"action\": \"allow\""));
        let blocked = xray_server(&identity(), 8443, "PRIVKEY", false).to_python_json();
        assert!(!blocked.contains("finalRules"));
    }

    #[test]
    fn the_client_config_binds_socks_and_pins_public_key() {
        let rendered = xray_client(&identity(), 8443, 1080, "PUBKEY").to_python_json();
        assert!(rendered.contains("\"protocol\": \"socks\""));
        assert!(rendered.contains("\"publicKey\": \"PUBKEY\""));
        assert!(rendered.contains("\"port\": 1080"));
        assert!(rendered.contains("\"port\": 8443"));
        assert!(rendered.contains("\"fingerprint\": \"chrome\""));
    }

    /// rust-reality falls back automatically on an auth failure; Xray has to be
    /// told where to send such a connection, so the matrix's Xray fallback server
    /// carries an explicit entry while the rust one does not.
    #[test]
    fn a_fallback_destination_is_emitted_only_when_requested() {
        let plain = xray_server(&identity(), 8443, "PRIVKEY", true).to_python_json();
        assert!(!plain.contains("fallbacks"));

        let with_fallback = xray_server_with_fallback(
            &identity(),
            8443,
            "PRIVKEY",
            true,
            Some("127.0.0.1:8080"),
        )
        .to_python_json();
        assert!(with_fallback.contains("\"fallbacks\""));
        assert!(with_fallback.contains("\"dest\": \"127.0.0.1:8080\""));
        // Everything else is unchanged.
        assert!(with_fallback.contains("\"decryption\": \"none\""));
        assert!(with_fallback.contains("xtls-rprx-vision"));
    }
}
