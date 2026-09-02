//! VLESS + REALITY configuration generation shared by benchmark suites.
//!
//! Benchmark suites compare rust-reality against Xray over the same VLESS +
//! REALITY + `xtls-rprx-vision` shape on loopback. Both sides' configurations
//! are built here as typed JSON, replacing the `jq` templates the shell scripts
//! embedded. Keeping this in one module means every suite renders both ends
//! identically.
//!
//! The rust-reality side used to come from `rust-reality config generate
//! standalone`, parsed back out of the subprocess's stdout. That command is
//! gone — the binary generates atomic material, never whole configurations —
//! so the harness composes the file itself, which is what an operator does and
//! what removes a subprocess plus a parse-back from every suite's setup.

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
    xray_server_with_outbound(identity, listen_port, private_key, fallback_dest, outbound)
}

/// Builds the deployment comparator whose only outbound is a local SOCKS5 hop.
#[must_use]
pub fn xray_server_with_socks(
    identity: &RealityIdentity,
    listen_port: u16,
    private_key: &str,
    socks_port: u16,
) -> Json {
    let outbound = Json::object([
        ("protocol", Json::string("socks")),
        (
            "settings",
            Json::object([(
                "servers",
                Json::Array(vec![Json::object([
                    ("address", Json::string("127.0.0.1")),
                    ("port", Json::Int(i64::from(socks_port))),
                ])]),
            )]),
        ),
    ]);
    xray_server_with_outbound(identity, listen_port, private_key, None, outbound)
}

fn xray_server_with_outbound(
    identity: &RealityIdentity,
    listen_port: u16,
    private_key: &str,
    fallback_dest: Option<&str>,
    outbound: Json,
) -> Json {
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

/// Everything a benchmark suite varies about a rust-reality entry node.
///
/// The defaults are what a measurement wants: bind loopback, log at `warn` so
/// the log sink never shows up in a sample, and derive every limit from the
/// machine. A suite overrides only what its question is about.
#[derive(Debug, Clone)]
pub struct RustServer {
    /// Address to bind. `127.0.0.1` unless a suite is about address families.
    pub listen: String,
    /// Port to bind.
    pub port: u16,
    /// A complete `listeners[0]` object, replacing `listen`/`port`.
    ///
    /// The address-family suite is *about* the listener, so it supplies the
    /// whole thing rather than being squeezed through one address.
    pub listener: Option<Json>,
    /// Cover target `host:port`.
    pub cover: String,
    /// Accepted client SNI. Absent uses the cover's own host.
    pub server_name: Option<String>,
    /// REALITY private key.
    pub private_key: String,
    /// The single authorized identity.
    pub uuid: String,
    /// That identity's short ID.
    pub short_id: String,
    /// Log level.
    pub log_level: String,
    /// Asset cache directory, kept inside the run's workspace.
    pub assets_cache: Option<String>,
    /// Extra top-level members, rendered after the required ones.
    ///
    /// This is the escape hatch for the handful of suites that are *about* a
    /// section — DNS, routing, runtime posture — rather than about traffic.
    pub extra: Vec<(String, Json)>,
}

impl RustServer {
    /// A loopback entry node with the given identity and cover.
    #[must_use]
    pub fn new(identity: &RealityIdentity, port: u16, private_key: &str) -> Self {
        Self {
            listen: "127.0.0.1".to_owned(),
            port,
            listener: None,
            cover: identity.target.clone(),
            server_name: Some(identity.server_name.clone()),
            private_key: private_key.to_owned(),
            uuid: identity.uuid.clone(),
            short_id: identity.short_id.clone(),
            log_level: "warn".to_owned(),
            assets_cache: None,
            extra: Vec::new(),
        }
    }

    /// Supplies the whole `listeners[0]` object.
    #[must_use]
    pub fn listener(mut self, listener: Json) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Sets the log level. Gates asserting structured events need `info`;
    /// measurement slots stay at `warn`.
    #[must_use]
    pub fn log_level(mut self, level: &str) -> Self {
        level.clone_into(&mut self.log_level);
        self
    }

    /// Points the asset cache at a directory inside the run's workspace.
    #[must_use]
    pub fn assets_cache(mut self, directory: impl Into<String>) -> Self {
        self.assets_cache = Some(directory.into());
        self
    }

    /// Adds one top-level member, such as `dns`, `outbounds`, or `runtime`.
    #[must_use]
    pub fn with(mut self, key: &str, value: Json) -> Self {
        self.extra.push((key.to_owned(), value));
        self
    }

    /// Renders the configuration.
    #[must_use]
    pub fn build(&self) -> Json {
        let listener = self.listener.clone().unwrap_or_else(|| {
            if self.listen.contains(':') {
                Json::object([
                    ("port", Json::Int(i64::from(self.port))),
                    ("ip", Json::string("ipv6Only")),
                    ("ipv6", Json::string(self.listen.clone())),
                ])
            } else {
                Json::object([
                    ("port", Json::Int(i64::from(self.port))),
                    ("ip", Json::string("ipv4Only")),
                    ("ipv4", Json::string(self.listen.clone())),
                ])
            }
        });

        let mut reality = vec![
            ("cover", Json::string(self.cover.clone())),
            ("privateKey", Json::string(self.private_key.clone())),
        ];
        if let Some(name) = &self.server_name {
            reality.push(("serverNames", Json::Array(vec![Json::string(name.clone())])));
        }

        let mut members = vec![
            ("role".to_owned(), Json::string("entry")),
            ("listeners".to_owned(), Json::Array(vec![listener])),
            ("reality".to_owned(), Json::object(reality)),
            (
                "users".to_owned(),
                Json::Array(vec![Json::object([
                    ("id", Json::string(self.uuid.clone())),
                    (
                        "shortIds",
                        Json::Array(vec![Json::string(self.short_id.clone())]),
                    ),
                ])]),
            ),
        ];
        members.extend(self.extra.iter().cloned());
        if !self.extra.iter().any(|(key, _)| key == "routing") {
            members.push((
                "routing".to_owned(),
                Json::object([("default", Json::string("direct"))]),
            ));
        }
        if let Some(cache) = &self.assets_cache {
            members.push((
                "assets".to_owned(),
                Json::object([("cacheDirectory", Json::string(cache.clone()))]),
            ));
        }
        members.push((
            "log".to_owned(),
            Json::object([
                ("level", Json::string(self.log_level.clone())),
                ("output", Json::string("stderr")),
            ]),
        ));
        Json::object(members)
    }
}

/// The internal link from a line node to its landing node.
#[derive(Debug, Clone)]
pub struct LandingLink {
    /// `nxr` or `handoff`.
    pub protocol: &'static str,
    /// Landing node address.
    pub address: String,
    /// Landing node port.
    pub port: u16,
    /// The pre-shared key both nodes carry.
    pub psk: String,
    /// The landing's public key, for `handoff` only.
    pub landing_public_key: Option<String>,
}

impl RustServer {
    /// Routes everything through a landing node instead of dialling directly.
    ///
    /// Adds the outbound *and* points `routing.default` at it, because a line
    /// node that declares a landing and then dials direct is not a line node.
    #[must_use]
    pub fn through_landing(self, link: &LandingLink) -> Self {
        let mut outbound = vec![
            ("type", Json::string(link.protocol)),
            ("address", Json::string(link.address.clone())),
            ("port", Json::Int(i64::from(link.port))),
            ("psk", Json::string(link.psk.clone())),
        ];
        if let Some(key) = &link.landing_public_key {
            outbound.push(("landingPublicKey", Json::string(key.clone())));
        }
        self.with(
            "outbounds",
            Json::object([("landing-1", Json::object(outbound))]),
        )
        .with(
            "routing",
            Json::object([("default", Json::string("landing-1"))]),
        )
    }
}

/// Renders a landing node: the hidden half of a LINE->LANDING topology.
///
/// A landing has no REALITY identity, no users, and no routing, so there is
/// nothing to vary beyond where it listens and what key it accepts.
#[must_use]
pub fn rust_landing(
    listen: &str,
    port: u16,
    link: &LandingLink,
    private_key: Option<&str>,
) -> Json {
    let listener = if listen.contains(':') {
        Json::object([
            ("port", Json::Int(i64::from(port))),
            ("ip", Json::string("ipv6Only")),
            ("ipv6", Json::string(listen)),
        ])
    } else {
        Json::object([
            ("port", Json::Int(i64::from(port))),
            ("ip", Json::string("ipv4Only")),
            ("ipv4", Json::string(listen)),
        ])
    };
    let mut landing = vec![
        ("protocol", Json::string(link.protocol)),
        ("psk", Json::string(link.psk.clone())),
    ];
    if let Some(key) = private_key {
        landing.push(("privateKey", Json::string(key.to_owned())));
    }
    Json::object([
        ("role", Json::string("landing")),
        ("listeners", Json::Array(vec![listener])),
        ("landing", Json::object(landing)),
        (
            "log",
            Json::object([
                ("level", Json::string("warn")),
                ("output", Json::string("stderr")),
            ]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A structurally valid placeholder key: the builder's output is fed to the
    /// real validator, so the material has to be well formed.
    const KEY: &str = "ERERERERERERERERERERERERERERERERERERERERERE";

    fn identity() -> RealityIdentity {
        RealityIdentity {
            uuid: "11111111-2222-4333-8444-555555555555".to_owned(),
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

        let with_fallback =
            xray_server_with_fallback(&identity(), 8443, "PRIVKEY", true, Some("127.0.0.1:8080"))
                .to_python_json();
        assert!(with_fallback.contains("\"fallbacks\""));
        assert!(with_fallback.contains("\"dest\": \"127.0.0.1:8080\""));
        // Everything else is unchanged.
        assert!(with_fallback.contains("\"decryption\": \"none\""));
        assert!(with_fallback.contains("xtls-rprx-vision"));
    }

    /// The builder must emit something `rust-reality check` accepts, and it is
    /// checked against the real parser rather than by inspecting strings.
    #[test]
    fn the_rust_server_config_is_a_valid_entry_node() {
        let rendered = RustServer::new(&identity(), 8443, KEY)
            .assets_cache("/tmp/assets")
            .build()
            .to_python_json();

        let config = rust_reality::config::load_bytes(
            std::path::Path::new("bench.json"),
            rendered.as_bytes(),
        )
        .unwrap_or_else(|error| panic!("the harness must emit a valid config:\n{error}"));

        assert_eq!(config.node().role().as_str(), "entry");
    }

    #[test]
    fn a_line_node_routes_through_its_landing() {
        let link = LandingLink {
            protocol: "nxr",
            address: "127.0.0.1".to_owned(),
            port: 7443,
            psk: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
            landing_public_key: None,
        };

        let rendered = RustServer::new(&identity(), 8443, KEY)
            .through_landing(&link)
            .build()
            .to_python_json();

        let config = rust_reality::config::load_bytes(
            std::path::Path::new("line.json"),
            rendered.as_bytes(),
        )
        .unwrap_or_else(|error| panic!("a line node must validate:\n{error}"));
        assert!(rendered.contains("\"default\": \"landing-1\""));
        assert_eq!(config.node().role().as_str(), "entry");
    }

    #[test]
    fn a_landing_node_validates_for_both_protocols() {
        for (protocol, private_key) in [
            ("nxr", None),
            (
                "handoff",
                Some("REREREREREREREREREREREREREREREREREREREREREQ"),
            ),
        ] {
            let link = LandingLink {
                protocol,
                address: "127.0.0.1".to_owned(),
                port: 7443,
                psk: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
                landing_public_key: None,
            };

            let rendered = rust_landing("127.0.0.1", 7443, &link, private_key).to_python_json();

            rust_reality::config::load_bytes(
                std::path::Path::new("landing.json"),
                rendered.as_bytes(),
            )
            .unwrap_or_else(|error| panic!("a {protocol} landing must validate:\n{error}"));
        }
    }

    #[test]
    fn an_extra_section_replaces_the_default_it_names() {
        // A suite that is about routing supplies its own, and must not end up
        // with two `routing` members.
        let rendered = RustServer::new(&identity(), 8443, KEY)
            .with(
                "routing",
                Json::object([("default", Json::string("block"))]),
            )
            .build()
            .to_python_json();

        assert_eq!(rendered.matches("\"routing\"").count(), 1);
        assert!(rendered.contains("\"default\": \"block\""));
        rust_reality::config::load_bytes(std::path::Path::new("bench.json"), rendered.as_bytes())
            .expect("a suite-supplied routing section must still validate");
    }

    #[test]
    fn an_ipv6_listen_address_selects_the_ipv6_family() {
        let mut server = RustServer::new(&identity(), 8443, KEY);
        server.listen = "::1".to_owned();

        let rendered = server.build().to_python_json();

        assert!(rendered.contains("\"ip\": \"ipv6Only\""));
        assert!(rendered.contains("\"ipv6\": \"::1\""));
        rust_reality::config::load_bytes(std::path::Path::new("bench.json"), rendered.as_bytes())
            .expect("an IPv6 listener must validate");
    }

    #[test]
    fn the_deployment_comparator_routes_only_through_socks() {
        let rendered = xray_server_with_socks(&identity(), 8443, "PRIVKEY", 1080).to_python_json();
        assert!(rendered.contains("\"protocol\": \"socks\""));
        assert!(rendered.contains("\"address\": \"127.0.0.1\""));
        assert!(rendered.contains("\"port\": 1080"));
        assert!(!rendered.contains("\"protocol\": \"freedom\""));
    }
}
