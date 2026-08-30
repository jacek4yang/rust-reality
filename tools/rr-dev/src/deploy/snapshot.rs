//! Typed deployment snapshots: the observable state of one remote host.
//!
//! A deployment transaction begins with `inspect` and every verdict it later
//! produces is anchored on the snapshot it captured. A snapshot carries only
//! secret-free facts — service identity, executable path and digest, listener
//! state, restart counters — so it can be written to evidence verbatim.

use std::fmt::Write as _;

use crate::perf::json_out::Json;

/// The release-generation pointers a CURRENT/PREVIOUS deployment maintains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationPointers {
    /// Resolved binary directory behind `current`.
    pub current_binary: Option<String>,
    /// Resolved config directory behind `current`.
    pub current_config: Option<String>,
    /// Resolved binary directory behind `previous`.
    pub previous_binary: Option<String>,
    /// Resolved config directory behind `previous`.
    pub previous_config: Option<String>,
}

impl GenerationPointers {
    /// Renders the pointers as evidence JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            (
                "currentBinary",
                Json::from_optional(&self.current_binary),
            ),
            (
                "currentConfig",
                Json::from_optional(&self.current_config),
            ),
            (
                "previousBinary",
                Json::from_optional(&self.previous_binary),
            ),
            (
                "previousConfig",
                Json::from_optional(&self.previous_config),
            ),
        ])
    }
}

/// One observed public listener (`address:port` as `ss -ltnH` reports it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// The raw listen address column.
    pub address: String,
    /// The listen port.
    pub port: u16,
}

impl Listener {
    /// Whether this listener is on a wildcard address.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        matches!(
            self.address.as_str(),
            "0.0.0.0" | "::" | "*" | "[::]" | "0.0.0.0:*"
        ) || self.address.starts_with('*')
            || self.address.starts_with("0.0.0.0")
            || self.address.starts_with("[::]")
    }
}

/// The secret-free observable state of one deployed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSnapshot {
    /// The SSH alias the snapshot came from.
    pub alias: String,
    /// The systemd unit state (`active`, `failed`, `inactive`, …).
    pub service_state: String,
    /// The main process id, when the service is running.
    pub pid: Option<u32>,
    /// The running executable's resolved path.
    pub executable: Option<String>,
    /// The running executable's SHA-256.
    pub executable_sha256: Option<String>,
    /// The first `--version` line of the running executable.
    pub version: Option<String>,
    /// Public listeners observed on 22/443 plus any other public port.
    pub listeners: Vec<Listener>,
    /// Whether TCP/22 is listening (SSH must always be intact).
    pub ssh_22_present: bool,
    /// Whether TCP/443 is listening.
    pub service_443_present: bool,
    /// systemd's restart counter for the unit.
    pub restarts: Option<i64>,
    /// The resolved CURRENT/PREVIOUS generation pointers.
    pub generations: Option<GenerationPointers>,
}

impl HostSnapshot {
    /// Ports a rust-reality node may legitimately expose publicly.
    ///
    /// TCP/22 is permanent administrative infrastructure and TCP/443 is the only
    /// public rust-reality listener; every other public port is unexpected.
    pub const EXPECTED_PUBLIC_PORTS: [u16; 2] = [22, 443];

    /// Public listeners outside the expected set.
    ///
    /// The legacy rule is retained deliberately: some hosts run an unrelated,
    /// firewall-blocked daemon on a wildcard port, so a *snapshot* records what
    /// is there while the *plan* rejects only ports a cutover would newly
    /// introduce.
    #[must_use]
    pub fn unexpected_public_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .listeners
            .iter()
            .filter(|listener| listener.is_wildcard())
            .map(|listener| listener.port)
            .filter(|port| !Self::EXPECTED_PUBLIC_PORTS.contains(port))
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Whether TCP/443 is owned and the unit is active.
    #[must_use]
    pub fn service_healthy(&self) -> bool {
        self.service_state == "active" && self.service_443_present
    }

    /// Renders the snapshot as evidence JSON (secret-free by construction).
    #[must_use]
    pub fn to_json(&self) -> Json {
        let mut object = vec![
            ("alias", Json::string(self.alias.clone())),
            ("serviceState", Json::string(self.service_state.clone())),
        ];
        if let Some(pid) = self.pid {
            object.push(("pid", Json::Int(i64::from(pid))));
        } else {
            object.push(("pid", Json::Null));
        }
        for (key, value) in [
            ("executable", &self.executable),
            ("executableSha256", &self.executable_sha256),
            ("version", &self.version),
        ] {
            object.push((key, Json::from_optional(value)));
        }
        object.push((
            "listeners",
            Json::Array(
                self.listeners
                    .iter()
                    .map(|listener| {
                        Json::object([
                            ("address", Json::string(listener.address.clone())),
                            ("port", Json::Int(i64::from(listener.port))),
                        ])
                    })
                    .collect(),
            ),
        ));
        object.push(("ssh22Present", Json::Bool(self.ssh_22_present)));
        object.push(("service443Present", Json::Bool(self.service_443_present)));
        object.push((
            "unexpectedPublicPorts",
            Json::Array(
                self.unexpected_public_ports()
                    .iter()
                    .map(|port| Json::Int(i64::from(*port)))
                    .collect(),
            ),
        ));
        object.push((
            "restarts",
            self.restarts.map_or(Json::Null, |restarts| {
                Json::Int(restarts)
            }),
        ));
        object.push((
            "generations",
            self.generations
                .as_ref()
                .map_or(Json::Null, |generations| generations.to_json()),
        ));
        Json::object(object)
    }

    /// A one-line secret-free summary for logs.
    #[must_use]
    pub fn summary_line(&self) -> String {
        let mut line = format!(
            "{} state={} pid={} 443={}",
            self.alias,
            self.service_state,
            self.pid.map_or(String::new(), |pid| pid.to_string()),
            self.service_443_present
        );
        if let Some(sha) = &self.executable_sha256 {
            let _ = write!(line, " exe-sha256={sha}");
        }
        let unexpected = self.unexpected_public_ports();
        if !unexpected.is_empty() {
            let _ = write!(line, " unexpected-ports={unexpected:?}");
        }
        line
    }
}

/// Parses one `ss -ltnH` output line into a listener.
///
/// The address column carries forms like `0.0.0.0:443`, `[::]:443`,
/// `127.0.0.1:8080` or `*:22`; the port is everything after the final colon.
#[must_use]
pub fn parse_listener(line: &str) -> Option<Listener> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (address, port_text) = line.rsplit_once(':')?;
    let port = port_text.parse().ok()?;
    Some(Listener {
        address: address.to_owned(),
        port,
    })
}

trait OptionalJson {
    fn from_optional(value: &Option<String>) -> Json;
}

impl OptionalJson for Json {
    fn from_optional(value: &Option<String>) -> Json {
        value
            .as_ref()
            .map_or(Json::Null, |text| Json::string(text.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners_parse_from_ss_output_shapes() {
        assert_eq!(
            parse_listener("0.0.0.0:443"),
            Some(Listener { address: "0.0.0.0".into(), port: 443 })
        );
        assert_eq!(
            parse_listener("[::]:22"),
            Some(Listener { address: "[::]".into(), port: 22 })
        );
        assert_eq!(
            parse_listener("*:9100"),
            Some(Listener { address: "*".into(), port: 9100 })
        );
        assert_eq!(
            parse_listener("127.0.0.1:8080"),
            Some(Listener { address: "127.0.0.1".into(), port: 8080 })
        );
        assert_eq!(parse_listener(""), None);
        assert_eq!(parse_listener("garbage"), None);
    }

    #[test]
    fn unexpected_ports_exclude_22_443_and_non_wildcard() {
        let snapshot = HostSnapshot {
            alias: "line".into(),
            service_state: "active".into(),
            pid: Some(4242),
            executable: Some("/opt/rust-reality/current/rust-reality".into()),
            executable_sha256: Some("a".repeat(64)),
            version: Some("rust-reality 1.9.0".into()),
            listeners: vec![
                Listener { address: "0.0.0.0".into(), port: 22 },
                Listener { address: "[::]".into(), port: 443 },
                Listener { address: "127.0.0.1".into(), port: 9100 },
                Listener { address: "0.0.0.0".into(), port: 19999 },
            ],
            ssh_22_present: true,
            service_443_present: true,
            restarts: Some(0),
            generations: None,
        };
        assert_eq!(snapshot.unexpected_public_ports(), vec![19_999]);
        assert!(snapshot.service_healthy());
        let line = snapshot.summary_line();
        assert!(line.contains("unexpected-ports=[19999]"), "{line}");
        assert!(line.contains("exe-sha256="), "{line}");
    }

    #[test]
    fn json_renders_snapshot_without_secrets() {
        let snapshot = HostSnapshot {
            alias: "landing".into(),
            service_state: "active".into(),
            pid: Some(100),
            executable: Some("/opt/rust-reality/current/rust-reality".into()),
            executable_sha256: Some("b".repeat(64)),
            version: Some("rust-reality 1.9.0".into()),
            listeners: vec![Listener { address: "0.0.0.0".into(), port: 22 }],
            ssh_22_present: true,
            service_443_present: false,
            restarts: Some(2),
            generations: Some(GenerationPointers {
                current_binary: Some("/opt/rust-reality/releases/r1".into()),
                current_config: Some("/etc/rust-reality/releases/r1".into()),
                previous_binary: Some("/opt/rust-reality/releases/r0".into()),
                previous_config: Some("/etc/rust-reality/releases/r0".into()),
            }),
        };
        let json = snapshot.to_json().to_compact_json();
        assert!(json.contains("\"service443Present\": false"), "{json}");
        assert!(json.contains("\"restarts\": 2"), "{json}");
        assert!(json.contains("releases/r1"), "{json}");
        assert!(!json.to_lowercase().contains("key"), "{json}");
    }
}
