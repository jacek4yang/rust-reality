//! Typed deployment snapshots: the observable state of one remote host.
//!
//! A deployment transaction begins with `inspect` and every verdict it later
//! produces is anchored on the snapshot it captured. A snapshot carries only
//! secret-free facts — service identity, executable path and digest, listener
//! state, restart counters — so it can be written to evidence verbatim.

use std::fmt::Write as _;

use crate::{
    deploy::{
        host::Host,
        remote::{Transport, checked},
    },
    perf::{json_in, json_out::Json},
};

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
                Json::from_optional(self.current_binary.as_ref()),
            ),
            (
                "currentConfig",
                Json::from_optional(self.current_config.as_ref()),
            ),
            (
                "previousBinary",
                Json::from_optional(self.previous_binary.as_ref()),
            ),
            (
                "previousConfig",
                Json::from_optional(self.previous_config.as_ref()),
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
            object.push((key, Json::from_optional(value.as_ref())));
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
                .map_or(Json::Null, GenerationPointers::to_json),
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

/// Captures one host's secret-free deployment state through the administrative
/// transport.
///
/// Every observation is a separate argv-only command. This intentionally avoids
/// the legacy remote Bash program: recorded transports can reproduce each reply,
/// failures identify the exact observation, and a process identity race fails the
/// snapshot instead of mixing facts from two processes.
///
/// # Errors
///
/// Returns the first failed observation or malformed remote value.
#[allow(clippy::too_many_lines)]
pub fn inspect(transport: &mut impl Transport, host: &Host) -> Result<HostSnapshot, String> {
    let service_state = transport
        .run(
            host,
            true,
            &strings(&["systemctl", "is-active", host.service()]),
        )?
        .stdout
        .trim()
        .to_owned();
    let pid_text = checked(
        transport,
        host,
        true,
        &strings(&[
            "systemctl",
            "show",
            host.service(),
            "-p",
            "MainPID",
            "--value",
        ]),
        "inspect service pid",
    )?;
    let pid = match pid_text.trim() {
        "" | "0" => None,
        text => Some(
            text.parse::<u32>()
                .map_err(|_| format!("inspect service pid returned {text:?}"))?,
        ),
    };
    let (executable, executable_sha256, version) = if let Some(pid) = pid {
        let proc_exe = format!("/proc/{pid}/exe");
        let executable = checked(
            transport,
            host,
            true,
            &["readlink".to_owned(), "-f".to_owned(), proc_exe],
            "inspect executable path",
        )?;
        if !executable.starts_with('/') || executable.chars().any(char::is_whitespace) {
            return Err(format!(
                "inspect executable path returned unsafe value {executable:?}"
            ));
        }
        let digest_line = checked(
            transport,
            host,
            true,
            &["sha256sum".to_owned(), executable.clone()],
            "inspect executable digest",
        )?;
        let digest = digest_line
            .split_whitespace()
            .next()
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .ok_or_else(|| format!("inspect executable digest returned {digest_line:?}"))?
            .to_owned();
        let version = checked(
            transport,
            host,
            true,
            &[executable.clone(), "--version".to_owned()],
            "inspect executable version",
        )?
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
        (Some(executable), Some(digest), Some(version))
    } else {
        (None, None, None)
    };

    let listener_text = checked(
        transport,
        host,
        true,
        &strings(&["ss", "-ltnH"]),
        "inspect TCP listeners",
    )?;
    let listeners: Vec<Listener> = listener_text
        .lines()
        .filter_map(parse_ss_listener)
        .collect();
    let ssh_22_present = listeners.iter().any(|listener| listener.port == 22);
    let service_443_present = listeners.iter().any(|listener| listener.port == 443);
    let restart_text = checked(
        transport,
        host,
        true,
        &strings(&[
            "systemctl",
            "show",
            host.service(),
            "-p",
            "NRestarts",
            "--value",
        ]),
        "inspect service restart count",
    )?;
    let restarts = if restart_text.trim().is_empty() {
        None
    } else {
        Some(
            restart_text
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("inspect restart count returned {restart_text:?}"))?,
        )
    };
    let current_binary = optional_readlink(transport, host, "/opt/rust-reality/current")?;
    let current_config = optional_readlink(transport, host, "/etc/rust-reality/current")?;
    let previous_binary = optional_readlink(transport, host, "/opt/rust-reality/previous")?;
    let previous_config = optional_readlink(transport, host, "/etc/rust-reality/previous")?;
    let generations = [
        &current_binary,
        &current_config,
        &previous_binary,
        &previous_config,
    ]
    .iter()
    .any(|value| value.is_some())
    .then_some(GenerationPointers {
        current_binary,
        current_config,
        previous_binary,
        previous_config,
    });

    Ok(HostSnapshot {
        alias: host.alias().to_owned(),
        service_state: if service_state.is_empty() {
            "unknown".to_owned()
        } else {
            service_state
        },
        pid,
        executable,
        executable_sha256,
        version,
        listeners,
        ssh_22_present,
        service_443_present,
        restarts,
        generations,
    })
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn optional_readlink(
    transport: &mut impl Transport,
    host: &Host,
    path: &str,
) -> Result<Option<String>, String> {
    let reply = transport.run(
        host,
        true,
        &["readlink".to_owned(), "-f".to_owned(), path.to_owned()],
    )?;
    if !reply.success() || reply.stdout.trim().is_empty() {
        return Ok(None);
    }
    let value = reply.stdout.trim();
    if !value.starts_with('/') || value.chars().any(char::is_whitespace) {
        return Err(format!("inspect generation pointer {path} returned {value:?}"));
    }
    Ok(Some(value.to_owned()))
}

/// Parses one complete `ss -ltnH` row, selecting its local-address column.
#[must_use]
pub fn parse_ss_listener(line: &str) -> Option<Listener> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let address = match fields.as_slice() {
        // Current iproute2: State Recv-Q Send-Q Local Peer
        // A recorded fixture may already contain only Local Address:Port.
        [_, _, _, local, ..] | [local] => *local,
        _ => return None,
    };
    parse_listener(address)
}

/// Parses a snapshot previously emitted by [`HostSnapshot::to_json`].
///
/// # Errors
///
/// Fails closed on a missing field, wrong type, out-of-range number, or malformed
/// listener/generation entry.
pub fn from_json(text: &str) -> Result<HostSnapshot, String> {
    let root = json_in::parse(text)?;
    let pid = optional_u32(&root, "pid")?;
    let listeners = json_field(root.array_field("snapshot", "listeners"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let path = format!("snapshot.listeners[{index}]");
            let port = json_field(value.int_field(&path, "port"))?;
            Ok(Listener {
                address: json_field(value.str_field(&path, "address"))?.to_owned(),
                port: u16::try_from(port)
                    .map_err(|_| format!("{path}.port: expected an unsigned 16-bit port"))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let generations = match json_field(root.field("snapshot", "generations"))? {
        json_in::Value::Null => None,
        value => Some(GenerationPointers {
            current_binary: optional_string(value, "currentBinary")?,
            current_config: optional_string(value, "currentConfig")?,
            previous_binary: optional_string(value, "previousBinary")?,
            previous_config: optional_string(value, "previousConfig")?,
        }),
    };
    Ok(HostSnapshot {
        alias: json_field(root.str_field("snapshot", "alias"))?.to_owned(),
        service_state: json_field(root.str_field("snapshot", "serviceState"))?.to_owned(),
        pid,
        executable: optional_string(&root, "executable")?,
        executable_sha256: optional_string(&root, "executableSha256")?,
        version: optional_string(&root, "version")?,
        listeners,
        ssh_22_present: json_field(json_field(root.field("snapshot", "ssh22Present"))?
            .as_bool("snapshot.ssh22Present"))?,
        service_443_present: json_field(json_field(root.field("snapshot", "service443Present"))?
            .as_bool("snapshot.service443Present"))?,
        restarts: optional_i64(&root, "restarts")?,
        generations,
    })
}

fn optional_string(value: &json_in::Value, key: &str) -> Result<Option<String>, String> {
    match json_field(value.field("snapshot", key))? {
        json_in::Value::Null => Ok(None),
        value => Ok(Some(
            json_field(value.as_str(&format!("snapshot.{key}")))?.to_owned(),
        )),
    }
}

fn optional_i64(value: &json_in::Value, key: &str) -> Result<Option<i64>, String> {
    match json_field(value.field("snapshot", key))? {
        json_in::Value::Null => Ok(None),
        value => Ok(Some(json_field(
            value.as_int(&format!("snapshot.{key}")),
        )?)),
    }
}

fn json_field<T>(result: Result<T, json_in::FieldError>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

fn optional_u32(value: &json_in::Value, key: &str) -> Result<Option<u32>, String> {
    optional_i64(value, key)?
        .map(|number| {
            u32::try_from(number)
                .map_err(|_| format!("snapshot.{key}: expected an unsigned 32-bit integer"))
        })
        .transpose()
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
    fn from_optional(value: Option<&String>) -> Json;
}

impl OptionalJson for Json {
    fn from_optional(value: Option<&String>) -> Json {
        value
            .map_or(Json::Null, |text| Json::string(text.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::{
        host::{HostRole, Topology},
        remote::{Reply, Transport},
    };
    use std::path::Path;

    #[derive(Default)]
    struct FakeTransport;

    impl Transport for FakeTransport {
        fn run(
            &mut self,
            _host: &Host,
            _privileged: bool,
            argv: &[String],
        ) -> Result<Reply, String> {
            let joined = argv.join(" ");
            let stdout = match joined.as_str() {
                "systemctl is-active rust-reality.service" => "active\n",
                "systemctl show rust-reality.service -p MainPID --value" => "4242\n",
                "readlink -f /proc/4242/exe" => {
                    "/opt/rust-reality/releases/r2/rust-reality\n"
                }
                "sha256sum /opt/rust-reality/releases/r2/rust-reality" => {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /opt/rust-reality/releases/r2/rust-reality\n"
                }
                "/opt/rust-reality/releases/r2/rust-reality --version" => {
                    "rust-reality 1.9.0\n"
                }
                "ss -ltnH" => {
                    "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 [::]:443 [::]:*\n"
                }
                "systemctl show rust-reality.service -p NRestarts --value" => "3\n",
                "readlink -f /opt/rust-reality/current" => {
                    "/opt/rust-reality/releases/r2\n"
                }
                "readlink -f /etc/rust-reality/current" => {
                    "/etc/rust-reality/releases/r2\n"
                }
                "readlink -f /opt/rust-reality/previous" => {
                    "/opt/rust-reality/releases/r1\n"
                }
                "readlink -f /etc/rust-reality/previous" => {
                    "/etc/rust-reality/releases/r1\n"
                }
                _ => return Err(format!("unexpected fake command {joined}")),
            };
            Ok(Reply {
                code: Some(0),
                stdout: stdout.to_owned(),
                stderr: String::new(),
            })
        }

        fn copy_to(&mut self, _host: &Host, _local: &Path, _remote: &str) -> Result<(), String> {
            Err("copy is not part of read-only inspection".to_owned())
        }
    }

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
        assert_eq!(from_json(&json).unwrap(), snapshot);
    }

    #[test]
    fn fake_transport_reproduces_a_complete_read_only_snapshot() {
        let topology = Topology::canonical().unwrap();
        let snapshot = inspect(&mut FakeTransport, topology.host(HostRole::Line)).unwrap();
        assert!(snapshot.service_healthy());
        assert!(snapshot.ssh_22_present);
        assert_eq!(snapshot.restarts, Some(3));
        assert_eq!(snapshot.listeners.len(), 2);
        assert_eq!(
            snapshot.generations.unwrap().previous_binary.as_deref(),
            Some("/opt/rust-reality/releases/r1")
        );
    }

    #[test]
    fn complete_ss_rows_and_address_only_fixtures_parse() {
        assert_eq!(parse_ss_listener("LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*"), parse_listener("0.0.0.0:443"));
        assert_eq!(parse_ss_listener("[::]:22"), parse_listener("[::]:22"));
        assert_eq!(parse_ss_listener("not enough fields"), None);
    }
}
