//! Typed deployment hosts and the administrative SSH boundary.
//!
//! A deployment talks to exactly two operator-defined remote hosts. The control
//! plane and the data plane use different network paths: administrative SSH goes
//! through the operator's own OpenSSH configuration (whose proxy route is local
//! operator policy, not repository policy), while the rust-reality data plane is
//! direct TCP. The repository therefore knows hosts only by their SSH alias and
//! role — never by address, user, port, or identity file, which all stay in the
//! operator's `~/.ssh/config`.
//!
//! Every remote operation is constructed as an argv, never a shell string, so a
//! release id or service name cannot smuggle a second command. Secret redaction
//! is applied before anything is logged or written to evidence.

use std::fmt;

/// The role a remote host plays in the two-node topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRole {
    /// The public entry node: direct client-facing TCP/443.
    Line,
    /// The downstream node: TCP/443 for LINE-origin traffic only.
    Landing,
}

impl HostRole {
    /// The stable lowercase role name used in evidence.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Landing => "landing",
        }
    }
}

impl fmt::Display for HostRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// One administrative host: a role plus the SSH alias that reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    role: HostRole,
    alias: String,
    service: String,
}

impl Host {
    /// Builds a host from its role and SSH alias, validating the alias shape.
    ///
    /// # Errors
    ///
    /// Returns a message when the alias is not a plausible SSH config alias:
    /// nonempty, no whitespace, and no characters that would end an argv token.
    pub fn new(role: HostRole, alias: &str, service: &str) -> Result<Self, String> {
        for (label, value) in [("alias", alias), ("service", service)] {
            if value.is_empty() || value.chars().any(char::is_whitespace) {
                return Err(format!("host {label} must be a single argv token"));
            }
        }
        Ok(Self {
            role,
            alias: alias.to_owned(),
            service: service.to_owned(),
        })
    }

    /// The SSH alias; the only host identifier the repository carries.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The systemd unit serving rust-reality on this host.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The non-mutating SSH argv to run `command` on this host.
    ///
    /// `BatchMode` keeps a hung run from blocking on a passphrase prompt, and the
    /// connect timeout bounds a dead route. The alias selects everything else
    /// (user, port, proxy route) from the operator's own configuration.
    #[must_use]
    pub fn ssh_argv(&self, command: &[String]) -> Vec<String> {
        let mut argv = vec![
            "ssh".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "ConnectTimeout=10".to_owned(),
            self.alias.clone(),
        ];
        argv.extend(command.iter().cloned());
        argv
    }

    /// The privileged SSH argv: `sudo -n` as the remote command.
    #[must_use]
    pub fn ssh_sudo_argv(&self, command: &[String]) -> Vec<String> {
        let mut argv = vec![
            "ssh".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "ConnectTimeout=10".to_owned(),
            self.alias.clone(),
            "sudo".to_owned(),
            "-n".to_owned(),
        ];
        argv.extend(command.iter().cloned());
        argv
    }
}

/// The fixed two-host topology the deployment family operates on.
///
/// Construction validates the repository-side contract: LINE is
/// `rust-reality-vps`, LANDING is `rust-reality-landing-vps`, both running the
/// same systemd unit name. Addresses, users, ports and the proxy route live in
/// the operator's SSH configuration and are never modelled here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    line: Host,
    landing: Host,
}

impl Topology {
    /// The canonical topology with the repository-defined aliases.
    ///
    /// # Errors
    ///
    /// Returns a message if the canonical names are internally invalid (which is
    /// a programming error, not an operator mistake).
    pub fn canonical() -> Result<Self, String> {
        Self::new("rust-reality-vps", "rust-reality-landing-vps")
    }

    /// Builds a topology from explicit aliases (tests use this).
    ///
    /// # Errors
    ///
    /// Returns a message when a service name or alias is not an argv token.
    pub fn new(line_alias: &str, landing_alias: &str) -> Result<Self, String> {
        Ok(Self {
            line: Host::new(HostRole::Line, line_alias, "rust-reality.service")?,
            landing: Host::new(HostRole::Landing, landing_alias, "rust-reality.service")?,
        })
    }

    /// Looks up a host by role.
    #[must_use]
    pub const fn host(&self, role: HostRole) -> &Host {
        match role {
            HostRole::Line => &self.line,
            HostRole::Landing => &self.landing,
        }
    }
}

/// Redacts known secret shapes from text destined for evidence or logs.
///
/// Full config documents are fingerprinted by [`crate::checks::config_identity`]
/// rather than copied; this guards the residual paths where config fragments or
/// key-value material could leak into a transcript. Each rule names a JSON string
/// field, a required value shape, and the marker that replaces the whole span:
/// only spans whose value matches the shape are rewritten, so ordinary text that
/// merely mentions a key name passes through untouched.
#[must_use]
pub fn redact_secrets(text: &str) -> String {
    let rules: [(&str, Shape, &str); 5] = [
        (
            "\"privateKey\":\"",
            Shape::base64url_min(20),
            "\"privateKey\":\"<redacted:private-key>\"",
        ),
        (
            "\"password\":\"",
            Shape::any(),
            "\"password\":\"<redacted:password>\"",
        ),
        ("\"id\":\"", Shape::uuid(), "\"id\":\"<redacted:uuid>\""),
        (
            "\"shortId\":\"",
            Shape::hex(16),
            "\"shortId\":\"<redacted:short-id>\"",
        ),
        (
            "\"shortIds\":[\"",
            Shape::hex(16),
            "\"shortIds\":[\"<redacted:short-id>\"",
        ),
    ];
    let mut result = text.to_owned();
    for (key, shape, replacement) in rules {
        result = redact_field(&result, key, &shape, replacement);
    }
    result
}

/// The value shape a redaction rule accepts.
struct Shape {
    /// Every value character must be in this set.
    charset: fn(u8) -> bool,
    /// The value's exact length, when the shape fixes it.
    exact_len: Option<usize>,
    /// The value's minimum length, when the shape only bounds it.
    min_len: usize,
    /// Required count of hexadecimal digits (UUIDs include separators).
    exact_hex_digits: Option<usize>,
}

impl Shape {
    fn any() -> Self {
        Self {
            charset: |_| true,
            exact_len: None,
            min_len: 0,
            exact_hex_digits: None,
        }
    }

    fn base64url_min(min_len: usize) -> Self {
        Self {
            charset: |byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-',
            exact_len: None,
            min_len,
            exact_hex_digits: None,
        }
    }

    fn hex(exact_len: usize) -> Self {
        Self {
            charset: |byte| byte.is_ascii_hexdigit(),
            exact_len: Some(exact_len),
            min_len: exact_len,
            exact_hex_digits: Some(exact_len),
        }
    }

    fn uuid() -> Self {
        // Canonical 8-4-4-4-12 hexadecimal with hyphens.
        Self {
            charset: |byte| byte.is_ascii_hexdigit() || byte == b'-',
            exact_len: Some(36),
            min_len: 36,
            exact_hex_digits: Some(32),
        }
    }

    fn matches(&self, value: &[u8]) -> bool {
        value.len() >= self.min_len
            && self.exact_len.is_none_or(|len| value.len() == len)
            && value.iter().all(|byte| (self.charset)(*byte))
            && self.exact_hex_digits.is_none_or(|expected| {
                value.iter().filter(|byte| byte.is_ascii_hexdigit()).count() == expected
            })
    }
}

/// Replaces every `"key":"<matching value>"` span with `replacement`.
///
/// A literal scan keeps the policy dependency-free: the rule fires only on an
/// exact key prefix followed by a quoted value with the rule's shape, so
/// prose that mentions a key cannot be corrupted.
fn redact_field(text: &str, key: &str, shape: &Shape, replacement: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(key) {
        result.push_str(&rest[..start]);
        let value_start = start + key.len();
        let bytes = rest.as_bytes();
        let mut end = value_start;
        while end < bytes.len() && bytes[end] != b'"' {
            end += 1;
        }
        let matched = end < bytes.len() && shape.matches(&bytes[value_start..end]);
        if matched {
            result.push_str(replacement);
            rest = &rest[end + 1..];
        } else {
            result.push_str(&rest[start..=end.min(bytes.len().saturating_sub(1))]);
            rest = &rest[Ord::min(end + 1, rest.len())..];
            if end >= bytes.len() {
                break;
            }
        }
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_topology_uses_the_fixed_aliases() {
        let topology = Topology::canonical().expect("canonical topology is valid");
        assert_eq!(topology.host(HostRole::Line).alias(), "rust-reality-vps");
        assert_eq!(
            topology.host(HostRole::Landing).alias(),
            "rust-reality-landing-vps"
        );
    }

    #[test]
    fn ssh_argv_uses_the_alias_and_nothing_but_the_alias() {
        let topology = Topology::new("line-alias", "landing-alias").unwrap();
        let argv = topology.host(HostRole::Line).ssh_argv(&[
            "true".to_owned(),
            "&&".to_owned(),
            "rm".to_owned(),
        ]);
        // The alias selects user/port/proxy from the operator's config; no
        // address, user, port, identity file, or proxy override is present.
        assert_eq!(
            argv,
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "line-alias",
                "true",
                "&&",
                "rm"
            ]
        );
    }

    #[test]
    fn sudo_argv_prepends_sudo_n_to_the_remote_command() {
        let topology = Topology::new("line", "landing").unwrap();
        let argv = topology.host(HostRole::Line).ssh_sudo_argv(&[
            "systemctl".to_owned(),
            "reload".to_owned(),
            "rust-reality.service".to_owned(),
        ]);
        assert_eq!(
            &argv[..8],
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "line",
                "sudo",
                "-n"
            ]
        );
        assert_eq!(&argv[8..], ["systemctl", "reload", "rust-reality.service"]);
    }

    #[test]
    fn a_whitespace_alias_is_rejected() {
        assert!(Host::new(HostRole::Line, "two words", "rust-reality.service").is_err());
        assert!(Host::new(HostRole::Line, "ok", "bad service").is_err());
        assert!(Host::new(HostRole::Line, "", "rust-reality.service").is_err());
    }

    #[test]
    fn redaction_hides_identity_values_but_keeps_structure() {
        let config = r#"{"inbounds":[{"settings":{"clients":[{"id":"0d67a4b2-3f0c-4c1e-9a2b-6f5e8d7c6b5a","shortIds":["0123456789abcdef"]}]}}],"outbounds":[],"privateKey":"kQ1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v"}"#;
        let redacted = redact_secrets(config);
        assert!(redacted.contains("<redacted:uuid>"), "{redacted}");
        assert!(redacted.contains("<redacted:short-id>"), "{redacted}");
        assert!(redacted.contains("<redacted:private-key>"), "{redacted}");
        assert!(!redacted.contains("0d67a4b2"), "{redacted}");
        assert!(!redacted.contains("0123456789abcdef"), "{redacted}");
        assert!(!redacted.contains("kQ1b2C3d4E5f6G7h8"), "{redacted}");
        // Structure survives so a redacted document stays diffable.
        assert!(redacted.contains("\"inbounds\""));
    }

    #[test]
    fn a_value_with_the_wrong_shape_is_not_redacted() {
        // A UUID-shaped "id" must be 36 characters; a shorter id stays intact.
        let text = r#"{"id":"vless-user-1","shortId":"01"}"#;
        assert_eq!(redact_secrets(text), text);
        // A password field with an empty value is still a secret field.
        let empty = r#"{"password":""}"#;
        assert_eq!(
            redact_secrets(empty),
            r#"{"password":"<redacted:password>"}"#
        );
    }

    #[test]
    fn ordinary_text_passes_through_redaction_unchanged() {
        let text = "service=rust-reality.service state=active";
        assert_eq!(redact_secrets(text), text);
    }
}
