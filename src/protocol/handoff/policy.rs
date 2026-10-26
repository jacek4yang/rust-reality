//! Sealable Handoff policy snapshot and session-kind wire types (ADR 0060).
//!
//! These types are compiled on LINE at transfer time and authorized on LANDING
//! after AEAD open. Encoding/decoding of the snapshot body stays in the parent
//! module alongside the continuation blob codec.

use super::HandoffError;
use crate::protocol::vless::{Address, Destination};

/// Maximum sealed policy-snapshot payload (ADR 0060 Option B foundation).
pub const MAX_POLICY_SNAPSHOT_LEN: usize = 1024;

/// Maximum first-match sealed route rules inside one policy snapshot.
pub const MAX_SEALED_HANDOFF_RULES: usize = 32;

/// Policy snapshot format version inside the continuation blob.
///
/// - Version 1: initial destination + `allow_destination_rewrites` flag only
///   (PR4). Decoded as rewrite-disabled / empty rule list.
/// - Version 2: ordered sealable route rules + default-outbound allow bit (PR5).
pub const HANDOFF_POLICY_SNAPSHOT_VERSION: u8 = 2;

/// Legacy PR4 policy snapshot version (still accepted on decode).
pub const HANDOFF_POLICY_SNAPSHOT_VERSION_V1: u8 = 1;

/// Vision session kind transferred with the TLS continuation (ADR 0060).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionKind {
    /// Ordinary Vision TCP relay after LANDING resume.
    Tcp = 0,
    /// Vision XUDP (Mux); LANDING owns TLS decrypt and UDP sockets.
    Xudp = 1,
}

impl SessionKind {
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Tcp),
            1 => Some(Self::Xudp),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// Sealable domain matcher (no geosite / regex / external assets).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealedDomainMatcher {
    /// `full:example.com`
    Full(String),
    /// `domain:example.com` / bare suffix
    Suffix(String),
    /// `keyword:foo`
    Keyword(String),
}

impl SealedDomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        match self {
            Self::Full(value) => domain == value.as_str(),
            Self::Suffix(value) => {
                domain == value.as_str()
                    || (domain.len() > value.len()
                        && domain.ends_with(value.as_str())
                        && domain.as_bytes()[domain.len() - value.len() - 1] == b'.')
            }
            Self::Keyword(value) => {
                value.is_empty()
                    || domain
                        .as_bytes()
                        .windows(value.len())
                        .any(|window| window == value.as_bytes())
            }
        }
    }
}

/// Sealable IPv4/IPv6 network (no geoip / external assets).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealedIpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl SealedIpNetwork {
    #[must_use]
    pub fn contains(self, address: std::net::IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, std::net::IpAddr::V4(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(addr) & mask) == (network & mask)
            }
            (Self::V6 { network, prefix }, std::net::IpAddr::V6(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(addr) & mask) == (network & mask)
            }
            _ => false,
        }
    }
}

/// Inclusive destination port range sealed into a Handoff policy rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedPortRange {
    pub start: u16,
    pub end: u16,
}

impl SealedPortRange {
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// One first-match sealed rule mirroring LINE routing for this Handoff outbound.
///
/// Empty domain / IP / port groups mean "match any" for that group (AND across
/// groups), matching [`crate::server::routing`] semantics for sealable rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedHandoffRouteRule {
    /// `true` when the matched outbound is the Handoff egress used for transfer.
    pub allow: bool,
    pub domains: Vec<SealedDomainMatcher>,
    pub ips: Vec<SealedIpNetwork>,
    pub ports: Vec<SealedPortRange>,
}

impl SealedHandoffRouteRule {
    fn matches(&self, destination: &Destination) -> bool {
        let port_ok = self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|range| range.contains(destination.port()));
        if !port_ok {
            return false;
        }
        let domain_ok = if self.domains.is_empty() {
            true
        } else {
            match destination.address() {
                Address::Domain(domain) => self.domains.iter().any(|m| m.matches(domain)),
                Address::Ipv4(_) | Address::Ipv6(_) => false,
            }
        };
        if !domain_ok {
            return false;
        }
        if self.ips.is_empty() {
            true
        } else {
            match destination.address() {
                Address::Ipv4(addr) => self
                    .ips
                    .iter()
                    .any(|net| net.contains(std::net::IpAddr::V4(*addr))),
                Address::Ipv6(addr) => self
                    .ips
                    .iter()
                    .any(|net| net.contains(std::net::IpAddr::V6(*addr))),
                Address::Domain(_) => false,
            }
        }
    }
}

/// Session-bound UDP authorization sealed at Handoff transfer (ADR 0060 Option B).
///
/// PR5: LANDING evaluates Keep destination rewrites against ordered sealable
/// route rules compiled on LINE at transfer time. Non-sealable matchers
/// (geosite/geoip/regexp/ext) force rewrite-disabled fail-closed snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffPolicySnapshot {
    initial_destination: Destination,
    allow_destination_rewrites: bool,
    /// First-match sealed rules (global then user), then [`Self::default_allow`].
    rules: Vec<SealedHandoffRouteRule>,
    /// Whether the user's default outbound is this Handoff egress.
    default_allow: bool,
}

impl HandoffPolicySnapshot {
    #[must_use]
    pub fn tcp_placeholder(destination: Destination) -> Self {
        Self {
            initial_destination: destination,
            allow_destination_rewrites: false,
            rules: Vec::new(),
            default_allow: false,
        }
    }

    /// Initial-destination-only XUDP policy (rewrites fail closed).
    #[must_use]
    pub fn xudp_initial(destination: Destination) -> Self {
        Self {
            initial_destination: destination,
            allow_destination_rewrites: false,
            rules: Vec::new(),
            default_allow: false,
        }
    }

    /// Multi-destination XUDP policy with ordered sealed rules (PR5).
    #[must_use]
    pub fn xudp_with_sealed_rules(
        destination: Destination,
        rules: Vec<SealedHandoffRouteRule>,
        default_allow: bool,
    ) -> Self {
        let allow_destination_rewrites = default_allow || rules.iter().any(|rule| rule.allow);
        Self {
            initial_destination: destination,
            allow_destination_rewrites,
            rules,
            default_allow,
        }
    }

    #[must_use]
    pub const fn initial_destination(&self) -> &Destination {
        &self.initial_destination
    }

    #[must_use]
    pub const fn allow_destination_rewrites(&self) -> bool {
        self.allow_destination_rewrites
    }

    #[must_use]
    pub fn sealed_rules(&self) -> &[SealedHandoffRouteRule] {
        &self.rules
    }

    #[must_use]
    pub const fn default_allow(&self) -> bool {
        self.default_allow
    }

    /// Authorize one XUDP New/Keep destination against this snapshot.
    ///
    /// # Errors
    ///
    /// Deny when the destination differs from the sealed initial target and
    /// either rewrites are disabled or no sealed rule / default allows it.
    pub fn authorize_udp_destination(&self, destination: &Destination) -> Result<(), HandoffError> {
        if destination == &self.initial_destination {
            return Ok(());
        }
        if !self.allow_destination_rewrites {
            return Err(HandoffError::State);
        }
        for rule in &self.rules {
            if rule.matches(destination) {
                return if rule.allow {
                    Ok(())
                } else {
                    Err(HandoffError::State)
                };
            }
        }
        if self.default_allow {
            Ok(())
        } else {
            Err(HandoffError::State)
        }
    }
}
