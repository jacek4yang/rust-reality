//! Routing correctness at scale: first-match ordering, conjunction semantics,
//! per-user versus global ordering, the unknown-UUID authorization invariant,
//! and the `IpIfNonMatch` two-pass path, all validated against an independent
//! config-level oracle on randomized rule sets straddling the indexed-path
//! threshold.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use rust_reality::runtime::policy::ResourceGovernorPolicy;
use rust_reality::{
    assets::{AssetMatcher, AssetSource},
    config::node::{
        routing::{DomainStrategy, RoutePolicy, RouteRule, RoutingConfig},
        user::UserConfig,
    },
    protocol::vless::{Address, Destination, UserId},
    runtime::ResourceGovernor,
    server::routing::{RouteContext, RouteResolutionError, RouteScope, RoutingTable},
};

const PRIMARY: &str = "11111111-1111-1111-1111-111111111111";
const PRIMARY_ID: UserId = UserId::new([0x11; 16]);

/// Deterministic stub: GeoSite/external label `L` matches `{L}.stubbed` and
/// `*.{L}.stubbed`; GeoIP label `gN` matches `198.51.100.N`.
struct StubAssets;

impl AssetMatcher for StubAssets {
    fn matches_domain(&self, source: &AssetSource, label: &str, domain: &str) -> bool {
        if *source == AssetSource::GeoIp {
            return false;
        }
        let marker = format!("{label}.stubbed");
        domain == marker || domain.ends_with(&format!(".{marker}"))
    }

    fn matches_ip(&self, source: &AssetSource, label: &str, address: IpAddr) -> bool {
        if *source != AssetSource::GeoIp {
            return false;
        }
        let Some(index) = label.strip_prefix('g').and_then(|n| n.parse::<u8>().ok()) else {
            return false;
        };
        matches!(address, IpAddr::V4(v4) if v4 == Ipv4Addr::new(198, 51, 100, index))
    }
}

/// xorshift64* so the test needs no external RNG dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn random_rule(rng: &mut Rng, index: usize) -> RouteRule {
    let mut domain = Vec::new();
    let mut ip = Vec::new();
    let mut port = Vec::new();
    for _ in 0..rng.below(3) {
        let matcher = match rng.below(8) {
            0 => format!("full:host{}.full.test", rng.below(50)),
            1 => format!("domain:sfx{}.s.test", rng.below(50)),
            2 => format!("keyword:tok{}", rng.below(50)),
            3 => [
                "regexp:^api\\.",
                "regexp:\\.internal$",
                "regexp:^cdn[0-9]+\\.",
            ][rng.below(3)]
            .to_owned(),
            4 => format!("geosite:l{}", rng.below(8)),
            5 => format!("ext:extra.dat:e{}", rng.below(4)),
            6 => format!("plain{}.plain.test", rng.below(50)),
            _ => "keyword:".to_owned(),
        };
        domain.push(matcher);
    }
    for _ in 0..rng.below(2) {
        ip.push(match rng.below(4) {
            0 => format!("10.{}.0.0/16", rng.below(256)),
            1 => "2001:db8::/32".to_owned(),
            2 => format!("geoip:g{}", rng.below(8)),
            _ => format!("198.51.100.{}/32", rng.below(256)),
        });
    }
    if rng.chance(30) {
        port.push(["53", "443", "1000-2000", "8000-9000"][rng.below(4)].to_owned());
    }
    // A rule with no condition is rejected by validation, so the generator
    // never produces one.
    if domain.is_empty() && ip.is_empty() && port.is_empty() {
        domain.push(format!("plain{index}.plain.test"));
    }
    RouteRule {
        name: Some(format!("rule-{index}")),
        outbound: format!("out-{:02}", rng.below(8)),
        domain: (!domain.is_empty()).then_some(domain),
        ip: (!ip.is_empty()).then_some(ip),
        port: (!port.is_empty()).then_some(port),
    }
}

fn random_destination(rng: &mut Rng) -> Destination {
    let port = [53u16, 443, 1500, 8443][rng.below(4)];
    match rng.below(4) {
        0 => Destination::new(
            Address::Ipv4(Ipv4Addr::new(10, rng.below(256) as u8, 1, 2)),
            port,
        ),
        1 => Destination::new(
            Address::Ipv4(Ipv4Addr::new(198, 51, 100, rng.below(256) as u8)),
            port,
        ),
        2 => {
            let domain = match rng.below(8) {
                0 => format!("host{}.full.test", rng.below(50)),
                1 => format!("WWW.HOST{}.FULL.TEST", rng.below(50)),
                2 => format!("deep.sub.sfx{}.s.test", rng.below(50)),
                3 => format!("x-tok{}-y.test", rng.below(50)),
                4 => format!("l{}.stubbed", rng.below(8)),
                5 => format!("www.l{}.stubbed", rng.below(8)),
                6 => "trailing.dot.test.".to_owned(),
                _ => format!("unrelated-{}.test", rng.below(1000)),
            };
            Destination::new(Address::Domain(domain), port)
        }
        _ => Destination::new(
            Address::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        ),
    }
}

/// Independent config-level oracle: interprets `RouteRule` strings directly,
/// sharing nothing with the router's compiled representation.
mod oracle {
    use super::{AssetMatcher, Destination, IpAddr, RouteRule, StubAssets};
    use rust_reality::{assets::AssetSource, protocol::vless::Address};

    pub(super) fn rule_matches(
        rule: &RouteRule,
        destination: &Destination,
        resolved: &[IpAddr],
        _inbound_tag: &str,
    ) -> bool {
        let domain = match destination.address() {
            Address::Domain(domain) => Some(domain.to_ascii_lowercase()),
            _ => None,
        };
        let domain_ok = rule.domain().is_empty()
            || domain.as_deref().is_some_and(|domain| {
                rule.domain()
                    .iter()
                    .any(|matcher| domain_matches(matcher, domain))
            });
        let ips: Vec<IpAddr> = match destination.address() {
            Address::Ipv4(v4) => vec![IpAddr::V4(*v4)],
            Address::Ipv6(v6) => vec![IpAddr::V6(*v6)],
            Address::Domain(_) => resolved.to_vec(),
        };
        let ip_ok = rule.ip().is_empty()
            || ips
                .iter()
                .any(|address| rule.ip().iter().any(|m| ip_matches(m, *address)));
        let port_ok = rule.port().is_empty()
            || rule.port().iter().any(|port| {
                let (start, end) = port
                    .split_once('-')
                    .map_or((port.as_str(), port.as_str()), |(a, b)| (a, b));
                let start: u16 = start.parse().expect("test ports parse");
                let end: u16 = end.parse().expect("test ports parse");
                start <= destination.port() && destination.port() <= end
            });
        domain_ok && ip_ok && port_ok
    }

    fn domain_matches(matcher: &str, domain: &str) -> bool {
        let lower = matcher.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("full:") {
            return domain == value;
        }
        if let Some(value) = lower.strip_prefix("domain:") {
            return suffix_matches(domain, value.trim_start_matches('.'));
        }
        if let Some(value) = lower.strip_prefix("keyword:") {
            return value.is_empty() || domain.contains(value);
        }
        if let Some(value) = matcher.strip_prefix("regexp:") {
            return regex::RegexBuilder::new(value)
                .case_insensitive(true)
                .build()
                .expect("test regex compiles")
                .is_match(domain);
        }
        if let Some(label) = lower.strip_prefix("geosite:") {
            return StubAssets.matches_domain(&AssetSource::GeoSite, label, domain);
        }
        if let Some(rest) = lower.strip_prefix("ext:") {
            let (file, label) = rest.split_once(':').expect("test ext matcher splits");
            return StubAssets.matches_domain(&AssetSource::External(file.into()), label, domain);
        }
        suffix_matches(domain, lower.trim_start_matches('.'))
    }

    fn suffix_matches(domain: &str, suffix: &str) -> bool {
        domain == suffix
            || (domain.len() > suffix.len()
                && domain.ends_with(suffix)
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
    }

    fn ip_matches(matcher: &str, address: IpAddr) -> bool {
        let lower = matcher.to_ascii_lowercase();
        if let Some(label) = lower.strip_prefix("geoip:") {
            return StubAssets.matches_ip(&AssetSource::GeoIp, label, address);
        }
        if lower.starts_with("ext:") {
            return false;
        }
        let (base, prefix) = lower
            .split_once('/')
            .map_or((lower.as_str(), None), |(a, p)| (a, Some(p)));
        let base: IpAddr = base.parse().expect("test CIDR parses");
        match (base, address) {
            (IpAddr::V4(base), IpAddr::V4(address)) => {
                let bits: u8 = prefix.map_or(32, |p| p.parse().expect("prefix parses"));
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(address) & mask == u32::from(base) & mask
            }
            (IpAddr::V6(base), IpAddr::V6(address)) => {
                let bits: u8 = prefix.map_or(128, |p| p.parse().expect("prefix parses"));
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(address) & mask == u128::from(base) & mask
            }
            _ => false,
        }
    }
}

/// The one identity every scale fixture routes for.
fn primary_user() -> UserConfig {
    UserConfig {
        id: PRIMARY.to_owned(),
        short_ids: vec!["0123456789abcdef".to_owned()],
        label: None,
        policy: Some("primary".to_owned()),
    }
}

fn compile(rules: Vec<RouteRule>) -> RoutingTable {
    let config = RoutingConfig {
        default: "fallback".to_owned(),
        strategy: Some(DomainStrategy::AsIs),
        rules: None,
        policies: Some(std::collections::BTreeMap::from([(
            "primary".to_owned(),
            RoutePolicy {
                default: "fallback".to_owned(),
                rules: Some(rules),
            },
        )])),
    };
    RoutingTable::compile(
        &config,
        &[primary_user()],
        Arc::new(StubAssets),
        ResourceGovernor::new(&ResourceGovernorPolicy::default()),
    )
    .expect("randomized routing config must compile")
}

#[test]
fn indexed_and_linear_paths_match_independent_oracle() {
    // Straddle the adaptive threshold: below, around, and well above it.
    for (seed, rule_count) in [(1, 1_usize), (2, 32), (3, 63), (4, 64), (5, 65), (6, 200)] {
        let mut rng = Rng(seed * 0x9E37_79B9 + 7);
        let rules: Vec<RouteRule> = (0..rule_count)
            .map(|index| random_rule(&mut rng, index))
            .collect();
        let table = compile(rules.clone());
        for _ in 0..40 {
            let destination = random_destination(&mut rng);
            let inbound_tag = ["in-a", "in-b", "in-c", "other"][rng.below(4)];
            let resolved: Vec<IpAddr> = if rng.chance(40) {
                vec![
                    IpAddr::V4(Ipv4Addr::new(10, rng.below(256) as u8, 9, 9)),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, rng.below(256) as u8)),
                ]
            } else {
                Vec::new()
            };
            let expected = rules
                .iter()
                .find(|rule| oracle::rule_matches(rule, &destination, &resolved, inbound_tag))
                .map_or(
                    // A default decision reports the policy by its
                    // configuration path, which is what an operator can look up.
                    (
                        "fallback",
                        "routing.policies.primary",
                        RouteScope::DefaultOutbound,
                    ),
                    |rule| {
                        (
                            rule.outbound.as_str(),
                            rule.name.as_deref().unwrap_or_default(),
                            RouteScope::Policy,
                        )
                    },
                );
            let context = RouteContext {
                user_id: PRIMARY_ID,
                inbound_tag,
                destination: &destination,
                resolved_ips: &resolved,
            };
            let decision = table.select(&context).expect("known user must route");
            let actual = (decision.outbound(), decision.rule_name(), decision.scope());
            assert_eq!(
                actual, expected,
                "seed {seed} rules {rule_count} destination {destination:?} tag {inbound_tag}"
            );
        }
    }
}

#[test]
fn global_rules_precede_user_rules_at_scale() {
    let mut rules: Vec<RouteRule> = (0..300)
        .map(|index| RouteRule {
            name: Some(format!("user-{index}")),
            outbound: "user-out".to_owned(),
            domain: Some(vec![format!("full:shared-{index}.test")]),
            ..RouteRule::default()
        })
        .collect();
    rules[150].domain = Some(vec!["full:contended.test".to_owned()]);
    let config = RoutingConfig {
        default: "fallback".to_owned(),
        strategy: Some(DomainStrategy::AsIs),
        rules: Some(vec![RouteRule {
            name: Some("global-wins".to_owned()),
            outbound: "global-out".to_owned(),
            domain: Some(vec!["full:contended.test".to_owned()]),
            ..RouteRule::default()
        }]),
        policies: Some(std::collections::BTreeMap::from([(
            "primary".to_owned(),
            RoutePolicy {
                default: "fallback".to_owned(),
                rules: Some(rules),
            },
        )])),
    };
    let table = RoutingTable::compile(
        &config,
        &[primary_user()],
        Arc::new(StubAssets),
        ResourceGovernor::new(&ResourceGovernorPolicy::default()),
    )
    .expect("config must compile");
    let destination = Destination::new(Address::Domain("Contended.TEST".to_owned()), 443);
    let context = RouteContext {
        user_id: PRIMARY_ID,
        inbound_tag: "in-a",
        destination: &destination,
        resolved_ips: &[],
    };
    let decision = table.select(&context).expect("known user must route");
    assert_eq!(decision.outbound(), "global-out");
    assert_eq!(decision.scope(), RouteScope::Global);
}

#[test]
fn unknown_uuid_is_rejected_before_any_rule_evaluation() {
    let table = compile(vec![RouteRule {
        name: Some("catch-all".to_owned()),
        outbound: "open".to_owned(),
        domain: Some(vec!["plain.catch.test".to_owned()]),
        ..RouteRule::default()
    }]);
    let destination = Destination::new(Address::Domain("anything.test".to_owned()), 443);
    let context = RouteContext {
        user_id: UserId::new([0xff; 16]),
        inbound_tag: "in-a",
        destination: &destination,
        resolved_ips: &[],
    };
    assert!(matches!(
        table.select(&context),
        Err(RouteResolutionError::UnknownUser)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn ip_if_non_match_resolves_numeric_literal_and_matches_ip_rule() {
    let mut rules: Vec<RouteRule> = (0..150)
        .map(|index| RouteRule {
            name: Some(format!("domain-{index}")),
            outbound: "domain-out".to_owned(),
            domain: Some(vec![format!("full:host{index}.full.test")]),
            ..RouteRule::default()
        })
        .collect();
    rules.push(RouteRule {
        name: Some("late-ip".to_owned()),
        outbound: "ip-out".to_owned(),
        ip: Some(vec!["203.0.113.0/24".to_owned()]),
        ..RouteRule::default()
    });
    let table = compile(rules);
    // No domain rule matches, so IpIfNonMatch must resolve the numeric
    // literal (without any real DNS) and match the late IP rule.
    let destination = Destination::new(Address::Domain("203.0.113.9".to_owned()), 443);
    let route = table
        .select_with_dns(
            PRIMARY_ID,
            "in-a",
            &destination,
            DomainStrategy::ResolveIfNoMatch,
            Duration::from_secs(1),
        )
        .await
        .expect("numeric literal must route without DNS");
    assert_eq!(route.decision().outbound(), "ip-out");
    assert_eq!(route.decision().rule_name(), "late-ip");
    assert_eq!(
        route.resolved_ips(),
        &[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn ip_if_non_match_early_domain_match_skips_resolution() {
    let mut rules: Vec<RouteRule> = (0..150)
        .map(|index| RouteRule {
            name: Some(format!("domain-{index}")),
            outbound: format!("out-{index}"),
            domain: Some(vec![format!("full:host{index}.full.test")]),
            ..RouteRule::default()
        })
        .collect();
    rules.push(RouteRule {
        name: Some("ip-rule".to_owned()),
        outbound: "ip-out".to_owned(),
        ip: Some(vec!["203.0.113.0/24".to_owned()]),
        ..RouteRule::default()
    });
    let table = compile(rules);
    // A pass-1 domain match must win without DNS even though the numeric
    // literal would also match the later IP rule after resolution.
    let destination = Destination::new(Address::Domain("host3.full.test".to_owned()), 443);
    let route = table
        .select_with_dns(
            PRIMARY_ID,
            "in-a",
            &destination,
            DomainStrategy::ResolveIfNoMatch,
            Duration::from_secs(1),
        )
        .await
        .expect("domain match must route without DNS");
    assert_eq!(route.decision().outbound(), "out-3");
    assert!(route.resolved_ips().is_empty());
}
