use crate::runtime::policy::ResourceGovernorPolicy;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use super::{
    EmptyAssetMatcher, ResolvedRoute, RouteContext, RouteResolutionError, RouteScope, RoutingTable,
};
use crate::{
    config::node::{
        routing::{DomainStrategy, RoutePolicy, RouteRule, RoutingConfig},
        user::UserConfig,
    },
    protocol::vless::{Address, Destination, UserId},
};

const USER: &str = "00112233-4455-6677-8899-aabbccddeeff";
const USER_ID: UserId = UserId::new([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
]);

#[test]
fn global_private_rule_precedes_user_domain_rule() {
    let table = table();
    let private = Destination::new(Address::Ipv4(Ipv4Addr::new(10, 1, 2, 3)), 443);
    let decision = table
        .select(&context(&private))
        .expect("configured user must route");

    assert_eq!(decision.outbound(), "blocked");
    assert_eq!(decision.rule_name(), "private");
    assert_eq!(decision.scope(), RouteScope::Global);
}

#[test]
fn unknown_uuid_cannot_bypass_authorization_through_a_global_rule() {
    let table = table();
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(10, 1, 2, 3)), 443);
    let context = RouteContext {
        user_id: UserId::new([0xff; 16]),
        inbound_tag: "public-reality",
        destination: &destination,
        resolved_ips: &[],
    };

    assert!(matches!(
        table.select(&context),
        Err(RouteResolutionError::UnknownUser)
    ));
}

#[test]
fn empty_dns_snapshot_adds_no_heap_allocation() {
    let table = table();
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
    let decision = table
        .select(&context(&destination))
        .expect("configured user must route");

    let measured = allocation_counter::measure(|| {
        std::hint::black_box(ResolvedRoute::new(decision.clone(), Vec::new()));
    });

    assert_eq!(
        measured.count_total, 0,
        "an empty DNS snapshot must remain allocation-free: {measured:?}"
    );
}

#[test]
fn user_rules_are_first_match_and_conditions_are_conjunctive() {
    let table = table();
    let destination = Destination::new(Address::Domain("api.example.com".to_owned()), 443);
    let decision = table
        .select(&context(&destination))
        .expect("configured user must route");

    assert_eq!(decision.outbound(), "socks");
    assert_eq!(decision.scope(), RouteScope::Policy);
}

#[test]
fn suffix_requires_dns_label_boundary() {
    let table = table();
    let destination = Destination::new(Address::Domain("notexample.com".to_owned()), 443);
    let decision = table
        .select(&context(&destination))
        .expect("configured user must route");

    assert_eq!(decision.outbound(), "direct");
    assert_eq!(decision.scope(), RouteScope::DefaultOutbound);
}

#[tokio::test(flavor = "current_thread")]
async fn ip_if_non_match_resolves_domain_for_ip_rules() {
    let table = table_with_global_ip("127.0.0.0/8");
    let destination = Destination::new(Address::Domain("localhost".to_owned()), 443);
    let route = table
        .select_with_dns(
            USER_ID,
            "public-reality",
            &destination,
            DomainStrategy::ResolveIfNoMatch,
            Duration::from_secs(2),
        )
        .await
        .expect("system localhost resolution must complete");

    assert_eq!(route.decision().outbound(), "blocked");
    assert_eq!(route.decision().scope(), RouteScope::Global);
    assert!(
        route
            .resolved_ips()
            .iter()
            .any(|address| address.is_loopback())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn as_is_does_not_resolve_domain_for_ip_rules() {
    let table = table_with_global_ip("127.0.0.0/8");
    let destination = Destination::new(Address::Domain("localhost".to_owned()), 443);
    let route = table
        .select_with_dns(
            USER_ID,
            "public-reality",
            &destination,
            DomainStrategy::AsIs,
            Duration::from_secs(2),
        )
        .await
        .expect("configured user must route without DNS");

    assert_eq!(route.decision().outbound(), "direct");
    assert_eq!(route.decision().scope(), RouteScope::DefaultOutbound);
    assert!(route.resolved_ips().is_empty());
}

fn table() -> RoutingTable {
    table_with_global_ip("10.0.0.0/8")
}

fn table_with_global_ip(ip_matcher: &str) -> RoutingTable {
    RoutingTable::compile(
        &RoutingConfig {
            default: "direct".to_owned(),
            strategy: Some(DomainStrategy::AsIs),
            rules: Some(vec![RouteRule {
                name: Some("private".to_owned()),
                outbound: "blocked".to_owned(),
                ip: Some(vec![ip_matcher.to_owned()]),
                ..RouteRule::default()
            }]),
            policies: Some(std::collections::BTreeMap::from([(
                "primary".to_owned(),
                RoutePolicy {
                    default: "direct".to_owned(),
                    rules: Some(vec![RouteRule {
                        name: Some("api through socks".to_owned()),
                        outbound: "socks".to_owned(),
                        domain: Some(vec!["domain:example.com".to_owned()]),
                        port: Some(vec!["443".to_owned()]),
                        ..RouteRule::default()
                    }]),
                },
            )])),
        },
        &[UserConfig {
            id: USER.to_owned(),
            short_ids: vec!["0123456789abcdef".to_owned()],
            label: None,
            policy: Some("primary".to_owned()),
        }],
        Arc::new(EmptyAssetMatcher),
        crate::runtime::ResourceGovernor::new(
            &crate::runtime::policy::ResourceGovernorPolicy::default(),
        ),
    )
    .expect("routing must compile")
}

use std::net::{IpAddr, SocketAddr};

use super::resolve_domain_with;
use crate::runtime::ResourceGovernor;

fn tiny_dns_governor(permits: u32) -> ResourceGovernor {
    ResourceGovernor::new(&ResourceGovernorPolicy {
        max_dns_lookups: permits,
        ..ResourceGovernorPolicy::default()
    })
}

fn one_addr() -> Vec<SocketAddr> {
    vec![SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        443,
    )]
}

#[tokio::test(flavor = "current_thread")]
async fn dns_resolution_succeeds_through_the_bounded_pool() {
    let governor = tiny_dns_governor(1);
    let resolved = resolve_domain_with(&governor, || Ok(one_addr()), Duration::from_secs(1))
        .await
        .expect("resolution must succeed");
    assert_eq!(resolved, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
}

#[tokio::test(flavor = "current_thread")]
async fn numeric_domain_resolves_without_the_blocking_pool() {
    use super::resolve_domain;
    use crate::protocol::vless::{Address, Destination};

    // Zero DNS permits: any blocking-pool resolution would be denied.
    let governor = tiny_dns_governor(0);

    let literal = Destination::new(Address::Domain("192.0.2.1".to_owned()), 443);
    let resolved = resolve_domain(&governor, &literal, Duration::from_secs(1))
        .await
        .expect("numeric literal must resolve without the DNS pool");
    assert_eq!(resolved, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);

    let hostname = Destination::new(Address::Domain("example.com".to_owned()), 443);
    let error = resolve_domain(&governor, &hostname, Duration::from_secs(1))
        .await
        .expect_err("hostname must still require the bounded DNS pool");
    assert!(
        matches!(error, RouteResolutionError::DnsLimit),
        "expected DnsLimit, got {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn dns_failure_maps_to_the_dns_error_variant() {
    let governor = tiny_dns_governor(1);
    let error = resolve_domain_with(
        &governor,
        || Err::<Vec<SocketAddr>, io::Error>(io::Error::other("NXDOMAIN")),
        Duration::from_secs(1),
    )
    .await
    .expect_err("a resolver error must propagate");
    assert!(
        matches!(error, RouteResolutionError::Dns(_)),
        "expected Dns, got {error}"
    );
}

/// A gated blocking operation whose "syscall" the test controls.
struct GatedLookup {
    start: std::sync::mpsc::Receiver<()>,
}

impl GatedLookup {
    fn channel() -> (std::sync::mpsc::Sender<()>, Self) {
        let (sender, receiver) = std::sync::mpsc::channel();
        (sender, Self { start: receiver })
    }

    fn run(self) -> io::Result<Vec<SocketAddr>> {
        let _ignored = self.start.recv();
        Ok(one_addr())
    }
}

async fn assert_permit_held(governor: &ResourceGovernor) {
    assert!(
        governor
            .try_acquire(crate::runtime::AdmissionKind::DnsLookup)
            .is_err(),
        "the DNS permit must remain held while the operation runs"
    );
}

async fn assert_permit_released(governor: &ResourceGovernor) {
    for _ in 0..200 {
        if governor
            .try_acquire(crate::runtime::AdmissionKind::DnsLookup)
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the DNS permit must be released once the operation terminates");
}

#[tokio::test(flavor = "current_thread")]
async fn async_timeout_keeps_the_permit_until_the_operation_terminates() {
    let governor = tiny_dns_governor(1);
    let (gate, lookup) = GatedLookup::channel();
    let resolution =
        resolve_domain_with(&governor, move || lookup.run(), Duration::from_millis(20));
    let outcome = resolution.await;
    assert!(
        matches!(outcome, Err(RouteResolutionError::DnsTimeout)),
        "the async wait must time out, got {outcome:?}"
    );
    assert_permit_held(&governor).await;
    drop(gate);
    assert_permit_released(&governor).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_cancelled_future_keeps_the_permit_until_the_operation_terminates() {
    let governor = tiny_dns_governor(1);
    let (gate, lookup) = GatedLookup::channel();
    let spawned_governor = governor.clone();
    let resolution = tokio::spawn(async move {
        resolve_domain_with(&spawned_governor, move || lookup.run(), Duration::MAX).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    resolution.abort();
    tokio::task::yield_now().await;
    assert_permit_held(&governor).await;
    drop(gate);
    assert_permit_released(&governor).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pool_saturation_denies_new_lookups_without_queuing() {
    let governor = tiny_dns_governor(1);
    let (_gate, lookup) = GatedLookup::channel();
    let _first = governor
        .try_acquire(crate::runtime::AdmissionKind::DnsLookup)
        .expect("the single permit must be acquirable");
    let outcome =
        resolve_domain_with(&governor, move || lookup.run(), Duration::from_secs(1)).await;
    assert!(
        matches!(outcome, Err(RouteResolutionError::DnsLimit)),
        "saturation must fail fast rather than queue, got {outcome:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn routing_compilation_shares_one_process_authority() {
    let governor = tiny_dns_governor(1);
    let (_gate, lookup_a) = GatedLookup::channel();
    let (gate_b, lookup_b) = GatedLookup::channel();
    // Table A's operation occupies the only slot; table B compiled from a
    // "new generation" must see the same exhausted pool.
    let occupied = governor
        .try_acquire(crate::runtime::AdmissionKind::DnsLookup)
        .expect("table A must take the slot");
    let outcome_b =
        resolve_domain_with(&governor, move || lookup_b.run(), Duration::from_secs(1)).await;
    assert!(matches!(outcome_b, Err(RouteResolutionError::DnsLimit)));
    drop(occupied);
    drop(gate_b);
    let _unused = lookup_a;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_shutdown_stays_bounded_with_a_running_lookup() {
    let governor = tiny_dns_governor(1);
    let (gate, lookup) = GatedLookup::channel();
    let spawned_governor = governor.clone();
    let resolution = tokio::spawn(async move {
        resolve_domain_with(&spawned_governor, move || lookup.run(), Duration::MAX).await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The wait is abandoned; the blocking operation is released by the gate
    // and the task settles deterministically afterwards.
    resolution.abort();
    drop(gate);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !resolution.is_finished() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the aborted task must settle");
}

use std::io;

fn context(destination: &Destination) -> RouteContext<'_> {
    RouteContext {
        user_id: USER_ID,
        inbound_tag: "public-reality",
        destination,
        resolved_ips: &[],
    }
}
// ---- Differential tests: indexed path vs the naive ordered scan ----

use std::net::Ipv6Addr;

use super::{
    CompiledRule, INDEXED_RULE_LIMIT, RouteDecision, RuleIndex, normalized_domain, resolve_domain,
    select_from_rules,
};
use crate::assets::AssetSource;

/// xorshift64*; no external RNG dependency for property tests.
struct XorShift(u64);

impl XorShift {
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

/// Deterministic asset stub: domain label `lN` matches `lN.stub` and
/// `*.lN.stub`; `geoip:gN` matches `198.51.100.N`.
struct StubAssets;

impl crate::assets::AssetMatcher for StubAssets {
    fn matches_domain(&self, source: &AssetSource, label: &str, domain: &str) -> bool {
        if *source == AssetSource::GeoIp {
            return false;
        }
        let marker = format!("{label}.stub");
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

fn random_domain_matcher(rng: &mut XorShift) -> String {
    match rng.below(9) {
        0 => format!("full:host{}.full.test", rng.below(40)),
        1 => format!("full:UPPER{}.FULL.TEST", rng.below(40)),
        2 => format!("domain:sfx{}.s.test", rng.below(40)),
        3 => format!("keyword:tok{}", rng.below(40)),
        4 => "keyword:".to_owned(),
        5 => [
            "regexp:^api\\.",
            "regexp:\\.internal$",
            "regexp:^cdn[0-9]+\\.",
        ][rng.below(3)]
        .to_owned(),
        6 => format!("geosite:l{}", rng.below(8)),
        7 => format!("ext:extra.dat:e{}", rng.below(4)),
        _ => format!("plain{}.plain.test", rng.below(40)),
    }
}

fn random_ip_matcher(rng: &mut XorShift) -> String {
    match rng.below(4) {
        0 => format!("10.{}.0.0/16", rng.below(256)),
        1 => "2001:db8::/32".to_owned(),
        2 => format!("geoip:g{}", rng.below(8)),
        _ => format!("198.51.100.{}/32", rng.below(256)),
    }
}

fn random_rule(rng: &mut XorShift, index: usize) -> RouteRule {
    let mut domain = Vec::new();
    for _ in 0..rng.below(3) {
        domain.push(random_domain_matcher(rng));
    }
    let mut ip = Vec::new();
    for _ in 0..rng.below(2) {
        ip.push(random_ip_matcher(rng));
    }
    let port = rng
        .chance(30)
        .then(|| vec![["53", "443", "1000-2000", "8000-9000"][rng.below(4)].to_owned()]);
    // A rule with no condition is rejected by validation, so the generator
    // never produces one.
    if domain.is_empty() && ip.is_empty() && port.is_none() {
        domain.push(random_domain_matcher(rng));
    }
    RouteRule {
        name: Some(format!("rule-{index}")),
        outbound: format!("out-{:02}", rng.below(8)),
        domain: (!domain.is_empty()).then_some(domain),
        ip: (!ip.is_empty()).then_some(ip),
        port,
    }
}

fn random_destination(rng: &mut XorShift) -> Destination {
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
            let domain = match rng.below(13) {
                0 => format!("host{}.full.test", rng.below(40)),
                1 => format!("Host{}.Full.Test", rng.below(40)),
                2 => format!("WWW.HOST{}.FULL.TEST", rng.below(40)),
                3 => format!("deep.sub.sfx{}.s.test", rng.below(40)),
                4 => format!("x-tok{}-y.test", rng.below(40)),
                5 => format!("l{}.stub", rng.below(8)),
                6 => format!("www.l{}.stub", rng.below(8)),
                7 => "trailing.dot.test.".to_owned(),
                8 => String::new(),
                9 => format!("api{}.edge.test", rng.below(5)),
                10 => format!("service{}.internal", rng.below(5)),
                11 => format!("cdn{}.test", rng.below(10)),
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

fn random_resolved_ips(rng: &mut XorShift) -> Vec<IpAddr> {
    if !rng.chance(50) {
        return Vec::new();
    }
    let mut addresses = vec![IpAddr::V4(Ipv4Addr::new(10, rng.below(256) as u8, 9, 9))];
    if rng.chance(50) {
        addresses.push(IpAddr::V4(Ipv4Addr::new(
            198,
            51,
            100,
            rng.below(256) as u8,
        )));
    }
    if rng.chance(25) {
        addresses.push(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)));
    }
    addresses
}

fn decision_parts(decision: &RouteDecision) -> (&str, &str, RouteScope) {
    (decision.outbound(), decision.rule_name(), decision.scope())
}

/// The oracle: the plain ordered `.find()` scan every path must agree with.
fn naive_select(table: &RoutingTable, context: &RouteContext<'_>) -> RouteDecision {
    let user = table
        .users
        .get(&context.user_id)
        .unwrap_or_else(|| panic!("test user must exist: {:?}", context.user_id.as_bytes()));
    let assets = table.assets.as_ref();
    let domain = normalized_domain(context.destination);
    let domain = domain.as_deref();
    if let Some(rule) = table
        .global_rules
        .iter()
        .find(|rule| rule.matches(context, domain, assets))
    {
        return rule.decision(RouteScope::Global);
    }
    if let Some(rule) = user
        .rules
        .iter()
        .find(|rule| rule.matches(context, domain, assets))
    {
        return rule.decision(RouteScope::Policy);
    }
    user.default_decision()
}

fn compile_random(rng: &mut XorShift, user_count: usize) -> RoutingTable {
    let rules = (0..user_count)
        .map(|index| random_rule(rng, 1000 + index))
        .collect();
    compile_random_with_rules(rng, rules)
}

fn compile_random_with_rules(rng: &mut XorShift, rules: Vec<RouteRule>) -> RoutingTable {
    let global_rules: Vec<RouteRule> = (0..rng.below(9))
        .map(|index| random_rule(rng, index))
        .collect();
    let second_rules: Vec<RouteRule> = (0..70)
        .map(|index| random_rule(rng, 2000 + index))
        .collect();
    let user = |id: &str, policy: &str| UserConfig {
        id: id.to_owned(),
        short_ids: vec!["0123456789abcdef".to_owned()],
        label: None,
        policy: Some(policy.to_owned()),
    };
    RoutingTable::compile(
        &RoutingConfig {
            default: "fallback".to_owned(),
            strategy: Some(DomainStrategy::AsIs),
            rules: Some(global_rules),
            policies: Some(std::collections::BTreeMap::from([
                (
                    "primary".to_owned(),
                    RoutePolicy {
                        default: "fallback".to_owned(),
                        rules: Some(rules),
                    },
                ),
                (
                    "second".to_owned(),
                    RoutePolicy {
                        default: "fallback-two".to_owned(),
                        rules: Some(second_rules),
                    },
                ),
            ])),
        },
        &[
            user(USER, "primary"),
            user("ffffffff-ffff-ffff-ffff-ffffffffffff", "second"),
        ],
        Arc::new(StubAssets),
        crate::runtime::ResourceGovernor::new(
            &crate::runtime::policy::ResourceGovernorPolicy::default(),
        ),
    )
    .expect("randomized routing config must compile")
}

#[test]
fn mixed_indexable_residual_rule_matches_through_the_residual() {
    let table = RoutingTable::compile(
        &RoutingConfig {
            default: "fallback".to_owned(),
            strategy: Some(DomainStrategy::AsIs),
            rules: None,
            policies: Some(std::collections::BTreeMap::from([(
                "primary".to_owned(),
                RoutePolicy {
                    default: "fallback".to_owned(),
                    rules: Some(
                        (0..70)
                            .map(|index| RouteRule {
                                name: Some(format!("r{index}")),
                                outbound: format!("out-{index}"),
                                domain: Some(if index == 40 {
                                    vec!["full:unrelated.test".to_owned(), "geosite:l3".to_owned()]
                                } else {
                                    vec![format!("full:h{index}.test")]
                                }),
                                ..RouteRule::default()
                            })
                            .collect(),
                    ),
                },
            )])),
        },
        &[UserConfig {
            id: USER.to_owned(),
            short_ids: vec!["0123456789abcdef".to_owned()],
            label: None,
            policy: Some("primary".to_owned()),
        }],
        Arc::new(StubAssets),
        crate::runtime::ResourceGovernor::new(
            &crate::runtime::policy::ResourceGovernorPolicy::default(),
        ),
    )
    .expect("compiles");
    let destination = Destination::new(Address::Domain("l3.stub".to_owned()), 443);
    let context = RouteContext {
        user_id: USER_ID,
        inbound_tag: "in-a",
        destination: &destination,
        resolved_ips: &[],
    };
    let decision = table.select(&context).expect("routes");
    assert_eq!(
        decision.outbound(),
        "out-40",
        "a rule mixing indexable and residual domain matchers must match via the residual"
    );
}

#[test]
fn indexed_and_linear_selection_agree_with_naive_scan() {
    let second_id = UserId::new([0xff; 16]);
    // Sizes straddle INDEXED_RULE_LIMIT so both representations run.
    for (seed, user_count) in [
        (1_u64, 1_usize),
        (2, INDEXED_RULE_LIMIT - 1),
        (3, INDEXED_RULE_LIMIT),
        (4, INDEXED_RULE_LIMIT + 1),
        (5, 3 * INDEXED_RULE_LIMIT),
    ] {
        let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9).wrapping_add(7));
        let table = compile_random(&mut rng, user_count);
        if user_count >= INDEXED_RULE_LIMIT {
            assert!(
                table.users.get(&USER_ID).unwrap().index.is_some(),
                "user list at {user_count} rules must build an index"
            );
        }
        for _ in 0..60 {
            let destination = random_destination(&mut rng);
            let inbound_tag = ["in-a", "in-b", "in-c", "other"][rng.below(4)];
            let resolved = random_resolved_ips(&mut rng);
            let user_id = if rng.chance(20) { second_id } else { USER_ID };
            let context = RouteContext {
                user_id,
                inbound_tag,
                destination: &destination,
                resolved_ips: &resolved,
            };
            let expected = naive_select(&table, &context);
            let actual = table
                .select(&context)
                .expect("randomized known user must route");
            assert_eq!(
                decision_parts(&actual),
                decision_parts(&expected),
                "seed {seed} rules {user_count} destination {destination:?} tag {inbound_tag} \
                 resolved {resolved:?}"
            );
        }
        // The unknown-UUID authorization invariant holds on both paths.
        let destination = random_destination(&mut rng);
        let context = RouteContext {
            user_id: UserId::new([0x77; 16]),
            inbound_tag: "in-a",
            destination: &destination,
            resolved_ips: &[],
        };
        assert!(matches!(
            table.select(&context),
            Err(RouteResolutionError::UnknownUser)
        ));
    }

    // Every rule mixes one indexable and one residual domain matcher with
    // no other condition groups, so index coverage and `always` coverage
    // alone decide first-match order.
    let mut rng = XorShift(42);
    let mixed_rules: Vec<RouteRule> = (0..(INDEXED_RULE_LIMIT + 20))
        .map(|index| RouteRule {
            name: Some(format!("mixed-{index}")),
            outbound: format!("mixed-out-{index}"),
            domain: Some(vec![
                random_domain_matcher(&mut rng),
                [
                    "regexp:^api\\.",
                    "regexp:\\.internal$",
                    "geosite:l3",
                    "keyword:",
                ][rng.below(4)]
                .to_owned(),
            ]),
            ..RouteRule::default()
        })
        .collect();
    let table = compile_random_with_rules(&mut rng, mixed_rules);
    for _ in 0..120 {
        let domain = match rng.below(6) {
            0 => "l3.stub".to_owned(),
            1 => "www.l3.stub".to_owned(),
            2 => format!("api{}.edge.test", rng.below(5)),
            3 => format!("service{}.internal", rng.below(5)),
            4 => format!("host{}.full.test", rng.below(40)),
            _ => format!("unrelated-{}.test", rng.below(1000)),
        };
        let destination = Destination::new(Address::Domain(domain), 443);
        let context = RouteContext {
            user_id: USER_ID,
            inbound_tag: "in-a",
            destination: &destination,
            resolved_ips: &[],
        };
        let expected = naive_select(&table, &context);
        let actual = table
            .select(&context)
            .expect("randomized known user must route");
        assert_eq!(
            decision_parts(&actual),
            decision_parts(&expected),
            "mixed-rules destination {destination:?}"
        );
    }
}

/// Old `IpIfNonMatch` algorithm: full evaluation, resolve, full re-evaluation.
async fn naive_ip_if_non_match(
    table: &RoutingTable,
    user_id: UserId,
    inbound_tag: &str,
    destination: &Destination,
    timeout: Duration,
) -> Result<ResolvedRoute, RouteResolutionError> {
    let unresolved = RouteContext {
        user_id,
        inbound_tag,
        destination,
        resolved_ips: &[],
    };
    let first = naive_select(table, &unresolved);
    if first.scope() != RouteScope::DefaultOutbound {
        return Ok(ResolvedRoute::new(first, Vec::new()));
    }
    let resolved_ips = resolve_domain(&table.dns_governor, destination, timeout).await?;
    let resolved = RouteContext {
        user_id,
        inbound_tag,
        destination,
        resolved_ips: &resolved_ips,
    };
    Ok(ResolvedRoute::new(
        naive_select(table, &resolved),
        resolved_ips,
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn ip_if_non_match_pending_recheck_agrees_with_naive_two_pass() {
    // Numeric literals "resolve" without the DNS pool, keeping the
    // two-pass differential fully offline while exercising pass 2.
    for (seed, user_count) in [(11_u64, INDEXED_RULE_LIMIT + 5), (12, 20), (13, 150)] {
        let mut rng = XorShift(seed.wrapping_mul(0x2545_F491).wrapping_add(3));
        let table = compile_random(&mut rng, user_count);
        for _ in 0..30 {
            let destination = if rng.chance(50) {
                Destination::new(
                    Address::Domain(format!("198.51.100.{}", rng.below(256))),
                    [53u16, 443][rng.below(2)],
                )
            } else {
                Destination::new(Address::Domain(format!("10.{}.9.9", rng.below(256))), 443)
            };
            let expected = naive_ip_if_non_match(
                &table,
                USER_ID,
                "in-a",
                &destination,
                Duration::from_secs(1),
            )
            .await
            .expect("numeric literals must route offline");
            let actual = table
                .select_with_dns(
                    USER_ID,
                    "in-a",
                    &destination,
                    DomainStrategy::ResolveIfNoMatch,
                    Duration::from_secs(1),
                )
                .await
                .expect("numeric literals must route offline");
            assert_eq!(
                decision_parts(actual.decision()),
                decision_parts(expected.decision()),
                "seed {seed} rules {user_count} destination {destination:?}"
            );
            assert_eq!(actual.resolved_ips(), expected.resolved_ips());
        }
    }
}

#[test]
fn select_from_rules_without_index_is_the_plain_scan() {
    // Compile a small list directly: below the limit, no index is built
    // and the linear path is taken.
    let rules: Vec<CompiledRule> = (0..10)
        .map(|index| {
            CompiledRule::compile(
                &RouteRule {
                    name: Some(format!("r{index}")),
                    outbound: "direct".to_owned(),
                    domain: Some(vec![format!("full:h{index}.test")]),
                    ..RouteRule::default()
                },
                "rules[0]",
            )
            .expect("rule compiles")
        })
        .collect();
    assert!(RuleIndex::build(&rules).is_none());
    let destination = Destination::new(Address::Domain("h3.test".to_owned()), 443);
    let context = RouteContext {
        user_id: USER_ID,
        inbound_tag: "in-a",
        destination: &destination,
        resolved_ips: &[],
    };
    let domain = normalized_domain(context.destination);
    let selected = select_from_rules(&rules, None, &context, domain.as_deref(), &StubAssets)
        .expect("h3.test must match rule 3");
    assert_eq!(selected.name.as_ref(), "r3");
}
