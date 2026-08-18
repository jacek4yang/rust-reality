//! Routing-table selection benchmarks over realistic mixed rule sets.
//!
//! Rule sets blend `full:`, `domain:`, `keyword:`, `regexp:`, `geosite:`,
//! `ext:`, CIDR, and `geoip:` conditions with port, network, and inbound-tag
//! groups, evaluated at 10 / 100 / 1,000 / 10,000 first-match rules. The
//! default mode runs Criterion; setting `ROUTING_PERCENTILES=1` instead runs a
//! fixed-iteration percentile harness and prints one JSON object per case so
//! before/after P95 comparisons can be archived as raw data.

use std::{
    borrow::Cow,
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use criterion::{BenchmarkId, Criterion, criterion_group};
use regex::{Regex, RegexBuilder};
use rust_reality::{
    assets::{AssetMatcher, AssetSource},
    config::{
        DnsStrategy, GlobalRule, Network, PortMatcher, ResourceGovernorConfig, RoutingConfig,
        UserPolicy,
    },
    protocol::vless::{Address, Destination, UserId},
    runtime::ResourceGovernor,
    server::routing::{RouteContext, RoutingTable},
};

const SIZES: &[usize] = &[10, 100, 1_000, 10_000];
const PRIMARY_USER: UserId = UserId::new([0x11; 16]);
const SECONDARY_USER: UserId = UserId::new([0x22; 16]);
const INBOUND_TAG: &str = "bench-in";

/// Asset-backed sets shaped like the production GeoSite/GeoIP snapshots.
struct BenchAssets {
    geosite: Vec<(String, BenchDomainSet)>,
    external: Vec<(String, BenchDomainSet)>,
    geoip: Vec<(String, Vec<(u32, u8)>)>,
}

struct BenchDomainSet {
    full: HashSet<String>,
    suffixes: HashSet<String>,
    substrings: Option<AhoCorasick>,
    regexes: Vec<Regex>,
}

impl BenchDomainSet {
    fn matches(&self, domain: &str) -> bool {
        let normalized = if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
        let domain = normalized.as_ref();
        self.full.contains(domain)
            || self.suffixes.contains(domain)
            || domain
                .match_indices('.')
                .any(|(index, _)| self.suffixes.contains(&domain[index + 1..]))
            || self
                .substrings
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(domain))
            || self.regexes.iter().any(|regex| regex.is_match(domain))
    }
}

impl AssetMatcher for BenchAssets {
    fn matches_domain(&self, source: &AssetSource, label: &str, domain: &str) -> bool {
        match source {
            AssetSource::GeoSite => self
                .geosite
                .iter()
                .find(|(name, _)| name == label)
                .is_some_and(|(_, set)| set.matches(domain)),
            AssetSource::External(file) => self
                .external
                .iter()
                .find(|(name, _)| name == file.as_ref())
                .is_some_and(|(_, set)| set.matches(domain)),
            AssetSource::GeoIp => false,
        }
    }

    fn matches_ip(&self, source: &AssetSource, label: &str, address: IpAddr) -> bool {
        if *source != AssetSource::GeoIp {
            return false;
        }
        let IpAddr::V4(address) = address else {
            return false;
        };
        self.geoip
            .iter()
            .find(|(name, _)| name == label)
            .is_some_and(|(_, networks)| {
                let address = u32::from(address);
                networks.iter().any(|(network, prefix)| {
                    let mask = if *prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                    address & mask == *network
                })
            })
    }
}

fn bench_assets() -> BenchAssets {
    let mut geosite = Vec::new();
    let mut labels: Vec<String> = (0..8).map(|index| format!("label{index}")).collect();
    labels.push("category-ads".to_owned());
    labels.push("targetlabel".to_owned());
    for label in &labels {
        let mut full = HashSet::new();
        let mut suffixes = HashSet::new();
        let mut substrings = Vec::new();
        for entry in 0..100 {
            full.insert(format!("gs{label}-{entry}.asset.bench"));
            suffixes.insert(format!("gsfx{label}-{entry}.asset.bench"));
            if entry < 30 {
                substrings.push(format!("gstok{label}-{entry}"));
            }
        }
        if label == "targetlabel" {
            full.insert("asset-hit.probe.example".to_owned());
        }
        let regexes = vec![
            RegexBuilder::new(&format!("^cdn-{label}-[0-9]+\\.asset\\.bench$"))
                .case_insensitive(true)
                .build()
                .expect("bench regex must compile"),
            RegexBuilder::new(&format!("^media-{label}-[0-9]+\\.asset\\.bench$"))
                .case_insensitive(true)
                .build()
                .expect("bench regex must compile"),
        ];
        geosite.push((
            label.clone(),
            BenchDomainSet {
                full,
                suffixes,
                substrings: Some(
                    AhoCorasickBuilder::new()
                        .ascii_case_insensitive(true)
                        .build(substrings)
                        .expect("bench substrings must compile"),
                ),
                regexes,
            },
        ));
    }
    let mut external = Vec::new();
    for tag in 0..4 {
        let mut full = HashSet::new();
        let mut suffixes = HashSet::new();
        for entry in 0..50 {
            full.insert(format!("ext{tag}-{entry}.asset.bench"));
            suffixes.insert(format!("extsfx{tag}-{entry}.asset.bench"));
        }
        external.push((
            format!("tag{tag}"),
            BenchDomainSet {
                full,
                suffixes,
                substrings: None,
                regexes: Vec::new(),
            },
        ));
    }
    let mut geoip = Vec::new();
    for label in 0..4 {
        let networks = (0..64)
            .map(|index| (u32::from(Ipv4Addr::new(11, label as u8, index, 0)), 24))
            .collect();
        geoip.push((format!("gi{label}"), networks));
    }
    BenchAssets {
        geosite,
        external,
        geoip,
    }
}

fn base_rule(index: usize) -> GlobalRule {
    GlobalRule {
        name: format!("rule-{index}"),
        outbound: format!("out-{:02}", index % 16),
        domain: Vec::new(),
        ip: Vec::new(),
        port: Vec::new(),
        network: Vec::new(),
        inbound_tag: Vec::new(),
    }
}

/// One mixed-shape rule; every matcher value is unique per index so crafted
/// probe destinations hit exactly the intended rule.
fn generated_rule(index: usize) -> GlobalRule {
    let mut rule = base_rule(index);
    match index % 20 {
        0..=4 => rule.domain = vec![format!("full:h{index}.full.bench")],
        5..=10 => rule.domain = vec![format!("domain:s{index}.sfx.bench")],
        11..=13 => rule.domain = vec![format!("keyword:kw{index}token")],
        14 => rule.domain = vec![format!("regexp:^r{index}[a-z]+\\.re\\.bench$")],
        15..=16 => rule.domain = vec![format!("geosite:label{}", index % 8)],
        17 => rule.domain = vec![format!("ext:bench.dat:tag{}", index % 4)],
        18 => {
            rule.ip = vec![format!("10.{}.{}.0/24", (index / 256) % 256, index % 256)];
        }
        _ => rule.ip = vec![format!("geoip:gi{}", index % 4)],
    }
    if index % 7 == 0 {
        rule.port = vec![PortMatcher("8000-9000".to_owned())];
    }
    if index % 11 == 0 {
        rule.network = vec![Network::Tcp];
    }
    if index % 13 == 0 {
        rule.inbound_tag = vec!["other-in".to_owned()];
    }
    rule
}

fn global_prelude() -> Vec<GlobalRule> {
    let cidrs = ["172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"];
    let mut rules: Vec<GlobalRule> = cidrs
        .iter()
        .enumerate()
        .map(|(index, cidr)| GlobalRule {
            ip: vec![(*cidr).to_owned()],
            ..base_rule(index)
        })
        .collect();
    rules.push(GlobalRule {
        domain: vec!["geosite:category-ads".to_owned()],
        ..base_rule(3)
    });
    rules.push(GlobalRule {
        domain: vec!["domain:internal.corp".to_owned()],
        ..base_rule(4)
    });
    rules.push(GlobalRule {
        domain: vec!["keyword:tracker".to_owned()],
        network: vec![Network::Udp],
        ..base_rule(5)
    });
    rules.push(GlobalRule {
        inbound_tag: vec!["admin-in".to_owned()],
        ..base_rule(6)
    });
    rules.push(GlobalRule {
        port: vec![PortMatcher("53".to_owned())],
        ..base_rule(7)
    });
    rules
}

fn secondary_policy() -> UserPolicy {
    let rules = (0..16)
        .map(|index| {
            if index == 8 {
                GlobalRule {
                    domain: vec!["full:secondary-probe.target.bench".to_owned()],
                    ..base_rule(1000 + index)
                }
            } else {
                GlobalRule {
                    domain: vec![format!("domain:secondary-{index}.sfx.bench")],
                    ..base_rule(1000 + index)
                }
            }
        })
        .collect();
    UserPolicy {
        name: "secondary".to_owned(),
        user_ids: vec!["22222222-2222-4222-8222-222222222222".to_owned()],
        default_outbound: "direct".to_owned(),
        rules,
    }
}

#[derive(Clone, Copy)]
enum Case {
    Early,
    Middle,
    Late,
    NoMatch,
    IpLiteral,
    AssetBacked,
    DnsRequired,
    UserPolicy,
}

impl Case {
    const ALL: &[Self] = &[
        Self::Early,
        Self::Middle,
        Self::Late,
        Self::NoMatch,
        Self::IpLiteral,
        Self::AssetBacked,
        Self::DnsRequired,
        Self::UserPolicy,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Early => "early_match",
            Self::Middle => "middle_match",
            Self::Late => "late_match",
            Self::NoMatch => "no_match",
            Self::IpLiteral => "ip_literal",
            Self::AssetBacked => "asset_backed",
            Self::DnsRequired => "dns_required",
            Self::UserPolicy => "user_policy",
        }
    }
}

/// A compiled table plus the destination that exercises the requested case.
struct Fixture {
    table: RoutingTable,
    user_id: UserId,
    destination: Destination,
    strategy: DnsStrategy,
}

fn fixture(size: usize, case: Case) -> Fixture {
    let mut rules: Vec<GlobalRule> = (0..size).map(generated_rule).collect();
    let mut user_id = PRIMARY_USER;
    let mut strategy = DnsStrategy::AsIs;
    let destination = match case {
        Case::Early | Case::Middle | Case::Late => {
            let position = match case {
                Case::Early => 0,
                Case::Middle => size / 2,
                _ => size - 1,
            };
            rules[position] = GlobalRule {
                domain: vec![format!("full:probe-{position}.target.bench")],
                ..base_rule(size)
            };
            Destination::new(
                Address::Domain(format!("probe-{position}.target.bench")),
                443,
            )
        }
        Case::NoMatch => Destination::new(Address::Domain("nomatch.probe.example".to_owned()), 443),
        Case::IpLiteral => {
            rules[size - 1] = GlobalRule {
                ip: vec!["10.255.255.0/24".to_owned()],
                ..base_rule(size)
            };
            Destination::new(Address::Ipv4(Ipv4Addr::new(10, 255, 255, 7)), 443)
        }
        Case::AssetBacked => {
            rules[size - 1] = GlobalRule {
                domain: vec!["geosite:targetlabel".to_owned()],
                ..base_rule(size)
            };
            Destination::new(Address::Domain("asset-hit.probe.example".to_owned()), 443)
        }
        Case::DnsRequired => {
            rules[size - 1] = GlobalRule {
                ip: vec!["203.0.113.0/24".to_owned()],
                ..base_rule(size)
            };
            strategy = DnsStrategy::IpIfNonMatch;
            // A numeric literal "resolves" without the blocking pool, so this
            // case isolates the two-pass IpIfNonMatch evaluation cost.
            Destination::new(Address::Domain("203.0.113.7".to_owned()), 443)
        }
        Case::UserPolicy => {
            user_id = SECONDARY_USER;
            Destination::new(Address::Domain("secondary-probe.target.bench".to_owned()), 443)
        }
    };
    let config = RoutingConfig {
        domain_strategy: strategy,
        global_rules: global_prelude(),
        users: vec![
            UserPolicy {
                name: "primary".to_owned(),
                user_ids: vec!["11111111-1111-4111-8111-111111111111".to_owned()],
                default_outbound: "direct".to_owned(),
                rules,
            },
            secondary_policy(),
        ],
    };
    let table = RoutingTable::compile(
        &config,
        Arc::new(bench_assets()),
        ResourceGovernor::new(&ResourceGovernorConfig::default()),
    )
    .expect("bench routing table must compile");
    Fixture {
        table,
        user_id,
        destination,
        strategy,
    }
}

fn run_once(fixture: &Fixture, runtime: &tokio::runtime::Runtime) {
    if matches!(fixture.strategy, DnsStrategy::IpIfNonMatch) {
        runtime.block_on(async {
            std::hint::black_box(
                fixture
                    .table
                    .select_with_dns(
                        fixture.user_id,
                        INBOUND_TAG,
                        std::hint::black_box(&fixture.destination),
                        fixture.strategy,
                        Duration::from_secs(1),
                    )
                    .await
                    .expect("bench user must route"),
            );
        });
        return;
    }
    let context = RouteContext {
        user_id: fixture.user_id,
        inbound_tag: INBOUND_TAG,
        destination: &fixture.destination,
        resolved_ips: &[],
    };
    std::hint::black_box(
        fixture
            .table
            .select(std::hint::black_box(&context))
            .expect("bench user must route"),
    );
}

fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("bench runtime must build")
}

fn routing_benchmarks(criterion: &mut Criterion) {
    let runtime = bench_runtime();
    let mut group = criterion.benchmark_group("routing/select");
    for &size in SIZES {
        for &case in Case::ALL {
            let fixture = fixture(size, case);
            group.bench_with_input(
                BenchmarkId::new(case.name(), size),
                &fixture,
                |bencher, fixture| {
                    bencher.iter(|| run_once(fixture, &runtime));
                },
            );
        }
    }
    group.finish();
}

/// Fixed-iteration percentile harness for archived before/after comparisons.
fn run_percentiles() {
    let runtime = bench_runtime();
    println!("{{\"format\":\"routing-percentiles-v1\"}}");
    for &size in SIZES {
        for &case in Case::ALL {
            let fixture = fixture(size, case);
            let iterations = (4_000_000_usize / size).clamp(300, 50_000);
            let mut samples = Vec::with_capacity(iterations);
            for _ in 0..iterations.min(200) {
                run_once(&fixture, &runtime);
            }
            for _ in 0..iterations {
                let start = Instant::now();
                run_once(&fixture, &runtime);
                samples.push(start.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            let percentile = |p: usize| samples[(samples.len() * p / 100).min(samples.len() - 1)];
            let mean = samples.iter().sum::<u64>() / samples.len() as u64;
            println!(
                "{{\"rules\":{size},\"case\":\"{}\",\"samples\":{iterations},\"p50_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"mean_ns\":{mean}}}",
                case.name(),
                percentile(50),
                percentile(95),
                percentile(99),
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(40);
    targets = routing_benchmarks
}

fn main() {
    if std::env::var_os("ROUTING_PERCENTILES").is_some() {
        run_percentiles();
        return;
    }
    benches();
}
