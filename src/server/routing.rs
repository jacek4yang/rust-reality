use std::{collections::HashMap, error::Error, fmt, io, net::IpAddr, sync::Arc, time::Duration};

use regex::{Regex, RegexBuilder};
use tokio::time;
use uuid::Uuid;

pub use crate::assets::{AssetMatcher, AssetSource, EmptyAssetMatcher};
use crate::{
    config::{DnsStrategy, GlobalRule, Network, RoutingConfig, UserPolicy},
    protocol::vless::{Address, Destination, UserId},
};

const MAX_RESOLVED_IPS: usize = 64;

/// Inputs evaluated by ordered routing rules.
pub struct RouteContext<'a> {
    pub user_id: UserId,
    pub inbound_tag: &'a str,
    pub destination: &'a Destination,
    pub resolved_ips: &'a [IpAddr],
}

impl fmt::Debug for RouteContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteContext")
            .field("user_id", &"[REDACTED]")
            .field("inbound_tag", &self.inbound_tag)
            .field("destination", &self.destination)
            .field("resolved_ip_count", &self.resolved_ips.len())
            .finish()
    }
}

/// Origin of the selected outbound decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteScope {
    Global,
    User,
    UserDefault,
}

/// One deterministic first-match routing result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecision {
    outbound: Arc<str>,
    rule_name: Arc<str>,
    scope: RouteScope,
}

impl RouteDecision {
    #[must_use]
    pub fn outbound(&self) -> &str {
        &self.outbound
    }

    #[must_use]
    pub fn rule_name(&self) -> &str {
        &self.rule_name
    }

    #[must_use]
    pub const fn scope(&self) -> RouteScope {
        self.scope
    }
}

/// Compiled, immutable global and UUID-grouped routing state.
#[derive(Clone)]
pub struct RoutingTable {
    global_rules: Arc<[CompiledRule]>,
    users: Arc<HashMap<UserId, CompiledUserPolicy>>,
    assets: Arc<dyn AssetMatcher>,
    global_has_ip_rules: bool,
    dns_governor: crate::runtime::ResourceGovernor,
}

impl RoutingTable {
    /// Compiles validated configuration and binds it to one immutable asset snapshot.
    ///
    /// # Errors
    ///
    /// Returns an invalid UUID, matcher, port range, CIDR, or regular expression.
    pub fn compile(
        config: &RoutingConfig,
        assets: Arc<dyn AssetMatcher>,
        dns_governor: crate::runtime::ResourceGovernor,
    ) -> Result<Self, RoutingCompileError> {
        let global_rules: Arc<[CompiledRule]> = config
            .global_rules
            .iter()
            .map(CompiledRule::compile)
            .collect::<Result<Vec<_>, _>>()?
            .into();
        let mut users = HashMap::new();
        for policy in &config.users {
            let compiled = CompiledUserPolicy::compile(policy)?;
            for user_id in &policy.user_ids {
                let uuid =
                    Uuid::parse_str(user_id).map_err(|_| RoutingCompileError::InvalidUuid)?;
                users.insert(UserId::new(*uuid.as_bytes()), compiled.clone());
            }
        }
        let global_has_ip_rules = global_rules
            .iter()
            .any(|rule: &CompiledRule| !rule.ips.is_empty());
        Ok(Self {
            global_rules,
            users: Arc::new(users),
            assets,
            global_has_ip_rules,
            dns_governor,
        })
    }

    /// Evaluates global rules, then the authenticated user's ordered rules, then default.
    ///
    /// # Errors
    ///
    /// Returns [`RouteError::UnknownUser`] if the immutable routing snapshot has no group.
    pub fn select(&self, context: &RouteContext<'_>) -> Result<RouteDecision, RouteError> {
        if let Some(rule) = self
            .global_rules
            .iter()
            .find(|rule| rule.matches(context, self.assets.as_ref()))
        {
            return Ok(rule.decision(RouteScope::Global));
        }
        let user = self
            .users
            .get(&context.user_id)
            .ok_or(RouteError::UnknownUser)?;
        if let Some(rule) = user
            .rules
            .iter()
            .find(|rule| rule.matches(context, self.assets.as_ref()))
        {
            return Ok(rule.decision(RouteScope::User));
        }
        Ok(RouteDecision {
            outbound: Arc::clone(&user.default_outbound),
            rule_name: Arc::clone(&user.name),
            scope: RouteScope::UserDefault,
        })
    }

    /// Resolves a domain only when required by the configured routing strategy,
    /// then evaluates the same immutable rules against a bounded IP snapshot.
    ///
    /// `IPIfNonMatch` first gives domain, port, network, and inbound-tag rules a
    /// chance to match. `IPOnDemand` resolves before rule evaluation whenever an
    /// IP rule exists. `AsIs` never resolves inside the router.
    ///
    /// # Errors
    ///
    /// Returns an unknown-user error before DNS work, or a bounded DNS error when
    /// resolution is required and cannot complete safely.
    pub async fn select_with_dns(
        &self,
        user_id: UserId,
        inbound_tag: &str,
        destination: &Destination,
        strategy: DnsStrategy,
        timeout: Duration,
    ) -> Result<ResolvedRoute, RouteResolutionError> {
        let user_has_ip_rules = self
            .users
            .get(&user_id)
            .ok_or(RouteError::UnknownUser)?
            .has_ip_rules;
        let needs_ip = self.global_has_ip_rules || user_has_ip_rules;
        let unresolved = RouteContext {
            user_id,
            inbound_tag,
            destination,
            resolved_ips: &[],
        };

        if !matches!(destination.address(), Address::Domain(_))
            || strategy == DnsStrategy::AsIs
            || !needs_ip
        {
            return Ok(ResolvedRoute::new(self.select(&unresolved)?, Vec::new()));
        }

        if strategy == DnsStrategy::IpIfNonMatch {
            let decision = self.select(&unresolved)?;
            if decision.scope() != RouteScope::UserDefault {
                return Ok(ResolvedRoute::new(decision, Vec::new()));
            }
        }

        let resolved_ips = resolve_domain(&self.dns_governor, destination, timeout).await?;
        let resolved = RouteContext {
            user_id,
            inbound_tag,
            destination,
            resolved_ips: &resolved_ips,
        };
        Ok(ResolvedRoute::new(self.select(&resolved)?, resolved_ips))
    }
}

impl fmt::Debug for RoutingTable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingTable")
            .field("global_rule_count", &self.global_rules.len())
            .field("user_count", &self.users.len())
            .field("assets", &"[IMMUTABLE SNAPSHOT]")
            .field("global_has_ip_rules", &self.global_has_ip_rules)
            .finish()
    }
}

#[derive(Clone)]
struct CompiledUserPolicy {
    name: Arc<str>,
    default_outbound: Arc<str>,
    rules: Arc<[CompiledRule]>,
    has_ip_rules: bool,
}

impl CompiledUserPolicy {
    fn compile(policy: &UserPolicy) -> Result<Self, RoutingCompileError> {
        let rules: Arc<[CompiledRule]> = policy
            .rules
            .iter()
            .map(CompiledRule::compile)
            .collect::<Result<Vec<_>, _>>()?
            .into();
        let has_ip_rules = rules.iter().any(|rule| !rule.ips.is_empty());
        Ok(Self {
            name: Arc::from(policy.name.as_str()),
            default_outbound: Arc::from(policy.default_outbound.as_str()),
            rules,
            has_ip_rules,
        })
    }
}

/// One route decision and the exact bounded DNS snapshot used to reach it.
#[derive(Clone, Debug)]
pub struct ResolvedRoute {
    decision: RouteDecision,
    resolved_ips: Arc<[IpAddr]>,
}

impl ResolvedRoute {
    fn new(decision: RouteDecision, resolved_ips: Vec<IpAddr>) -> Self {
        Self {
            decision,
            resolved_ips: resolved_ips.into(),
        }
    }

    /// Returns the first-match routing decision.
    #[must_use]
    pub const fn decision(&self) -> &RouteDecision {
        &self.decision
    }

    /// Returns the exact addresses considered by IP and GeoIP rules.
    #[must_use]
    pub fn resolved_ips(&self) -> &[IpAddr] {
        &self.resolved_ips
    }
}

async fn resolve_domain(
    governor: &crate::runtime::ResourceGovernor,
    destination: &Destination,
    timeout: Duration,
) -> Result<Vec<IpAddr>, RouteResolutionError> {
    let Address::Domain(domain) = destination.address() else {
        return Ok(Vec::new());
    };
    // A numeric literal carried as a domain "resolves" to itself; skip the
    // blocking resolver pool entirely.
    if let Ok(ip) = domain.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let lookup = (domain.to_owned(), destination.port());
    resolve_domain_with(
        governor,
        move || std::net::ToSocketAddrs::to_socket_addrs(&lookup),
        timeout,
    )
    .await
}

/// Resolves through `lookup` on a blocking thread, bounding both the wait and,
/// independently, the underlying operation.
///
/// The permit is held inside the blocking task, so an async timeout or a
/// cancelled future can abandon the wait but never the accounting: the
/// underlying resolver operation holds one bounded slot until it actually
/// returns, and the DNS pool bounds every queued and running operation alike
/// (there is no separate unbounded request queue).
async fn resolve_domain_with<F, I>(
    governor: &crate::runtime::ResourceGovernor,
    lookup: F,
    timeout: Duration,
) -> Result<Vec<IpAddr>, RouteResolutionError>
where
    F: FnOnce() -> io::Result<I> + Send + 'static,
    I: IntoIterator<Item = std::net::SocketAddr> + Send + 'static,
{
    let permit = governor
        .try_acquire(crate::runtime::AdmissionKind::DnsLookup)
        .map_err(|_| RouteResolutionError::DnsLimit)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        let result = lookup();
        drop(permit);
        let _ignored = sender.send(result);
    });
    let addresses = time::timeout(timeout, receiver)
        .await
        .map_err(|_| RouteResolutionError::DnsTimeout)?
        .map_err(|_| RouteResolutionError::Dns(io::Error::other("DNS resolver task failed")))?
        .map_err(RouteResolutionError::Dns)?;
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(MAX_RESOLVED_IPS)
        .map_err(|_| RouteResolutionError::Allocation)?;
    for address in addresses {
        let ip = address.ip();
        if resolved.contains(&ip) {
            continue;
        }
        if resolved.len() == MAX_RESOLVED_IPS {
            return Err(RouteResolutionError::TooManyAddresses);
        }
        resolved.push(ip);
    }
    if resolved.is_empty() {
        return Err(RouteResolutionError::NoAddresses);
    }
    Ok(resolved)
}

#[derive(Clone)]
struct CompiledRule {
    name: Arc<str>,
    outbound: Arc<str>,
    domains: Arc<[DomainMatcher]>,
    ips: Arc<[IpMatcher]>,
    ports: Arc<[PortRange]>,
    networks: Arc<[Network]>,
    inbound_tags: Arc<[Arc<str>]>,
}

impl CompiledRule {
    fn compile(rule: &GlobalRule) -> Result<Self, RoutingCompileError> {
        Ok(Self {
            name: Arc::from(rule.name.as_str()),
            outbound: Arc::from(rule.outbound.as_str()),
            domains: rule
                .domain
                .iter()
                .map(|matcher| DomainMatcher::compile(matcher))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
            ips: rule
                .ip
                .iter()
                .map(|matcher| IpMatcher::compile(matcher))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
            ports: rule
                .port
                .iter()
                .map(|matcher| PortRange::compile(&matcher.0))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
            networks: rule.network.clone().into(),
            inbound_tags: rule
                .inbound_tag
                .iter()
                .map(|tag| Arc::from(tag.as_str()))
                .collect::<Vec<_>>()
                .into(),
        })
    }

    fn matches(&self, context: &RouteContext<'_>, assets: &dyn AssetMatcher) -> bool {
        let domain_matches = self.domains.is_empty()
            || match context.destination.address() {
                Address::Domain(domain) => self
                    .domains
                    .iter()
                    .any(|matcher| matcher.matches(domain, assets)),
                Address::Ipv4(_) | Address::Ipv6(_) => false,
            };
        let ip_matches = self.ips.is_empty()
            || destination_ips(context).any(|address| {
                self.ips
                    .iter()
                    .any(|matcher| matcher.matches(address, assets))
            });
        domain_matches
            && ip_matches
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|range| range.contains(context.destination.port())))
            && (self.networks.is_empty() || self.networks.contains(&Network::Tcp))
            && (self.inbound_tags.is_empty()
                || self
                    .inbound_tags
                    .iter()
                    .any(|tag| tag.as_ref() == context.inbound_tag))
    }

    fn decision(&self, scope: RouteScope) -> RouteDecision {
        RouteDecision {
            outbound: Arc::clone(&self.outbound),
            rule_name: Arc::clone(&self.name),
            scope,
        }
    }
}

fn destination_ips<'a>(context: &'a RouteContext<'a>) -> impl Iterator<Item = IpAddr> + 'a {
    let immediate = match context.destination.address() {
        Address::Ipv4(address) => Some(IpAddr::V4(*address)),
        Address::Ipv6(address) => Some(IpAddr::V6(*address)),
        Address::Domain(_) => None,
    };
    immediate
        .into_iter()
        .chain(context.resolved_ips.iter().copied())
}

#[derive(Clone)]
enum DomainMatcher {
    Full(Arc<str>),
    Suffix(Arc<str>),
    Keyword(Arc<str>),
    Regex(Arc<Regex>),
    Asset {
        source: AssetSource,
        label: Arc<str>,
    },
}

impl DomainMatcher {
    fn compile(input: &str) -> Result<Self, RoutingCompileError> {
        let lower = input.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("full:") {
            return Ok(Self::Full(Arc::from(value)));
        }
        if let Some(value) = lower.strip_prefix("domain:") {
            return Ok(Self::Suffix(Arc::from(value.trim_start_matches('.'))));
        }
        if let Some(value) = lower.strip_prefix("keyword:") {
            return Ok(Self::Keyword(Arc::from(value)));
        }
        if let Some(value) = input.strip_prefix("regexp:") {
            return RegexBuilder::new(value)
                .case_insensitive(true)
                .build()
                .map(Arc::new)
                .map(Self::Regex)
                .map_err(|_| RoutingCompileError::InvalidRegex);
        }
        if let Some(label) = lower.strip_prefix("geosite:") {
            return Ok(Self::Asset {
                source: AssetSource::GeoSite,
                label: Arc::from(label),
            });
        }
        if let Some((file, label)) = external_matcher(input) {
            return Ok(Self::Asset {
                source: AssetSource::External(Arc::from(file)),
                label: Arc::from(label.to_ascii_lowercase()),
            });
        }
        Ok(Self::Suffix(Arc::from(lower.trim_start_matches('.'))))
    }

    fn matches(&self, domain: &str, assets: &dyn AssetMatcher) -> bool {
        match self {
            Self::Full(value) => domain.eq_ignore_ascii_case(value),
            Self::Suffix(value) => domain_suffix_matches(domain, value),
            Self::Keyword(value) => ascii_contains_ignore_case(domain, value),
            Self::Regex(regex) => regex.is_match(domain),
            Self::Asset { source, label } => assets.matches_domain(source, label, domain),
        }
    }
}

fn domain_suffix_matches(domain: &str, suffix: &str) -> bool {
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }
    let Some(prefix_length) = domain.len().checked_sub(suffix.len()) else {
        return false;
    };
    prefix_length > 0
        && domain.as_bytes().get(prefix_length - 1) == Some(&b'.')
        && domain[prefix_length..].eq_ignore_ascii_case(suffix)
}

fn ascii_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[derive(Clone)]
enum IpMatcher {
    Network(IpNetwork),
    Asset {
        source: AssetSource,
        label: Arc<str>,
    },
}

impl IpMatcher {
    fn compile(input: &str) -> Result<Self, RoutingCompileError> {
        let lower = input.to_ascii_lowercase();
        if let Some(label) = lower.strip_prefix("geoip:") {
            return Ok(Self::Asset {
                source: AssetSource::GeoIp,
                label: Arc::from(label),
            });
        }
        if let Some((file, label)) = external_matcher(input) {
            return Ok(Self::Asset {
                source: AssetSource::External(Arc::from(file)),
                label: Arc::from(label.to_ascii_lowercase()),
            });
        }
        IpNetwork::compile(&lower).map(Self::Network)
    }

    fn matches(&self, address: IpAddr, assets: &dyn AssetMatcher) -> bool {
        match self {
            Self::Network(network) => network.contains(address),
            Self::Asset { source, label } => assets.matches_ip(source, label, address),
        }
    }
}

fn external_matcher(input: &str) -> Option<(&str, &str)> {
    if !input.get(..4)?.eq_ignore_ascii_case("ext:") {
        return None;
    }
    input.get(4..)?.split_once(':')
}

#[derive(Clone, Copy)]
enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    fn compile(input: &str) -> Result<Self, RoutingCompileError> {
        let (address, prefix) = input
            .split_once('/')
            .map_or((input, None), |(address, prefix)| (address, Some(prefix)));
        let address: IpAddr = address
            .parse()
            .map_err(|_| RoutingCompileError::InvalidIp)?;
        match address {
            IpAddr::V4(address) => {
                let prefix = parse_prefix(prefix, 32)?;
                let mask = prefix_mask_u32(prefix);
                Ok(Self::V4 {
                    network: u32::from(address) & mask,
                    prefix,
                })
            }
            IpAddr::V6(address) => {
                let prefix = parse_prefix(prefix, 128)?;
                let mask = prefix_mask_u128(prefix);
                Ok(Self::V6 {
                    network: u128::from(address) & mask,
                    prefix,
                })
            }
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, IpAddr::V4(address)) => {
                u32::from(address) & prefix_mask_u32(prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(address)) => {
                u128::from(address) & prefix_mask_u128(prefix) == network
            }
            (Self::V4 { .. }, IpAddr::V6(_)) | (Self::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }
}

fn parse_prefix(prefix: Option<&str>, maximum: u8) -> Result<u8, RoutingCompileError> {
    let prefix = prefix.map_or(Ok(maximum), |value| {
        value
            .parse::<u8>()
            .map_err(|_| RoutingCompileError::InvalidIp)
    })?;
    if prefix > maximum {
        return Err(RoutingCompileError::InvalidIp);
    }
    Ok(prefix)
}

const fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Clone, Copy)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn compile(input: &str) -> Result<Self, RoutingCompileError> {
        let (start, end) = input
            .split_once('-')
            .map_or((input, input), |(start, end)| (start, end));
        let start = start
            .parse()
            .map_err(|_| RoutingCompileError::InvalidPort)?;
        let end = end.parse().map_err(|_| RoutingCompileError::InvalidPort)?;
        if start == 0 || start > end {
            return Err(RoutingCompileError::InvalidPort);
        }
        Ok(Self { start, end })
    }

    const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// Validated routing configuration could not be compiled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingCompileError {
    InvalidUuid,
    InvalidRegex,
    InvalidIp,
    InvalidPort,
}

impl fmt::Display for RoutingCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid => formatter.write_str("routing contains an invalid UUID"),
            Self::InvalidRegex => {
                formatter.write_str("routing contains an invalid regular expression")
            }
            Self::InvalidIp => formatter.write_str("routing contains an invalid IP matcher"),
            Self::InvalidPort => formatter.write_str("routing contains an invalid port matcher"),
        }
    }
}

impl Error for RoutingCompileError {}

/// Routing state has no policy for an authenticated UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    UnknownUser,
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("authenticated VLESS user has no routing policy")
    }
}

impl Error for RouteError {}

/// DNS-assisted route evaluation failed before any outbound was selected.
#[derive(Debug)]
pub enum RouteResolutionError {
    Route(RouteError),
    DnsTimeout,
    DnsLimit,
    Dns(io::Error),
    NoAddresses,
    TooManyAddresses,
    Allocation,
}

impl fmt::Display for RouteResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(source) => source.fmt(formatter),
            Self::DnsTimeout => formatter.write_str("routing DNS resolution timed out"),
            Self::DnsLimit => {
                formatter.write_str("routing DNS resolution exceeded the bounded resolver pool")
            }
            Self::Dns(_) => formatter.write_str("routing DNS resolution failed"),
            Self::NoAddresses => formatter.write_str("routing DNS returned no addresses"),
            Self::TooManyAddresses => {
                formatter.write_str("routing DNS exceeded the bounded address count")
            }
            Self::Allocation => formatter.write_str("routing DNS allocation failed"),
        }
    }
}

impl Error for RouteResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Route(source) => Some(source),
            Self::Dns(source) => Some(source),
            Self::DnsTimeout
            | Self::DnsLimit
            | Self::NoAddresses
            | Self::TooManyAddresses
            | Self::Allocation => None,
        }
    }
}

impl From<RouteError> for RouteResolutionError {
    fn from(source: RouteError) -> Self {
        Self::Route(source)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use super::{EmptyAssetMatcher, RouteContext, RouteScope, RoutingTable};
    use crate::{
        config::{DnsStrategy, GlobalRule, Network, PortMatcher, RoutingConfig, UserPolicy},
        protocol::vless::{Address, Destination, UserId},
    };

    const USER: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const USER_ID: UserId = UserId::new([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
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
    fn user_rules_are_first_match_and_conditions_are_conjunctive() {
        let table = table();
        let destination = Destination::new(Address::Domain("api.example.com".to_owned()), 443);
        let decision = table
            .select(&context(&destination))
            .expect("configured user must route");

        assert_eq!(decision.outbound(), "socks");
        assert_eq!(decision.scope(), RouteScope::User);
    }

    #[test]
    fn suffix_requires_dns_label_boundary() {
        let table = table();
        let destination = Destination::new(Address::Domain("notexample.com".to_owned()), 443);
        let decision = table
            .select(&context(&destination))
            .expect("configured user must route");

        assert_eq!(decision.outbound(), "direct");
        assert_eq!(decision.scope(), RouteScope::UserDefault);
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
                DnsStrategy::IpIfNonMatch,
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
                DnsStrategy::AsIs,
                Duration::from_secs(2),
            )
            .await
            .expect("configured user must route without DNS");

        assert_eq!(route.decision().outbound(), "direct");
        assert_eq!(route.decision().scope(), RouteScope::UserDefault);
        assert!(route.resolved_ips().is_empty());
    }

    fn table() -> RoutingTable {
        table_with_global_ip("10.0.0.0/8")
    }

    fn table_with_global_ip(ip_matcher: &str) -> RoutingTable {
        RoutingTable::compile(
            &RoutingConfig {
                domain_strategy: DnsStrategy::AsIs,
                global_rules: vec![GlobalRule {
                    name: "private".to_owned(),
                    outbound: "blocked".to_owned(),
                    domain: Vec::new(),
                    ip: vec![ip_matcher.to_owned()],
                    port: Vec::new(),
                    network: Vec::new(),
                    inbound_tag: Vec::new(),
                }],
                users: vec![UserPolicy {
                    name: "primary".to_owned(),
                    user_ids: vec![USER.to_owned()],
                    default_outbound: "direct".to_owned(),
                    rules: vec![GlobalRule {
                        name: "api through socks".to_owned(),
                        outbound: "socks".to_owned(),
                        domain: vec!["domain:example.com".to_owned()],
                        ip: Vec::new(),
                        port: vec![PortMatcher("443".to_owned())],
                        network: vec![Network::Tcp],
                        inbound_tag: vec!["public-reality".to_owned()],
                    }],
                }],
            },
            Arc::new(EmptyAssetMatcher),
            crate::runtime::ResourceGovernor::new(&crate::config::ResourceGovernorConfig::default()),
        )
        .expect("routing must compile")
    }

    use std::net::{IpAddr, SocketAddr};

    use super::{RouteResolutionError, resolve_domain_with};
    use crate::{config::ResourceGovernorConfig, runtime::ResourceGovernor};

    fn tiny_dns_governor(permits: u32) -> ResourceGovernor {
        ResourceGovernor::new(&ResourceGovernorConfig {
            max_dns_lookups: permits,
            ..ResourceGovernorConfig::default()
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
}
