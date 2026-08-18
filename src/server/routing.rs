use std::{
    borrow::Cow, collections::HashMap, error::Error, fmt, io, net::IpAddr, sync::Arc,
    time::Duration,
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex::{Regex, RegexBuilder};
use tokio::time;
use uuid::Uuid;

pub use crate::assets::{AssetMatcher, AssetSource, EmptyAssetMatcher};
use crate::{
    config::{DnsStrategy, GlobalRule, Network, RoutingConfig, UserPolicy},
    protocol::vless::{Address, Destination, UserId},
    user_map::AdaptiveUserMap,
};

const MAX_RESOLVED_IPS: usize = 64;

/// Measured crossover on the release build (benches/routing.rs): below 64
/// rules the compact ordered scan wins; at 64+ rules the compiled candidate
/// index (exact/suffix maps plus one Aho-Corasick pass) costs less than the
/// per-rule matcher walk. Mirrors the AdaptiveUserMap representation split.
const INDEXED_RULE_LIMIT: usize = 64;

/// Inputs evaluated by ordered routing rules.
pub struct RouteContext<'a> {
    pub user_id: UserId,
    pub inbound_tag: &'a str,
    pub destination: &'a Destination,
    pub resolved_ips: &'a [IpAddr],
}

/// ASCII-lowercases the destination domain once per request; every domain
/// matcher (including asset sets) consumes this normalized form. An IP
/// destination has no domain to match. Already-lowercase domains borrow.
fn normalized_domain(destination: &Destination) -> Option<Cow<'_, str>> {
    match destination.address() {
        Address::Domain(domain) if domain.bytes().any(|byte| byte.is_ascii_uppercase()) => {
            Some(Cow::Owned(domain.to_ascii_lowercase()))
        }
        Address::Domain(domain) => Some(Cow::Borrowed(domain.as_str())),
        Address::Ipv4(_) | Address::Ipv6(_) => None,
    }
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
    global_index: Option<RuleIndex>,
    users: Arc<AdaptiveUserMap<Arc<CompiledUserPolicy>>>,
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
        let global_index = RuleIndex::build(&global_rules);
        let mut users = Vec::new();
        for policy in &config.users {
            let compiled = Arc::new(CompiledUserPolicy::compile(policy)?);
            for user_id in &policy.user_ids {
                let uuid =
                    Uuid::parse_str(user_id).map_err(|_| RoutingCompileError::InvalidUuid)?;
                users.push((UserId::new(*uuid.as_bytes()), Arc::clone(&compiled)));
            }
        }
        let global_has_ip_rules = global_rules
            .iter()
            .any(|rule: &CompiledRule| !rule.ips.is_empty());
        Ok(Self {
            global_rules,
            global_index,
            users: Arc::new(AdaptiveUserMap::from_entries(users)),
            assets,
            global_has_ip_rules,
            dns_governor,
        })
    }

    /// Approximate heap bytes held by the compiled candidate indices, for
    /// capacity reporting. Excludes the rules themselves.
    #[doc(hidden)]
    #[must_use]
    pub fn index_memory_bytes(&self) -> usize {
        let mut seen: Vec<*const CompiledUserPolicy> = Vec::new();
        let mut total = self
            .global_index
            .as_ref()
            .map_or(0, RuleIndex::memory_bytes);
        self.users.for_each_value(|policy| {
            let pointer = Arc::as_ptr(policy);
            if !seen.contains(&pointer) {
                seen.push(pointer);
                total += policy.index.as_ref().map_or(0, RuleIndex::memory_bytes);
            }
        });
        total
    }

    /// Evaluates global rules, then the authenticated user's ordered rules, then default.
    ///
    /// # Errors
    ///
    /// Returns [`RouteResolutionError::UnknownUser`] if the routing snapshot has no group.
    pub fn select(
        &self,
        context: &RouteContext<'_>,
    ) -> Result<RouteDecision, RouteResolutionError> {
        let user = self
            .users
            .get(&context.user_id)
            .ok_or(RouteResolutionError::UnknownUser)?;
        let domain = normalized_domain(context.destination);
        Ok(self.select_for_user(context, domain.as_deref(), user))
    }

    fn select_for_user(
        &self,
        context: &RouteContext<'_>,
        domain: Option<&str>,
        user: &CompiledUserPolicy,
    ) -> RouteDecision {
        if let Some(rule) = select_from_rules(
            &self.global_rules,
            self.global_index.as_ref(),
            context,
            domain,
            self.assets.as_ref(),
        ) {
            return rule.decision(RouteScope::Global);
        }
        if let Some(rule) = select_from_rules(
            &user.rules,
            user.index.as_ref(),
            context,
            domain,
            self.assets.as_ref(),
        ) {
            return rule.decision(RouteScope::User);
        }
        user.default_decision()
    }

    /// First pass of `IPIfNonMatch`: ordered evaluation ignoring IP groups.
    ///
    /// Returns the first rule whose non-IP conditions all pass and which has
    /// no IP conditions (an immediate decision, no DNS), collecting every rule
    /// that passes its non-IP conditions but still needs resolved IPs into
    /// `pending`, in first-match order across global then user rules.
    fn select_besides_ip<'s>(
        &'s self,
        context: &RouteContext<'_>,
        domain: Option<&str>,
        user: &'s CompiledUserPolicy,
        pending: &mut Vec<(&'s CompiledRule, RouteScope)>,
    ) -> Option<(&'s CompiledRule, RouteScope)> {
        let assets = self.assets.as_ref();
        if let Some(rule) = collect_besides_ip(
            &self.global_rules,
            self.global_index.as_ref(),
            context,
            domain,
            assets,
            RouteScope::Global,
            pending,
        ) {
            return Some((rule, RouteScope::Global));
        }
        if let Some(rule) = collect_besides_ip(
            &user.rules,
            user.index.as_ref(),
            context,
            domain,
            assets,
            RouteScope::User,
            pending,
        ) {
            return Some((rule, RouteScope::User));
        }
        None
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
        let user = self
            .users
            .get(&user_id)
            .ok_or(RouteResolutionError::UnknownUser)?;
        let needs_ip = self.global_has_ip_rules || user.has_ip_rules;
        let unresolved = RouteContext {
            user_id,
            inbound_tag,
            destination,
            resolved_ips: &[],
        };
        let domain = normalized_domain(destination);

        if !matches!(destination.address(), Address::Domain(_))
            || strategy == DnsStrategy::AsIs
            || !needs_ip
        {
            return Ok(ResolvedRoute::new(
                self.select_for_user(&unresolved, domain.as_deref(), user),
                Vec::new(),
            ));
        }

        if strategy == DnsStrategy::IpIfNonMatch {
            // Pass 1 ignores IP conditions. A rule that matches without any IP
            // condition is the exact old pass-1 full match (an unresolved
            // domain can never satisfy an IP condition), so it decides without
            // DNS. Rules failing only their IP group are re-checked in pass-2
            // order instead of re-evaluating the entire ruleset: non-IP
            // conditions do not consult `resolved_ips`, so no other rule's
            // outcome can change after resolution.
            let mut pending = Vec::new();
            if let Some((rule, scope)) =
                self.select_besides_ip(&unresolved, domain.as_deref(), user, &mut pending)
            {
                return Ok(ResolvedRoute::new(rule.decision(scope), Vec::new()));
            }
            let resolved_ips = resolve_domain(&self.dns_governor, destination, timeout).await?;
            let resolved = RouteContext {
                user_id,
                inbound_tag,
                destination,
                resolved_ips: &resolved_ips,
            };
            for (rule, scope) in pending {
                if rule.ip_group_matches(&resolved, self.assets.as_ref()) {
                    return Ok(ResolvedRoute::new(rule.decision(scope), resolved_ips));
                }
            }
            return Ok(ResolvedRoute::new(user.default_decision(), resolved_ips));
        }

        let resolved_ips = resolve_domain(&self.dns_governor, destination, timeout).await?;
        let resolved = RouteContext {
            user_id,
            inbound_tag,
            destination,
            resolved_ips: &resolved_ips,
        };
        Ok(ResolvedRoute::new(
            self.select_for_user(&resolved, domain.as_deref(), user),
            resolved_ips,
        ))
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

/// First full match in first-match order, or none.
///
/// Without an index this is the compact ordered scan; with an index only
/// candidate rules (index hits plus rules that always need direct evaluation)
/// are visited, still in original rule order.
fn select_from_rules<'r>(
    rules: &'r [CompiledRule],
    index: Option<&'r RuleIndex>,
    context: &RouteContext<'_>,
    domain: Option<&str>,
    assets: &dyn AssetMatcher,
) -> Option<&'r CompiledRule> {
    let Some(index) = index else {
        return rules
            .iter()
            .find(|rule| rule.matches(context, domain, assets));
    };
    for (position, hit) in index.ordered_candidates(domain) {
        let rule = &rules[position];
        if rule.matches_indexed(hit, context, domain, assets) {
            return Some(rule);
        }
    }
    None
}

/// Ordered scan ignoring IP conditions; see [`RoutingTable::select_besides_ip`].
fn collect_besides_ip<'r>(
    rules: &'r [CompiledRule],
    index: Option<&'r RuleIndex>,
    context: &RouteContext<'_>,
    domain: Option<&str>,
    assets: &dyn AssetMatcher,
    scope: RouteScope,
    pending: &mut Vec<(&'r CompiledRule, RouteScope)>,
) -> Option<&'r CompiledRule> {
    match index {
        None => {
            for rule in rules {
                if !rule.matches_besides_ip(context, domain, assets) {
                    continue;
                }
                if rule.ips.is_empty() {
                    return Some(rule);
                }
                pending.push((rule, scope));
            }
            None
        }
        Some(index) => {
            for (position, hit) in index.ordered_candidates(domain) {
                let rule = &rules[position];
                if !rule.matches_besides_ip_indexed(hit, context, domain, assets) {
                    continue;
                }
                if rule.ips.is_empty() {
                    return Some(rule);
                }
                pending.push((rule, scope));
            }
            None
        }
    }
}

struct CompiledUserPolicy {
    name: Arc<str>,
    default_outbound: Arc<str>,
    rules: Arc<[CompiledRule]>,
    index: Option<RuleIndex>,
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
        let index = RuleIndex::build(&rules);
        let has_ip_rules = rules.iter().any(|rule| !rule.ips.is_empty());
        Ok(Self {
            name: Arc::from(policy.name.as_str()),
            default_outbound: Arc::from(policy.default_outbound.as_str()),
            rules,
            index,
            has_ip_rules,
        })
    }

    fn default_decision(&self) -> RouteDecision {
        RouteDecision {
            outbound: Arc::clone(&self.default_outbound),
            rule_name: Arc::clone(&self.name),
            scope: RouteScope::UserDefault,
        }
    }
}

/// One route decision and the exact bounded DNS snapshot used to reach it.
#[derive(Debug)]
pub struct ResolvedRoute {
    decision: RouteDecision,
    resolved_ips: Vec<IpAddr>,
}

impl ResolvedRoute {
    fn new(decision: RouteDecision, resolved_ips: Vec<IpAddr>) -> Self {
        Self {
            decision,
            resolved_ips,
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

/// Multiply-rotate hasher (FxHash) for the index maps. Keys come from the
/// operator's configuration, not from the wire, so collision resistance
/// against chosen keys is not required; attackers only ever probe lookups.
#[derive(Clone, Default)]
struct DomainBuildHasher;

impl std::hash::BuildHasher for DomainBuildHasher {
    type Hasher = DomainHasher;

    fn build_hasher(&self) -> DomainHasher {
        DomainHasher(0)
    }
}

struct DomainHasher(u64);

impl DomainHasher {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(Self::SEED);
    }
}

impl std::hash::Hasher for DomainHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            self.add(u64::from_le_bytes(chunk.try_into().unwrap_or_default()));
        }
        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut word = [0_u8; 8];
            word[..remainder.len()].copy_from_slice(remainder);
            self.add(u64::from_le_bytes(word));
        }
    }

    fn write_u8(&mut self, byte: u8) {
        self.add(u64::from(byte));
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// Compiled candidate index for one rule list at or above
/// [`INDEXED_RULE_LIMIT`].
///
/// `full` and `suffix` map normalized matcher values to the rule indices whose
/// domain group contains them; `keywords` runs one Aho-Corasick pass over the
/// normalized destination domain. Index hits reproduce exactly what the
/// ordered scan's `Full`/`Suffix`/`Keyword` matchers would report, because all
/// three comparisons are plain byte equality after one-time ASCII lowercasing.
/// Rules whose domain group is not fully covered by the index (no domain
/// conditions, or at least one regex/asset/empty-keyword matcher) also live in
/// `always` and are evaluated directly every request, so a residual matcher
/// hit is never lost when the indexed matchers miss.
#[derive(Clone)]
struct RuleIndex {
    full: HashMap<Box<str>, Box<[u32]>, DomainBuildHasher>,
    suffix: HashMap<Box<str>, Box<[u32]>, DomainBuildHasher>,
    keywords: Option<AhoCorasick>,
    keyword_rules: Box<[Box<[u32]>]>,
    keyword_pattern_bytes: usize,
    always: Box<[u32]>,
}

impl RuleIndex {
    fn build(rules: &[CompiledRule]) -> Option<Self> {
        if rules.len() < INDEXED_RULE_LIMIT || u32::try_from(rules.len()).is_err() {
            return None;
        }
        let mut full: HashMap<&str, Vec<u32>> = HashMap::new();
        let mut suffix: HashMap<&str, Vec<u32>> = HashMap::new();
        let mut keyword_patterns: Vec<&str> = Vec::new();
        let mut keyword_ids: HashMap<&str, u32> = HashMap::new();
        let mut keyword_rules: Vec<Vec<u32>> = Vec::new();
        let mut always = Vec::new();
        for (position, rule) in rules.iter().enumerate() {
            let position = u32::try_from(position).ok()?;
            let mut indexed = false;
            for matcher in rule.domains.iter() {
                match matcher {
                    DomainMatcher::Full(value) => {
                        full.entry(value.as_ref()).or_default().push(position);
                        indexed = true;
                    }
                    DomainMatcher::Suffix(value) => {
                        suffix.entry(value.as_ref()).or_default().push(position);
                        indexed = true;
                    }
                    DomainMatcher::Keyword(value) if !value.is_empty() => {
                        let next = u32::try_from(keyword_patterns.len()).ok()?;
                        let pattern = *keyword_ids.entry(value.as_ref()).or_insert_with(|| {
                            keyword_patterns.push(value.as_ref());
                            keyword_rules.push(Vec::new());
                            next
                        });
                        keyword_rules[usize::try_from(pattern).ok()?].push(position);
                        indexed = true;
                    }
                    _ => {}
                }
            }
            // A rule is skipped when no index hits only if its domain group is
            // fully covered by the index; anything with a non-indexable
            // matcher (or no domain matchers at all) must be evaluated
            // directly every request, in original order.
            if !indexed || !rule.residual_domains.is_empty() {
                always.push(position);
            }
        }
        let keyword_pattern_bytes = keyword_patterns.iter().map(|pattern| pattern.len()).sum();
        let keywords = if keyword_patterns.is_empty() {
            None
        } else {
            // Fall back to the ordered scan if the automaton cannot be built.
            Some(AhoCorasickBuilder::new().build(keyword_patterns).ok()?)
        };
        Some(Self {
            full: full
                .into_iter()
                .map(|(key, positions)| (Box::from(key), positions.into_boxed_slice()))
                .collect::<HashMap<_, _, DomainBuildHasher>>(),
            suffix: suffix
                .into_iter()
                .map(|(key, positions)| (Box::from(key), positions.into_boxed_slice()))
                .collect::<HashMap<_, _, DomainBuildHasher>>(),
            keywords,
            keyword_rules: keyword_rules
                .into_iter()
                .map(Vec::into_boxed_slice)
                .collect(),
            keyword_pattern_bytes,
            always: always.into_boxed_slice(),
        })
    }

    /// Candidate rule indices in ascending order, each tagged by whether its
    /// indexed domain matchers hit. `always` entries are tagged `false`.
    fn ordered_candidates(&self, domain: Option<&str>) -> OrderedCandidates<'_> {
        let mut hits = Vec::new();
        if let Some(domain) = domain {
            if let Some(positions) = self.full.get(domain) {
                hits.extend_from_slice(positions);
            }
            if let Some(positions) = self.suffix.get(domain) {
                hits.extend_from_slice(positions);
            }
            // A suffix matcher hits exactly when its value is a label-boundary
            // tail of the domain (or the domain itself, looked up above).
            for (index, _) in domain.match_indices('.') {
                if let Some(positions) = self.suffix.get(&domain[index + 1..]) {
                    hits.extend_from_slice(positions);
                }
            }
            if let Some(keywords) = &self.keywords {
                for found in keywords.find_iter(domain) {
                    hits.extend_from_slice(&self.keyword_rules[found.pattern().as_usize()]);
                }
            }
        }
        hits.sort_unstable();
        hits.dedup();
        OrderedCandidates {
            always: self.always.iter().peekable(),
            hits: hits.into_iter().peekable(),
        }
    }

    fn memory_bytes(&self) -> usize {
        let map_bytes = |map: &HashMap<Box<str>, Box<[u32]>, DomainBuildHasher>| {
            map.iter()
                .map(|(key, positions)| key.len() + positions.len() * 4 + 64)
                .sum::<usize>()
        };
        std::mem::size_of::<Self>()
            + map_bytes(&self.full)
            + map_bytes(&self.suffix)
            + self.keyword_pattern_bytes
            + self
                .keyword_rules
                .iter()
                .map(|positions| positions.len() * 4 + 24)
                .sum::<usize>()
            + self.always.len() * 4
    }
}

/// Merges the static `always` list with per-request index hits, preserving the
/// original rule order; rules absent from both cannot match and are skipped.
struct OrderedCandidates<'a> {
    always: std::iter::Peekable<std::slice::Iter<'a, u32>>,
    hits: std::iter::Peekable<std::vec::IntoIter<u32>>,
}

impl Iterator for OrderedCandidates<'_> {
    /// (rule position, indexed-domain-matchers-hit)
    type Item = (usize, bool);

    fn next(&mut self) -> Option<Self::Item> {
        let always = self.always.peek().map(|position| **position);
        let hit = self.hits.peek().copied();
        let (position, hit) = match (always, hit) {
            (Some(always), Some(hit)) => {
                if always < hit {
                    self.always.next();
                    (always, false)
                } else if hit < always {
                    self.hits.next();
                    (hit, true)
                } else {
                    self.always.next();
                    self.hits.next();
                    (always, true)
                }
            }
            (Some(always), None) => {
                self.always.next();
                (always, false)
            }
            (None, Some(hit)) => {
                self.hits.next();
                (hit, true)
            }
            (None, None) => return None,
        };
        Some((usize::try_from(position).ok()?, hit))
    }
}

#[derive(Clone)]
struct CompiledRule {
    name: Arc<str>,
    outbound: Arc<str>,
    domains: Arc<[DomainMatcher]>,
    /// Non-indexable domain matchers (regex, asset, empty keyword); the
    /// indexed path evaluates only these directly per candidate rule.
    residual_domains: Arc<[DomainMatcher]>,
    ips: Arc<[IpMatcher]>,
    ports: Arc<[PortRange]>,
    networks: Arc<[Network]>,
    inbound_tags: Arc<[Arc<str>]>,
}

impl CompiledRule {
    fn compile(rule: &GlobalRule) -> Result<Self, RoutingCompileError> {
        let domains: Arc<[DomainMatcher]> = rule
            .domain
            .iter()
            .map(|matcher| DomainMatcher::compile(matcher))
            .collect::<Result<Vec<_>, _>>()?
            .into();
        let residual_domains: Arc<[DomainMatcher]> = domains
            .iter()
            .filter(|matcher| !matcher.is_indexable())
            .cloned()
            .collect();
        Ok(Self {
            name: Arc::from(rule.name.as_str()),
            outbound: Arc::from(rule.outbound.as_str()),
            domains,
            residual_domains,
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

    fn matches(
        &self,
        context: &RouteContext<'_>,
        domain: Option<&str>,
        assets: &dyn AssetMatcher,
    ) -> bool {
        self.domain_group_matches(domain, assets)
            && self.ip_group_matches(context, assets)
            && self.static_groups_match(context)
    }

    /// Domain group on the linear path: all matchers over the normalized domain.
    fn domain_group_matches(&self, domain: Option<&str>, assets: &dyn AssetMatcher) -> bool {
        if self.domains.is_empty() {
            return true;
        }
        let Some(domain) = domain else {
            return false;
        };
        self.domains
            .iter()
            .any(|matcher| matcher.matches(domain, assets))
    }

    /// Domain group on the indexed path: an index hit settles the group;
    /// otherwise only non-indexable matchers are evaluated.
    fn indexed_domain_matches(
        &self,
        hit: bool,
        domain: Option<&str>,
        assets: &dyn AssetMatcher,
    ) -> bool {
        if self.domains.is_empty() || hit {
            return true;
        }
        let Some(domain) = domain else {
            return false;
        };
        self.residual_domains
            .iter()
            .any(|matcher| matcher.matches(domain, assets))
    }

    fn ip_group_matches(&self, context: &RouteContext<'_>, assets: &dyn AssetMatcher) -> bool {
        self.ips.is_empty()
            || destination_ips(context).any(|address| {
                self.ips
                    .iter()
                    .any(|matcher| matcher.matches(address, assets))
            })
    }

    /// Port, network, and inbound-tag groups; never consult `resolved_ips`.
    fn static_groups_match(&self, context: &RouteContext<'_>) -> bool {
        (self.ports.is_empty()
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

    fn matches_indexed(
        &self,
        hit: bool,
        context: &RouteContext<'_>,
        domain: Option<&str>,
        assets: &dyn AssetMatcher,
    ) -> bool {
        self.indexed_domain_matches(hit, domain, assets)
            && self.ip_group_matches(context, assets)
            && self.static_groups_match(context)
    }

    fn matches_besides_ip(
        &self,
        context: &RouteContext<'_>,
        domain: Option<&str>,
        assets: &dyn AssetMatcher,
    ) -> bool {
        self.domain_group_matches(domain, assets) && self.static_groups_match(context)
    }

    fn matches_besides_ip_indexed(
        &self,
        hit: bool,
        context: &RouteContext<'_>,
        domain: Option<&str>,
        assets: &dyn AssetMatcher,
    ) -> bool {
        self.indexed_domain_matches(hit, domain, assets) && self.static_groups_match(context)
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

    /// Whether the matcher compiles into the candidate index. Empty keywords
    /// match every domain and stay on the direct-evaluation path.
    fn is_indexable(&self) -> bool {
        match self {
            Self::Full(_) | Self::Suffix(_) => true,
            Self::Keyword(value) => !value.is_empty(),
            Self::Regex(_) | Self::Asset { .. } => false,
        }
    }

    /// Matches against the request-normalized (ASCII-lowercased) domain.
    ///
    /// Matcher values were lowercased at compile time, so the old
    /// case-insensitive comparisons are plain byte comparisons here. Regexes
    /// were compiled case-insensitive and asset sets normalize internally, so
    /// both observe identical results on normalized input.
    fn matches(&self, domain: &str, assets: &dyn AssetMatcher) -> bool {
        match self {
            Self::Full(value) => domain == value.as_ref(),
            Self::Suffix(value) => domain_suffix_matches(domain, value),
            Self::Keyword(value) => keyword_matches(domain, value),
            Self::Regex(regex) => regex.is_match(domain),
            Self::Asset { source, label } => assets.matches_domain(source, label, domain),
        }
    }
}

/// Substring match over normalized (lowercase) inputs. A plain window scan
/// beats `str::contains` here: domains are short and `TwoWaySearcher`
/// construction dominates at these sizes. The candidate index handles keyword
/// matching at scale via one Aho-Corasick pass per request.
fn keyword_matches(domain: &str, needle: &str) -> bool {
    needle.is_empty()
        || domain
            .as_bytes()
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
}

/// Label-boundary suffix match over normalized (lowercase) inputs.
fn domain_suffix_matches(domain: &str, suffix: &str) -> bool {
    domain == suffix
        || (domain.len() > suffix.len()
            && domain.ends_with(suffix)
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
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

/// DNS-assisted route evaluation failed before any outbound was selected.
#[derive(Debug)]
pub enum RouteResolutionError {
    /// The immutable routing snapshot has no policy for an authenticated UUID.
    UnknownUser,
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
            Self::UnknownUser => {
                formatter.write_str("authenticated VLESS user has no routing policy")
            }
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
            Self::Dns(source) => Some(source),
            Self::UnknownUser
            | Self::DnsTimeout
            | Self::DnsLimit
            | Self::NoAddresses
            | Self::TooManyAddresses
            | Self::Allocation => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use super::{
        EmptyAssetMatcher, ResolvedRoute, RouteContext, RouteResolutionError, RouteScope,
        RoutingTable,
    };
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

    use super::resolve_domain_with;
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
    // ---- Differential tests: indexed path vs the naive ordered scan ----

    use std::net::Ipv6Addr;

    use super::{
        CompiledRule, INDEXED_RULE_LIMIT, RouteDecision, RuleIndex, normalized_domain,
        resolve_domain, select_from_rules,
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

    fn random_rule(rng: &mut XorShift, index: usize) -> GlobalRule {
        let mut rule = GlobalRule {
            name: format!("rule-{index}"),
            outbound: format!("out-{:02}", rng.below(8)),
            domain: Vec::new(),
            ip: Vec::new(),
            port: Vec::new(),
            network: Vec::new(),
            inbound_tag: Vec::new(),
        };
        for _ in 0..rng.below(3) {
            rule.domain.push(random_domain_matcher(rng));
        }
        for _ in 0..rng.below(2) {
            rule.ip.push(random_ip_matcher(rng));
        }
        if rng.chance(30) {
            rule.port.push(PortMatcher(
                ["53", "443", "1000-2000", "8000-9000"][rng.below(4)].to_owned(),
            ));
        }
        if rng.chance(30) {
            rule.network = match rng.below(3) {
                0 => vec![Network::Tcp],
                // A udp-only rule never matches today; both paths must agree.
                1 => vec![Network::Udp],
                _ => vec![Network::Tcp, Network::Udp],
            };
        }
        if rng.chance(30) {
            rule.inbound_tag = vec![["in-a", "in-b", "in-c"][rng.below(3)].to_owned()];
        }
        rule
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
            return rule.decision(RouteScope::User);
        }
        user.default_decision()
    }

    fn compile_random(rng: &mut XorShift, user_count: usize) -> RoutingTable {
        let rules = (0..user_count)
            .map(|index| random_rule(rng, 1000 + index))
            .collect();
        compile_random_with_rules(rng, rules)
    }

    fn compile_random_with_rules(rng: &mut XorShift, rules: Vec<GlobalRule>) -> RoutingTable {
        let global_rules = (0..rng.below(9))
            .map(|index| random_rule(rng, index))
            .collect();
        let second_rules = (0..70)
            .map(|index| random_rule(rng, 2000 + index))
            .collect();
        RoutingTable::compile(
            &RoutingConfig {
                domain_strategy: DnsStrategy::AsIs,
                global_rules,
                users: vec![
                    UserPolicy {
                        name: "primary".to_owned(),
                        user_ids: vec![USER.to_owned()],
                        default_outbound: "fallback".to_owned(),
                        rules,
                    },
                    UserPolicy {
                        name: "second".to_owned(),
                        user_ids: vec!["ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned()],
                        default_outbound: "fallback-two".to_owned(),
                        rules: second_rules,
                    },
                ],
            },
            Arc::new(StubAssets),
            crate::runtime::ResourceGovernor::new(
                &crate::config::ResourceGovernorConfig::default(),
            ),
        )
        .expect("randomized routing config must compile")
    }

    #[test]
    fn mixed_indexable_residual_rule_matches_through_the_residual() {
        let table =
            RoutingTable::compile(
                &RoutingConfig {
                    domain_strategy: DnsStrategy::AsIs,
                    global_rules: Vec::new(),
                    users: vec![UserPolicy {
                        name: "primary".to_owned(),
                        user_ids: vec![USER.to_owned()],
                        default_outbound: "fallback".to_owned(),
                        rules: (0..70)
                            .map(|index| GlobalRule {
                                name: format!("r{index}"),
                                outbound: format!("out-{index}"),
                                domain: if index == 40 {
                                    vec!["full:unrelated.test".to_owned(), "geosite:l3".to_owned()]
                                } else {
                                    vec![format!("full:h{index}.test")]
                                },
                                ip: Vec::new(),
                                port: Vec::new(),
                                network: Vec::new(),
                                inbound_tag: Vec::new(),
                            })
                            .collect(),
                    }],
                },
                Arc::new(StubAssets),
                crate::runtime::ResourceGovernor::new(
                    &crate::config::ResourceGovernorConfig::default(),
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
        let mixed_rules: Vec<GlobalRule> = (0..(INDEXED_RULE_LIMIT + 20))
            .map(|index| GlobalRule {
                name: format!("mixed-{index}"),
                outbound: format!("mixed-out-{index}"),
                domain: vec![
                    random_domain_matcher(&mut rng),
                    [
                        "regexp:^api\\.",
                        "regexp:\\.internal$",
                        "geosite:l3",
                        "keyword:",
                    ][rng.below(4)]
                    .to_owned(),
                ],
                ip: Vec::new(),
                port: Vec::new(),
                network: Vec::new(),
                inbound_tag: Vec::new(),
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
        if first.scope() != RouteScope::UserDefault {
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
                        DnsStrategy::IpIfNonMatch,
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
                CompiledRule::compile(&GlobalRule {
                    name: format!("r{index}"),
                    outbound: "direct".to_owned(),
                    domain: vec![format!("full:h{index}.test")],
                    ip: Vec::new(),
                    port: Vec::new(),
                    network: Vec::new(),
                    inbound_tag: Vec::new(),
                })
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
}
