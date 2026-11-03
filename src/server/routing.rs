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
    config::node::{
        routing::{DomainStrategy, RouteRule, RoutingConfig},
        user::UserConfig,
    },
    protocol::{
        handoff::{
            HandoffPolicySnapshot, MAX_SEALED_HANDOFF_RULES, SealedDomainMatcher,
            SealedHandoffRouteRule, SealedIpNetwork, SealedPortRange,
        },
        vless::{Address, Destination, UserId},
    },
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
///
/// The scope says *which list* decided, and it is reported next to the name
/// of that list, so the two together locate the decision in the file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteScope {
    /// A rule in `routing.rules`, which every user is subject to.
    Global,
    /// A rule inside the policy the user follows.
    Policy,
    /// No rule matched, so the `default` of whichever list applied was used.
    ///
    /// That list is `routing` for a user who follows no policy, and
    /// `routing.policies.<name>` for one who does — which is why the name is
    /// reported beside this and the wording does not claim a policy exists.
    DefaultOutbound,
}

impl RouteScope {
    /// The stable name used in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global rule",
            Self::Policy => "policy rule",
            Self::DefaultOutbound => "default outbound",
        }
    }
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
        clients: &[UserConfig],
        assets: Arc<dyn AssetMatcher>,
        dns_governor: crate::runtime::ResourceGovernor,
    ) -> Result<Self, RoutingCompileError> {
        let global_rules = compile_rules(config.rules(), "routing.rules")?;
        let global_index = RuleIndex::build(&global_rules);

        // Every user follows exactly one policy: the one it names, or the
        // global default. Compiling each named policy once and sharing it
        // keeps the per-user map a pointer per identity.
        let fallback = Arc::new(CompiledUserPolicy::compile(
            "routing",
            &config.default,
            config.rules(),
        )?);
        let mut named: HashMap<&str, Arc<CompiledUserPolicy>> = HashMap::new();
        for (name, policy) in config.policies() {
            let compiled = CompiledUserPolicy::compile(
                &format!("routing.policies.{name}"),
                &policy.default,
                policy.rules(),
            )?;
            named.insert(name.as_str(), Arc::new(compiled));
        }

        let mut users = Vec::with_capacity(clients.len());
        for client in clients {
            let policy = match &client.policy {
                Some(name) => named
                    .get(name.as_str())
                    .cloned()
                    .ok_or(RoutingCompileError::UnknownPolicy)?,
                None => Arc::clone(&fallback),
            };
            let uuid = Uuid::parse_str(&client.id).map_err(|_| RoutingCompileError::InvalidUuid)?;
            users.push((UserId::new(*uuid.as_bytes()), policy));
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

    /// Compile a session-bound Handoff XUDP policy snapshot (ADR 0060 Option B / PR5).
    ///
    /// Seals first-match sealable route rules for `user_id` relative to
    /// `handoff_outbound`. Geosite / GeoIP / regexp / external matchers cannot be
    /// evaluated on LANDING without assets, so their presence fail-closes to an
    /// initial-destination-only snapshot (`allow_destination_rewrites = false`).
    #[must_use]
    pub fn seal_handoff_xudp_policy(
        &self,
        user_id: UserId,
        handoff_outbound: &str,
        initial_destination: Destination,
    ) -> HandoffPolicySnapshot {
        let Some(user) = self.users.get(&user_id) else {
            return HandoffPolicySnapshot::xudp_initial(initial_destination);
        };
        let mut sealed = Vec::new();
        for rule in self.global_rules.iter().chain(user.rules.iter()) {
            match seal_compiled_rule(rule, handoff_outbound) {
                Ok(None) => {}
                Ok(Some(sealed_rule)) => {
                    if sealed.len() >= MAX_SEALED_HANDOFF_RULES {
                        return HandoffPolicySnapshot::xudp_initial(initial_destination);
                    }
                    sealed.push(sealed_rule);
                }
                Err(()) => {
                    // Non-sealable matcher: do not silently widen authority.
                    return HandoffPolicySnapshot::xudp_initial(initial_destination);
                }
            }
        }
        let default_allow = user.default_outbound.as_ref() == handoff_outbound;
        HandoffPolicySnapshot::xudp_with_sealed_rules(initial_destination, sealed, default_allow)
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
            return rule.decision(RouteScope::Policy);
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
            RouteScope::Policy,
            pending,
        ) {
            return Some((rule, RouteScope::Policy));
        }
        None
    }

    /// Resolves a domain destination for UDP egress after routing has already
    /// decided without DNS (`asIs`, a domain rule matched first, or no IP
    /// rules). UDP sockets and the NXR / Handoff landward contracts carry
    /// addresses only, so XUDP must resolve on LINE once the route is known.
    /// The route decision itself is unchanged.
    ///
    /// # Errors
    ///
    /// Returns a bounded DNS error when resolution cannot complete safely.
    pub async fn resolve_udp_egress(
        &self,
        destination: &Destination,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, RouteResolutionError> {
        resolve_domain(&self.dns_governor, destination, timeout).await
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
        strategy: DomainStrategy,
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
            || strategy == DomainStrategy::AsIs
            || !needs_ip
        {
            return Ok(ResolvedRoute::new(
                self.select_for_user(&unresolved, domain.as_deref(), user),
                Vec::new(),
            ));
        }

        if strategy == DomainStrategy::ResolveIfNoMatch {
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
    fn compile(
        name: &str,
        default_outbound: &str,
        rule_list: &[RouteRule],
    ) -> Result<Self, RoutingCompileError> {
        let rules = compile_rules(rule_list, name)?;
        let index = RuleIndex::build(&rules);
        let has_ip_rules = rules.iter().any(|rule| !rule.ips.is_empty());
        Ok(Self {
            name: Arc::from(name),
            default_outbound: Arc::from(default_outbound),
            rules,
            index,
            has_ip_rules,
        })
    }

    fn default_decision(&self) -> RouteDecision {
        RouteDecision {
            outbound: Arc::clone(&self.default_outbound),
            rule_name: Arc::clone(&self.name),
            scope: RouteScope::DefaultOutbound,
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
        let (chunks, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks {
            self.add(u64::from_le_bytes(*chunk));
        }
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
}

/// Compiles an ordered rule list, labelling each rule by position when the
/// operator did not name it.
fn compile_rules(
    rules: &[RouteRule],
    label: &str,
) -> Result<Arc<[CompiledRule]>, RoutingCompileError> {
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| CompiledRule::compile(rule, &format!("{label}[{index}]")))
        .collect::<Result<Vec<_>, _>>()
        .map(Into::into)
}

impl CompiledRule {
    fn compile(rule: &RouteRule, label: &str) -> Result<Self, RoutingCompileError> {
        let domains: Arc<[DomainMatcher]> = rule
            .domain()
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
            name: Arc::from(rule.name.as_deref().unwrap_or(label)),
            outbound: Arc::from(rule.outbound.as_str()),
            domains,
            residual_domains,
            ips: rule
                .ip()
                .iter()
                .map(|matcher| IpMatcher::compile(matcher))
                .collect::<Result<Vec<_>, _>>()?
                .into(),
            ports: rule
                .port()
                .iter()
                .map(|matcher| PortRange::compile(matcher))
                .collect::<Result<Vec<_>, _>>()?
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

    /// The port group; never consults `resolved_ips`.
    ///
    /// This used to also test a network group and an inbound-tag group. Both
    /// were always true — every flow is TCP, and a node has one identity — so
    /// the conditions that fed them no longer exist and neither do the tests.
    fn static_groups_match(&self, context: &RouteContext<'_>) -> bool {
        self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|range| range.contains(context.destination.port()))
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

/// Attempts to seal one compiled rule for Handoff LANDING evaluation.
///
/// Returns `Ok(None)` for rules that are vacuous after filtering (should not happen),
/// `Ok(Some(rule))` when every matcher is sealable, and `Err(())` when any matcher
/// requires runtime assets or regexp evaluation.
fn seal_compiled_rule(
    rule: &CompiledRule,
    handoff_outbound: &str,
) -> Result<Option<SealedHandoffRouteRule>, ()> {
    let mut domains = Vec::with_capacity(rule.domains.len());
    for matcher in rule.domains.iter() {
        domains.push(seal_domain_matcher(matcher)?);
    }
    let mut ips = Vec::with_capacity(rule.ips.len());
    for matcher in rule.ips.iter() {
        ips.push(seal_ip_matcher(matcher)?);
    }
    let ports = rule
        .ports
        .iter()
        .map(|range| SealedPortRange {
            start: range.start,
            end: range.end,
        })
        .collect();
    Ok(Some(SealedHandoffRouteRule {
        allow: rule.outbound.as_ref() == handoff_outbound,
        domains,
        ips,
        ports,
    }))
}

fn seal_domain_matcher(matcher: &DomainMatcher) -> Result<SealedDomainMatcher, ()> {
    match matcher {
        DomainMatcher::Full(value) => Ok(SealedDomainMatcher::Full(value.to_string())),
        DomainMatcher::Suffix(value) => Ok(SealedDomainMatcher::Suffix(value.to_string())),
        DomainMatcher::Keyword(value) => Ok(SealedDomainMatcher::Keyword(value.to_string())),
        DomainMatcher::Regex(_) | DomainMatcher::Asset { .. } => Err(()),
    }
}

fn seal_ip_matcher(matcher: &IpMatcher) -> Result<SealedIpNetwork, ()> {
    match matcher {
        IpMatcher::Network(IpNetwork::V4 { network, prefix }) => Ok(SealedIpNetwork::V4 {
            network: *network,
            prefix: *prefix,
        }),
        IpMatcher::Network(IpNetwork::V6 { network, prefix }) => Ok(SealedIpNetwork::V6 {
            network: *network,
            prefix: *prefix,
        }),
        IpMatcher::Asset { .. } => Err(()),
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
    /// A user names a routing policy that is not declared. Semantic validation
    /// rejects this first; reaching it here means compilation ran on a node
    /// that was never validated.
    UnknownPolicy,
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
            Self::UnknownPolicy => {
                formatter.write_str("a user names a routing policy that is not declared")
            }
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
mod tests;
