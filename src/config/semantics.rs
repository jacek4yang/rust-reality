//! Semantic validation: does this well-formed node describe a server that can
//! actually run?
//!
//! [`crate::config::parse`] has already decided that the document is a node of
//! a known role with no unknown fields. What is left is everything the shape
//! cannot express on its own — that references resolve, that keys decode, that
//! bounds are coherent, that no two listeners want the same socket, that no
//! two secrets are the same secret.
//!
//! This stays offline. It resolves no name, opens no socket, and reads no
//! file, because `rust-reality check` promises exactly that and an operator
//! validating a configuration for another host must get the same answer as one
//! validating it in place.
//!
//! Numeric limits are checked only where the operator pinned them. An unpinned
//! limit is derived from the detected machine, which is a runtime fact rather
//! than a configuration one; relations between a pinned value and a derived one
//! belong to the effective-policy compile, not here.

use std::{collections::BTreeMap, collections::HashSet, error::Error, fmt};

use zeroize::Zeroizing;

use super::{
    node::{
        DomainStrategy, EntryConfig, LandingConfig, LandingProtocol, NodeConfig, OutboundConfig,
        Role, RoutePolicy, RouteRule, RoutingConfig,
        dns::DnsConfig,
        listener::ListenerConfig,
        log::{LogConfig, LogOutput},
        outbound::{BUILTIN_OUTBOUNDS, is_builtin_outbound},
        runtime::{LimitOverrides, RuntimeConfig},
    },
    secret::SecretString,
    syntax,
};

/// Largest accepted value for any configured deadline, in milliseconds.
const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1_000;

/// Largest accepted clock-skew tolerance, in seconds.
const MAX_TIME_DIFFERENCE_SECONDS: u64 = 300;

/// Bounds on file-log rotation.
const MIN_LOG_FILE_BYTES: u64 = 64 * 1024;
const MAX_LOG_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LOG_FILES: u16 = 64;

/// Bounds on the DNS cache.
const MAX_DNS_CACHE_ENTRIES: u32 = 65_536;
const MAX_DNS_TTL_SECONDS: u32 = 86_400;
const MAX_DNS_SYSTEM_REUSE_MS: u64 = 60_000;

/// Smallest useful Handoff first-downlink-byte deadline, in milliseconds.
const MIN_HANDOFF_FIRST_BYTE_TIMEOUT_MS: u64 = 1_000;

/// Largest number of retired keys accepted during one rotation window.
const MAX_PREVIOUS_KEYS: usize = 2;

/// One semantic failure, located by configuration path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticError {
    path: String,
    message: String,
}

impl SemanticError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// The configuration path of the offending value.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What the value must satisfy.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.message)
    }
}

impl Error for SemanticError {}

fn fail<T>(path: impl Into<String>, message: impl Into<String>) -> Result<T, SemanticError> {
    Err(SemanticError::new(path, message))
}

/// A node that has passed semantic validation.
///
/// The only way to build one is [`validate`], so a function taking a
/// `ValidatedConfig` cannot be handed a configuration nobody checked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConfig(NodeConfig);

impl ValidatedConfig {
    /// The validated node.
    #[must_use]
    pub fn node(&self) -> &NodeConfig {
        &self.0
    }

    /// The role this node performs.
    #[must_use]
    pub fn role(&self) -> Role {
        self.0.role()
    }

    /// Consumes the wrapper and returns the node.
    #[must_use]
    pub fn into_node(self) -> NodeConfig {
        self.0
    }
}

/// Validates one parsed node.
///
/// # Errors
///
/// Returns the first failure, identified by configuration path.
pub fn validate(node: NodeConfig) -> Result<ValidatedConfig, SemanticError> {
    match &node {
        NodeConfig::Entry(entry) => validate_entry(entry)?,
        NodeConfig::Landing(landing) => validate_landing(landing)?,
    }
    Ok(ValidatedConfig(node))
}

// ---------------------------------------------------------------- entry role

fn validate_entry(entry: &EntryConfig) -> Result<(), SemanticError> {
    validate_listeners(&entry.listeners)?;
    validate_reality(entry)?;
    let outbounds = validate_outbounds(entry.outbounds.as_ref())?;
    validate_users(entry)?;
    validate_routing(&entry.routing, &outbounds)?;
    validate_assets(entry)?;
    validate_dns(entry.dns.as_ref())?;
    validate_log(entry.log.as_ref())?;
    validate_runtime(entry.runtime.as_ref())?;
    validate_key_independence(entry_key_material(entry))
}

fn validate_reality(entry: &EntryConfig) -> Result<(), SemanticError> {
    let reality = &entry.reality;
    if let Err(rule) = syntax::check_endpoint(&reality.cover) {
        return fail("reality.cover", rule);
    }
    if syntax::decode_key(reality.private_key.expose()).is_none() {
        return fail("reality.privateKey", syntax::KEY_RULE);
    }

    match &reality.server_names {
        Some(names) => {
            if names.is_empty() {
                return fail(
                    "reality.serverNames",
                    "must contain at least one name, or be omitted to accept the cover host",
                );
            }
            let mut seen = HashSet::new();
            for (index, name) in names.iter().enumerate() {
                let path = format!("reality.serverNames[{index}]");
                if !crate::server_name::is_server_name_pattern(name) {
                    return fail(
                        path,
                        "must be an ASCII DNS name or a leftmost single-label wildcard such as *.example.com",
                    );
                }
                if !seen.insert(name.to_ascii_lowercase()) {
                    return fail(path, "name is listed more than once");
                }
            }
        }
        None => {
            // The cover host becomes the accepted name, so it has to be one.
            let host = reality
                .cover_host()
                .ok_or_else(|| SemanticError::new("reality.cover", "must be host:port"))?;
            if !crate::server_name::is_server_name_pattern(host) {
                return fail(
                    "reality.cover",
                    "host is not a DNS name, so `reality.serverNames` must state the names clients send",
                );
            }
        }
    }

    if reality.max_time_diff_ms() > MAX_TIMEOUT_MS {
        return fail(
            "reality.maxTimeDiffMs",
            format!("must not exceed {MAX_TIMEOUT_MS}"),
        );
    }
    Ok(())
}

fn validate_users(entry: &EntryConfig) -> Result<(), SemanticError> {
    if entry.users.is_empty() {
        return fail("users", "must contain at least one client identity");
    }
    let mut identities = HashSet::new();
    let mut short_ids = HashSet::new();
    for (index, user) in entry.users.iter().enumerate() {
        let path = format!("users[{index}]");
        if !syntax::is_uuid(&user.id) {
            return fail(
                format!("{path}.id"),
                "must be a canonical hyphenated UUID from `rust-reality generate uuid`",
            );
        }
        if !identities.insert(user.id.to_ascii_lowercase()) {
            return fail(
                format!("{path}.id"),
                "identity is configured more than once",
            );
        }
        if user.short_ids.is_empty() {
            return fail(
                format!("{path}.shortIds"),
                "must contain at least one short ID owned by this identity",
            );
        }
        for (short_index, short_id) in user.short_ids.iter().enumerate() {
            let short_path = format!("{path}.shortIds[{short_index}]");
            if !syntax::is_short_id(short_id) {
                return fail(
                    short_path,
                    "must be 2 to 16 hexadecimal characters, an even number of them",
                );
            }
            if !short_ids.insert(short_id.to_ascii_lowercase()) {
                return fail(short_path, "short ID is already owned by another identity");
            }
        }
        if let Some(policy) = &user.policy
            && !entry.routing.has_policy(policy)
        {
            return fail(
                format!("{path}.policy"),
                format!("no routing policy named `{policy}` is declared"),
            );
        }
    }
    Ok(())
}

fn validate_routing(
    routing: &RoutingConfig,
    outbounds: &OutboundNames,
) -> Result<(), SemanticError> {
    outbounds.check(&routing.default, "routing.default")?;
    for (index, rule) in routing.rules().iter().enumerate() {
        validate_rule(&format!("routing.rules[{index}]"), rule, outbounds)?;
    }
    for (name, policy) in routing.policies() {
        let path = format!("routing.policies.{name}");
        if name.trim().is_empty() {
            return fail("routing.policies", "a policy name must not be empty");
        }
        validate_policy(&path, policy, outbounds)?;
    }
    // Every strategy is implementable; naming it here keeps the match
    // exhaustive so a new strategy cannot be added without a decision.
    match routing.strategy() {
        DomainStrategy::AsIs
        | DomainStrategy::ResolveIfNoMatch
        | DomainStrategy::ResolveOnDemand => {}
    }
    Ok(())
}

fn validate_policy(
    path: &str,
    policy: &RoutePolicy,
    outbounds: &OutboundNames,
) -> Result<(), SemanticError> {
    outbounds.check(&policy.default, &format!("{path}.default"))?;
    for (index, rule) in policy.rules().iter().enumerate() {
        validate_rule(&format!("{path}.rules[{index}]"), rule, outbounds)?;
    }
    Ok(())
}

fn validate_rule(
    path: &str,
    rule: &RouteRule,
    outbounds: &OutboundNames,
) -> Result<(), SemanticError> {
    if let Some(name) = &rule.name
        && name.trim().is_empty()
    {
        return fail(format!("{path}.name"), "must not be empty");
    }
    if !rule.has_condition() {
        return fail(
            path,
            "must state at least one condition, or it would shadow every rule after it",
        );
    }
    outbounds.check(&rule.outbound, &format!("{path}.outbound"))?;
    for (index, matcher) in rule.domain().iter().enumerate() {
        if let Err(rule) = syntax::check_domain_matcher(matcher) {
            return fail(format!("{path}.domain[{index}]"), rule);
        }
    }
    for (index, matcher) in rule.ip().iter().enumerate() {
        if let Err(rule) = syntax::check_ip_matcher(matcher) {
            return fail(format!("{path}.ip[{index}]"), rule);
        }
    }
    for (index, matcher) in rule.port().iter().enumerate() {
        if let Err(rule) = syntax::check_port_matcher(matcher) {
            return fail(format!("{path}.port[{index}]"), rule);
        }
    }
    Ok(())
}

fn validate_assets(entry: &EntryConfig) -> Result<(), SemanticError> {
    let Some(assets) = &entry.assets else {
        return Ok(());
    };
    if let Some(url) = &assets.geoip
        && let Err(rule) = syntax::check_asset_url(url)
    {
        return fail("assets.geoip", rule);
    }
    if let Some(url) = &assets.geosite
        && let Err(rule) = syntax::check_asset_url(url)
    {
        return fail("assets.geosite", rule);
    }
    if assets.reload_interval_seconds() == 0 {
        return fail(
            "assets.reloadIntervalSeconds",
            "must be greater than zero; omit the field to poll once a day",
        );
    }
    Ok(())
}

// -------------------------------------------------------------- landing role

fn validate_landing(landing: &LandingConfig) -> Result<(), SemanticError> {
    validate_listeners(&landing.listeners)?;
    let outbounds = validate_outbounds(landing.outbounds.as_ref())?;
    validate_landing_protocol(&landing.landing)?;
    validate_egress(landing, &outbounds)?;
    validate_dns(landing.dns.as_ref())?;
    validate_log(landing.log.as_ref())?;
    validate_runtime(landing.runtime.as_ref())?;
    validate_key_independence(landing_key_material(landing))
}

fn validate_landing_protocol(protocol: &LandingProtocol) -> Result<(), SemanticError> {
    if syntax::decode_key(protocol.psk().expose()).is_none() {
        return fail("landing.psk", syntax::KEY_RULE);
    }
    if let LandingProtocol::Handoff(settings) = protocol {
        if syntax::decode_key(settings.private_key.expose()).is_none() {
            return fail("landing.privateKey", syntax::KEY_RULE);
        }
        validate_previous_keys(
            "landing.previousPsks",
            settings.previous_psks(),
            &settings.psk,
        )?;
        validate_previous_keys(
            "landing.previousPrivateKeys",
            settings.previous_private_keys(),
            &settings.private_key,
        )?;
    }

    let timing = protocol.timing();
    if !(1..=MAX_TIME_DIFFERENCE_SECONDS).contains(&timing.max_time_difference_seconds) {
        return fail(
            "landing.maxTimeDifferenceSeconds",
            format!("must be between 1 and {MAX_TIME_DIFFERENCE_SECONDS}"),
        );
    }
    for (field, value) in [
        ("preAuthIdleTimeoutMs", timing.pre_auth_idle_timeout_ms),
        ("authenticationTimeoutMs", timing.authentication_timeout_ms),
        ("connectTimeoutMs", timing.connect_timeout_ms),
    ] {
        check_timeout(&format!("landing.{field}"), value)?;
    }
    Ok(())
}

fn validate_previous_keys(
    path: &str,
    previous: &[SecretString],
    active: &SecretString,
) -> Result<(), SemanticError> {
    if previous.len() > MAX_PREVIOUS_KEYS {
        return fail(
            path,
            format!("must not accept more than {MAX_PREVIOUS_KEYS} retired keys at once"),
        );
    }
    let mut seen = Vec::with_capacity(previous.len());
    for (index, key) in previous.iter().enumerate() {
        let path = format!("{path}[{index}]");
        let Some(decoded) = syntax::decode_key(key.expose()) else {
            return fail(path, syntax::KEY_RULE);
        };
        if key.expose() == active.expose() {
            return fail(
                path,
                "is the active key; a retired key must be one that was replaced",
            );
        }
        if seen.contains(&decoded) {
            return fail(path, "is listed more than once");
        }
        seen.push(decoded);
    }
    Ok(())
}

fn validate_egress(
    landing: &LandingConfig,
    outbounds: &OutboundNames,
) -> Result<(), SemanticError> {
    let egress = landing.egress();
    outbounds.check(egress, "egress")?;
    if let Some(declared) = outbounds.declared.get(egress)
        && matches!(declared, OutboundConfig::Handoff(_))
    {
        return fail(
            "egress",
            "must not be a handoff outbound: a landing node does not transfer to another landing",
        );
    }
    Ok(())
}

// ------------------------------------------------------------ shared sections

fn validate_listeners(listeners: &[ListenerConfig]) -> Result<(), SemanticError> {
    if listeners.is_empty() {
        return fail("listeners", "must contain at least one endpoint");
    }
    let mut bound = HashSet::new();
    for (index, listener) in listeners.iter().enumerate() {
        let path = format!("listeners[{index}]");
        if listener.port == 0 {
            return fail(format!("{path}.port"), "must be greater than zero");
        }
        for address in listener.bind_addresses() {
            if !bound.insert(address) {
                return fail(
                    format!("{path}.port"),
                    format!("{address} is already bound by an earlier listener"),
                );
            }
        }
    }
    Ok(())
}

/// The outbound names a reference may resolve to.
struct OutboundNames<'a> {
    declared: &'a BTreeMap<String, OutboundConfig>,
}

impl OutboundNames<'_> {
    fn check(&self, name: &str, path: &str) -> Result<(), SemanticError> {
        if is_builtin_outbound(name) || self.declared.contains_key(name) {
            return Ok(());
        }
        let mut known: Vec<&str> = BUILTIN_OUTBOUNDS.to_vec();
        known.extend(self.declared.keys().map(String::as_str));
        fail(
            path,
            format!(
                "no outbound named `{name}`; known outbounds are {}",
                known.join(", ")
            ),
        )
    }
}

/// An empty declaration set, so a node with no `outbounds` still resolves the
/// built-in names.
static NO_OUTBOUNDS: std::sync::LazyLock<BTreeMap<String, OutboundConfig>> =
    std::sync::LazyLock::new(BTreeMap::new);

fn validate_outbounds(
    declared: Option<&BTreeMap<String, OutboundConfig>>,
) -> Result<OutboundNames<'_>, SemanticError> {
    let declared = declared.unwrap_or(&NO_OUTBOUNDS);
    for (name, outbound) in declared {
        let path = format!("outbounds.{name}");
        if name.trim().is_empty() {
            return fail("outbounds", "an outbound name must not be empty");
        }
        if is_builtin_outbound(name) {
            return fail(
                path,
                format!("`{name}` is built in and always available; choose another name"),
            );
        }
        validate_outbound(&path, outbound)?;
    }
    Ok(OutboundNames { declared })
}

fn validate_outbound(path: &str, outbound: &OutboundConfig) -> Result<(), SemanticError> {
    if !syntax::is_hostname_or_ip(outbound.address()) {
        return fail(
            format!("{path}.address"),
            "must be a valid ASCII DNS name or IP address",
        );
    }
    if outbound.port() == 0 {
        return fail(format!("{path}.port"), "must be greater than zero");
    }

    match outbound {
        OutboundConfig::Socks5(settings) => {
            if settings.username.is_some() != settings.password.is_some() {
                return fail(
                    path,
                    "username and password must either both be present or both be absent",
                );
            }
            for (field, value) in [
                ("username", settings.username.as_ref()),
                ("password", settings.password.as_ref()),
            ] {
                let Some(value) = value else { continue };
                if value.is_empty() {
                    return fail(format!("{path}.{field}"), "must not be empty");
                }
                if value.expose().len() > usize::from(u8::MAX) {
                    return fail(
                        format!("{path}.{field}"),
                        "must not exceed 255 bytes, which is what SOCKS5 can carry",
                    );
                }
            }
        }
        OutboundConfig::Nxr(settings) => {
            if syntax::decode_key(settings.psk.expose()).is_none() {
                return fail(format!("{path}.psk"), syntax::KEY_RULE);
            }
        }
        OutboundConfig::Handoff(settings) => {
            if syntax::decode_key(settings.psk.expose()).is_none() {
                return fail(format!("{path}.psk"), syntax::KEY_RULE);
            }
            if syntax::decode_key(&settings.landing_public_key).is_none() {
                return fail(format!("{path}.landingPublicKey"), syntax::KEY_RULE);
            }
            check_timeout(
                &format!("{path}.connectTimeoutMs"),
                settings.connect_timeout_ms(),
            )?;
            let first_byte = settings.first_byte_timeout_ms();
            if !(MIN_HANDOFF_FIRST_BYTE_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&first_byte) {
                return fail(
                    format!("{path}.firstByteTimeoutMs"),
                    format!(
                        "must be between {MIN_HANDOFF_FIRST_BYTE_TIMEOUT_MS} and {MAX_TIMEOUT_MS}"
                    ),
                );
            }
            if first_byte <= settings.connect_timeout_ms() {
                return fail(
                    format!("{path}.firstByteTimeoutMs"),
                    "must exceed connectTimeoutMs: the landing answers only after it has read, authenticated, and dialled",
                );
            }
        }
    }
    Ok(())
}

fn validate_dns(dns: Option<&DnsConfig>) -> Result<(), SemanticError> {
    let Some(dns) = dns else { return Ok(()) };
    if let Some(servers) = &dns.servers {
        if servers.is_empty() {
            return fail(
                "dns.servers",
                "must contain at least one resolver, or be omitted to use the system resolver",
            );
        }
        let uses_system = servers
            .iter()
            .any(|server| server == super::node::dns::SYSTEM_RESOLVER);
        if uses_system && servers.len() > 1 {
            return fail(
                "dns.servers",
                "`system` selects the operating system resolver and cannot be combined with others",
            );
        }
        if !uses_system {
            for (index, server) in servers.iter().enumerate() {
                let path = format!("dns.servers[{index}]");
                // A bare address is allowed; a port makes it an endpoint.
                if server.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                if let Err(rule) = syntax::check_endpoint(server)
                    && !syntax::is_hostname(server)
                {
                    return fail(path, rule);
                }
            }
        }
    }
    check_timeout("dns.timeoutMs", dns.timeout_ms())?;

    let Some(cache) = &dns.cache else {
        return Ok(());
    };
    if let Some(entries) = cache.max_entries
        && !(1..=MAX_DNS_CACHE_ENTRIES).contains(&entries)
    {
        return fail(
            "dns.cache.maxEntries",
            format!("must be between 1 and {MAX_DNS_CACHE_ENTRIES}"),
        );
    }
    for (field, value) in [
        ("minTtlSeconds", cache.min_ttl_seconds()),
        ("maxTtlSeconds", cache.max_ttl_seconds()),
        ("negativeTtlSeconds", cache.negative_ttl_seconds()),
        ("staticTtlSeconds", cache.static_ttl_seconds()),
    ] {
        if value > MAX_DNS_TTL_SECONDS {
            return fail(
                format!("dns.cache.{field}"),
                format!("must not exceed {MAX_DNS_TTL_SECONDS}"),
            );
        }
    }
    if cache.min_ttl_seconds() > cache.max_ttl_seconds() {
        return fail(
            "dns.cache.minTtlSeconds",
            "must not exceed dns.cache.maxTtlSeconds",
        );
    }
    if cache.system_reuse_ms() > MAX_DNS_SYSTEM_REUSE_MS {
        return fail(
            "dns.cache.systemReuseMs",
            format!("must not exceed {MAX_DNS_SYSTEM_REUSE_MS}"),
        );
    }
    Ok(())
}

fn validate_log(log: Option<&LogConfig>) -> Result<(), SemanticError> {
    let Some(log) = log else { return Ok(()) };
    match (log.output(), &log.file) {
        (LogOutput::File, None) => {
            return fail("log.file", "is required when `log.output` is `file`");
        }
        (output, Some(_)) if output != LogOutput::File => {
            return fail(
                "log.file",
                format!(
                    "is meaningful only with `log.output` set to `file`, but the output is `{}`",
                    output.as_str()
                ),
            );
        }
        _ => {}
    }

    let Some(file) = &log.file else {
        return Ok(());
    };
    if file.path.as_os_str().is_empty() {
        return fail("log.file.path", "must not be empty");
    }
    if !(MIN_LOG_FILE_BYTES..=MAX_LOG_FILE_BYTES).contains(&file.max_bytes()) {
        return fail(
            "log.file.maxBytes",
            format!("must be between {MIN_LOG_FILE_BYTES} and {MAX_LOG_FILE_BYTES}"),
        );
    }
    if !(1..=MAX_LOG_FILES).contains(&file.max_files()) {
        return fail(
            "log.file.maxFiles",
            format!("must be between 1 and {MAX_LOG_FILES}"),
        );
    }
    if file.max_total_bytes() < file.max_bytes() {
        return fail(
            "log.file.maxTotalBytes",
            "must be at least log.file.maxBytes, or one file could not be filled",
        );
    }
    Ok(())
}

fn validate_runtime(runtime: Option<&RuntimeConfig>) -> Result<(), SemanticError> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    if runtime.tuning() != super::node::runtime::TuningMode::Adaptive
        && runtime.status_file.is_some()
    {
        return fail(
            "runtime.statusFile",
            "is published only in `adaptive` tuning mode; remove it or set `runtime.tuning` to `adaptive`",
        );
    }
    validate_limits(&runtime.limits())
}

fn validate_limits(limits: &LimitOverrides) -> Result<(), SemanticError> {
    for (field, value) in [
        ("maxConnections", limits.max_connections),
        ("maxHandshakes", limits.max_handshakes),
    ] {
        if let Some(value) = value
            && value == 0
        {
            return fail(
                format!("runtime.limits.{field}"),
                "must be greater than zero; omit it to derive from the machine",
            );
        }
    }
    for (field, value) in [
        ("clientHelloTimeoutMs", limits.client_hello_timeout_ms),
        ("handshakeTimeoutMs", limits.handshake_timeout_ms),
        ("connectTimeoutMs", limits.connect_timeout_ms),
        ("fallbackTimeoutMs", limits.fallback_timeout_ms),
    ] {
        if let Some(value) = value {
            check_timeout(&format!("runtime.limits.{field}"), value)?;
        }
    }
    // Relations hold only where the operator pinned both sides. A pin against
    // a derived value is settled when the effective policy is compiled, which
    // is the only place the derived value exists.
    if let (Some(handshakes), Some(connections)) = (limits.max_handshakes, limits.max_connections)
        && handshakes > connections
    {
        return fail(
            "runtime.limits.maxHandshakes",
            "must not exceed runtime.limits.maxConnections",
        );
    }
    if let (Some(hello), Some(handshake)) =
        (limits.client_hello_timeout_ms, limits.handshake_timeout_ms)
        && hello > handshake
    {
        return fail(
            "runtime.limits.clientHelloTimeoutMs",
            "must not exceed runtime.limits.handshakeTimeoutMs",
        );
    }
    if let (Some(connect), Some(fallback)) = (limits.connect_timeout_ms, limits.fallback_timeout_ms)
        && connect > fallback
    {
        return fail(
            "runtime.limits.connectTimeoutMs",
            "must not exceed runtime.limits.fallbackTimeoutMs",
        );
    }
    if limits.pipe_pool == Some(true) && limits.splice == Some(false) {
        return fail(
            "runtime.limits.pipePool",
            "pools splice pipes, so it cannot be enabled while `splice` is disabled",
        );
    }
    Ok(())
}

fn check_timeout(path: &str, value: u64) -> Result<(), SemanticError> {
    if !(1..=MAX_TIMEOUT_MS).contains(&value) {
        return fail(path, format!("must be between 1 and {MAX_TIMEOUT_MS}"));
    }
    Ok(())
}

// ------------------------------------------------------------ key separation

/// One key found in the file, with the path that declared it.
type KeyMaterial = (String, Zeroizing<Vec<u8>>);

/// Rejects two configuration values that carry the same key material.
///
/// Every key in a deployment is meant to be generated independently. Reuse
/// inside one file is the copy-paste mistake an operator actually makes, and
/// it is cheap to catch here; reuse *across* nodes stays the operator's
/// obligation because no single file can see it.
///
/// A landing's public key is compared too. It can never equal a private key by
/// chance, so a match means the wrong half of a key pair was pasted — which is
/// worth catching loudly.
fn validate_key_independence(material: Vec<KeyMaterial>) -> Result<(), SemanticError> {
    for (index, (path, key)) in material.iter().enumerate() {
        if let Some((earlier, _)) = material[..index].iter().find(|(_, other)| other == key) {
            return fail(
                path.clone(),
                format!(
                    "carries the same key material as `{earlier}`; every key must be generated independently"
                ),
            );
        }
    }
    Ok(())
}

fn entry_key_material(entry: &EntryConfig) -> Vec<KeyMaterial> {
    let mut material = Vec::new();
    push_key(
        &mut material,
        "reality.privateKey",
        entry.reality.private_key.expose(),
    );
    push_outbound_keys(&mut material, entry.outbounds.as_ref());
    material
}

fn landing_key_material(landing: &LandingConfig) -> Vec<KeyMaterial> {
    let mut material = Vec::new();
    push_key(&mut material, "landing.psk", landing.landing.psk().expose());
    if let LandingProtocol::Handoff(settings) = &landing.landing {
        push_key(
            &mut material,
            "landing.privateKey",
            settings.private_key.expose(),
        );
        for (index, key) in settings.previous_psks().iter().enumerate() {
            push_key(
                &mut material,
                &format!("landing.previousPsks[{index}]"),
                key.expose(),
            );
        }
        for (index, key) in settings.previous_private_keys().iter().enumerate() {
            push_key(
                &mut material,
                &format!("landing.previousPrivateKeys[{index}]"),
                key.expose(),
            );
        }
    }
    push_outbound_keys(&mut material, landing.outbounds.as_ref());
    material
}

fn push_outbound_keys(
    material: &mut Vec<KeyMaterial>,
    outbounds: Option<&BTreeMap<String, OutboundConfig>>,
) {
    for (name, outbound) in outbounds.into_iter().flatten() {
        match outbound {
            OutboundConfig::Socks5(_) => {}
            OutboundConfig::Nxr(settings) => {
                push_key(
                    material,
                    &format!("outbounds.{name}.psk"),
                    settings.psk.expose(),
                );
            }
            OutboundConfig::Handoff(settings) => {
                push_key(
                    material,
                    &format!("outbounds.{name}.psk"),
                    settings.psk.expose(),
                );
                push_key(
                    material,
                    &format!("outbounds.{name}.landingPublicKey"),
                    &settings.landing_public_key,
                );
            }
        }
    }
}

fn push_key(material: &mut Vec<KeyMaterial>, path: &str, encoded: &str) {
    if let Some(decoded) = syntax::decode_key(encoded) {
        material.push((path.to_owned(), decoded));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    use super::{ValidatedConfig, validate};
    use crate::config::parse::parse_bytes;

    /// A distinct, well-formed 32-byte key, so tests never collide by accident.
    fn key(seed: u8) -> String {
        BASE64_URL_SAFE_NO_PAD.encode([seed; 32])
    }

    fn entry_json(body: &str) -> String {
        format!(
            r#"{{
              "role": "entry",
              "listeners": [{{ "port": 443 }}],
              "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
              "users": [{{ "id": "11111111-1111-4111-8111-111111111111",
                           "shortIds": ["ab"] }}],
              "routing": {{ "default": "direct" }}
              {body}
            }}"#,
            key(1)
        )
    }

    fn landing_json(body: &str) -> String {
        format!(
            r#"{{
              "role": "landing",
              "listeners": [{{ "port": 7443 }}],
              "landing": {{ "protocol": "handoff", "psk": "{}", "privateKey": "{}" }}
              {body}
            }}"#,
            key(2),
            key(3)
        )
    }

    fn check(json: &str) -> Result<ValidatedConfig, super::SemanticError> {
        let node = parse_bytes(Path::new("config.json"), json.as_bytes())
            .unwrap_or_else(|error| panic!("must parse before it can be validated: {error}"));
        validate(node)
    }

    fn accept(json: &str) -> ValidatedConfig {
        check(json).unwrap_or_else(|error| panic!("must validate: {error}"))
    }

    fn reject(json: &str) -> super::SemanticError {
        check(json).expect_err("must not validate")
    }

    // ------------------------------------------------------------- acceptance

    #[test]
    fn a_minimal_standalone_node_validates() {
        let validated = accept(&entry_json(""));

        assert_eq!(validated.role(), crate::config::node::Role::Entry);
    }

    #[test]
    fn a_minimal_landing_validates() {
        accept(&landing_json(""));
    }

    #[test]
    fn a_line_node_with_a_handoff_landing_validates() {
        accept(&format!(
            r#"{{
              "role": "entry",
              "listeners": [{{ "port": 443 }}],
              "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
              "users": [{{ "id": "11111111-1111-4111-8111-111111111111",
                           "shortIds": ["ab"], "policy": "split" }}],
              "outbounds": {{ "landing-1": {{ "type": "handoff", "address": "10.0.0.2",
                              "port": 7443, "psk": "{}", "landingPublicKey": "{}" }} }},
              "routing": {{
                "default": "landing-1",
                "rules": [{{ "ip": ["geoip:private"], "outbound": "block" }}],
                "policies": {{ "split": {{ "default": "landing-1",
                  "rules": [{{ "domain": ["geosite:cn"], "outbound": "direct" }}] }} }}
              }}
            }}"#,
            key(1),
            key(2),
            key(3)
        ));
    }

    // -------------------------------------------------------------- listeners

    #[test]
    fn two_listeners_may_share_a_family_but_not_a_socket() {
        accept(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}},{{"port":8443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
            key(1)
        ));

        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}},{{"port":443,"ip":"ipv4Only"}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
            key(1)
        ));
        assert_eq!(error.path(), "listeners[1].port");
        assert!(error.message().contains("already bound"), "{error}");
    }

    #[test]
    fn port_zero_is_refused() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":0}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "listeners[0].port");
    }

    // ---------------------------------------------------------------- reality

    #[test]
    fn the_cover_must_carry_a_port() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "reality.cover");
        assert!(error.message().contains("host:port"), "{error}");
    }

    #[test]
    fn a_malformed_private_key_states_the_rule_without_echoing_the_value() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
            BASE64_URL_SAFE_NO_PAD.encode([9u8; 31])
        ));

        assert_eq!(error.path(), "reality.privateKey");
        assert!(error.message().contains("32 bytes"), "{error}");
        assert!(
            !error
                .message()
                .contains(&BASE64_URL_SAFE_NO_PAD.encode([9u8; 31])),
            "a diagnostic must never echo key material"
        );
    }

    #[test]
    fn an_ip_cover_requires_explicit_server_names() {
        let ip_cover = |names: &str| {
            format!(
                r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"93.184.216.34:443","privateKey":"{}"{names}}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "routing":{{"default":"direct"}}}}"#,
                key(1)
            )
        };

        let error = reject(&ip_cover(""));
        assert_eq!(error.path(), "reality.cover");
        assert!(error.message().contains("serverNames"), "{error}");

        accept(&ip_cover(r#","serverNames":["www.example.com"]"#));
    }

    #[test]
    fn server_names_reject_unsafe_patterns_and_repeats() {
        let with_names = |names: &str| {
            format!(
                r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}",
                                 "serverNames":{names}}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "routing":{{"default":"direct"}}}}"#,
                key(1)
            )
        };

        accept(&with_names(r#"["www.example.com","*.example.com"]"#));
        assert_eq!(
            reject(&with_names(r#"["*"]"#)).path(),
            "reality.serverNames[0]"
        );
        assert_eq!(reject(&with_names("[]")).path(), "reality.serverNames");
        let repeat = reject(&with_names(r#"["a.example.com","A.EXAMPLE.COM"]"#));
        assert_eq!(repeat.path(), "reality.serverNames[1]");
        assert!(repeat.message().contains("more than once"), "{repeat}");
    }

    // ------------------------------------------------------------------ users

    #[test]
    fn identities_and_short_ids_must_be_unique_across_the_node() {
        let users = |users: &str| {
            format!(
                r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                     "users":{users},
                     "routing":{{"default":"direct"}}}}"#,
                key(1)
            )
        };

        let duplicate_identity = reject(&users(
            r#"[{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]},
                {"id":"11111111-1111-4111-8111-111111111111","shortIds":["cd"]}]"#,
        ));
        assert_eq!(duplicate_identity.path(), "users[1].id");

        let shared_short_id = reject(&users(
            r#"[{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]},
                {"id":"22222222-2222-4222-8222-222222222222","shortIds":["AB"]}]"#,
        ));
        assert_eq!(shared_short_id.path(), "users[1].shortIds[0]");
        assert!(
            shared_short_id.message().contains("another identity"),
            "{shared_short_id}"
        );

        assert_eq!(reject(&users("[]")).path(), "users");
        assert_eq!(
            reject(&users(r#"[{"id":"not-a-uuid","shortIds":["ab"]}]"#)).path(),
            "users[0].id"
        );
        assert_eq!(
            reject(&users(
                r#"[{"id":"11111111-1111-4111-8111-111111111111","shortIds":["abc"]}]"#
            ))
            .path(),
            "users[0].shortIds[0]"
        );
    }

    #[test]
    fn a_user_policy_must_name_a_declared_policy() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111",
                            "shortIds":["ab"],"policy":"missing"}}],
                 "routing":{{"default":"direct"}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "users[0].policy");
        assert!(error.message().contains("missing"), "{error}");
    }

    // ---------------------------------------------------------------- routing

    #[test]
    fn every_outbound_reference_must_resolve_and_names_the_alternatives() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"nowhere"}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "routing.default");
        assert!(error.message().contains("nowhere"), "{error}");
        assert!(
            error.message().contains("direct") && error.message().contains("block"),
            "the message must list what does exist: {error}"
        );
    }

    #[test]
    fn a_rule_without_a_condition_is_refused() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct",
                             "rules":[{{"outbound":"block"}}]}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "routing.rules[0]");
        assert!(error.message().contains("shadow"), "{error}");
    }

    #[test]
    fn matchers_are_validated_inside_policies_too() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct","policies":{{"p":{{"default":"direct",
                   "rules":[{{"ip":["10.0.0.0/99"],"outbound":"block"}}]}}}}}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "routing.policies.p.rules[0].ip[0]");
    }

    // -------------------------------------------------------------- outbounds

    #[test]
    fn a_built_in_name_cannot_be_redeclared() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "outbounds":{{"direct":{{"type":"socks5","address":"10.0.0.9","port":1080}}}},
                 "routing":{{"default":"direct"}}}}"#,
            key(1)
        ));

        assert_eq!(error.path(), "outbounds.direct");
        assert!(error.message().contains("built in"), "{error}");
    }

    #[test]
    fn socks5_credentials_must_come_as_a_pair() {
        let socks = |credentials: &str| {
            format!(
                r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "outbounds":{{"up":{{"type":"socks5","address":"10.0.0.9","port":1080{credentials}}}}},
                     "routing":{{"default":"up"}}}}"#,
                key(1)
            )
        };

        accept(&socks(""));
        accept(&socks(r#","username":"u","password":"p""#));
        assert_eq!(reject(&socks(r#","username":"u""#)).path(), "outbounds.up");
        assert_eq!(
            reject(&socks(r#","username":"","password":"p""#)).path(),
            "outbounds.up.username"
        );
    }

    #[test]
    fn a_handoff_outbound_must_answer_after_it_connects() {
        let handoff = |timeouts: &str| {
            format!(
                r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "outbounds":{{"l":{{"type":"handoff","address":"10.0.0.2","port":7443,
                       "psk":"{}","landingPublicKey":"{}"{timeouts}}}}},
                     "routing":{{"default":"l"}}}}"#,
                key(1),
                key(2),
                key(3)
            )
        };

        accept(&handoff(""));
        let error = reject(&handoff(
            r#","connectTimeoutMs":20000,"firstByteTimeoutMs":10000"#,
        ));
        assert_eq!(error.path(), "outbounds.l.firstByteTimeoutMs");
        assert!(
            error.message().contains("exceed connectTimeoutMs"),
            "{error}"
        );
    }

    // ---------------------------------------------------------------- landing

    #[test]
    fn a_landing_egress_may_not_chain_to_another_landing() {
        let error = reject(&format!(
            r#"{{"role":"landing","listeners":[{{"port":7443}}],
                 "landing":{{"protocol":"handoff","psk":"{}","privateKey":"{}"}},
                 "outbounds":{{"next":{{"type":"handoff","address":"10.0.0.3","port":7443,
                   "psk":"{}","landingPublicKey":"{}"}}}},
                 "egress":"next"}}"#,
            key(2),
            key(3),
            key(4),
            key(5)
        ));

        assert_eq!(error.path(), "egress");
        assert!(error.message().contains("another landing"), "{error}");
    }

    #[test]
    fn an_unknown_egress_is_refused_and_direct_is_the_default() {
        accept(&landing_json(""));
        accept(&landing_json(r#","egress":"block""#));
        assert_eq!(
            reject(&landing_json(r#","egress":"nowhere""#)).path(),
            "egress"
        );
    }

    #[test]
    fn a_rotation_window_is_bounded_and_may_not_relist_the_active_key() {
        let rotate = |previous: &str| {
            format!(
                r#"{{"role":"landing","listeners":[{{"port":7443}}],
                     "landing":{{"protocol":"handoff","psk":"{}","privateKey":"{}",
                                 "previousPsks":{previous}}}}}"#,
                key(2),
                key(3)
            )
        };

        accept(&rotate(&format!(r#"["{}"]"#, key(9))));
        accept(&rotate(&format!(r#"["{}","{}"]"#, key(9), key(10))));

        let too_many = reject(&rotate(&format!(
            r#"["{}","{}","{}"]"#,
            key(9),
            key(10),
            key(11)
        )));
        assert_eq!(too_many.path(), "landing.previousPsks");

        let active = reject(&rotate(&format!(r#"["{}"]"#, key(2))));
        assert_eq!(active.path(), "landing.previousPsks[0]");
        assert!(active.message().contains("active key"), "{active}");

        let repeat = reject(&rotate(&format!(r#"["{}","{}"]"#, key(9), key(9))));
        assert_eq!(repeat.path(), "landing.previousPsks[1]");
    }

    // ----------------------------------------------------------- key reuse

    #[test]
    fn two_values_may_not_carry_the_same_key_material() {
        let error = reject(&format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "outbounds":{{"l":{{"type":"nxr","address":"10.0.0.2","port":7443,"psk":"{}"}}}},
                 "routing":{{"default":"l"}}}}"#,
            key(1),
            key(1)
        ));

        assert_eq!(error.path(), "outbounds.l.psk");
        assert!(error.message().contains("reality.privateKey"), "{error}");
        assert!(error.message().contains("independently"), "{error}");
    }

    #[test]
    fn pasting_a_private_key_where_the_public_half_belongs_is_caught() {
        let error = reject(&format!(
            r#"{{"role":"landing","listeners":[{{"port":7443}}],
                 "landing":{{"protocol":"handoff","psk":"{}","privateKey":"{}"}},
                 "outbounds":{{"up":{{"type":"handoff","address":"10.0.0.3","port":7443,
                   "psk":"{}","landingPublicKey":"{}"}}}}}}"#,
            key(2),
            key(3),
            key(4),
            key(3)
        ));

        assert_eq!(error.path(), "outbounds.up.landingPublicKey");
        assert!(error.message().contains("landing.privateKey"), "{error}");
    }

    // ------------------------------------------------------------------- dns

    #[test]
    fn the_system_resolver_cannot_be_mixed_with_others() {
        let dns = |servers: &str| entry_json(&format!(r#","dns":{{"servers":{servers}}}"#));

        accept(&dns(r#"["system"]"#));
        accept(&dns(r#"["1.1.1.1","[2606:4700:4700::1111]:53"]"#));
        assert_eq!(
            reject(&dns(r#"["system","1.1.1.1"]"#)).path(),
            "dns.servers"
        );
        assert_eq!(reject(&dns("[]")).path(), "dns.servers");
    }

    #[test]
    fn dns_cache_bounds_must_be_ordered() {
        let error = reject(&entry_json(
            r#","dns":{"cache":{"minTtlSeconds":100,"maxTtlSeconds":50}}"#,
        ));

        assert_eq!(error.path(), "dns.cache.minTtlSeconds");
    }

    // ------------------------------------------------------------------- log

    #[test]
    fn file_logging_and_the_file_block_imply_each_other() {
        assert_eq!(
            reject(&entry_json(r#","log":{"output":"file"}"#)).path(),
            "log.file"
        );
        assert_eq!(
            reject(&entry_json(
                r#","log":{"output":"stderr","file":{"path":"/var/log/rr.log"}}"#
            ))
            .path(),
            "log.file"
        );
        accept(&entry_json(
            r#","log":{"output":"file","file":{"path":"/var/log/rr.log"}}"#,
        ));
    }

    #[test]
    fn log_rotation_bounds_are_checked() {
        assert_eq!(
            reject(&entry_json(
                r#","log":{"output":"file","file":{"path":"/var/log/rr.log","maxBytes":1024}}"#
            ))
            .path(),
            "log.file.maxBytes"
        );
        assert_eq!(
            reject(&entry_json(
                r#","log":{"output":"file","file":{"path":"/var/log/rr.log","maxTotalBytes":1024}}"#
            ))
            .path(),
            "log.file.maxTotalBytes"
        );
    }

    // --------------------------------------------------------------- runtime

    #[test]
    fn a_status_file_without_adaptive_tuning_is_refused() {
        assert_eq!(
            reject(&entry_json(r#","runtime":{"statusFile":"/run/rr.json"}"#)).path(),
            "runtime.statusFile"
        );
        accept(&entry_json(
            r#","runtime":{"tuning":"adaptive","statusFile":"/run/rr.json"}"#,
        ));
    }

    #[test]
    fn pinned_limits_are_checked_against_each_other_only_when_both_are_pinned() {
        // Only one side pinned: the other derives, so the relation is settled
        // when the effective policy is compiled, not here.
        accept(&entry_json(
            r#","runtime":{"limits":{"maxHandshakes":100000}}"#,
        ));

        let error = reject(&entry_json(
            r#","runtime":{"limits":{"maxConnections":1024,"maxHandshakes":2048}}"#,
        ));
        assert_eq!(error.path(), "runtime.limits.maxHandshakes");

        let ordering = reject(&entry_json(
            r#","runtime":{"limits":{"clientHelloTimeoutMs":9000,"handshakeTimeoutMs":3000}}"#,
        ));
        assert_eq!(ordering.path(), "runtime.limits.clientHelloTimeoutMs");
    }

    #[test]
    fn pooling_splice_pipes_requires_splice() {
        let error = reject(&entry_json(
            r#","runtime":{"limits":{"splice":false,"pipePool":true}}"#,
        ));

        assert_eq!(error.path(), "runtime.limits.pipePool");
    }

    #[test]
    fn a_zero_limit_is_refused_rather_than_silently_disabling_the_server() {
        assert_eq!(
            reject(&entry_json(r#","runtime":{"limits":{"maxConnections":0}}"#)).path(),
            "runtime.limits.maxConnections"
        );
    }

    // ---------------------------------------------------------------- assets

    #[test]
    fn asset_sources_must_be_https() {
        assert_eq!(
            reject(&entry_json(
                r#","assets":{"geoip":"http://example.com/geoip.dat"}"#
            ))
            .path(),
            "assets.geoip"
        );
        accept(&entry_json(
            r#","assets":{"geoip":"https://example.com/geoip.dat"}"#,
        ));
    }
}
