use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    net::IpAddr,
    path::Path,
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

use super::{
    Config, GlobalRule, InboundConfig, LogOutput, Network, NxrInboundConfig, OutboundConfig,
    PortMatcher, RelayPolicy, SecretString, VlessInboundConfig,
};
use crate::server_name::is_server_name_pattern;

const MIN_LOG_FILE_BYTES: u64 = 64 * 1024;
const MAX_LOG_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LOG_FILES: u16 = 64;
const MAX_BLACKHOLE_DELAY_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1_000;
const MAX_NXR_TIME_DIFFERENCE_SECONDS: u64 = 300;
const MAX_NXR_NONCE_ENTRIES: u32 = 1_000_000;
const MAX_NXR_NONCE_RETENTION_SECONDS: u64 = 86_400;
const MIN_RELAY_BUFFER_BYTES: usize = 4 * 1024;
const MAX_RELAY_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_RELAY_BUFFERS: usize = 65_536;
/// Kernel pipe capacity reserved worst-case per splice pipe. The kernel
/// allocates pipe pages lazily, but capacity is the hard bound a full pipe
/// can pin; a splice relay holds two pipe pairs (four pipes) at this size.
const SPLICE_PIPE_CAPACITY_BYTES: u64 = 256 * 1024;

/// One validation failure identified by a stable JSON path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    path: String,
    message: String,
}

impl ConfigError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Returns the JSON path that failed validation.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns a secret-free explanation of the invariant.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid configuration at {}: {}",
            self.path, self.message
        )
    }
}

impl Error for ConfigError {}

/// Validates every cross-reference and production invariant before publication.
///
/// # Errors
///
/// Returns the first stable, secret-free validation failure.
pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
    validate_log(config)?;
    validate_assets_and_dns(config)?;
    let users = validate_inbounds(config)?;
    let outbounds = validate_outbounds(config)?;
    validate_routing(config, &users, &outbounds)?;
    validate_policy(config)
}

fn validate_log(config: &Config) -> Result<(), ConfigError> {
    match (config.log.output, config.log.file.as_ref()) {
        (LogOutput::File, None) => {
            return fail("log.file", "is required when log.output is file");
        }
        (LogOutput::Stderr | LogOutput::Journald, Some(_)) => {
            return fail("log.file", "is only allowed when log.output is file");
        }
        (LogOutput::File, Some(file)) => {
            if file.path.as_os_str().is_empty() {
                return fail("log.file.path", "must not be empty");
            }
            if !(MIN_LOG_FILE_BYTES..=MAX_LOG_FILE_BYTES).contains(&file.max_bytes) {
                return fail(
                    "log.file.maxBytes",
                    format!("must be between {MIN_LOG_FILE_BYTES} and {MAX_LOG_FILE_BYTES}"),
                );
            }
            if !(1..=MAX_LOG_FILES).contains(&file.max_files) {
                return fail(
                    "log.file.maxFiles",
                    format!("must be between 1 and {MAX_LOG_FILES}"),
                );
            }
            let maximum_total = file.max_bytes.saturating_mul(u64::from(file.max_files));
            if !(file.max_bytes..=maximum_total).contains(&file.max_total_bytes) {
                return fail(
                    "log.file.maxTotalBytes",
                    "must fit at least one file and no more than maxBytes * maxFiles",
                );
            }
        }
        (LogOutput::Stderr | LogOutput::Journald, None) => {}
    }
    Ok(())
}

fn validate_assets_and_dns(config: &Config) -> Result<(), ConfigError> {
    validate_asset_url("assets.geoip", &config.assets.geoip)?;
    validate_asset_url("assets.geosite", &config.assets.geosite)?;
    if config.assets.cache_directory.as_os_str().is_empty() {
        return fail("assets.cacheDirectory", "must not be empty");
    }
    if config.assets.reload_interval_seconds == 0 {
        return fail("assets.reloadIntervalSeconds", "must be greater than zero");
    }
    if !(1..=300).contains(&config.assets.request_timeout_seconds) {
        return fail("assets.requestTimeoutSeconds", "must be between 1 and 300");
    }
    if !(1024..=512 * 1024 * 1024).contains(&config.assets.max_bytes) {
        return fail("assets.maxBytes", "must be between 1024 and 536870912");
    }
    if config.dns.servers != ["system"] {
        return fail(
            "dns.servers",
            "currently supports exactly one system resolver; custom resolvers must not be ignored",
        );
    }
    validate_timeout("dns.timeoutMs", config.dns.timeout_ms)
}

fn validate_asset_url(path: &str, value: &str) -> Result<(), ConfigError> {
    let uri = value
        .parse::<ureq::http::Uri>()
        .map_err(|_| ConfigError::new(path, "must be a valid HTTPS URL"))?;
    if uri.scheme_str() != Some("https") || uri.authority().is_none() {
        return fail(path, "must be an HTTPS URL with a host");
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return fail(path, "must not contain embedded credentials");
    }
    Ok(())
}

fn validate_inbounds(config: &Config) -> Result<HashSet<String>, ConfigError> {
    if config.inbounds.is_empty() {
        return fail("inbounds", "must contain at least one listener");
    }

    let mut tags = HashSet::new();
    let mut users = HashSet::new();
    let mut listeners = HashSet::new();
    for (index, inbound) in config.inbounds.iter().enumerate() {
        let path = format!("inbounds[{index}]");
        validate_tag(&format!("{path}.tag"), inbound.tag(), &mut tags)?;
        if inbound.port() == 0 {
            return fail(format!("{path}.port"), "must be greater than zero");
        }
        if !listeners.insert((inbound.listen(), inbound.port())) {
            return fail(
                format!("{path}.port"),
                "listen address and port are configured more than once",
            );
        }
        match inbound {
            InboundConfig::Vless(inbound) => validate_vless_inbound(&path, inbound, &mut users)?,
            InboundConfig::Nxr(inbound) => validate_nxr_inbound(&path, inbound)?,
        }
    }
    Ok(users)
}

fn validate_vless_inbound(
    path: &str,
    inbound: &VlessInboundConfig,
    users: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    if inbound.settings.decryption != "none" {
        return fail(format!("{path}.settings.decryption"), "must be none");
    }
    if inbound.settings.clients.is_empty() {
        return fail(
            format!("{path}.settings.clients"),
            "must contain at least one UUID",
        );
    }
    for (client_index, client) in inbound.settings.clients.iter().enumerate() {
        let client_path = format!("{path}.settings.clients[{client_index}]");
        validate_uuid(&format!("{client_path}.id"), &client.id)?;
        let normalized = client.id.to_ascii_lowercase();
        if !users.insert(normalized) {
            return fail(
                format!("{client_path}.id"),
                "UUID is configured more than once",
            );
        }
        if client.flow != "xtls-rprx-vision" {
            return fail(format!("{client_path}.flow"), "must be xtls-rprx-vision");
        }
    }
    if inbound.stream_settings.network != Network::Tcp {
        return fail(format!("{path}.streamSettings.network"), "must be tcp");
    }
    if inbound.stream_settings.security != "reality" {
        return fail(format!("{path}.streamSettings.security"), "must be reality");
    }

    let reality = &inbound.stream_settings.reality_settings;
    validate_endpoint(
        &format!("{path}.streamSettings.realitySettings.target"),
        &reality.target,
    )?;
    if reality.server_names.is_empty() {
        return fail(
            format!("{path}.streamSettings.realitySettings.serverNames"),
            "must contain at least one DNS name",
        );
    }
    let mut server_names = HashSet::new();
    for (name_index, name) in reality.server_names.iter().enumerate() {
        let name_path = format!("{path}.streamSettings.realitySettings.serverNames[{name_index}]");
        if !is_server_name_pattern(name) {
            return fail(
                name_path,
                "must be a concrete ASCII DNS name or a leftmost single-label wildcard such as *.lmu.edu",
            );
        }
        if !server_names.insert(name.to_ascii_lowercase()) {
            return fail(
                name_path,
                "server name pattern is configured more than once",
            );
        }
    }
    validate_base64_key(
        &format!("{path}.streamSettings.realitySettings.privateKey"),
        &reality.private_key,
    )?;
    if reality.short_ids.is_empty() {
        return fail(
            format!("{path}.streamSettings.realitySettings.shortIds"),
            "must contain at least one short ID",
        );
    }
    let mut short_ids = HashSet::new();
    for (short_index, short_id) in reality.short_ids.iter().enumerate() {
        let short_path = format!("{path}.streamSettings.realitySettings.shortIds[{short_index}]");
        if !(2..=16).contains(&short_id.len())
            || !short_id.len().is_multiple_of(2)
            || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return fail(short_path, "must be 2 to 16 even hexadecimal characters");
        }
        if !short_ids.insert(short_id.to_ascii_lowercase()) {
            return fail(short_path, "short ID is configured more than once");
        }
    }
    if reality.max_time_diff_ms > MAX_TIMEOUT_MS {
        return fail(
            format!("{path}.streamSettings.realitySettings.maxTimeDiffMs"),
            format!("must not exceed {MAX_TIMEOUT_MS}"),
        );
    }
    Ok(())
}

fn validate_nxr_inbound(path: &str, inbound: &NxrInboundConfig) -> Result<(), ConfigError> {
    let settings = &inbound.settings;
    validate_base64_key(
        &format!("{path}.settings.preSharedKey"),
        &settings.pre_shared_key,
    )?;
    if !(1..=MAX_NXR_TIME_DIFFERENCE_SECONDS).contains(&settings.max_time_difference_seconds) {
        return fail(
            format!("{path}.settings.maxTimeDifferenceSeconds"),
            format!("must be between 1 and {MAX_NXR_TIME_DIFFERENCE_SECONDS}"),
        );
    }
    if !(1..=MAX_NXR_NONCE_ENTRIES).contains(&settings.max_nonce_entries) {
        return fail(
            format!("{path}.settings.maxNonceEntries"),
            format!("must be between 1 and {MAX_NXR_NONCE_ENTRIES}"),
        );
    }
    let minimum_retention = settings
        .max_time_difference_seconds
        .saturating_mul(2)
        .saturating_add(1);
    if !(minimum_retention..=MAX_NXR_NONCE_RETENTION_SECONDS)
        .contains(&settings.nonce_retention_seconds)
    {
        return fail(
            format!("{path}.settings.nonceRetentionSeconds"),
            format!("must be between {minimum_retention} and {MAX_NXR_NONCE_RETENTION_SECONDS}"),
        );
    }
    validate_timeout(
        &format!("{path}.settings.authenticationTimeoutMs"),
        settings.authentication_timeout_ms,
    )?;
    validate_timeout(
        &format!("{path}.settings.connectTimeoutMs"),
        settings.connect_timeout_ms,
    )
}

fn validate_base64_key(path: &str, key: &SecretString) -> Result<(), ConfigError> {
    validate_nonempty_secret(path, key)?;
    let decoded = Zeroizing::new(
        BASE64_URL_SAFE_NO_PAD
            .decode(key.expose())
            .map_err(|_| ConfigError::new(path, "must be URL-safe unpadded base64"))?,
    );
    if decoded.len() != 32 {
        return fail(path, "must decode to exactly 32 bytes");
    }
    Ok(())
}

fn validate_outbounds(config: &Config) -> Result<HashSet<String>, ConfigError> {
    if config.outbounds.is_empty() {
        return fail("outbounds", "must contain at least one transport");
    }

    let mut tags = HashSet::new();
    for (index, outbound) in config.outbounds.iter().enumerate() {
        let path = format!("outbounds[{index}]");
        validate_tag(&format!("{path}.tag"), outbound.tag(), &mut tags)?;
        match outbound {
            OutboundConfig::Direct { .. } => {}
            OutboundConfig::Blackhole { settings, .. } => {
                if settings.response_delay_ms > MAX_BLACKHOLE_DELAY_MS {
                    return fail(
                        format!("{path}.settings.responseDelayMs"),
                        format!("must not exceed {MAX_BLACKHOLE_DELAY_MS}"),
                    );
                }
            }
            OutboundConfig::Socks5 { settings, .. } => {
                validate_hostname_or_ip(&format!("{path}.settings.address"), &settings.address)?;
                if settings.port == 0 {
                    return fail(format!("{path}.settings.port"), "must be greater than zero");
                }
                if settings.username.is_some() != settings.password.is_some() {
                    return fail(
                        format!("{path}.settings"),
                        "username and password must either both be present or both be absent",
                    );
                }
                if settings
                    .username
                    .as_ref()
                    .is_some_and(SecretString::is_empty)
                    || settings
                        .password
                        .as_ref()
                        .is_some_and(SecretString::is_empty)
                {
                    return fail(
                        format!("{path}.settings"),
                        "SOCKS5 credentials must not be empty",
                    );
                }
                if settings
                    .username
                    .as_ref()
                    .is_some_and(|value| value.expose().len() > usize::from(u8::MAX))
                    || settings
                        .password
                        .as_ref()
                        .is_some_and(|value| value.expose().len() > usize::from(u8::MAX))
                {
                    return fail(
                        format!("{path}.settings"),
                        "SOCKS5 credentials must not exceed 255 bytes",
                    );
                }
            }
            OutboundConfig::Nxr { settings, .. } => {
                validate_hostname_or_ip(&format!("{path}.settings.address"), &settings.address)?;
                if settings.port == 0 {
                    return fail(format!("{path}.settings.port"), "must be greater than zero");
                }
                let key = Zeroizing::new(
                    BASE64_URL_SAFE_NO_PAD
                        .decode(settings.pre_shared_key.expose())
                        .map_err(|_| {
                            ConfigError::new(
                                format!("{path}.settings.preSharedKey"),
                                "must be URL-safe unpadded base64",
                            )
                        })?,
                );
                if key.len() != 32 {
                    return fail(
                        format!("{path}.settings.preSharedKey"),
                        "must decode to exactly 32 bytes",
                    );
                }
            }
        }
    }
    Ok(tags)
}

fn validate_routing(
    config: &Config,
    users: &HashSet<String>,
    outbounds: &HashSet<String>,
) -> Result<(), ConfigError> {
    let inbound_tags: HashSet<&str> = config
        .inbounds
        .iter()
        .filter_map(InboundConfig::as_vless)
        .map(|inbound| inbound.tag.as_str())
        .collect();
    for (index, rule) in config.routing.global_rules.iter().enumerate() {
        validate_rule(
            &format!("routing.globalRules[{index}]"),
            rule,
            outbounds,
            &inbound_tags,
        )?;
    }
    if config.routing.users.is_empty() {
        return if users.is_empty() {
            Ok(())
        } else {
            fail("routing.users", "must contain at least one user policy")
        };
    }

    let mut names = HashSet::new();
    let mut assignments: HashMap<String, String> = HashMap::new();
    for (index, policy) in config.routing.users.iter().enumerate() {
        let path = format!("routing.users[{index}]");
        if policy.name.trim().is_empty() || !names.insert(policy.name.as_str()) {
            return fail(format!("{path}.name"), "must be non-empty and unique");
        }
        validate_outbound_reference(
            &format!("{path}.defaultOutbound"),
            &policy.default_outbound,
            outbounds,
        )?;
        if policy.user_ids.is_empty() {
            return fail(format!("{path}.userIds"), "must contain at least one UUID");
        }
        for (user_index, user_id) in policy.user_ids.iter().enumerate() {
            let user_path = format!("{path}.userIds[{user_index}]");
            validate_uuid(&user_path, user_id)?;
            let normalized = user_id.to_ascii_lowercase();
            if !users.contains(&normalized) {
                return fail(user_path, "does not reference a configured inbound UUID");
            }
            if let Some(previous) = assignments.insert(normalized, policy.name.clone()) {
                return fail(
                    user_path,
                    format!("UUID is already assigned to routing group {previous}"),
                );
            }
        }
        for (rule_index, rule) in policy.rules.iter().enumerate() {
            validate_rule(
                &format!("{path}.rules[{rule_index}]"),
                rule,
                outbounds,
                &inbound_tags,
            )?;
        }
    }

    if assignments.len() != users.len() {
        return fail(
            "routing.users",
            "every configured inbound UUID must be assigned exactly once",
        );
    }
    Ok(())
}

fn validate_rule(
    path: &str,
    rule: &GlobalRule,
    outbounds: &HashSet<String>,
    inbound_tags: &HashSet<&str>,
) -> Result<(), ConfigError> {
    if rule.name.trim().is_empty() {
        return fail(format!("{path}.name"), "must not be empty");
    }
    validate_outbound_reference(&format!("{path}.outbound"), &rule.outbound, outbounds)?;
    if rule.domain.is_empty()
        && rule.ip.is_empty()
        && rule.port.is_empty()
        && rule.network.is_empty()
        && rule.inbound_tag.is_empty()
    {
        return fail(path, "must contain at least one match condition");
    }
    for (index, matcher) in rule.domain.iter().enumerate() {
        validate_domain_matcher(&format!("{path}.domain[{index}]"), matcher)?;
    }
    for (index, matcher) in rule.ip.iter().enumerate() {
        validate_ip_matcher(&format!("{path}.ip[{index}]"), matcher)?;
    }
    for (index, matcher) in rule.port.iter().enumerate() {
        validate_port_matcher(&format!("{path}.port[{index}]"), matcher)?;
    }
    for (index, tag) in rule.inbound_tag.iter().enumerate() {
        if !inbound_tags.contains(tag.as_str()) {
            return fail(
                format!("{path}.inboundTag[{index}]"),
                "does not reference a configured inbound tag",
            );
        }
    }
    Ok(())
}

fn validate_domain_matcher(path: &str, matcher: &str) -> Result<(), ConfigError> {
    let matcher = matcher.trim();
    if matcher.is_empty() {
        return fail(path, "must not be empty");
    }
    if let Some(rest) = matcher.strip_prefix("ext:") {
        let Some((file, tag)) = rest.split_once(':') else {
            return fail(path, "ext matcher must be ext:file:tag");
        };
        if file.is_empty() || tag.is_empty() || tag.contains(':') {
            return fail(path, "ext matcher must contain one file and one tag");
        }
        let file_path = Path::new(file);
        if file_path.is_absolute()
            || file_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return fail(path, "ext file must be a relative path without traversal");
        }
        return Ok(());
    }
    for prefix in ["domain:", "full:", "keyword:", "regexp:", "geosite:"] {
        if let Some(value) = matcher.strip_prefix(prefix) {
            return if value.is_empty() {
                fail(path, "matcher value must not be empty")
            } else {
                Ok(())
            };
        }
    }
    validate_hostname(path, matcher)
}

fn validate_ip_matcher(path: &str, matcher: &str) -> Result<(), ConfigError> {
    if let Some(label) = matcher.strip_prefix("geoip:") {
        return if label.is_empty() {
            fail(path, "GeoIP label must not be empty")
        } else {
            Ok(())
        };
    }
    if matcher.starts_with("ext:") {
        return validate_domain_matcher(path, matcher);
    }
    if let Some((address, prefix)) = matcher.split_once('/') {
        let address: IpAddr = address
            .parse()
            .map_err(|_| ConfigError::new(path, "CIDR address is invalid"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| ConfigError::new(path, "CIDR prefix is invalid"))?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        return if prefix > maximum {
            fail(path, format!("CIDR prefix must not exceed {maximum}"))
        } else {
            Ok(())
        };
    }
    matcher
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| ConfigError::new(path, "must be an IP, CIDR, geoip:tag, or ext:file:tag"))
}

fn validate_port_matcher(path: &str, matcher: &PortMatcher) -> Result<(), ConfigError> {
    let parse = |value: &str| {
        value
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| ConfigError::new(path, "port must be between 1 and 65535"))
    };
    if let Some((start, end)) = matcher.0.split_once('-') {
        let start = parse(start)?;
        let end = parse(end)?;
        if start > end {
            return fail(path, "port range start must not exceed its end");
        }
        Ok(())
    } else {
        parse(&matcher.0).map(|_| ())
    }
}

fn validate_policy(config: &Config) -> Result<(), ConfigError> {
    let governor = &config.policy.resource_governor;
    for (path, value) in [
        (
            "policy.resourceGovernor.maxConnections",
            governor.max_connections,
        ),
        (
            "policy.resourceGovernor.maxHandshakes",
            governor.max_handshakes,
        ),
        (
            "policy.resourceGovernor.maxFallbacks",
            governor.max_fallbacks,
        ),
        (
            "policy.resourceGovernor.maxCryptoOperations",
            governor.max_crypto_operations,
        ),
        (
            "policy.resourceGovernor.maxReplayEntries",
            governor.max_replay_entries,
        ),
        (
            "policy.resourceGovernor.maxDnsLookups",
            governor.max_dns_lookups,
        ),
    ] {
        if value == 0 {
            return fail(path, "must be greater than zero");
        }
    }
    if governor.max_handshakes > governor.max_connections
        || governor.max_fallbacks > governor.max_connections
        || governor.max_crypto_operations > governor.max_handshakes
        || governor.max_dns_lookups > governor.max_connections
    {
        return fail(
            "policy.resourceGovernor",
            "child admission limits must not exceed their parent limits",
        );
    }
    for (path, timeout) in [
        (
            "policy.resourceGovernor.clientHelloTimeoutMs",
            governor.client_hello_timeout_ms,
        ),
        (
            "policy.resourceGovernor.handshakeTimeoutMs",
            governor.handshake_timeout_ms,
        ),
        (
            "policy.resourceGovernor.connectTimeoutMs",
            governor.connect_timeout_ms,
        ),
        (
            "policy.resourceGovernor.fallbackTimeoutMs",
            governor.fallback_timeout_ms,
        ),
        (
            "policy.resourceGovernor.replayRetentionMs",
            governor.replay_retention_ms,
        ),
    ] {
        validate_timeout(path, timeout)?;
    }
    if governor.client_hello_timeout_ms > governor.handshake_timeout_ms {
        return fail(
            "policy.resourceGovernor.clientHelloTimeoutMs",
            "must not exceed handshakeTimeoutMs",
        );
    }
    if governor.connect_timeout_ms > governor.fallback_timeout_ms {
        return fail(
            "policy.resourceGovernor.connectTimeoutMs",
            "must not exceed fallbackTimeoutMs",
        );
    }

    let barrier = &config.policy.direct_barrier;
    if barrier.max_concurrent == 0 || barrier.max_per_second == 0 {
        return fail("policy.directBarrier", "limits must be greater than zero");
    }
    if barrier.max_concurrent > governor.max_connections {
        return fail(
            "policy.directBarrier.maxConcurrent",
            "must not exceed maxConnections",
        );
    }

    let relay = &config.policy.relay;
    if !(MIN_RELAY_BUFFER_BYTES..=MAX_RELAY_BUFFER_BYTES).contains(&relay.buffer_bytes) {
        return fail(
            "policy.relay.bufferBytes",
            format!("must be between {MIN_RELAY_BUFFER_BYTES} and {MAX_RELAY_BUFFER_BYTES}"),
        );
    }
    if !(2..=MAX_RELAY_BUFFERS).contains(&relay.max_pooled_buffers) {
        return fail(
            "policy.relay.maxPooledBuffers",
            format!("must be between 2 and {MAX_RELAY_BUFFERS}"),
        );
    }
    if relay.splice {
        if relay.max_splice_relays == 0 {
            return fail(
                "policy.relay.maxSpliceRelays",
                "must be greater than zero when splice is enabled",
            );
        }
        if relay.max_splice_relays > governor.max_connections {
            return fail(
                "policy.relay.maxSpliceRelays",
                "must not exceed maxConnections",
            );
        }
    }
    validate_relay_memory(relay)?;
    Ok(())
}

/// Rejects an impossible relay memory budget before any listener binds.
///
/// Every product is checked. `maxPooledBuffers` is a buffer count, never a byte
/// budget, so the buffered term multiplies the count by the buffer size rather
/// than treating the count as bytes.
fn validate_relay_memory(relay: &RelayPolicy) -> Result<(), ConfigError> {
    let buffer_bytes = u64::try_from(relay.buffer_bytes).unwrap_or(u64::MAX);
    let buffered = u64::try_from(relay.max_pooled_buffers)
        .ok()
        .and_then(|buffers| buffers.checked_mul(buffer_bytes))
        .ok_or_else(|| ConfigError::new("policy.relay.maxPooledBuffers", "budget overflows"))?;

    // Kernel pipe capacity is reserved worst-case, even though the kernel
    // allocates pipe pages lazily. With the process pool enabled the retained
    // pool is the binding term (it subsumes per-session creation); without it
    // every splice relay holds two pipe pairs.
    let splice_pipes = if !relay.splice {
        0
    } else if relay.pipe_pool {
        u64::from(relay.max_pooled_pipes)
            .checked_mul(2)
            .and_then(|pipes| pipes.checked_mul(SPLICE_PIPE_CAPACITY_BYTES))
            .ok_or_else(|| ConfigError::new("policy.relay.maxPooledPipes", "budget overflows"))?
    } else {
        u64::from(relay.max_splice_relays)
            .checked_mul(4)
            .and_then(|pipes| pipes.checked_mul(SPLICE_PIPE_CAPACITY_BYTES))
            .ok_or_else(|| ConfigError::new("policy.relay.maxSpliceRelays", "budget overflows"))?
    };

    let relay_total = buffered
        .checked_add(splice_pipes)
        .ok_or_else(|| ConfigError::new("policy.relay", "budget overflows"))?;
    if relay_total > relay.max_relay_memory_bytes {
        return fail(
            "policy.relay.maxRelayMemoryBytes",
            format!("configured backends require {relay_total} bytes"),
        );
    }
    Ok(())
}

fn validate_timeout(path: &str, timeout: u64) -> Result<(), ConfigError> {
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout) {
        return fail(path, format!("must be between 1 and {MAX_TIMEOUT_MS}"));
    }
    Ok(())
}

fn validate_outbound_reference(
    path: &str,
    outbound: &str,
    outbounds: &HashSet<String>,
) -> Result<(), ConfigError> {
    if !outbounds.contains(outbound) {
        return fail(path, "does not reference a configured outbound tag");
    }
    Ok(())
}

fn validate_tag(path: &str, tag: &str, existing: &mut HashSet<String>) -> Result<(), ConfigError> {
    if tag.is_empty()
        || tag.len() > 64
        || !tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return fail(
            path,
            "must be 1 to 64 ASCII letters, digits, dots, dashes, or underscores",
        );
    }
    if !existing.insert(tag.to_owned()) {
        return fail(path, "tag is configured more than once");
    }
    Ok(())
}

fn validate_uuid(path: &str, uuid: &str) -> Result<(), ConfigError> {
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
    {
        return fail(path, "must be a canonical hyphenated UUID");
    }
    Ok(())
}

fn validate_endpoint(path: &str, endpoint: &str) -> Result<(), ConfigError> {
    if endpoint.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(());
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return fail(path, "must be host:port");
    };
    if host.contains(':') {
        return fail(path, "IPv6 addresses must use bracketed host:port syntax");
    }
    validate_hostname_or_ip(path, host)?;
    port.parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .map(|_| ())
        .ok_or_else(|| ConfigError::new(path, "port must be between 1 and 65535"))
}

fn validate_hostname_or_ip(path: &str, host: &str) -> Result<(), ConfigError> {
    if host.parse::<IpAddr>().is_ok() {
        Ok(())
    } else {
        validate_hostname(path, host)
    }
}

fn validate_hostname(path: &str, host: &str) -> Result<(), ConfigError> {
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return fail(path, "must be a valid ASCII DNS name or IP address");
    }
    Ok(())
}

fn validate_nonempty_secret(path: &str, value: &SecretString) -> Result<(), ConfigError> {
    if value.is_empty() {
        return fail(path, "must not be empty");
    }
    Ok(())
}

fn fail<T>(path: impl Into<String>, message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::new(path, message))
}

#[cfg(test)]
mod tests {
    use crate::config::{
        Config, LogOutput, NxrInboundConfig, NxrInboundSettings, NxrSettings, OutboundConfig,
        SecretString, validate_config,
    };

    use super::ConfigError;

    fn valid_config() -> Config {
        serde_json::from_str(crate::config::test_config_json()).expect("fixture must decode")
    }

    #[test]
    fn accepts_strict_production_configuration() {
        validate_config(&valid_config()).expect("fixture must validate");
    }

    #[test]
    fn rejects_plain_vless_inbound() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .security = "none".to_owned();

        assert_eq!(
            validate_config(&config)
                .expect_err("plain VLESS must be rejected")
                .path(),
            "inbounds[0].streamSettings.security"
        );
    }

    #[test]
    fn rejects_duplicate_listener_addresses() {
        let mut config = valid_config();
        let mut duplicate = config.inbounds[0].clone();
        let duplicate_vless = duplicate
            .as_vless_mut()
            .expect("fixture must contain VLESS");
        duplicate_vless.tag = "duplicate-inbound".to_owned();
        duplicate_vless.settings.clients[0].id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned();
        config.inbounds.push(duplicate);

        assert_eq!(
            validate_config(&config)
                .expect_err("duplicate socket binding must fail")
                .path(),
            "inbounds[1].port"
        );
    }

    #[test]
    fn assigns_each_uuid_exactly_once() {
        let mut config = valid_config();
        config.routing.users[0].user_ids.clear();

        assert_eq!(
            validate_config(&config)
                .expect_err("missing assignment must fail")
                .path(),
            "routing.users[0].userIds"
        );
    }

    #[test]
    fn rejects_missing_outbound_reference() {
        let mut config = valid_config();
        config.routing.users[0].default_outbound = "missing".to_owned();

        assert_eq!(
            validate_config(&config)
                .expect_err("unknown outbound must fail")
                .path(),
            "routing.users[0].defaultOutbound"
        );
    }

    #[test]
    fn file_logging_requires_bounded_file_settings() {
        let mut config = valid_config();
        config.log.output = LogOutput::File;

        assert_eq!(
            validate_config(&config).expect_err("file settings must be required"),
            ConfigError::new("log.file", "is required when log.output is file")
        );
    }

    #[test]
    fn rejects_malformed_reality_private_key() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .private_key = SecretString::new("not-base64!");

        assert_eq!(
            validate_config(&config)
                .expect_err("malformed private key must fail")
                .path(),
            "inbounds[0].streamSettings.realitySettings.privateKey"
        );
    }

    #[test]
    fn bounds_reality_client_clock_difference() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .max_time_diff_ms = 600_001;

        assert_eq!(
            validate_config(&config)
                .expect_err("unbounded client-clock difference must fail")
                .path(),
            "inbounds[0].streamSettings.realitySettings.maxTimeDiffMs"
        );
    }

    #[test]
    fn accepts_leftmost_reality_server_name_wildcard() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .server_names = vec!["*.lmu.edu".to_owned()];

        validate_config(&config).expect("one-label wildcard must validate");
    }

    #[test]
    fn rejects_unsafe_or_duplicate_reality_server_name_patterns() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .server_names = vec!["www.*.edu".to_owned()];
        assert_eq!(
            validate_config(&config)
                .expect_err("non-leftmost wildcard must fail")
                .path(),
            "inbounds[0].streamSettings.realitySettings.serverNames[0]"
        );

        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .stream_settings
            .reality_settings
            .server_names = vec!["*.lmu.edu".to_owned(), "*.LMU.EDU".to_owned()];
        assert_eq!(
            validate_config(&config)
                .expect_err("case-insensitive duplicate must fail")
                .path(),
            "inbounds[0].streamSettings.realitySettings.serverNames[1]"
        );
    }

    #[test]
    fn accepts_internal_nxr_listener_without_public_routing_identity() {
        let mut config = valid_config();
        let key = SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo");
        config
            .inbounds
            .push(crate::config::InboundConfig::Nxr(NxrInboundConfig {
                tag: "landing-internal".to_owned(),
                listen: "127.0.0.1".parse().expect("address must parse"),
                port: 9443,
                settings: NxrInboundSettings {
                    pre_shared_key: key,
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 120,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                },
            }));

        validate_config(&config).expect("NXR listener must validate independently");
    }

    #[test]
    fn nxr_replay_retention_covers_the_entire_timestamp_window() {
        let mut config = valid_config();
        config
            .inbounds
            .push(crate::config::InboundConfig::Nxr(NxrInboundConfig {
                tag: "landing-internal".to_owned(),
                listen: "127.0.0.1".parse().expect("address must parse"),
                port: 9443,
                settings: NxrInboundSettings {
                    pre_shared_key: SecretString::new(
                        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
                    ),
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 60,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                },
            }));

        assert_eq!(
            validate_config(&config)
                .expect_err("short replay retention must fail")
                .path(),
            "inbounds[1].settings.nonceRetentionSeconds"
        );
    }

    #[test]
    fn assets_require_https_without_embedded_credentials() {
        let mut config = valid_config();
        config.assets.geoip = "http://example.com/geoip.dat".to_owned();
        assert_eq!(
            validate_config(&config)
                .expect_err("plaintext asset URL must fail")
                .path(),
            "assets.geoip"
        );

        config.assets.geoip = "https://token@example.com/geoip.dat".to_owned();
        assert_eq!(
            validate_config(&config)
                .expect_err("asset URL credentials must fail")
                .path(),
            "assets.geoip"
        );
    }

    #[test]
    fn external_assets_cannot_escape_cache_directory() {
        let mut config = valid_config();
        config.routing.global_rules[0].domain = vec!["ext:../private.dat:test".to_owned()];

        assert_eq!(
            validate_config(&config)
                .expect_err("asset traversal must fail")
                .path(),
            "routing.globalRules[0].domain[0]"
        );
    }

    #[test]
    fn nxr_uses_one_independent_fixed_size_psk_without_pool_settings() {
        let mut config = valid_config();
        config.outbounds.push(OutboundConfig::Nxr {
            tag: "landing".to_owned(),
            settings: NxrSettings {
                address: "127.0.0.1".to_owned(),
                port: 9443,
                pre_shared_key: SecretString::new("too-short"),
            },
        });

        assert_eq!(
            validate_config(&config)
                .expect_err("malformed NXR PSK must fail")
                .path(),
            "outbounds[2].settings.preSharedKey"
        );
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let config = valid_config();
        let debug = format!("{config:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("ERERERERERERERERERERERERERERERERERERERERERE"));
    }

    #[test]
    fn an_enabled_kernel_backend_needs_a_nonzero_relay_limit() {
        let mut config = valid_config();
        config.policy.relay.splice = true;
        config.policy.relay.max_splice_relays = 0;
        assert_eq!(
            validate_config(&config)
                .expect_err("an enabled backend with a zero bound must fail closed")
                .path(),
            "policy.relay.maxSpliceRelays"
        );
    }

    #[test]
    fn a_kernel_relay_limit_may_not_exceed_max_connections() {
        let mut config = valid_config();
        config.policy.relay.splice = true;
        config.policy.relay.max_splice_relays = config.policy.resource_governor.max_connections + 1;

        assert_eq!(
            validate_config(&config)
                .expect_err("a relay bound above maxConnections must fail closed")
                .path(),
            "policy.relay.maxSpliceRelays"
        );
    }

    #[test]
    fn an_impossible_relay_memory_budget_is_rejected_before_binding() {
        let mut config = valid_config();
        config.policy.relay.buffer_bytes = 1024 * 1024;
        config.policy.relay.max_pooled_buffers = 65_536;
        config.policy.relay.max_relay_memory_bytes = 1;

        assert_eq!(
            validate_config(&config)
                .expect_err("an oversized buffered budget must fail closed")
                .path(),
            "policy.relay.maxRelayMemoryBytes"
        );
    }

    #[test]
    fn pooled_buffers_are_counted_as_buffers_rather_than_bytes() {
        let mut config = valid_config();
        config.policy.relay.buffer_bytes = 32 * 1024;
        config.policy.relay.max_pooled_buffers = 4_096;
        // 4096 buffers x 32 KiB is exactly 128 MiB; a byte budget one below
        // must be rejected. With splice enabled, the budget must additionally
        // cover the relays' pipe pairs (4 pipes x 256 KiB per relay).
        let splice_pipes = u64::from(config.policy.relay.max_splice_relays) * 4 * 256 * 1024;
        config.policy.relay.max_relay_memory_bytes = 4_096 * 32 * 1024 - 1;
        assert!(validate_config(&config).is_err());

        config.policy.relay.max_relay_memory_bytes = 4_096 * 32 * 1024 + splice_pipes;
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_unimplemented_custom_dns_resolvers() {
        let mut config = valid_config();
        config.dns.servers = vec!["1.1.1.1".to_owned()];

        assert_eq!(
            validate_config(&config)
                .expect_err("custom DNS must not be silently ignored")
                .path(),
            "dns.servers"
        );
    }

    #[test]
    fn accepts_dedicated_resource_mode() {
        let mut config: serde_json::Value =
            serde_json::from_str(crate::config::test_config_json()).expect("fixture must decode");
        config["runtime"] = serde_json::json!({ "resourceMode": "dedicated" });
        let config: Config = serde_json::from_value(config).expect("dedicated mode must decode");

        assert_eq!(
            config.runtime.resource_mode,
            crate::config::ResourceMode::Dedicated
        );
        validate_config(&config).expect("dedicated mode must validate");
    }

    #[test]
    fn defaults_to_standard_resource_mode() {
        let config = valid_config();
        assert_eq!(
            config.runtime.resource_mode,
            crate::config::ResourceMode::Standard
        );
        assert_eq!(config.runtime.resource_mode.as_str(), "standard");
        validate_config(&config).expect("the default mode must validate");
    }

    #[test]
    fn rejects_unknown_resource_mode_values() {
        let mut config: serde_json::Value =
            serde_json::from_str(crate::config::test_config_json()).expect("fixture must decode");
        config["runtime"] = serde_json::json!({ "resourceMode": "exclusive" });
        assert!(
            serde_json::from_value::<Config>(config).is_err(),
            "an unknown resourceMode must fail closed at decode time"
        );
    }

    #[test]
    fn rejects_unknown_runtime_fields() {
        let mut config: serde_json::Value =
            serde_json::from_str(crate::config::test_config_json()).expect("fixture must decode");
        config["runtime"] = serde_json::json!({ "resourceMode": "dedicated", "tuning": {} });
        assert!(
            serde_json::from_value::<Config>(config).is_err(),
            "deny_unknown_fields applies to the runtime section"
        );
    }
}
