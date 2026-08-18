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
    Config, GlobalRule, HandoffInboundConfig, InboundConfig, LogOutput, Network, NxrInboundConfig,
    OutboundConfig, PortMatcher, RelayPolicy, SecretString, VlessInboundConfig,
};
use crate::{network::ConnectionPlanner, server_name::is_server_name_pattern};

const MIN_LOG_FILE_BYTES: u64 = 64 * 1024;
const MAX_LOG_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_LOG_FILES: u16 = 64;
const MAX_BLACKHOLE_DELAY_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 10 * 60 * 1_000;
const MAX_NXR_TIME_DIFFERENCE_SECONDS: u64 = 300;
const MAX_NXR_NONCE_ENTRIES: u32 = 1_000_000;
const MAX_NXR_NONCE_RETENTION_SECONDS: u64 = 86_400;
const MAX_HANDOFF_TIME_DIFFERENCE_SECONDS: u64 = 300;
const MAX_HANDOFF_NONCE_ENTRIES: u32 = 1_000_000;
const MAX_HANDOFF_NONCE_RETENTION_SECONDS: u64 = 86_400;
/// Retired keys of each kind a Handoff landing may still accept during a
/// rotation window; the open path's candidate space stays bounded at 3 x 3.
const MAX_HANDOFF_PREVIOUS_KEYS: usize = 2;
const MIN_HANDOFF_FIRST_BYTE_TIMEOUT_MS: u64 = 1_000;
const MIN_RELAY_BUFFER_BYTES: usize = 4 * 1024;
const MAX_RELAY_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_RELAY_BUFFERS: usize = 65_536;
/// Nanosecond GCRA cannot represent a finer refill interval than one token
/// per nanosecond. Reject larger values instead of silently under-delivering
/// the configured steady-state rate.
const MAX_DIRECT_DIALS_PER_SECOND: u32 = 1_000_000_000;
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
    pub(crate) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
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
    validate_network(config)?;
    let users = validate_inbounds(config)?;
    let outbounds = validate_outbounds(config)?;
    validate_routing(config, &users, &outbounds)?;
    validate_handoff_egress(config)?;
    validate_handoff_key_independence(config)?;
    validate_policy(config)
}

fn validate_network(config: &Config) -> Result<(), ConfigError> {
    let dial = &config.network.dial;
    if dial.fallback_delay_ms > 5_000 {
        return fail("network.dial.fallbackDelayMs", "must be at most 5000");
    }
    if !(1..=3_600).contains(&dial.route_refresh_seconds) {
        return fail(
            "network.dial.routeRefreshSeconds",
            "must be between 1 and 3600",
        );
    }
    if !(1..=3_600).contains(&dial.hard_failure_penalty_seconds) {
        return fail(
            "network.dial.hardFailurePenaltySeconds",
            "must be between 1 and 3600",
        );
    }
    if !(1..=86_400).contains(&dial.latency_memory_seconds) {
        return fail(
            "network.dial.latencyMemorySeconds",
            "must be between 1 and 86400",
        );
    }
    Ok(())
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
    validate_dns_servers(&config.dns)?;
    validate_timeout("dns.timeoutMs", config.dns.timeout_ms)?;
    validate_dns_cache(&config.dns.cache)
}

/// Upper bound for every DNS cache entry count and TTL field.
const MAX_DNS_CACHE_ENTRIES: u32 = 65_536;
/// Upper bound for DNS cache TTL fields (one day).
const MAX_DNS_TTL_SECONDS: u32 = 86_400;

fn validate_dns_servers(dns: &crate::config::DnsConfig) -> Result<(), ConfigError> {
    if dns.servers.is_empty() {
        return fail(
            "dns.servers",
            "must name the system resolver or upstream servers",
        );
    }
    let system = dns
        .servers
        .iter()
        .filter(|server| server.as_str() == "system")
        .count();
    if system > 0 && dns.servers.len() > 1 {
        return fail(
            "dns.servers",
            "the system resolver must not be mixed with upstream DNS servers",
        );
    }
    if system == 1 {
        return Ok(());
    }
    for (index, server) in dns.servers.iter().enumerate() {
        crate::server::dns::parse_server_spec(server).map_err(|reason| {
            ConfigError::new(format!("dns.servers[{index}]"), reason.to_string())
        })?;
    }
    Ok(())
}

fn validate_dns_cache(cache: &crate::config::DnsCacheConfig) -> Result<(), ConfigError> {
    if !(1..=MAX_DNS_CACHE_ENTRIES).contains(&cache.max_entries) {
        return fail(
            "dns.cache.maxEntries",
            format!("must be between 1 and {MAX_DNS_CACHE_ENTRIES}"),
        );
    }
    if cache.max_ttl_seconds == 0 || cache.max_ttl_seconds > MAX_DNS_TTL_SECONDS {
        return fail(
            "dns.cache.maxTtlSeconds",
            format!("must be between 1 and {MAX_DNS_TTL_SECONDS}"),
        );
    }
    if cache.min_ttl_seconds > cache.max_ttl_seconds {
        return fail(
            "dns.cache.minTtlSeconds",
            "must not exceed dns.cache.maxTtlSeconds",
        );
    }
    if cache.negative_ttl_seconds > MAX_DNS_TTL_SECONDS {
        return fail(
            "dns.cache.negativeTtlSeconds",
            format!("must not exceed {MAX_DNS_TTL_SECONDS}"),
        );
    }
    if cache.static_ttl_seconds == 0 || cache.static_ttl_seconds > MAX_DNS_TTL_SECONDS {
        return fail(
            "dns.cache.staticTtlSeconds",
            format!("must be between 1 and {MAX_DNS_TTL_SECONDS}"),
        );
    }
    Ok(())
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
        for address in ConnectionPlanner::listener_addresses(inbound.listen(), inbound.port()) {
            if !listeners.insert(address) {
                return fail(
                    format!("{path}.port"),
                    "expanded listen address and port are configured more than once",
                );
            }
        }
        match inbound {
            InboundConfig::Vless(inbound) => validate_vless_inbound(&path, inbound, &mut users)?,
            InboundConfig::Nxr(inbound) => validate_nxr_inbound(&path, inbound)?,
            InboundConfig::Handoff(inbound) => validate_handoff_inbound(&path, inbound)?,
        }
    }
    Ok(users)
}

fn validate_vless_inbound(
    path: &str,
    inbound: &VlessInboundConfig,
    users: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let mut short_ids = HashSet::new();
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
        if client.short_ids.is_empty() {
            return fail(
                format!("{client_path}.shortIds"),
                "must contain at least one short ID owned by this UUID",
            );
        }
        for (short_index, short_id) in client.short_ids.iter().enumerate() {
            let short_path = format!("{client_path}.shortIds[{short_index}]");
            if !(2..=16).contains(&short_id.len())
                || !short_id.len().is_multiple_of(2)
                || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return fail(short_path, "must be 2 to 16 even hexadecimal characters");
            }
            if !short_ids.insert(short_id.to_ascii_lowercase()) {
                return fail(
                    short_path,
                    "short ID is already owned by another entry in this inbound",
                );
            }
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

fn validate_handoff_inbound(path: &str, inbound: &HandoffInboundConfig) -> Result<(), ConfigError> {
    let settings = &inbound.settings;
    validate_base64_key(
        &format!("{path}.settings.preSharedKey"),
        &settings.pre_shared_key,
    )?;
    validate_base64_key(
        &format!("{path}.settings.privateKey"),
        &settings.private_key,
    )?;
    validate_handoff_previous_keys(
        &format!("{path}.settings.previousPreSharedKeys"),
        &settings.previous_pre_shared_keys,
        &settings.pre_shared_key,
    )?;
    validate_handoff_previous_keys(
        &format!("{path}.settings.previousPrivateKeys"),
        &settings.previous_private_keys,
        &settings.private_key,
    )?;
    if !(1..=MAX_HANDOFF_TIME_DIFFERENCE_SECONDS).contains(&settings.max_time_difference_seconds) {
        return fail(
            format!("{path}.settings.maxTimeDifferenceSeconds"),
            format!("must be between 1 and {MAX_HANDOFF_TIME_DIFFERENCE_SECONDS}"),
        );
    }
    if !(1..=MAX_HANDOFF_NONCE_ENTRIES).contains(&settings.max_nonce_entries) {
        return fail(
            format!("{path}.settings.maxNonceEntries"),
            format!("must be between 1 and {MAX_HANDOFF_NONCE_ENTRIES}"),
        );
    }
    let minimum_retention = settings
        .max_time_difference_seconds
        .saturating_mul(2)
        .saturating_add(1);
    if !(minimum_retention..=MAX_HANDOFF_NONCE_RETENTION_SECONDS)
        .contains(&settings.nonce_retention_seconds)
    {
        return fail(
            format!("{path}.settings.nonceRetentionSeconds"),
            format!(
                "must be between {minimum_retention} and {MAX_HANDOFF_NONCE_RETENTION_SECONDS}"
            ),
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

/// Validates one retired-key list of a Handoff rotation window.
///
/// Each entry must be an independent 32-byte base64 key, the list is bounded
/// at [`MAX_HANDOFF_PREVIOUS_KEYS`], no entry repeats inside the list, and no
/// entry equals the active key it retired from — a previous key that still
/// matches the active key would silently mark an open window that rotates
/// nothing. The active key is shape-validated by the caller first, so its
/// decode cannot fail here.
fn validate_handoff_previous_keys(
    path: &str,
    keys: &[SecretString],
    active: &SecretString,
) -> Result<(), ConfigError> {
    if keys.len() > MAX_HANDOFF_PREVIOUS_KEYS {
        return fail(
            path,
            format!("must contain at most {MAX_HANDOFF_PREVIOUS_KEYS} retired keys"),
        );
    }
    let active = decode_key_material(active);
    let mut seen: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let entry_path = format!("{path}[{index}]");
        validate_base64_key(&entry_path, key)?;
        let decoded =
            decode_key_material(key).expect("a key that just passed shape validation must decode");
        if active
            .as_ref()
            .is_some_and(|active| active.as_slice() == decoded.as_slice())
        {
            return fail(entry_path, "must differ from the active key it retires");
        }
        if seen
            .iter()
            .any(|other| other.as_slice() == decoded.as_slice())
        {
            return fail(entry_path, "retired key is configured more than once");
        }
        seen.push(decoded);
    }
    Ok(())
}

/// Enforces that a Handoff landing's egress selects a dialable outbound.
///
/// The egress tag must reference a configured outbound, and that outbound
/// must not be `handoff`-typed: a landing that transferred its sessions onward
/// would chain landings and recurse the transfer protocol, so direct, SOCKS5,
/// NXR, and blackhole transports are the only dial targets a landing accepts.
fn validate_handoff_egress(config: &Config) -> Result<(), ConfigError> {
    for (index, inbound) in config.inbounds.iter().enumerate() {
        let InboundConfig::Handoff(inbound) = inbound else {
            continue;
        };
        let Some(egress) = &inbound.settings.egress else {
            continue;
        };
        let path = format!("inbounds[{index}].settings.egress");
        let outbound = config
            .outbounds
            .iter()
            .find(|outbound| outbound.tag() == egress);
        match outbound {
            None => {
                return fail(path, "must reference a configured outbound tag");
            }
            Some(OutboundConfig::Handoff { .. }) => {
                return fail(
                    path,
                    "must not reference a handoff outbound; landing chaining is not supported",
                );
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Enforces Handoff key independence within one configuration file.
///
/// A Handoff pre-shared key or static private key MUST be generated
/// independently of the NXR pre-shared keys and the REALITY private keys —
/// and a retired key accepted during a rotation window carries exactly the
/// same requirement, so the previous-key lists are compared against the same
/// material. Same-file reuse is exactly the copy-paste error an operator
/// makes, and it is cheap to reject here. Cross-node reuse remains an
/// operator obligation.
fn validate_handoff_key_independence(config: &Config) -> Result<(), ConfigError> {
    let mut nxr_psks: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut reality_keys: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    for inbound in &config.inbounds {
        match inbound {
            InboundConfig::Vless(inbound) => {
                if let Some(key) =
                    decode_key_material(&inbound.stream_settings.reality_settings.private_key)
                {
                    reality_keys.push(key);
                }
            }
            InboundConfig::Nxr(inbound) => {
                if let Some(key) = decode_key_material(&inbound.settings.pre_shared_key) {
                    nxr_psks.push(key);
                }
            }
            InboundConfig::Handoff(_) => {}
        }
    }
    for outbound in &config.outbounds {
        if let OutboundConfig::Nxr { settings, .. } = outbound
            && let Some(key) = decode_key_material(&settings.pre_shared_key)
        {
            nxr_psks.push(key);
        }
    }
    for (index, inbound) in config.inbounds.iter().enumerate() {
        let InboundConfig::Handoff(inbound) = inbound else {
            continue;
        };
        let path = format!("inbounds[{index}].settings");
        if shares_key_material(&inbound.settings.pre_shared_key, &nxr_psks) {
            return fail(
                format!("{path}.preSharedKey"),
                "must be generated independently of every NXR preSharedKey in this configuration",
            );
        }
        if shares_key_material(&inbound.settings.pre_shared_key, &reality_keys) {
            return fail(
                format!("{path}.preSharedKey"),
                "must be generated independently of every REALITY privateKey in this configuration",
            );
        }
        if shares_key_material(&inbound.settings.private_key, &reality_keys) {
            return fail(
                format!("{path}.privateKey"),
                "must be generated independently of every REALITY privateKey in this configuration",
            );
        }
        for (key_index, key) in inbound.settings.previous_pre_shared_keys.iter().enumerate() {
            let path = format!("{path}.previousPreSharedKeys[{key_index}]");
            if shares_key_material(key, &nxr_psks) {
                return fail(
                    path,
                    "must be generated independently of every NXR preSharedKey in this configuration",
                );
            }
            if shares_key_material(key, &reality_keys) {
                return fail(
                    path,
                    "must be generated independently of every REALITY privateKey in this configuration",
                );
            }
        }
        for (key_index, key) in inbound.settings.previous_private_keys.iter().enumerate() {
            if shares_key_material(key, &reality_keys) {
                return fail(
                    format!("{path}.previousPrivateKeys[{key_index}]"),
                    "must be generated independently of every REALITY privateKey in this configuration",
                );
            }
        }
    }
    for (index, outbound) in config.outbounds.iter().enumerate() {
        let OutboundConfig::Handoff { settings, .. } = outbound else {
            continue;
        };
        if shares_key_material(&settings.pre_shared_key, &nxr_psks) {
            return fail(
                format!("outbounds[{index}].settings.preSharedKey"),
                "must be generated independently of every NXR preSharedKey in this configuration",
            );
        }
        if shares_key_material(&settings.pre_shared_key, &reality_keys) {
            return fail(
                format!("outbounds[{index}].settings.preSharedKey"),
                "must be generated independently of every REALITY privateKey in this configuration",
            );
        }
    }
    Ok(())
}

/// Decodes one already shape-validated base64 key for cross-field comparison;
/// undecodable keys are reported by the field-level validators.
fn decode_key_material(key: &SecretString) -> Option<Zeroizing<Vec<u8>>> {
    BASE64_URL_SAFE_NO_PAD
        .decode(key.expose())
        .ok()
        .map(Zeroizing::new)
}

fn shares_key_material(key: &SecretString, others: &[Zeroizing<Vec<u8>>]) -> bool {
    decode_key_material(key).is_some_and(|key| {
        others
            .iter()
            .any(|other| other.as_slice() == key.as_slice())
    })
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
            OutboundConfig::Handoff { settings, .. } => {
                validate_hostname_or_ip(&format!("{path}.settings.address"), &settings.address)?;
                if settings.port == 0 {
                    return fail(format!("{path}.settings.port"), "must be greater than zero");
                }
                validate_base64_key(
                    &format!("{path}.settings.preSharedKey"),
                    &settings.pre_shared_key,
                )?;
                let public = BASE64_URL_SAFE_NO_PAD
                    .decode(&settings.landing_public_key)
                    .map_err(|_| {
                        ConfigError::new(
                            format!("{path}.settings.landingPublicKey"),
                            "must be URL-safe unpadded base64",
                        )
                    })?;
                if public.len() != 32 {
                    return fail(
                        format!("{path}.settings.landingPublicKey"),
                        "must decode to exactly 32 bytes",
                    );
                }
                validate_timeout(
                    &format!("{path}.settings.connectTimeoutMs"),
                    settings.connect_timeout_ms,
                )?;
                if !(MIN_HANDOFF_FIRST_BYTE_TIMEOUT_MS..=MAX_TIMEOUT_MS)
                    .contains(&settings.first_byte_timeout_ms)
                {
                    return fail(
                        format!("{path}.settings.firstByteTimeoutMs"),
                        format!(
                            "must be between {MIN_HANDOFF_FIRST_BYTE_TIMEOUT_MS} and {MAX_TIMEOUT_MS}"
                        ),
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
    for (index, network) in rule.network.iter().enumerate() {
        if *network != Network::Tcp {
            return fail(
                format!("{path}.network[{index}]"),
                "only tcp flows exist, so a udp rule can never match; remove the rule",
            );
        }
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
    if barrier.max_per_second > MAX_DIRECT_DIALS_PER_SECOND {
        return fail(
            "policy.directBarrier.maxPerSecond",
            format!("must not exceed {MAX_DIRECT_DIALS_PER_SECOND}"),
        );
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
    use std::net::IpAddr;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    use crate::config::{
        Config, DialMode, ListenConfig, ListenMode, LogOutput, NxrInboundConfig,
        NxrInboundSettings, NxrSettings, OutboundConfig, SecretString, validate_config,
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
    fn rejects_direct_rate_finer_than_the_monotonic_clock_domain() {
        let mut config = valid_config();
        config.policy.direct_barrier.max_per_second = 1_000_000_001;

        assert_eq!(
            validate_config(&config)
                .expect_err("sub-nanosecond rates cannot be represented exactly")
                .path(),
            "policy.directBarrier.maxPerSecond"
        );
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
    fn rejects_short_id_reused_by_another_uuid() {
        let mut config = valid_config();
        let inbound = config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS");
        let mut second = inbound.settings.clients[0].clone();
        second.id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned();
        second.short_ids = vec!["0123456789ABCDEF".to_owned()];
        inbound.settings.clients.push(second);

        assert_eq!(
            validate_config(&config)
                .expect_err("one short ID cannot belong to two UUIDs")
                .path(),
            "inbounds[0].settings.clients[1].shortIds[0]"
        );
    }

    #[test]
    fn requires_at_least_one_short_id_per_uuid() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must contain VLESS")
            .settings
            .clients[0]
            .short_ids
            .clear();

        assert_eq!(
            validate_config(&config)
                .expect_err("every UUID must own a short ID")
                .path(),
            "inbounds[0].settings.clients[0].shortIds"
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
    fn rejects_expanded_dual_stack_listener_collisions() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must be VLESS")
            .listen = ListenConfig {
            mode: ListenMode::DualStack,
            ..ListenConfig::default()
        };
        let mut duplicate = config.inbounds[0].clone();
        let duplicate_vless = duplicate
            .as_vless_mut()
            .expect("fixture must contain VLESS");
        duplicate_vless.tag = "duplicate-inbound".to_owned();
        duplicate_vless.listen = ListenConfig {
            mode: ListenMode::Ipv6Only,
            ..ListenConfig::default()
        };
        duplicate_vless.settings.clients[0].id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned();
        config.inbounds.push(duplicate);

        let error = validate_config(&config).expect_err("expanded sockets must collide");
        assert_eq!(error.path(), "inbounds[1].port");
    }

    #[test]
    fn validates_listener_topology_independently_from_dial_mode() {
        let mut config = valid_config();
        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must be VLESS")
            .listen = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into();
        config.network.dial.mode = DialMode::Ipv6Only;
        validate_config(&config).expect("IPv4 listen and IPv6-only dialing are independent");

        config.inbounds[0]
            .as_vless_mut()
            .expect("fixture must be VLESS")
            .listen = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST).into();
        config.network.dial.mode = DialMode::Ipv4Only;
        validate_config(&config).expect("IPv6 listen and IPv4-only dialing are independent");
    }

    #[test]
    fn rejects_network_timing_values_outside_their_bounds() {
        let mut config = valid_config();
        config.network.dial.fallback_delay_ms = 5_001;
        assert_eq!(
            validate_config(&config)
                .expect_err("fallback bound must hold")
                .path(),
            "network.dial.fallbackDelayMs"
        );

        let mut config = valid_config();
        config.network.dial.route_refresh_seconds = 0;
        assert_eq!(
            validate_config(&config)
                .expect_err("route lifetime must be positive")
                .path(),
            "network.dial.routeRefreshSeconds"
        );

        let mut config = valid_config();
        config.network.dial.hard_failure_penalty_seconds = 3_601;
        assert_eq!(
            validate_config(&config)
                .expect_err("penalty bound must hold")
                .path(),
            "network.dial.hardFailurePenaltySeconds"
        );

        let mut config = valid_config();
        config.network.dial.latency_memory_seconds = 0;
        assert_eq!(
            validate_config(&config)
                .expect_err("health lifetime must be positive")
                .path(),
            "network.dial.latencyMemorySeconds"
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
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
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
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
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
    fn accepts_internal_handoff_listener_and_outbound_independently() {
        let mut config = valid_config();
        let key = SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo");
        config.inbounds.push(crate::config::InboundConfig::Handoff(
            crate::config::HandoffInboundConfig {
                tag: "handoff-landing".to_owned(),
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                port: 9444,
                settings: crate::config::HandoffInboundSettings {
                    pre_shared_key: key.clone(),
                    private_key: key,
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 120,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                    egress: None,
                    previous_pre_shared_keys: Vec::new(),
                    previous_private_keys: Vec::new(),
                },
            },
        ));
        config.outbounds.push(OutboundConfig::Handoff {
            tag: "handoff-line".to_owned(),
            settings: crate::config::HandoffSettings {
                address: "10.0.0.3".to_owned(),
                port: 9444,
                pre_shared_key: SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"),
                landing_public_key: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
                connect_timeout_ms: 10_000,
                first_byte_timeout_ms: 15_000,
            },
        });

        validate_config(&config).expect("handoff listener and outbound must validate");
    }

    fn handoff_landing_inbound(egress: Option<&str>) -> crate::config::InboundConfig {
        let key = SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo");
        crate::config::InboundConfig::Handoff(crate::config::HandoffInboundConfig {
            tag: "handoff-landing".to_owned(),
            listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
            port: 9444,
            settings: crate::config::HandoffInboundSettings {
                pre_shared_key: key.clone(),
                private_key: key,
                max_time_difference_seconds: 30,
                max_nonce_entries: 4_096,
                nonce_retention_seconds: 120,
                authentication_timeout_ms: 3_000,
                connect_timeout_ms: 10_000,
                egress: egress.map(str::to_owned),
                previous_pre_shared_keys: Vec::new(),
                previous_private_keys: Vec::new(),
            },
        })
    }

    #[test]
    fn rejects_handoff_egress_with_an_unknown_tag() {
        let mut config = valid_config();
        config
            .inbounds
            .push(handoff_landing_inbound(Some("missing")));

        let error = validate_config(&config).expect_err("an unknown egress tag must fail");
        assert_eq!(error.path(), "inbounds[1].settings.egress");
        assert_eq!(error.message(), "must reference a configured outbound tag");
    }

    #[test]
    fn rejects_handoff_egress_chaining_a_handoff_outbound() {
        let mut config = valid_config();
        config
            .inbounds
            .push(handoff_landing_inbound(Some("handoff-line")));
        config.outbounds.push(OutboundConfig::Handoff {
            tag: "handoff-line".to_owned(),
            settings: crate::config::HandoffSettings {
                address: "10.0.0.3".to_owned(),
                port: 9444,
                pre_shared_key: SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"),
                landing_public_key: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
                connect_timeout_ms: 10_000,
                first_byte_timeout_ms: 15_000,
            },
        });

        let error = validate_config(&config)
            .expect_err("a handoff-typed egress must fail: landings cannot be chained");
        assert_eq!(error.path(), "inbounds[1].settings.egress");
    }

    #[test]
    fn accepts_handoff_egress_to_dialable_outbounds() {
        let key = SecretString::new("WVpZWVpZWVpZWVpZWVpZWVpZWVpZWVpZWVpZWVpZWVo");
        for tag in ["direct", "block", "socks", "nxr-hop"] {
            let mut config = valid_config();
            config.inbounds.push(handoff_landing_inbound(Some(tag)));
            config.outbounds.push(OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: crate::config::Socks5Settings {
                    address: "10.0.0.4".to_owned(),
                    port: 1080,
                    username: None,
                    password: None,
                },
            });
            config.outbounds.push(OutboundConfig::Nxr {
                tag: "nxr-hop".to_owned(),
                settings: crate::config::NxrSettings {
                    address: "10.0.0.5".to_owned(),
                    port: 9443,
                    pre_shared_key: key.clone(),
                },
            });

            validate_config(&config)
                .unwrap_or_else(|error| panic!("egress to `{tag}` must validate: {error}"));
        }
    }

    #[test]
    fn handoff_inbound_settings_decode_without_egress() {
        let settings: crate::config::HandoffInboundSettings = serde_json::from_str(
            r#"{
                "preSharedKey": "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
                "privateKey": "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"
            }"#,
        )
        .expect("handoff inbound settings must decode");
        assert_eq!(
            settings.egress, None,
            "a missing field must default to None"
        );
    }

    #[test]
    fn rejects_handoff_key_material_that_is_not_32_byte_base64() {
        let mut config = valid_config();
        config.outbounds.push(OutboundConfig::Handoff {
            tag: "handoff-line".to_owned(),
            settings: crate::config::HandoffSettings {
                address: "10.0.0.3".to_owned(),
                port: 9444,
                pre_shared_key: SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"),
                landing_public_key: "not-base64!".to_owned(),
                connect_timeout_ms: 10_000,
                first_byte_timeout_ms: 15_000,
            },
        });

        assert_eq!(
            validate_config(&config)
                .expect_err("a malformed landing public key must fail")
                .path(),
            "outbounds[2].settings.landingPublicKey"
        );
    }

    #[test]
    fn handoff_first_byte_timeout_is_bounded_and_defaults() {
        for (value, expect_valid) in [
            (0_u64, false),
            (999, false),
            (1_000, true),
            (600_000, true),
            (600_001, false),
        ] {
            let mut config = valid_config();
            config.outbounds.push(OutboundConfig::Handoff {
                tag: "handoff-line".to_owned(),
                settings: crate::config::HandoffSettings {
                    address: "10.0.0.3".to_owned(),
                    port: 9444,
                    pre_shared_key: SecretString::new(
                        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
                    ),
                    landing_public_key: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
                    connect_timeout_ms: 10_000,
                    first_byte_timeout_ms: value,
                },
            });
            let result = validate_config(&config);
            if expect_valid {
                result.expect("an in-bounds first-byte timeout must validate");
            } else {
                assert_eq!(
                    result
                        .expect_err("an out-of-bounds first-byte timeout must fail")
                        .path(),
                    "outbounds[2].settings.firstByteTimeoutMs"
                );
            }
        }

        let settings: crate::config::HandoffSettings = serde_json::from_str(
            r#"{
                "address": "10.0.0.3",
                "port": 9444,
                "preSharedKey": "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
                "landingPublicKey": "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
                "connectTimeoutMs": 10000
            }"#,
        )
        .expect("handoff settings must decode");
        assert_eq!(
            settings.first_byte_timeout_ms, 15_000,
            "a missing field must default to 15 s"
        );
    }

    #[test]
    fn handoff_replay_retention_covers_the_entire_timestamp_window() {
        let mut config = valid_config();
        let key = SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo");
        config.inbounds.push(crate::config::InboundConfig::Handoff(
            crate::config::HandoffInboundConfig {
                tag: "handoff-landing".to_owned(),
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                port: 9444,
                settings: crate::config::HandoffInboundSettings {
                    pre_shared_key: key.clone(),
                    private_key: key,
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 60,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                    egress: None,
                    previous_pre_shared_keys: Vec::new(),
                    previous_private_keys: Vec::new(),
                },
            },
        ));

        assert_eq!(
            validate_config(&config)
                .expect_err("short replay retention must fail")
                .path(),
            "inbounds[1].settings.nonceRetentionSeconds"
        );
    }

    #[test]
    fn rejects_handoff_psk_shared_with_nxr() {
        let shared = SecretString::new("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo");
        // Handoff inbound reusing an NXR inbound's PSK.
        let mut config = valid_config();
        config
            .inbounds
            .push(crate::config::InboundConfig::Nxr(NxrInboundConfig {
                tag: "landing-internal".to_owned(),
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                port: 9443,
                settings: NxrInboundSettings {
                    pre_shared_key: shared.clone(),
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 120,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                },
            }));
        config.inbounds.push(crate::config::InboundConfig::Handoff(
            crate::config::HandoffInboundConfig {
                tag: "handoff-landing".to_owned(),
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                port: 9444,
                settings: crate::config::HandoffInboundSettings {
                    pre_shared_key: shared.clone(),
                    private_key: SecretString::new("WVpZWVpZWVpZWVpZWVpZWVpZWVpZWVpZWVpZWVpZWVo"),
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 120,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                    egress: None,
                    previous_pre_shared_keys: Vec::new(),
                    previous_private_keys: Vec::new(),
                },
            },
        ));
        assert_eq!(
            validate_config(&config)
                .expect_err("a shared Handoff/NXR PSK must fail")
                .path(),
            "inbounds[2].settings.preSharedKey"
        );

        // Handoff outbound reusing an NXR outbound's PSK.
        let mut config = valid_config();
        config.outbounds.push(OutboundConfig::Nxr {
            tag: "landing".to_owned(),
            settings: NxrSettings {
                address: "127.0.0.1".to_owned(),
                port: 9443,
                pre_shared_key: shared.clone(),
            },
        });
        config.outbounds.push(OutboundConfig::Handoff {
            tag: "handoff-line".to_owned(),
            settings: crate::config::HandoffSettings {
                address: "10.0.0.3".to_owned(),
                port: 9444,
                pre_shared_key: shared,
                landing_public_key: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
                connect_timeout_ms: 10_000,
                first_byte_timeout_ms: 15_000,
            },
        });
        assert_eq!(
            validate_config(&config)
                .expect_err("a shared Handoff/NXR PSK must fail")
                .path(),
            "outbounds[3].settings.preSharedKey"
        );
    }

    #[test]
    fn rejects_handoff_private_key_shared_with_reality() {
        let mut config = valid_config();
        // The fixture REALITY private key, reused as the Handoff static key.
        let shared = SecretString::new("ERERERERERERERERERERERERERERERERERERERERERE");
        config.inbounds.push(crate::config::InboundConfig::Handoff(
            crate::config::HandoffInboundConfig {
                tag: "handoff-landing".to_owned(),
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                port: 9444,
                settings: crate::config::HandoffInboundSettings {
                    pre_shared_key: SecretString::new(
                        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
                    ),
                    private_key: shared,
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 120,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                    egress: None,
                    previous_pre_shared_keys: Vec::new(),
                    previous_private_keys: Vec::new(),
                },
            },
        ));

        assert_eq!(
            validate_config(&config)
                .expect_err("a shared Handoff/REALITY private key must fail")
                .path(),
            "inbounds[1].settings.privateKey"
        );
    }

    #[test]
    fn rejects_handoff_psk_shared_with_reality_private_key() {
        // The two 32-byte secrets coexisting in one generated line.json: the
        // fixture REALITY private key reused as a Handoff outbound PSK.
        let shared = SecretString::new("ERERERERERERERERERERERERERERERERERERERERERE");
        let mut config = valid_config();
        config.outbounds.push(OutboundConfig::Handoff {
            tag: "handoff-line".to_owned(),
            settings: crate::config::HandoffSettings {
                address: "10.0.0.3".to_owned(),
                port: 9444,
                pre_shared_key: shared,
                landing_public_key: "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_owned(),
                connect_timeout_ms: 10_000,
                first_byte_timeout_ms: 15_000,
            },
        });
        assert_eq!(
            validate_config(&config)
                .expect_err("a Handoff PSK equal to a REALITY privateKey must fail")
                .path(),
            "outbounds[2].settings.preSharedKey"
        );
    }

    /// A Handoff landing inbound whose active pair is `[0x5a; 32]` /
    /// `[0x5a; 32]` with the given retired-key lists.
    fn handoff_landing_with_previous(
        previous_psks: Vec<[u8; 32]>,
        previous_secrets: Vec<[u8; 32]>,
    ) -> crate::config::InboundConfig {
        let encode = |bytes: [u8; 32]| SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(bytes));
        let active = encode([0x5a; 32]);
        crate::config::InboundConfig::Handoff(crate::config::HandoffInboundConfig {
            tag: "handoff-landing".to_owned(),
            listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
            port: 9444,
            settings: crate::config::HandoffInboundSettings {
                pre_shared_key: active.clone(),
                private_key: active,
                max_time_difference_seconds: 30,
                max_nonce_entries: 4_096,
                nonce_retention_seconds: 120,
                authentication_timeout_ms: 3_000,
                connect_timeout_ms: 10_000,
                egress: None,
                previous_pre_shared_keys: previous_psks.into_iter().map(encode).collect(),
                previous_private_keys: previous_secrets.into_iter().map(encode).collect(),
            },
        })
    }

    #[test]
    fn accepts_handoff_previous_keys_within_the_rotation_bound() {
        let mut config = valid_config();
        config.inbounds.push(handoff_landing_with_previous(
            vec![[0x5b; 32], [0x5c; 32]],
            vec![[0x5d; 32]],
        ));

        validate_config(&config)
            .expect("two retired PSKs and one retired static key must validate");
    }

    #[test]
    fn rejects_handoff_previous_keys_above_the_rotation_bound() {
        let mut config = valid_config();
        config.inbounds.push(handoff_landing_with_previous(
            vec![[0x5b; 32], [0x5c; 32], [0x5d; 32]],
            Vec::new(),
        ));
        let error = validate_config(&config).expect_err("three retired PSKs must fail");
        assert_eq!(error.path(), "inbounds[1].settings.previousPreSharedKeys");

        let mut config = valid_config();
        config.inbounds.push(handoff_landing_with_previous(
            Vec::new(),
            vec![[0x5b; 32], [0x5c; 32], [0x5d; 32]],
        ));
        let error = validate_config(&config).expect_err("three retired static keys must fail");
        assert_eq!(error.path(), "inbounds[1].settings.previousPrivateKeys");
    }

    #[test]
    fn rejects_malformed_handoff_previous_keys() {
        for (field, bad) in [
            ("previousPreSharedKeys", SecretString::new("not-base64!")),
            ("previousPrivateKeys", SecretString::new("not-base64!")),
        ] {
            let mut config = valid_config();
            let mut inbound = handoff_landing_with_previous(Vec::new(), Vec::new());
            let crate::config::InboundConfig::Handoff(handoff) = &mut inbound else {
                panic!("helper must build a handoff inbound")
            };
            if field == "previousPreSharedKeys" {
                handoff.settings.previous_pre_shared_keys = vec![bad];
            } else {
                handoff.settings.previous_private_keys = vec![bad];
            }
            config.inbounds.push(inbound);
            assert_eq!(
                validate_config(&config)
                    .expect_err("a malformed retired key must fail")
                    .path(),
                format!("inbounds[1].settings.{field}[0]")
            );
        }

        // A well-formed base64 value of the wrong length fails the same way.
        let mut config = valid_config();
        let mut inbound = handoff_landing_with_previous(Vec::new(), Vec::new());
        let crate::config::InboundConfig::Handoff(handoff) = &mut inbound else {
            panic!("helper must build a handoff inbound")
        };
        handoff.settings.previous_private_keys =
            vec![SecretString::new(BASE64_URL_SAFE_NO_PAD.encode([0x5b; 16]))];
        config.inbounds.push(inbound);
        assert_eq!(
            validate_config(&config)
                .expect_err("a 16-byte retired key must fail")
                .path(),
            "inbounds[1].settings.previousPrivateKeys[0]"
        );
    }

    #[test]
    fn rejects_duplicate_handoff_previous_keys_within_a_list() {
        let mut config = valid_config();
        config.inbounds.push(handoff_landing_with_previous(
            vec![[0x5b; 32], [0x5b; 32]],
            Vec::new(),
        ));
        let error = validate_config(&config).expect_err("a repeated retired key must fail");
        assert_eq!(
            error.path(),
            "inbounds[1].settings.previousPreSharedKeys[1]"
        );
        assert_eq!(error.message(), "retired key is configured more than once");
    }

    #[test]
    fn rejects_handoff_previous_keys_equal_to_the_active_key() {
        let mut config = valid_config();
        config
            .inbounds
            .push(handoff_landing_with_previous(vec![[0x5a; 32]], Vec::new()));
        let error =
            validate_config(&config).expect_err("a retired PSK equal to the active PSK must fail");
        assert_eq!(
            error.path(),
            "inbounds[1].settings.previousPreSharedKeys[0]"
        );
        assert_eq!(
            error.message(),
            "must differ from the active key it retires"
        );

        let mut config = valid_config();
        config
            .inbounds
            .push(handoff_landing_with_previous(Vec::new(), vec![[0x5a; 32]]));
        let error = validate_config(&config)
            .expect_err("a retired static key equal to the active static key must fail");
        assert_eq!(error.path(), "inbounds[1].settings.previousPrivateKeys[0]");
    }

    #[test]
    fn rejects_handoff_previous_psk_shared_with_nxr() {
        let mut config = valid_config();
        config
            .inbounds
            .push(crate::config::InboundConfig::Nxr(NxrInboundConfig {
                tag: "landing-internal".to_owned(),
                listen: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into(),
                port: 9443,
                settings: NxrInboundSettings {
                    pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode([0x5b; 32])),
                    max_time_difference_seconds: 30,
                    max_nonce_entries: 4_096,
                    nonce_retention_seconds: 120,
                    authentication_timeout_ms: 3_000,
                    connect_timeout_ms: 10_000,
                },
            }));
        config
            .inbounds
            .push(handoff_landing_with_previous(vec![[0x5b; 32]], Vec::new()));
        assert_eq!(
            validate_config(&config)
                .expect_err("a retired PSK equal to an NXR preSharedKey must fail")
                .path(),
            "inbounds[2].settings.previousPreSharedKeys[0]"
        );
    }

    #[test]
    fn rejects_handoff_previous_keys_shared_with_reality_private_key() {
        // The fixture REALITY private key is `[0x11; 32]`.
        let mut config = valid_config();
        config
            .inbounds
            .push(handoff_landing_with_previous(vec![[0x11; 32]], Vec::new()));
        assert_eq!(
            validate_config(&config)
                .expect_err("a retired PSK equal to a REALITY privateKey must fail")
                .path(),
            "inbounds[1].settings.previousPreSharedKeys[0]"
        );

        let mut config = valid_config();
        config
            .inbounds
            .push(handoff_landing_with_previous(Vec::new(), vec![[0x11; 32]]));
        assert_eq!(
            validate_config(&config)
                .expect_err("a retired static key equal to a REALITY privateKey must fail")
                .path(),
            "inbounds[1].settings.previousPrivateKeys[0]"
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
    fn udp_routing_rules_are_rejected_because_they_can_never_match() {
        let mut config = valid_config();
        config.routing.global_rules[0].network = vec![crate::config::Network::Udp];

        assert_eq!(
            validate_config(&config)
                .expect_err("a udp-only rule must fail validation")
                .path(),
            "routing.globalRules[0].network[0]"
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
    fn accepts_custom_dns_resolvers_with_valid_syntax() {
        let mut config = valid_config();
        config.dns.servers = vec!["1.1.1.1".to_owned(), "[2606:4700:4700::1111]:53".to_owned()];
        validate_config(&config).expect("IP literal resolvers must validate");

        config.dns.servers = vec!["dns.example.com:853".to_owned()];
        validate_config(&config).expect("hostname resolver with port must validate");
    }

    #[test]
    fn rejects_mixed_system_and_custom_dns_resolvers() {
        let mut config = valid_config();
        config.dns.servers = vec!["system".to_owned(), "1.1.1.1".to_owned()];

        assert_eq!(
            validate_config(&config)
                .expect_err("system must not mix with upstream servers")
                .path(),
            "dns.servers"
        );
    }

    #[test]
    fn rejects_invalid_dns_server_entries() {
        for servers in [
            vec![String::new()],
            vec!["1.1.1.1:99999".to_owned()],
            vec!["-bad-.example.com".to_owned()],
            vec!["example.com:noport".to_owned()],
        ] {
            let mut config = valid_config();
            config.dns.servers = servers;
            assert!(
                validate_config(&config).is_err(),
                "invalid dns.servers must be rejected"
            );
        }
    }

    #[test]
    fn rejects_incoherent_dns_cache_bounds() {
        let mut config = valid_config();
        config.dns.cache.max_entries = 0;
        assert_eq!(
            validate_config(&config)
                .expect_err("zero-entry cache must be rejected")
                .path(),
            "dns.cache.maxEntries"
        );

        let mut config = valid_config();
        config.dns.cache.min_ttl_seconds = 600;
        config.dns.cache.max_ttl_seconds = 60;
        assert_eq!(
            validate_config(&config)
                .expect_err("min TTL above max TTL must be rejected")
                .path(),
            "dns.cache.minTtlSeconds"
        );

        let mut config = valid_config();
        config.dns.cache.static_ttl_seconds = 0;
        assert_eq!(
            validate_config(&config)
                .expect_err("zero static TTL must be rejected")
                .path(),
            "dns.cache.staticTtlSeconds"
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
