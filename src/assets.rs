use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use arc_swap::ArcSwap;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use ureq::{
    Agent,
    http::header::{
        ACCEPT, ACCEPT_ENCODING, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
    },
};

use crate::config::Config;

/// Immutable GeoIP/GeoSite lookup used by one routing snapshot.
pub trait AssetMatcher: Send + Sync {
    /// Returns whether a domain belongs to one compiled asset label.
    fn matches_domain(&self, source: &AssetSource, label: &str, domain: &str) -> bool;

    /// Returns whether an address belongs to one compiled asset label.
    fn matches_ip(&self, source: &AssetSource, label: &str, address: IpAddr) -> bool;
}

/// Asset origin for community default files or `ext:file:tag` matchers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum AssetSource {
    GeoSite,
    GeoIp,
    External(Arc<str>),
}

/// Empty initial snapshot: static rules work while missing asset labels never match.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyAssetMatcher;

impl AssetMatcher for EmptyAssetMatcher {
    fn matches_domain(&self, _source: &AssetSource, _label: &str, _domain: &str) -> bool {
        false
    }

    fn matches_ip(&self, _source: &AssetSource, _label: &str, _address: IpAddr) -> bool {
        false
    }
}

type DomainSets = HashMap<AssetSource, HashMap<String, DomainSet>>;
type IpSets = HashMap<AssetSource, HashMap<String, IpSet>>;

/// One complete parsed asset generation retained by active routing snapshots.
pub struct AssetSnapshot {
    generation: u64,
    domains: DomainSets,
    ips: IpSets,
}

impl AssetSnapshot {
    /// Loads only files referenced by configured routing rules.
    ///
    /// Each file is read through a hard byte limit. The returned snapshot is
    /// complete or an error; partial label sets are never published.
    ///
    /// # Errors
    ///
    /// Returns an I/O, size, protobuf, UTF-8, regex, or network error.
    pub fn load(config: &Config) -> Result<Self, AssetLoadError> {
        Self::load_generation(config, 0)
    }

    /// Returns the monotonically increasing publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns non-sensitive counts for startup and self-test output.
    #[must_use]
    pub fn summary(&self) -> AssetSummary {
        AssetSummary {
            generation: self.generation,
            domain_sources: self.domains.len(),
            domain_labels: self.domains.values().map(HashMap::len).sum(),
            ip_sources: self.ips.len(),
            ip_labels: self.ips.values().map(HashMap::len).sum(),
        }
    }

    pub(crate) fn load_generation(
        config: &Config,
        generation: u64,
    ) -> Result<Self, AssetLoadError> {
        let requirements = AssetRequirements::from_config(config);
        let maximum = usize::try_from(config.assets.max_bytes)
            .map_err(|_| AssetLoadError::SizeLimitUnsupported)?;
        let fetcher = AssetFetcher::new(config);
        let mut cache_updates = Vec::new();
        let mut domains = HashMap::new();
        let mut ips = HashMap::new();

        if !requirements.geosite.is_empty() {
            let candidate = fetcher.fetch("geosite.dat", &config.assets.geosite, maximum)?;
            let (parsed, update) = parse_candidate(candidate, maximum, |input| {
                parse_geosite_list(input, &requirements.geosite)
            })?;
            domains.insert(AssetSource::GeoSite, parsed);
            cache_updates.extend(update);
        }
        if !requirements.geoip.is_empty() {
            let candidate = fetcher.fetch("geoip.dat", &config.assets.geoip, maximum)?;
            let (parsed, update) = parse_candidate(candidate, maximum, |input| {
                parse_geoip_list(input, &requirements.geoip)
            })?;
            ips.insert(AssetSource::GeoIp, parsed);
            cache_updates.extend(update);
        }
        for (file, labels) in requirements.external_domains {
            let path = resolve_external(&config.assets.cache_directory, &file)?;
            let bytes = read_bounded(&path, maximum)?;
            domains.insert(
                AssetSource::External(Arc::from(file)),
                parse_geosite_list(&bytes, &labels)?,
            );
        }
        for (file, labels) in requirements.external_ips {
            let path = resolve_external(&config.assets.cache_directory, &file)?;
            let bytes = read_bounded(&path, maximum)?;
            ips.insert(
                AssetSource::External(Arc::from(file)),
                parse_geoip_list(&bytes, &labels)?,
            );
        }

        for update in cache_updates {
            update.commit()?;
        }

        Ok(Self {
            generation,
            domains,
            ips,
        })
    }
}

/// Non-sensitive description of one loaded asset generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetSummary {
    pub generation: u64,
    pub domain_sources: usize,
    pub domain_labels: usize,
    pub ip_sources: usize,
    pub ip_labels: usize,
}

impl AssetMatcher for AssetSnapshot {
    fn matches_domain(&self, source: &AssetSource, label: &str, domain: &str) -> bool {
        self.domains
            .get(source)
            .and_then(|labels| labels.get(label))
            .is_some_and(|set| set.matches(domain))
    }

    fn matches_ip(&self, source: &AssetSource, label: &str, address: IpAddr) -> bool {
        self.ips
            .get(source)
            .and_then(|labels| labels.get(label))
            .is_some_and(|set| set.matches(address))
    }
}

impl fmt::Debug for AssetSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let domain_labels: usize = self.domains.values().map(HashMap::len).sum();
        let ip_labels: usize = self.ips.values().map(HashMap::len).sum();
        formatter
            .debug_struct("AssetSnapshot")
            .field("generation", &self.generation)
            .field("domain_labels", &domain_labels)
            .field("ip_labels", &ip_labels)
            .finish()
    }
}

/// Lock-free publication of complete last-good asset generations.
pub struct AssetStore {
    current: ArcSwap<AssetSnapshot>,
    generation: AtomicU64,
    update: Mutex<()>,
}

impl AssetStore {
    /// Loads generation zero from the current routing requirements.
    ///
    /// # Errors
    ///
    /// Returns an asset load error without constructing a partial store.
    pub fn new(config: &Config) -> Result<Self, AssetLoadError> {
        Ok(Self {
            current: ArcSwap::from_pointee(AssetSnapshot::load_generation(config, 0)?),
            generation: AtomicU64::new(0),
            update: Mutex::new(()),
        })
    }

    /// Acquires the current immutable generation.
    #[must_use]
    pub fn load(&self) -> Arc<AssetSnapshot> {
        self.current.load_full()
    }

    /// Fully parses and atomically publishes a replacement generation.
    ///
    /// Existing connections retain the old snapshot. Any error keeps the current
    /// generation unchanged.
    ///
    /// # Errors
    ///
    /// Returns an asset load or generation exhaustion error.
    pub fn reload(&self, config: &Config) -> Result<u64, AssetUpdateError> {
        let _guard = self
            .update
            .lock()
            .map_err(|_| AssetUpdateError::Unavailable)?;
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(AssetUpdateError::GenerationExhausted)?;
        let snapshot = AssetSnapshot::load_generation(config, generation)?;
        self.generation.store(generation, Ordering::Release);
        self.current.store(Arc::new(snapshot));
        Ok(generation)
    }
}

#[derive(Default)]
struct AssetRequirements {
    geosite: HashSet<String>,
    geoip: HashSet<String>,
    external_domains: HashMap<String, HashSet<String>>,
    external_ips: HashMap<String, HashSet<String>>,
}

impl AssetRequirements {
    fn from_config(config: &Config) -> Self {
        let mut requirements = Self::default();
        for rule in config
            .routing
            .global_rules
            .iter()
            .chain(config.routing.users.iter().flat_map(|policy| &policy.rules))
        {
            for matcher in &rule.domain {
                if matcher
                    .get(..8)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("geosite:"))
                {
                    if let Some(label) = matcher.get(8..) {
                        requirements.geosite.insert(label.to_ascii_lowercase());
                    }
                } else if let Some((file, label)) = parse_external(matcher) {
                    requirements
                        .external_domains
                        .entry(file.to_owned())
                        .or_default()
                        .insert(label.to_ascii_lowercase());
                }
            }
            for matcher in &rule.ip {
                if matcher
                    .get(..6)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("geoip:"))
                {
                    if let Some(label) = matcher.get(6..) {
                        requirements.geoip.insert(label.to_ascii_lowercase());
                    }
                } else if let Some((file, label)) = parse_external(matcher) {
                    requirements
                        .external_ips
                        .entry(file.to_owned())
                        .or_default()
                        .insert(label.to_ascii_lowercase());
                }
            }
        }
        requirements
    }
}

fn parse_external(input: &str) -> Option<(&str, &str)> {
    let prefix = input.get(..4)?;
    if !prefix.eq_ignore_ascii_case("ext:") {
        return None;
    }
    input.get(4..)?.split_once(':')
}

struct AssetFetcher {
    agent: Agent,
    cache_directory: PathBuf,
}

impl AssetFetcher {
    fn new(config: &Config) -> Self {
        let agent_config = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(
                config.assets.request_timeout_seconds,
            )))
            .max_redirects(5)
            .http_status_as_error(false)
            .user_agent("rust-reality-assets/0.1")
            .build();
        Self {
            agent: agent_config.into(),
            cache_directory: config.assets.cache_directory.clone(),
        }
    }

    fn fetch(
        &self,
        name: &str,
        url: &str,
        maximum: usize,
    ) -> Result<AssetCandidate, AssetLoadError> {
        let data_path = self.cache_directory.join(name);
        let metadata_path = self.cache_directory.join(format!("{name}.metadata.json"));
        let metadata = read_cache_metadata(&metadata_path, url);
        let mut request = self
            .agent
            .get(url)
            .header(ACCEPT, "application/octet-stream")
            .header(ACCEPT_ENCODING, "identity");
        if data_path.is_file()
            && let Some(metadata) = &metadata
        {
            if let Some(etag) = &metadata.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &metadata.last_modified {
                request = request.header(IF_MODIFIED_SINCE, last_modified);
            }
        }

        let downloaded = match request.call() {
            Ok(response) => match response.status().as_u16() {
                200 => (|| {
                    let etag = response_header(&response, ETAG);
                    let last_modified = response_header(&response, LAST_MODIFIED);
                    let body_limit = maximum
                        .checked_add(1)
                        .ok_or(AssetLoadError::SizeLimitUnsupported)?;
                    let bytes = response
                        .into_body()
                        .with_config()
                        .limit(
                            u64::try_from(body_limit)
                                .map_err(|_| AssetLoadError::SizeLimitUnsupported)?,
                        )
                        .read_to_vec()
                        .map_err(|error| {
                            if matches!(&error, ureq::Error::BodyExceedsLimit(_)) {
                                AssetLoadError::TooLarge {
                                    path: data_path.clone(),
                                    maximum,
                                }
                            } else {
                                AssetLoadError::Download(AssetDownloadFailure::from_ureq(&error))
                            }
                        })?;
                    if bytes.len() > maximum {
                        return Err(AssetLoadError::TooLarge {
                            path: data_path.clone(),
                            maximum,
                        });
                    }
                    Ok((bytes, etag, last_modified))
                })(),
                304 => Err(AssetLoadError::Download(
                    AssetDownloadFailure::CacheUnavailable,
                )),
                status => Err(AssetLoadError::Download(AssetDownloadFailure::HttpStatus(
                    status,
                ))),
            },
            Err(error) => Err(AssetLoadError::Download(AssetDownloadFailure::from_ureq(
                &error,
            ))),
        };
        match downloaded {
            Ok((bytes, etag, last_modified)) => Ok(AssetCandidate::Downloaded {
                bytes: Arc::from(bytes),
                fallback_path: data_path.clone(),
                update: CacheUpdate {
                    data_path,
                    metadata_path,
                    bytes: Arc::from([]),
                    metadata: CacheMetadata {
                        source: url.to_owned(),
                        etag,
                        last_modified,
                    },
                },
            }
            .with_shared_bytes()),
            Err(AssetLoadError::Download(failure)) => {
                cached_candidate(&data_path, maximum, failure)
            }
            Err(error) => Err(error),
        }
    }
}

enum AssetCandidate {
    Cached(Vec<u8>),
    Downloaded {
        bytes: Arc<[u8]>,
        fallback_path: PathBuf,
        update: CacheUpdate,
    },
}

impl AssetCandidate {
    fn with_shared_bytes(mut self) -> Self {
        if let Self::Downloaded { bytes, update, .. } = &mut self {
            update.bytes = Arc::clone(bytes);
        }
        self
    }
}

fn cached_candidate(
    path: &Path,
    maximum: usize,
    failure: AssetDownloadFailure,
) -> Result<AssetCandidate, AssetLoadError> {
    read_bounded(path, maximum)
        .map(AssetCandidate::Cached)
        .map_err(|_| AssetLoadError::Download(failure))
}

fn parse_candidate<T>(
    candidate: AssetCandidate,
    maximum: usize,
    parse: impl Fn(&[u8]) -> Result<T, AssetLoadError>,
) -> Result<(T, Option<CacheUpdate>), AssetLoadError> {
    match candidate {
        AssetCandidate::Cached(bytes) => parse(&bytes).map(|parsed| (parsed, None)),
        AssetCandidate::Downloaded {
            bytes,
            fallback_path,
            update,
        } => match parse(&bytes) {
            Ok(parsed) => Ok((parsed, Some(update))),
            Err(download_error) => {
                match read_bounded(&fallback_path, maximum).and_then(|cached| parse(&cached)) {
                    Ok(parsed) => Ok((parsed, None)),
                    Err(_) => Err(download_error),
                }
            }
        },
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheMetadata {
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_modified: Option<String>,
}

fn read_cache_metadata(path: &Path, source: &str) -> Option<CacheMetadata> {
    let bytes = read_bounded(path, 16 * 1024).ok()?;
    let metadata: CacheMetadata = serde_json::from_slice(&bytes).ok()?;
    (metadata.source == source).then_some(metadata)
}

fn response_header(
    response: &ureq::http::Response<ureq::Body>,
    name: ureq::http::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 8 * 1024)
        .map(str::to_owned)
}

struct CacheUpdate {
    data_path: PathBuf,
    metadata_path: PathBuf,
    bytes: Arc<[u8]>,
    metadata: CacheMetadata,
}

impl CacheUpdate {
    fn commit(self) -> Result<(), AssetLoadError> {
        let parent = self
            .data_path
            .parent()
            .ok_or(AssetLoadError::InvalidCachePath)?;
        fs::create_dir_all(parent).map_err(|source| AssetLoadError::Io {
            path: parent.to_owned(),
            source,
        })?;
        write_atomic(&self.data_path, &self.bytes)?;
        let metadata =
            serde_json::to_vec(&self.metadata).map_err(|_| AssetLoadError::InvalidCacheMetadata)?;
        write_atomic(&self.metadata_path, &metadata)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AssetLoadError> {
    let parent = path.parent().ok_or(AssetLoadError::InvalidCachePath)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(AssetLoadError::InvalidCachePath)?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| AssetLoadError::Random)?;
    let nonce = u64::from_ne_bytes(random);
    let temporary = parent.join(format!(
        ".{file_name}.{}-{nonce:016x}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| AssetLoadError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.write_all(bytes).map_err(|source| AssetLoadError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| AssetLoadError::Io {
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, path).map_err(|source| AssetLoadError::Io {
            path: path.to_owned(),
            source,
        })?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), AssetLoadError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| AssetLoadError::Io {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), AssetLoadError> {
    Ok(())
}

fn resolve_external(default_file: &Path, external: &str) -> Result<PathBuf, AssetLoadError> {
    let external = Path::new(external);
    if external.is_absolute()
        || external
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(AssetLoadError::InvalidExternalPath);
    }
    Ok(default_file.join(external))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, AssetLoadError> {
    let file = File::open(path).map_err(|source| AssetLoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    if file
        .metadata()
        .map_err(|source| AssetLoadError::Io {
            path: path.to_owned(),
            source,
        })?
        .len()
        > u64::try_from(maximum).map_err(|_| AssetLoadError::SizeLimitUnsupported)?
    {
        return Err(AssetLoadError::TooLarge {
            path: path.to_owned(),
            maximum,
        });
    }
    let read_limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(AssetLoadError::SizeLimitUnsupported)?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| AssetLoadError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(AssetLoadError::TooLarge {
            path: path.to_owned(),
            maximum,
        });
    }
    Ok(bytes)
}

struct DomainSet {
    substrings: Option<AhoCorasick>,
    regexes: Arc<[Regex]>,
    suffixes: HashSet<String>,
    full: HashSet<String>,
}

impl DomainSet {
    fn compile(entries: &[&[u8]]) -> Result<Self, AssetLoadError> {
        let mut substrings = Vec::new();
        let mut regexes = Vec::new();
        let mut suffixes = HashSet::new();
        let mut full = HashSet::new();
        for entry in entries {
            let (kind, value) = parse_domain(entry)?;
            match kind {
                0 => substrings.push(value.to_ascii_lowercase()),
                1 => regexes.push(
                    RegexBuilder::new(value)
                        .case_insensitive(true)
                        .size_limit(2 * 1024 * 1024)
                        .dfa_size_limit(2 * 1024 * 1024)
                        .build()
                        .map_err(|error| match error {
                            regex::Error::CompiledTooBig(_) => AssetLoadError::RegexTooLarge,
                            _ => AssetLoadError::InvalidRegexSyntax,
                        })?,
                ),
                2 => {
                    suffixes.insert(value.trim_start_matches('.').to_ascii_lowercase());
                }
                3 => {
                    full.insert(value.to_ascii_lowercase());
                }
                _ => return Err(AssetLoadError::InvalidDomainType(kind)),
            }
        }
        let substrings = if substrings.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .build(substrings)
                    .map_err(|_| AssetLoadError::InvalidSubstringSet)?,
            )
        };
        Ok(Self {
            substrings,
            regexes: regexes.into(),
            suffixes,
            full,
        })
    }

    fn matches(&self, domain: &str) -> bool {
        let normalized = if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
        let domain = normalized.as_ref();
        self.full.contains(domain)
            || suffix_set_matches(&self.suffixes, domain)
            || self
                .substrings
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(domain))
            || self.regexes.iter().any(|regex| regex.is_match(domain))
    }
}

fn suffix_set_matches(suffixes: &HashSet<String>, domain: &str) -> bool {
    suffixes.contains(domain)
        || domain
            .match_indices('.')
            .any(|(index, _)| suffixes.contains(&domain[index + 1..]))
}

struct IpSet {
    ipv4: PrefixTrie,
    ipv6: PrefixTrie,
    reverse: bool,
}

impl IpSet {
    fn compile(networks: &[&[u8]], reverse: bool) -> Result<Self, AssetLoadError> {
        let mut ipv4 = PrefixTrie::new(32);
        let mut ipv6 = PrefixTrie::new(128);
        for encoded in networks {
            match parse_cidr(encoded)? {
                IpNetwork::V4 { network, prefix } => {
                    ipv4.insert(u128::from(network), prefix)?;
                }
                IpNetwork::V6 { network, prefix } => ipv6.insert(network, prefix)?,
            }
        }
        Ok(Self {
            ipv4,
            ipv6,
            reverse,
        })
    }

    fn matches(&self, address: IpAddr) -> bool {
        let matched = match address {
            IpAddr::V4(address) => self.ipv4.contains(u128::from(u32::from(address))),
            IpAddr::V6(address) => self.ipv6.contains(u128::from(address)),
        };
        matched ^ self.reverse
    }
}

struct PrefixTrie {
    width: u8,
    nodes: Vec<PrefixNode>,
}

impl PrefixTrie {
    fn new(width: u8) -> Self {
        Self {
            width,
            nodes: vec![PrefixNode::default()],
        }
    }

    fn insert(&mut self, value: u128, prefix: u8) -> Result<(), AssetLoadError> {
        let mut node_index = 0_usize;
        for offset in 0..prefix {
            let branch = usize::from(((value >> (self.width - offset - 1)) & 1) != 0);
            let child = if let Some(child) = self.nodes[node_index].children[branch] {
                usize::try_from(child).map_err(|_| AssetLoadError::TooManyNetworks)?
            } else {
                let child =
                    u32::try_from(self.nodes.len()).map_err(|_| AssetLoadError::TooManyNetworks)?;
                self.nodes.push(PrefixNode::default());
                self.nodes[node_index].children[branch] = Some(child);
                usize::try_from(child).map_err(|_| AssetLoadError::TooManyNetworks)?
            };
            node_index = child;
        }
        self.nodes[node_index].terminal = true;
        Ok(())
    }

    fn contains(&self, value: u128) -> bool {
        let mut node_index = 0_usize;
        for offset in 0..self.width {
            let Some(node) = self.nodes.get(node_index) else {
                return false;
            };
            if node.terminal {
                return true;
            }
            let branch = usize::from(((value >> (self.width - offset - 1)) & 1) != 0);
            let Some(child) = node.children[branch] else {
                return false;
            };
            let Ok(child) = usize::try_from(child) else {
                return false;
            };
            node_index = child;
        }
        self.nodes.get(node_index).is_some_and(|node| node.terminal)
    }
}

#[derive(Default)]
struct PrefixNode {
    children: [Option<u32>; 2],
    terminal: bool,
}

#[derive(Clone, Copy)]
enum IpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpNetwork {
    fn new(address: &[u8], prefix: u64) -> Result<Self, AssetLoadError> {
        match address {
            [a, b, c, d] if prefix <= 32 => {
                let prefix = u8::try_from(prefix).map_err(|_| AssetLoadError::InvalidCidr)?;
                let address = u32::from(Ipv4Addr::new(*a, *b, *c, *d));
                Ok(Self::V4 {
                    network: address & mask_u32(prefix),
                    prefix,
                })
            }
            bytes if bytes.len() == 16 && prefix <= 128 => {
                let octets: [u8; 16] = bytes.try_into().map_err(|_| AssetLoadError::InvalidCidr)?;
                let prefix = u8::try_from(prefix).map_err(|_| AssetLoadError::InvalidCidr)?;
                let address = u128::from(Ipv6Addr::from(octets));
                Ok(Self::V6 {
                    network: address & mask_u128(prefix),
                    prefix,
                })
            }
            _ => Err(AssetLoadError::InvalidCidr),
        }
    }
}

const fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn parse_geosite_list(
    input: &[u8],
    required: &HashSet<String>,
) -> Result<HashMap<String, DomainSet>, AssetLoadError> {
    let mut labels = HashMap::new();
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        if let FieldValue::Bytes(message) = field.value
            && field.number == 1
        {
            let (code, entries) = scan_geosite(message)?;
            if required.contains(&code) {
                let set = DomainSet::compile(&entries)?;
                if labels.insert(code.clone(), set).is_some() {
                    return Err(AssetLoadError::DuplicateLabel(code));
                }
            }
        }
    }
    ensure_required_labels(required, &labels)?;
    Ok(labels)
}

fn scan_geosite(input: &[u8]) -> Result<(String, Vec<&[u8]>), AssetLoadError> {
    let mut code = None;
    let mut entries = Vec::new();
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => code = Some(utf8(value)?.to_ascii_lowercase()),
            (2, FieldValue::Bytes(value)) => entries.push(value),
            _ => {}
        }
    }
    let code = code
        .filter(|value| !value.is_empty())
        .ok_or(AssetLoadError::MissingCode)?;
    Ok((code, entries))
}

fn parse_domain(input: &[u8]) -> Result<(u64, &str), AssetLoadError> {
    let mut kind = 0;
    let mut value = None;
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Varint(raw)) => kind = raw,
            (2, FieldValue::Bytes(raw)) => value = Some(utf8(raw)?),
            _ => {}
        }
    }
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or(AssetLoadError::MissingValue)?;
    Ok((kind, value))
}

fn parse_geoip_list(
    input: &[u8],
    required: &HashSet<String>,
) -> Result<HashMap<String, IpSet>, AssetLoadError> {
    let mut labels = HashMap::new();
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        if let FieldValue::Bytes(message) = field.value
            && field.number == 1
        {
            let (code, networks, reverse) = scan_geoip(message)?;
            if required.contains(&code) {
                let set = IpSet::compile(&networks, reverse)?;
                if labels.insert(code.clone(), set).is_some() {
                    return Err(AssetLoadError::DuplicateLabel(code));
                }
            }
        }
    }
    ensure_required_labels(required, &labels)?;
    Ok(labels)
}

fn scan_geoip(input: &[u8]) -> Result<(String, Vec<&[u8]>, bool), AssetLoadError> {
    let mut code = None;
    let mut networks = Vec::new();
    let mut reverse = false;
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => code = Some(utf8(value)?.to_ascii_lowercase()),
            (2, FieldValue::Bytes(value)) => networks.push(value),
            (3, FieldValue::Varint(value)) => reverse = value != 0,
            _ => {}
        }
    }
    let code = code
        .filter(|value| !value.is_empty())
        .ok_or(AssetLoadError::MissingCode)?;
    Ok((code, networks, reverse))
}

fn ensure_required_labels<T>(
    required: &HashSet<String>,
    parsed: &HashMap<String, T>,
) -> Result<(), AssetLoadError> {
    if let Some(missing) = required.iter().find(|label| !parsed.contains_key(*label)) {
        return Err(AssetLoadError::MissingLabel(missing.clone()));
    }
    Ok(())
}

fn parse_cidr(input: &[u8]) -> Result<IpNetwork, AssetLoadError> {
    let mut address = None;
    let mut prefix = 0;
    let mut reader = ProtoReader::new(input);
    while let Some(field) = reader.next()? {
        match (field.number, field.value) {
            (1, FieldValue::Bytes(value)) => address = Some(value),
            (2, FieldValue::Varint(value)) => prefix = value,
            _ => {}
        }
    }
    IpNetwork::new(address.ok_or(AssetLoadError::InvalidCidr)?, prefix)
}

fn utf8(input: &[u8]) -> Result<&str, AssetLoadError> {
    str::from_utf8(input).map_err(|_| AssetLoadError::InvalidUtf8)
}

struct ProtoReader<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> ProtoReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn next(&mut self) -> Result<Option<ProtoField<'a>>, AssetLoadError> {
        if self.cursor == self.input.len() {
            return Ok(None);
        }
        let key = read_varint(self.input, &mut self.cursor)?;
        let number = key >> 3;
        if number == 0 {
            return Err(AssetLoadError::InvalidProtobuf);
        }
        let value = match key & 7 {
            0 => FieldValue::Varint(read_varint(self.input, &mut self.cursor)?),
            1 => {
                skip(self.input, &mut self.cursor, 8)?;
                FieldValue::Ignored
            }
            2 => {
                let length = usize::try_from(read_varint(self.input, &mut self.cursor)?)
                    .map_err(|_| AssetLoadError::InvalidProtobuf)?;
                let end = self
                    .cursor
                    .checked_add(length)
                    .ok_or(AssetLoadError::InvalidProtobuf)?;
                let bytes = self
                    .input
                    .get(self.cursor..end)
                    .ok_or(AssetLoadError::TruncatedProtobuf)?;
                self.cursor = end;
                FieldValue::Bytes(bytes)
            }
            5 => {
                skip(self.input, &mut self.cursor, 4)?;
                FieldValue::Ignored
            }
            _ => return Err(AssetLoadError::InvalidProtobuf),
        };
        Ok(Some(ProtoField { number, value }))
    }
}

struct ProtoField<'a> {
    number: u64,
    value: FieldValue<'a>,
}

enum FieldValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Ignored,
}

fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, AssetLoadError> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input
            .get(*cursor)
            .ok_or(AssetLoadError::TruncatedProtobuf)?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(AssetLoadError::InvalidProtobuf);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(AssetLoadError::InvalidProtobuf)
}

fn skip(input: &[u8], cursor: &mut usize, length: usize) -> Result<(), AssetLoadError> {
    let end = cursor
        .checked_add(length)
        .ok_or(AssetLoadError::InvalidProtobuf)?;
    if end > input.len() {
        return Err(AssetLoadError::TruncatedProtobuf);
    }
    *cursor = end;
    Ok(())
}

/// Loading a complete asset generation failed.
#[derive(Debug)]
pub enum AssetLoadError {
    Io { path: PathBuf, source: io::Error },
    TooLarge { path: PathBuf, maximum: usize },
    Download(AssetDownloadFailure),
    SizeLimitUnsupported,
    InvalidCachePath,
    InvalidExternalPath,
    InvalidCacheMetadata,
    Random,
    InvalidProtobuf,
    TruncatedProtobuf,
    InvalidUtf8,
    MissingCode,
    MissingValue,
    MissingLabel(String),
    InvalidDomainType(u64),
    InvalidRegexSyntax,
    RegexTooLarge,
    InvalidSubstringSet,
    InvalidCidr,
    TooManyNetworks,
    DuplicateLabel(String),
}

impl fmt::Display for AssetLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, .. } => write!(formatter, "failed to read asset {}", path.display()),
            Self::TooLarge { path, maximum } => {
                write!(
                    formatter,
                    "asset {} exceeds {maximum} bytes",
                    path.display()
                )
            }
            Self::Download(reason) => {
                write!(
                    formatter,
                    "asset download failed ({reason}) and validated cache is unavailable"
                )
            }
            Self::SizeLimitUnsupported => formatter.write_str("asset size limit is unsupported"),
            Self::InvalidCachePath => formatter.write_str("asset cache path is invalid"),
            Self::InvalidExternalPath => formatter.write_str("external asset path is invalid"),
            Self::InvalidCacheMetadata => formatter.write_str("asset cache metadata is invalid"),
            Self::Random => formatter.write_str("asset cache nonce generation failed"),
            Self::InvalidProtobuf => formatter.write_str("asset protobuf is invalid"),
            Self::TruncatedProtobuf => formatter.write_str("asset protobuf is truncated"),
            Self::InvalidUtf8 => formatter.write_str("asset text is not valid UTF-8"),
            Self::MissingCode => formatter.write_str("asset entry has no code"),
            Self::MissingValue => formatter.write_str("asset domain has no value"),
            Self::MissingLabel(_) => {
                formatter.write_str("asset does not contain a referenced label")
            }
            Self::InvalidDomainType(kind) => {
                write!(formatter, "asset domain type {kind} is invalid")
            }
            Self::InvalidRegexSyntax => {
                formatter.write_str("asset regular expression syntax is unsupported")
            }
            Self::RegexTooLarge => {
                formatter.write_str("asset regular expression exceeds the compilation limit")
            }
            Self::InvalidSubstringSet => formatter.write_str("asset substring set is invalid"),
            Self::InvalidCidr => formatter.write_str("asset CIDR is invalid"),
            Self::TooManyNetworks => {
                formatter.write_str("asset contains too many network prefixes")
            }
            Self::DuplicateLabel(_) => formatter.write_str("asset contains a duplicate label"),
        }
    }
}

/// Sanitized reason why a remote asset could not replace a validated cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetDownloadFailure {
    BadUrl,
    Timeout,
    NameResolution,
    Tls,
    Redirect,
    HttpStatus(u16),
    Protocol,
    Transport,
    CacheUnavailable,
}

impl AssetDownloadFailure {
    fn from_ureq(error: &ureq::Error) -> Self {
        match error {
            ureq::Error::Http(_) | ureq::Error::BadUri(_) | ureq::Error::RequireHttpsOnly(_) => {
                Self::BadUrl
            }
            ureq::Error::Timeout(_) => Self::Timeout,
            ureq::Error::HostNotFound => Self::NameResolution,
            ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::Pem(_) => Self::Tls,
            ureq::Error::RedirectFailed | ureq::Error::TooManyRedirects => Self::Redirect,
            ureq::Error::StatusCode(status) => Self::HttpStatus(*status),
            ureq::Error::Protocol(_) | ureq::Error::LargeResponseHeader(_, _) => Self::Protocol,
            _ => Self::Transport,
        }
    }
}

impl fmt::Display for AssetDownloadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadUrl => formatter.write_str("invalid URL"),
            Self::Timeout => formatter.write_str("timeout"),
            Self::NameResolution => formatter.write_str("name resolution"),
            Self::Tls => formatter.write_str("TLS verification"),
            Self::Redirect => formatter.write_str("redirect policy"),
            Self::HttpStatus(status) => write!(formatter, "HTTP status {status}"),
            Self::Protocol => formatter.write_str("HTTP protocol"),
            Self::Transport => formatter.write_str("network transport"),
            Self::CacheUnavailable => formatter.write_str("HTTP 304 without cache"),
        }
    }
}

impl Error for AssetLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Atomic asset publication failed without replacing the last-good snapshot.
#[derive(Debug)]
pub enum AssetUpdateError {
    Load(AssetLoadError),
    GenerationExhausted,
    Unavailable,
}

impl From<AssetLoadError> for AssetUpdateError {
    fn from(source: AssetLoadError) -> Self {
        Self::Load(source)
    }
}

impl fmt::Display for AssetUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(source) => source.fmt(formatter),
            Self::GenerationExhausted => formatter.write_str("asset generation exhausted"),
            Self::Unavailable => formatter.write_str("asset updater is unavailable"),
        }
    }
}

impl Error for AssetUpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Load(source) => Some(source),
            Self::GenerationExhausted | Self::Unavailable => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
        sync::Arc,
        thread,
        time::Duration,
    };

    use super::{
        AssetDownloadFailure, AssetLoadError, AssetMatcher, AssetSnapshot, AssetSource, AssetStore,
    };
    use crate::config::Config;

    #[test]
    fn loads_xray_geosite_and_geoip_wire_shapes() {
        let (config, directory) = fixture();
        let snapshot = AssetSnapshot::load(&config).expect("asset vectors must load");

        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
        assert!(!snapshot.matches_domain(&AssetSource::GeoSite, "test", "notexample.com"));
        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "has-NEEDLE-here.test"));
        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "secure42.example"));
        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "EXACT.example"));
        assert!(snapshot.matches_ip(
            &AssetSource::GeoIp,
            "private",
            Ipv4Addr::new(10, 1, 2, 3).into()
        ));
        assert!(!snapshot.matches_ip(
            &AssetSource::GeoIp,
            "private",
            Ipv4Addr::new(11, 1, 2, 3).into()
        ));
        assert!(snapshot.matches_ip(&AssetSource::GeoIp, "private", Ipv6Addr::LOCALHOST.into()));

        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn failed_reload_preserves_last_good_snapshot() {
        let (config, directory) = fixture();
        let store = AssetStore::new(&config).expect("initial assets must load");
        let before = store.load();
        fs::remove_file(directory.join("geoip.dat")).expect("temporary geoip must be removed");

        store
            .reload(&config)
            .expect_err("missing asset must fail reload");
        let after = store.load();

        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.generation(), 0);
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn downloads_once_then_revalidates_cached_asset_with_etag() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
        let address = listener.local_addr().expect("listener address must exist");
        let body = geosite_list();
        let server = thread::spawn(move || {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().expect("asset request must arrive");
                let mut request = [0_u8; 4096];
                let length = stream.read(&mut request).expect("asset request must read");
                let request = String::from_utf8_lossy(&request[..length]);
                if request_index == 0 {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"test-vector\"\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(headers.as_bytes())
                        .and_then(|()| stream.write_all(&body))
                        .expect("asset response must write");
                } else {
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains("if-none-match: \"test-vector\"")
                    );
                    stream
                        .write_all(b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n")
                        .expect("asset response must write");
                }
            }
        });

        let suffix = format!("{}-etag", std::process::id());
        let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.geosite = format!("http://{address}/geosite.dat");
        config.assets.cache_directory = directory.clone();
        config.routing.global_rules[0].domain = vec!["geosite:test".to_owned()];
        config.routing.global_rules[0].ip.clear();

        let first = AssetSnapshot::load(&config).expect("downloaded asset must load");
        let second = AssetSnapshot::load(&config).expect("revalidated cache must load");

        assert!(first.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
        assert!(second.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn response_body_timeout_falls_back_to_validated_cache() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
        let address = listener.local_addr().expect("listener address must exist");
        let body = geosite_list();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("asset request must arrive");
            let mut request = [0_u8; 4096];
            stream.read(&mut request).expect("asset request must read");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .and_then(|()| stream.write_all(&body[..1]))
                .expect("partial asset response must write");
            thread::sleep(Duration::from_millis(1_500));
        });

        let suffix = format!("{}-body-timeout", std::process::id());
        let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
        fs::create_dir(&directory).expect("temporary asset cache must be created");
        fs::write(directory.join("geosite.dat"), geosite_list())
            .expect("cached geosite must be written");
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.geosite = format!("http://{address}/geosite.dat");
        config.assets.cache_directory = directory.clone();
        config.assets.request_timeout_seconds = 1;
        config.routing.global_rules[0].domain = vec!["geosite:test".to_owned()];
        config.routing.global_rules[0].ip.clear();

        let snapshot = AssetSnapshot::load(&config)
            .expect("a timed-out response body must fall back to the validated cache");

        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));
        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn oversized_response_body_does_not_fall_back_to_validated_cache() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
        let address = listener.local_addr().expect("listener address must exist");
        let maximum = 1024_usize;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("asset request must arrive");
            let mut request = [0_u8; 4096];
            stream.read(&mut request).expect("asset request must read");
            let body = vec![0_u8; maximum + 2];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .and_then(|()| stream.write_all(&body))
                .expect("oversized asset response must write");
        });

        let suffix = format!("{}-body-too-large", std::process::id());
        let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
        fs::create_dir(&directory).expect("temporary asset cache must be created");
        fs::write(directory.join("geosite.dat"), geosite_list())
            .expect("cached geosite must be written");
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.geosite = format!("http://{address}/geosite.dat");
        config.assets.cache_directory = directory.clone();
        config.assets.max_bytes = u64::try_from(maximum).expect("maximum must fit u64");
        config.routing.global_rules[0].domain = vec!["geosite:test".to_owned()];
        config.routing.global_rules[0].ip.clear();

        let error = match AssetSnapshot::load(&config) {
            Ok(_) => panic!("an oversized body must fail instead of using cached assets"),
            Err(error) => error,
        };
        match error {
            AssetLoadError::TooLarge {
                path,
                maximum: observed,
            } => {
                assert_eq!(path, directory.join("geosite.dat"));
                assert_eq!(observed, maximum);
            }
            other => panic!("oversized body returned the wrong error: {other}"),
        }

        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn maximum_plus_one_response_body_does_not_fall_back_to_validated_cache() {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
        let address = listener.local_addr().expect("listener address must exist");
        let maximum = 1024_usize;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("asset request must arrive");
            let mut request = [0_u8; 4096];
            stream.read(&mut request).expect("asset request must read");
            let body = vec![0_u8; maximum + 1];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .and_then(|()| stream.write_all(&body))
                .expect("maximum-plus-one asset response must write");
        });

        let suffix = format!("{}-body-maximum-plus-one", std::process::id());
        let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
        fs::create_dir(&directory).expect("temporary asset cache must be created");
        fs::write(directory.join("geosite.dat"), geosite_list())
            .expect("cached geosite must be written");
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.geosite = format!("http://{address}/geosite.dat");
        config.assets.cache_directory = directory.clone();
        config.assets.max_bytes = u64::try_from(maximum).expect("maximum must fit u64");
        config.routing.global_rules[0].domain = vec!["geosite:test".to_owned()];
        config.routing.global_rules[0].ip.clear();

        let error = match AssetSnapshot::load(&config) {
            Ok(_) => panic!("a maximum-plus-one body must fail instead of using cached assets"),
            Err(error) => error,
        };
        match error {
            AssetLoadError::TooLarge {
                path,
                maximum: observed,
            } => {
                assert_eq!(path, directory.join("geosite.dat"));
                assert_eq!(observed, maximum);
            }
            other => panic!("maximum-plus-one body returned the wrong error: {other}"),
        }

        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn unsupported_maximum_does_not_fall_back_to_validated_cache() {
        let (address, server) = one_response_server("200 OK");
        let (config, directory) = remote_geosite_fixture(address, "unsupported-maximum", u64::MAX);
        fs::write(directory.join("geosite.dat"), geosite_list())
            .expect("cached geosite must be written");

        let error = match AssetSnapshot::load(&config) {
            Ok(_) => panic!("an unsupported maximum must fail instead of using cached assets"),
            Err(error) => error,
        };
        assert!(matches!(error, AssetLoadError::SizeLimitUnsupported));

        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn http_error_falls_back_to_validated_cache() {
        let (address, server) = one_response_server("503 Service Unavailable");
        let (config, directory) = remote_geosite_fixture(address, "status-cache", 1024);
        fs::write(directory.join("geosite.dat"), geosite_list())
            .expect("cached geosite must be written");

        let snapshot = AssetSnapshot::load(&config)
            .expect("an HTTP error must fall back to the validated cache");
        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "test", "api.example.com"));

        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn http_error_with_missing_cache_preserves_download_failure() {
        let (address, server) = one_response_server("503 Service Unavailable");
        let (config, directory) = remote_geosite_fixture(address, "status-missing-cache", 1024);

        let error = match AssetSnapshot::load(&config) {
            Ok(_) => panic!("an HTTP error without cache must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AssetLoadError::Download(AssetDownloadFailure::HttpStatus(503))
        ));

        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    fn http_error_with_oversized_cache_preserves_download_failure() {
        let maximum = 1024_u64;
        let (address, server) = one_response_server("503 Service Unavailable");
        let (config, directory) =
            remote_geosite_fixture(address, "status-oversized-cache", maximum);
        fs::write(
            directory.join("geosite.dat"),
            vec![0_u8; usize::try_from(maximum).expect("maximum must fit usize") + 1],
        )
        .expect("oversized cached geosite must be written");

        let error = match AssetSnapshot::load(&config) {
            Ok(_) => panic!("an HTTP error with oversized cache must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AssetLoadError::Download(AssetDownloadFailure::HttpStatus(503))
        ));

        server.join().expect("asset test server must complete");
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    #[test]
    #[ignore = "downloads the current community release from GitHub"]
    fn loads_live_community_geoip_and_geosite_release() {
        let suffix = format!("{}-live", std::process::id());
        let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.cache_directory = directory.clone();
        config.routing.global_rules[0].domain = vec!["geosite:cn".to_owned()];
        config.routing.global_rules[0].ip = vec!["geoip:private".to_owned()];

        let snapshot = AssetSnapshot::load(&config).expect("community assets must load");

        assert!(snapshot.matches_domain(&AssetSource::GeoSite, "cn", "www.baidu.com"));
        assert!(snapshot.matches_ip(
            &AssetSource::GeoIp,
            "private",
            Ipv4Addr::new(10, 1, 2, 3).into()
        ));
        assert_eq!(snapshot.summary().domain_labels, 1);
        assert_eq!(snapshot.summary().ip_labels, 1);
        assert!(
            fs::metadata(directory.join("geoip.dat"))
                .expect("validated GeoIP cache must exist")
                .len()
                > 1024
        );
        assert!(
            fs::metadata(directory.join("geosite.dat"))
                .expect("validated GeoSite cache must exist")
                .len()
                > 1024
        );
        fs::remove_dir_all(directory).expect("temporary asset cache must be removed");
    }

    fn one_response_server(status: &str) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("asset test listener must bind");
        let address = listener.local_addr().expect("listener address must exist");
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("asset request must arrive");
            let mut request = [0_u8; 4096];
            stream.read(&mut request).expect("asset request must read");
            stream
                .write_all(response.as_bytes())
                .expect("asset response must write");
        });
        (address, server)
    }

    fn remote_geosite_fixture(
        address: SocketAddr,
        suffix: &str,
        maximum: u64,
    ) -> (Config, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-assets-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("temporary asset cache must be created");
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.geosite = format!("http://{address}/geosite.dat");
        config.assets.cache_directory = directory.clone();
        config.assets.max_bytes = maximum;
        config.routing.global_rules[0].domain = vec!["geosite:test".to_owned()];
        config.routing.global_rules[0].ip.clear();
        (config, directory)
    }

    fn fixture() -> (Config, std::path::PathBuf) {
        let suffix = format!("{}-{:?}", std::process::id(), std::thread::current().id());
        let directory = std::env::temp_dir().join(format!("rust-reality-assets-{suffix}"));
        fs::create_dir(&directory).expect("temporary asset cache must be created");
        fs::write(directory.join("geoip.dat"), geoip_list())
            .expect("temporary geoip must be written");
        fs::write(directory.join("geosite.dat"), geosite_list())
            .expect("temporary geosite must be written");
        let mut config: Config = serde_json::from_str(crate::config::test_config_json())
            .expect("fixture config must parse");
        config.assets.geoip = "invalid://cached/geoip.dat".to_owned();
        config.assets.geosite = "invalid://cached/geosite.dat".to_owned();
        config.assets.cache_directory = directory.clone();
        config.assets.request_timeout_seconds = 1;
        config.routing.global_rules[0].domain = vec!["geosite:test".to_owned()];
        config.routing.global_rules[0].ip = vec!["geoip:private".to_owned()];
        (config, directory)
    }

    fn geosite_list() -> Vec<u8> {
        let mut site = Vec::new();
        bytes_field(&mut site, 1, b"TEST");
        for (kind, value) in [
            (2, "example.com"),
            (0, "needle"),
            (1, r"^secure[0-9]+\.example$"),
            (3, "exact.example"),
        ] {
            let mut domain = Vec::new();
            varint_field(&mut domain, 1, kind);
            bytes_field(&mut domain, 2, value.as_bytes());
            bytes_field(&mut site, 2, &domain);
        }
        let mut list = Vec::new();
        bytes_field(&mut list, 1, &site);
        list
    }

    fn geoip_list() -> Vec<u8> {
        let mut cidr = Vec::new();
        bytes_field(&mut cidr, 1, &[10, 0, 0, 0]);
        varint_field(&mut cidr, 2, 8);
        let mut ipv6 = Vec::new();
        bytes_field(&mut ipv6, 1, &Ipv6Addr::LOCALHOST.octets());
        varint_field(&mut ipv6, 2, 128);
        let mut entry = Vec::new();
        bytes_field(&mut entry, 1, b"PRIVATE");
        bytes_field(&mut entry, 2, &cidr);
        bytes_field(&mut entry, 2, &ipv6);
        let mut list = Vec::new();
        bytes_field(&mut list, 1, &entry);
        list
    }

    fn bytes_field(output: &mut Vec<u8>, number: u8, value: &[u8]) {
        output.push((number << 3) | 2);
        encode_varint(output, value.len() as u64);
        output.extend_from_slice(value);
    }

    fn varint_field(output: &mut Vec<u8>, number: u8, value: u64) {
        output.push(number << 3);
        encode_varint(output, value);
    }

    fn encode_varint(output: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            output.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
    }
}
