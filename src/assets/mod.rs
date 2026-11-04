//! Geo routing assets (geoip/geosite) used by entry routing rules.
//!
//! [`AssetSnapshot`] is an immutable, parsed view of the configured asset
//! files; [`AssetStore`] holds the current snapshot behind an `ArcSwap` so
//! readers get lock-free access while [`AssetStore::reload`] swaps in a
//! freshly loaded generation. Downloading and conditional-update logic
//! (ETag / Last-Modified) lives here too; the `.dat` wire parsing lives in
//! the private `dat` submodule.

mod dat;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    str,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use ureq::{
    Agent,
    http::header::{
        ACCEPT, ACCEPT_ENCODING, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED,
    },
};

use crate::config::node::entry::EntryConfig;

use dat::{DomainSet, IpSet, parse_geoip_list, parse_geosite_list};

/// Absolute deadline for one asset request including its response body.
///
/// Derived rather than configured: this bounds how long a poll may stall, and
/// an operator has no information that would set it better.
const ASSET_REQUEST_TIMEOUT_SECONDS: u64 = 120;

/// Largest number of bytes accepted from any one asset or external file.
const MAX_ASSET_BYTES: u64 = 128 * 1024 * 1024;

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
    pub fn load(config: &EntryConfig) -> Result<Self, AssetLoadError> {
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
        config: &EntryConfig,
        generation: u64,
    ) -> Result<Self, AssetLoadError> {
        let requirements = AssetRequirements::from_config(config);
        let assets = config.assets.clone().unwrap_or_default();
        let maximum =
            usize::try_from(MAX_ASSET_BYTES).map_err(|_| AssetLoadError::SizeLimitUnsupported)?;
        let fetcher = AssetFetcher::new(config);
        let mut cache_updates = Vec::new();
        let mut domains = HashMap::new();
        let mut ips = HashMap::new();

        if !requirements.geosite.is_empty() {
            let candidate = fetcher.fetch("geosite.dat", assets.geosite(), maximum)?;
            let (parsed, update) = parse_candidate(candidate, maximum, |input| {
                parse_geosite_list(input, &requirements.geosite)
            })?;
            domains.insert(AssetSource::GeoSite, parsed);
            cache_updates.extend(update);
        }
        if !requirements.geoip.is_empty() {
            let candidate = fetcher.fetch("geoip.dat", assets.geoip(), maximum)?;
            let (parsed, update) = parse_candidate(candidate, maximum, |input| {
                parse_geoip_list(input, &requirements.geoip)
            })?;
            ips.insert(AssetSource::GeoIp, parsed);
            cache_updates.extend(update);
        }
        for (file, labels) in requirements.external_domains {
            let path = resolve_external(&assets.cache_directory(), &file)?;
            let bytes = read_bounded(&path, maximum)?;
            domains.insert(
                AssetSource::External(Arc::from(file)),
                parse_geosite_list(&bytes, &labels)?,
            );
        }
        for (file, labels) in requirements.external_ips {
            let path = resolve_external(&assets.cache_directory(), &file)?;
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
    pub fn new(config: &EntryConfig) -> Result<Self, AssetLoadError> {
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
    pub fn reload(&self, config: &EntryConfig) -> Result<u64, AssetUpdateError> {
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
    fn from_config(config: &EntryConfig) -> Self {
        let mut requirements = Self::default();
        for rule in config.routing.rules().iter().chain(
            config
                .routing
                .policies()
                .flat_map(|(_, policy)| policy.rules()),
        ) {
            for matcher in rule.domain() {
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
            for matcher in rule.ip() {
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
    fn new(config: &EntryConfig) -> Self {
        let agent_config = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(ASSET_REQUEST_TIMEOUT_SECONDS)))
            .max_redirects(5)
            .http_status_as_error(false)
            .user_agent("rust-reality-assets/0.1")
            .build();
        Self {
            agent: agent_config.into(),
            cache_directory: config.assets.clone().unwrap_or_default().cache_directory(),
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
mod tests;
