use std::{
    collections::HashMap,
    error::Error,
    fmt, io,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant as MonotonicInstant, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    config::{NxrInboundConfig, RelayPolicy},
    protocol::{
        nxr::{
            NxrKey, NxrProtocolError, REQUEST_HEADER_LEN, decode_authenticated_request,
            request_len_from_header,
        },
        vless::Destination,
    },
    transport::{
        relay::RelayStats,
        tcp_relay::{TcpRelay, TcpRelayConfigError},
    },
};

use super::connector::{DestinationConnectError, DestinationConnector};

const REPLAY_SHARDS: usize = 16;

type NonceEntries = HashMap<[u8; 16], MonotonicInstant>;
type NonceShards = Box<[Mutex<NonceEntries>]>;

/// Bounded nonce cache shared by all generations of one NXR landing listener.
#[derive(Clone)]
pub struct NxrReplayCache {
    inner: Arc<NxrReplayCacheInner>,
}

struct NxrReplayCacheInner {
    shards: NonceShards,
    capacity: usize,
    used: AtomicUsize,
    retention: Duration,
}

impl NxrReplayCache {
    /// Compiles the bounded replay policy for one validated NXR listener.
    ///
    /// # Errors
    ///
    /// Rejects an unrepresentable capacity or unavailable replay policy.
    pub fn from_inbound(inbound: &NxrInboundConfig) -> Result<Self, NxrLandingConfigError> {
        let capacity = usize::try_from(inbound.settings.max_nonce_entries)
            .map_err(|_| NxrLandingConfigError::Capacity)?;
        Self::new(
            capacity,
            Duration::from_secs(inbound.settings.nonce_retention_seconds),
        )
        .map_err(NxrLandingConfigError::Replay)
    }

    /// Creates an independently bounded nonce cache.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or retention before allocating shards.
    pub fn new(capacity: usize, retention: Duration) -> Result<Self, NxrReplayError> {
        if capacity == 0 || retention.is_zero() {
            return Err(NxrReplayError::Unavailable);
        }
        let shards = (0..REPLAY_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Ok(Self {
            inner: Arc::new(NxrReplayCacheInner {
                shards,
                capacity,
                used: AtomicUsize::new(0),
                retention,
            }),
        })
    }

    /// Atomically records a verified nonce until its monotonic retention deadline.
    ///
    /// # Errors
    ///
    /// Rejects duplicate nonces, exhausted bounded capacity, allocation failure,
    /// and unrepresentable monotonic deadlines.
    pub fn reserve(&self, nonce: [u8; 16]) -> Result<(), NxrReplayError> {
        self.reserve_at(nonce, MonotonicInstant::now())
    }

    /// Removes every expired nonce and returns the number of released entries.
    pub fn purge_expired(&self) -> usize {
        self.purge_expired_at(MonotonicInstant::now())
    }

    fn reserve_at(&self, nonce: [u8; 16], now: MonotonicInstant) -> Result<(), NxrReplayError> {
        let expires_at = now
            .checked_add(self.inner.retention)
            .ok_or(NxrReplayError::Unavailable)?;
        self.purge_expired_at(now);
        let shard = nonce_shard(nonce);
        let mut entries = lock_recover(&self.inner.shards[shard]);
        if entries.contains_key(&nonce) {
            return Err(NxrReplayError::Duplicate);
        }
        entries
            .try_reserve(1)
            .map_err(|_| NxrReplayError::Capacity)?;
        reserve_slot(&self.inner)?;
        entries.insert(nonce, expires_at);
        Ok(())
    }

    fn purge_expired_at(&self, now: MonotonicInstant) -> usize {
        let removed: usize = self
            .inner
            .shards
            .iter()
            .map(|shard| {
                let mut entries = lock_recover(shard);
                let previous = entries.len();
                entries.retain(|_, expires_at| *expires_at > now);
                previous.saturating_sub(entries.len())
            })
            .sum();
        if removed != 0 {
            self.inner.used.fetch_sub(removed, Ordering::AcqRel);
        }
        removed
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.used.load(Ordering::Acquire)
    }
}

fn reserve_slot(inner: &NxrReplayCacheInner) -> Result<(), NxrReplayError> {
    let mut observed = inner.used.load(Ordering::Acquire);
    loop {
        if observed >= inner.capacity {
            return Err(NxrReplayError::Capacity);
        }
        match inner.used.compare_exchange_weak(
            observed,
            observed + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(current) => observed = current,
        }
    }
}

fn nonce_shard(nonce: [u8; 16]) -> usize {
    usize::from(nonce[0]) % REPLAY_SHARDS
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Verified NXR request policy with an independent HMAC key and replay cache.
#[derive(Clone)]
pub struct NxrAuthenticator {
    key: NxrKey,
    replay: NxrReplayCache,
    maximum_time_difference: u64,
}

impl NxrAuthenticator {
    /// Binds a PSK, time window in seconds, and bounded nonce cache.
    #[must_use]
    pub const fn new(key: NxrKey, replay: NxrReplayCache, maximum_time_difference: u64) -> Self {
        Self {
            key,
            replay,
            maximum_time_difference,
        }
    }

    /// Verifies HMAC and time first, reserves the nonce second, and only then
    /// returns a parsed destination that callers may resolve or connect.
    ///
    /// # Errors
    ///
    /// Rejects malformed or unauthenticated requests, stale timestamps, duplicate
    /// nonces, and exhausted replay capacity.
    pub fn authenticate(
        &self,
        request: &[u8],
        now: u64,
    ) -> Result<Destination, NxrAuthenticationError> {
        let authenticated =
            decode_authenticated_request(request, &self.key, now, self.maximum_time_difference)?;
        self.replay.reserve(*authenticated.nonce())?;
        let (_, destination) = authenticated.into_parts();
        Ok(destination)
    }
}

/// One NXR landing connection: authenticate once, connect once, then relay raw
/// bytes with normal TCP half-close semantics.
#[derive(Clone)]
pub struct NxrLandingHandler {
    authenticator: NxrAuthenticator,
    connector: DestinationConnector,
    authentication_timeout: Duration,
    relay: TcpRelay,
}

impl NxrLandingHandler {
    /// Compiles one validated internal listener with a new replay cache.
    ///
    /// # Errors
    ///
    /// Rejects invalid key material or replay-cache policy.
    pub fn from_inbound(
        inbound: &NxrInboundConfig,
        relay_policy: &RelayPolicy,
    ) -> Result<Self, NxrLandingConfigError> {
        let replay = NxrReplayCache::from_inbound(inbound)?;
        let relay = TcpRelay::new(relay_policy).map_err(NxrLandingConfigError::Relay)?;
        Self::from_inbound_with_replay(inbound, replay, relay)
    }

    /// Compiles one validated listener while retaining its process-lifetime
    /// replay history across immutable runtime generations.
    ///
    /// # Errors
    ///
    /// Rejects malformed or incorrectly sized PSK material.
    pub fn from_inbound_with_replay(
        inbound: &NxrInboundConfig,
        replay: NxrReplayCache,
        relay: TcpRelay,
    ) -> Result<Self, NxrLandingConfigError> {
        let decoded = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(inbound.settings.pre_shared_key.expose())
                .map_err(|_| NxrLandingConfigError::Key)?,
        );
        let key: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| NxrLandingConfigError::Key)?;
        Ok(Self::new(
            NxrAuthenticator::new(
                NxrKey::new(key),
                replay,
                inbound.settings.max_time_difference_seconds,
            ),
            Duration::from_millis(inbound.settings.connect_timeout_ms),
            Duration::from_millis(inbound.settings.authentication_timeout_ms),
            relay,
        ))
    }

    /// Creates a landing handler from already compiled policy.
    #[must_use]
    pub const fn new(
        authenticator: NxrAuthenticator,
        connect_timeout: Duration,
        authentication_timeout: Duration,
        relay: TcpRelay,
    ) -> Self {
        Self {
            authenticator,
            connector: DestinationConnector::new(connect_timeout),
            authentication_timeout,
            relay,
        }
    }

    /// Processes a single NXR TCP connection. Authentication failures return
    /// without writing a response and occur before destination DNS or connect.
    ///
    /// # Errors
    ///
    /// Returns bounded request-read, clock, authentication, destination, or relay
    /// errors. Callers must silently close on every error.
    pub async fn handle(&self, mut inbound: TcpStream) -> Result<RelayStats, NxrLandingError> {
        let request = read_request(&mut inbound, self.authentication_timeout).await?;
        let now = unix_seconds()?;
        let destination = self.authenticator.authenticate(&request, now)?;
        let mut outbound = self.connector.connect(&destination).await?;
        self.relay
            .relay(&mut inbound, &mut outbound)
            .await
            .map_err(NxrLandingError::Relay)
    }
}

/// Validated NXR listener state could not be compiled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrLandingConfigError {
    /// PSK decoding or length did not match the protocol contract.
    Key,
    /// Replay capacity could not be represented on this target.
    Capacity,
    /// Replay cache initialization failed.
    Replay(NxrReplayError),
    /// Bounded plaintext relay state could not be compiled.
    Relay(TcpRelayConfigError),
}

impl fmt::Display for NxrLandingConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid NXR landing listener configuration")
    }
}

impl Error for NxrLandingConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Replay(source) => Some(source),
            Self::Relay(source) => Some(source),
            Self::Key | Self::Capacity => None,
        }
    }
}

async fn read_request(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>, NxrLandingError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(NxrLandingError::Timeout)?;
    let mut header = [0_u8; REQUEST_HEADER_LEN];
    read_exact_before(stream, &mut header, deadline).await?;
    let total = request_len_from_header(&header).map_err(NxrLandingError::Protocol)?;
    let mut request = Vec::new();
    request
        .try_reserve_exact(total)
        .map_err(|_| NxrLandingError::Allocation)?;
    request.extend_from_slice(&header);
    request.resize(total, 0);
    read_exact_before(stream, &mut request[REQUEST_HEADER_LEN..], deadline).await?;
    Ok(request)
}

async fn read_exact_before(
    stream: &mut TcpStream,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), NxrLandingError> {
    time::timeout_at(deadline, stream.read_exact(output))
        .await
        .map_err(|_| NxrLandingError::Timeout)?
        .map(|_| ())
        .map_err(NxrLandingError::Read)
}

fn unix_seconds() -> Result<u64, NxrLandingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| NxrLandingError::Clock)
}

/// A verified nonce could not be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrReplayError {
    Duplicate,
    Capacity,
    Unavailable,
}

impl fmt::Display for NxrReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NXR replay admission failed")
    }
}

impl Error for NxrReplayError {}

/// One NXR HMAC, time, or nonce check failed.
#[derive(Debug)]
pub enum NxrAuthenticationError {
    Protocol(NxrProtocolError),
    Replay(NxrReplayError),
}

impl fmt::Display for NxrAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NXR authentication rejected")
    }
}

impl Error for NxrAuthenticationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(source) => Some(source),
            Self::Replay(source) => Some(source),
        }
    }
}

impl From<NxrProtocolError> for NxrAuthenticationError {
    fn from(source: NxrProtocolError) -> Self {
        Self::Protocol(source)
    }
}

impl From<NxrReplayError> for NxrAuthenticationError {
    fn from(source: NxrReplayError) -> Self {
        Self::Replay(source)
    }
}

/// One NXR landing connection failed and must close silently.
#[derive(Debug)]
pub enum NxrLandingError {
    Timeout,
    Read(io::Error),
    Protocol(NxrProtocolError),
    Allocation,
    Clock,
    Authentication(NxrAuthenticationError),
    Destination(DestinationConnectError),
    Relay(io::Error),
}

impl fmt::Display for NxrLandingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NXR landing connection closed")
    }
}

impl Error for NxrLandingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(source) | Self::Relay(source) => Some(source),
            Self::Protocol(source) => Some(source),
            Self::Authentication(source) => Some(source),
            Self::Destination(source) => Some(source),
            Self::Timeout | Self::Allocation | Self::Clock => None,
        }
    }
}

impl From<NxrAuthenticationError> for NxrLandingError {
    fn from(source: NxrAuthenticationError) -> Self {
        Self::Authentication(source)
    }
}

impl From<DestinationConnectError> for NxrLandingError {
    fn from(source: DestinationConnectError) -> Self {
        Self::Destination(source)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time,
    };

    use super::{NxrAuthenticator, NxrLandingHandler, NxrReplayCache, NxrReplayError};
    use crate::{
        config::RelayPolicy,
        protocol::{
            nxr::{NxrKey, encode_request},
            vless::{Address, Destination},
        },
        transport::tcp_relay::TcpRelay,
    };

    #[test]
    fn replay_cache_is_bounded_and_expires_monotonically() {
        let cache =
            NxrReplayCache::new(1, Duration::from_millis(100)).expect("cache policy must compile");
        let now = std::time::Instant::now();
        cache
            .reserve_at([1; 16], now)
            .expect("first nonce must reserve");
        assert_eq!(
            cache.reserve_at([1; 16], now),
            Err(NxrReplayError::Duplicate)
        );
        assert_eq!(
            cache.reserve_at([2; 16], now),
            Err(NxrReplayError::Capacity)
        );
        cache
            .reserve_at([2; 16], now + Duration::from_millis(101))
            .expect("expired nonce must release capacity");
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn authenticator_rejects_nonce_reuse_before_returning_destination() {
        let key = NxrKey::new([0x11; 32]);
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let authenticator = NxrAuthenticator::new(key.clone(), cache, 5);
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let mut request = Vec::new();
        encode_request(&destination, 100, [0x22; 16], &key, &mut request)
            .expect("request must encode");

        assert_eq!(
            authenticator
                .authenticate(&request, 100)
                .expect("first request must authenticate"),
            destination
        );
        assert!(authenticator.authenticate(&request, 100).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn landing_relays_raw_payload_and_preserves_half_close() {
        const REQUEST: &[u8] = b"request after auth";
        const RESPONSE: &[u8] = b"response after half-close";

        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target must bind");
        let target_address = target_listener.local_addr().expect("target address");
        let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let landing_address = landing_listener.local_addr().expect("landing address");
        let key = NxrKey::new([0x33; 32]);
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let handler = NxrLandingHandler::new(
            NxrAuthenticator::new(key.clone(), cache, 5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TcpRelay::new(&RelayPolicy::default()).expect("relay policy must compile"),
        );
        let destination =
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_address.port());
        let now = super::unix_seconds().expect("test clock must be valid");
        let mut authentication = Vec::new();
        encode_request(&destination, now, [0x44; 16], &key, &mut authentication)
            .expect("request must encode");

        let exchange = async {
            let landing = async {
                let (stream, _) = landing_listener.accept().await?;
                handler.handle(stream).await.map_err(io::Error::other)
            };
            let line = async {
                let mut stream = TcpStream::connect(landing_address).await?;
                stream.set_nodelay(true)?;
                stream.write_all(&authentication).await?;
                stream.write_all(REQUEST).await?;
                stream.shutdown().await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let target = async {
                let (mut stream, _) = target_listener.accept().await?;
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await?;
                stream.write_all(RESPONSE).await?;
                stream.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(landing, line, target)
        };

        let (landing, line, target) = time::timeout(Duration::from_secs(3), exchange)
            .await
            .expect("NXR loopback must not time out");
        let stats = landing.expect("landing relay must succeed");
        assert_eq!(line.expect("line client must succeed"), RESPONSE);
        assert_eq!(target.expect("target must succeed"), REQUEST);
        assert_eq!(stats.inbound_to_outbound_bytes(), REQUEST.len() as u64);
        assert_eq!(stats.outbound_to_inbound_bytes(), RESPONSE.len() as u64);
    }
}
