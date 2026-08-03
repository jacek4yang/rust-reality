use std::{error::Error, fmt, io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time,
};

use crate::{
    config::ResourceGovernorConfig,
    runtime::{AdmissionDenied, AdmissionKind, ResourceGovernor},
    transport::relay::{RelayStats, relay_bidirectional},
};

/// Completed fallback byte counts, including the already-consumed wire prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackStats {
    forwarded_prefix: u64,
    relay: RelayStats,
}

impl FallbackStats {
    /// Returns the exact number of pre-read bytes forwarded before live relay.
    #[must_use]
    pub const fn forwarded_prefix_bytes(self) -> u64 {
        self.forwarded_prefix
    }

    /// Returns the subsequent bidirectional relay counts.
    #[must_use]
    pub const fn relay(self) -> RelayStats {
        self.relay
    }
}

/// A bounded cover-target fallback failure.
#[derive(Debug)]
pub enum FallbackError {
    /// Global fallback admission rejected the session without queuing.
    Admission(AdmissionDenied),
    /// Cover target connection exceeded its configured deadline.
    ConnectTimeout,
    /// The entire fallback session exceeded its configured lifetime.
    SessionTimeout,
    /// Target connection, exact prefix forwarding, or relay failed.
    Io(io::Error),
}

impl fmt::Display for FallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(_) => formatter.write_str("REALITY fallback admission denied"),
            Self::ConnectTimeout => formatter.write_str("REALITY cover connection timed out"),
            Self::SessionTimeout => formatter.write_str("REALITY fallback session timed out"),
            Self::Io(_) => formatter.write_str("REALITY fallback I/O failed"),
        }
    }
}

impl Error for FallbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::ConnectTimeout | Self::SessionTimeout => None,
        }
    }
}

/// Connects failed REALITY handshakes to their cover target under hard bounds.
#[derive(Clone)]
pub struct RealityFallback {
    target: Arc<str>,
    governor: ResourceGovernor,
    connect_timeout: Duration,
    session_timeout: Duration,
}

impl RealityFallback {
    /// Creates immutable fallback state from a validated listener snapshot.
    #[must_use]
    pub fn new(
        target: impl Into<Arc<str>>,
        governor: ResourceGovernor,
        config: &ResourceGovernorConfig,
    ) -> Self {
        Self {
            target: target.into(),
            governor,
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            session_timeout: Duration::from_millis(config.fallback_timeout_ms),
        }
    }

    /// Forwards every consumed byte before relaying any new client input.
    ///
    /// The caller must pass the exact owned prefix from `read_client_hello`; this
    /// method never reparses, normalizes, or reconstructs attacker-controlled bytes.
    /// Admission is non-waiting and both connection setup and total lifetime are
    /// bounded. The permit is released on timeout, cancellation, and every error.
    ///
    /// # Errors
    ///
    /// Returns an admission, deadline, connection, prefix-write, or relay error.
    pub async fn relay<I>(
        &self,
        inbound: &mut I,
        consumed_prefix: &[u8],
    ) -> Result<FallbackStats, FallbackError>
    where
        I: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let _permit = self
            .governor
            .try_acquire(AdmissionKind::Fallback)
            .map_err(FallbackError::Admission)?;
        let operation = async {
            let connect = TcpStream::connect(self.target.as_ref());
            let mut cover = time::timeout(self.connect_timeout, connect)
                .await
                .map_err(|_| FallbackError::ConnectTimeout)?
                .map_err(FallbackError::Io)?;
            cover.set_nodelay(true).map_err(FallbackError::Io)?;
            cover
                .write_all(consumed_prefix)
                .await
                .map_err(FallbackError::Io)?;
            let relay = relay_bidirectional(inbound, &mut cover)
                .await
                .map_err(FallbackError::Io)?;
            let forwarded_prefix =
                u64::try_from(consumed_prefix.len()).map_or(u64::MAX, |length| length);
            Ok(FallbackStats {
                forwarded_prefix,
                relay,
            })
        };

        time::timeout(self.session_timeout, operation)
            .await
            .map_err(|_| FallbackError::SessionTimeout)?
    }
}

impl fmt::Debug for RealityFallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFallback")
            .field("target", &"[CONFIGURED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("session_timeout", &self.session_timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        net::TcpListener,
        time::timeout,
    };

    use super::{FallbackError, RealityFallback};
    use crate::{config::ResourceGovernorConfig, runtime::ResourceGovernor};

    const PREFIX: &[u8] = b"exact-fragmented-client-hello-prefix";
    const SUFFIX: &[u8] = b"bytes-read-after-fallback-connect";
    const RESPONSE: &[u8] = b"cover-response";

    #[tokio::test(flavor = "current_thread")]
    async fn forwards_consumed_prefix_byte_exactly_before_live_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = RealityFallback::new(target, ResourceGovernor::new(&config), &config);
        let (mut client, mut inbound) = duplex(256);

        let exchange = async {
            let fallback_io = fallback.relay(&mut inbound, PREFIX);
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut request = Vec::new();
                cover.read_to_end(&mut request).await?;
                cover.write_all(RESPONSE).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("fallback exchange must finish");

        let stats = fallback_result.expect("fallback must succeed");
        let response = client_result.expect("client I/O must succeed");
        let request = cover_result.expect("cover I/O must succeed");
        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(SUFFIX);
        assert_eq!(request, expected);
        assert_eq!(response, RESPONSE);
        assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
        assert_eq!(
            stats.relay().inbound_to_outbound_bytes(),
            SUFFIX.len() as u64
        );
        assert_eq!(
            stats.relay().outbound_to_inbound_bytes(),
            RESPONSE.len() as u64
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_releases_fallback_admission_permit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let mut config = ResourceGovernorConfig {
            max_fallbacks: 1,
            fallback_timeout_ms: 10,
            ..ResourceGovernorConfig::default()
        };
        config.connect_timeout_ms = 100;
        let fallback = RealityFallback::new(
            listener
                .local_addr()
                .expect("cover listener address must exist")
                .to_string(),
            ResourceGovernor::new(&config),
            &config,
        );

        for _ in 0..2 {
            let (_client, mut inbound) = duplex(1);
            assert!(matches!(
                fallback.relay(&mut inbound, &[]).await,
                Err(FallbackError::SessionTimeout)
            ));
        }
    }
}
