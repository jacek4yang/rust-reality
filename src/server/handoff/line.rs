//! LINE-side Handoff transfer endpoint.
//!
//! Internal to [`crate::server::handoff`]: compiles the landing dial target and
//! seals one authenticated session transfer. Behavior-preserving modularization
//! only — no wire, crypto, or trust changes.

use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    net::TcpStream,
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    protocol::handoff::{ContinuationState, HandoffPsk, seal_transfer},
    transport::{FdBudget, FdPermit},
};
use rr_session::AttemptTransport;

use super::super::{
    connector::{DestinationConnectError, DestinationConnector},
    counted_write::write_all_counted_before,
    warm_pool::{AdaptiveTcpPool, WarmPoolAuthority, WarmUsePermit},
};
use super::error::HandoffLineError;
use crate::config::node::outbound::HandoffOutboundConfig;
use crate::runtime::policy::WarmConnectionPolicy;

/// Compiled LINE-side landing endpoint for session transfers.
///
/// Key material is independent of the NXR pre-shared key and of any REALITY
/// private key; `Debug` never reveals it.
#[derive(Clone)]
pub struct HandoffLine {
    address: Arc<str>,
    port: u16,
    psk: HandoffPsk,
    landing_public: [u8; 32],
    connect_timeout: Duration,
    first_byte_timeout: Duration,
    connector: DestinationConnector,
    pool: Option<AdaptiveTcpPool>,
    udp_port: u16,
    udp_mtu: Option<u16>,
}

impl HandoffLine {
    /// Compiles validated outbound settings into secret-safe runtime state.
    ///
    /// Returns `None` only when key material does not decode, which validated
    /// configuration has already excluded.
    #[must_use]
    pub fn from_settings(settings: &HandoffOutboundConfig) -> Option<Self> {
        Self::from_settings_with_connector(
            settings,
            DestinationConnector::new(Duration::from_millis(settings.connect_timeout_ms())),
        )
    }

    /// Compiles settings while sharing the process network environment.
    #[must_use]
    pub(crate) fn from_settings_with_connector(
        settings: &HandoffOutboundConfig,
        connector: DestinationConnector,
    ) -> Option<Self> {
        let psk = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.decode(settings.psk.expose()).ok()?);
        let psk: [u8; 32] = psk.as_slice().try_into().ok()?;
        let public = BASE64_URL_SAFE_NO_PAD
            .decode(&settings.landing_public_key)
            .ok()?;
        let public: [u8; 32] = public.as_slice().try_into().ok()?;
        Some(Self {
            address: Arc::from(settings.address.as_str()),
            port: settings.port,
            psk: HandoffPsk::new(psk),
            landing_public: public,
            connect_timeout: Duration::from_millis(settings.connect_timeout_ms()),
            first_byte_timeout: Duration::from_millis(settings.first_byte_timeout_ms()),
            connector: connector.with_timeout(Duration::from_millis(settings.connect_timeout_ms())),
            pool: None,
            udp_port: settings.udp_port(),
            udp_mtu: settings.udp_mtu,
        })
    }

    /// Compiles an optional generation-owned raw TCP pool. Key material stays
    /// in this immutable line object and never enters the pool identity.
    pub(crate) fn from_settings_with_warm_pool(
        settings: &HandoffOutboundConfig,
        connector: DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<(u64, WarmPoolAuthority, &WarmConnectionPolicy)>,
    ) -> Option<Self> {
        let mut line = Self::from_settings_with_connector(settings, connector)?;
        if settings.warm_tcp.unwrap_or(true)
            && let Some((generation, authority, policy)) = warm
        {
            line.pool = Some(AdaptiveTcpPool::new(
                Arc::from(format!("{}:{}", settings.address, settings.port)),
                generation,
                line.connector.clone(),
                fd_budget.clone(),
                authority,
                policy,
            ));
        }
        Some(line)
    }

    pub(crate) const fn warm_pool(&self) -> Option<&AdaptiveTcpPool> {
        self.pool.as_ref()
    }

    /// Landing host and UDP port of the native XUDP channel.
    pub(crate) fn udp_endpoint(&self) -> (&str, u16) {
        (&self.address, self.udp_port)
    }

    /// Operator-fixed native UDP channel MTU, when configured.
    pub(crate) const fn udp_mtu(&self) -> Option<u16> {
        self.udp_mtu
    }

    /// The pair PSK and landing static public key the native UDP open seals
    /// against (same key material as the TCP transfer, distinct HKDF label).
    pub(crate) const fn udp_keys(&self) -> (&HandoffPsk, &[u8; 32]) {
        (&self.psk, &self.landing_public)
    }

    /// The dial deadline, reused as the native UDP open acknowledgement
    /// deadline.
    pub(crate) const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the deadline for LANDING's first downlink byte after the
    /// transfer write — the rejection-detection window for the silent
    /// protocol. A successful transfer produces immediate downlink (the
    /// resumed response header and opening Vision frame are LANDING's first
    /// sealed record), while every rejection closes the connection silently.
    /// The validated configuration bounds this above zero; it must exceed
    /// the landing node's authentication and destination-dial budgets, or
    /// viable but slow sessions are reset.
    #[must_use]
    pub(crate) const fn first_byte_timeout(&self) -> Duration {
        self.first_byte_timeout
    }

    /// Dials LANDING and writes the one sealed transfer message.
    ///
    /// The dial and the bounded write share one deadline derived from the
    /// configured connect timeout. The connection stays open in both
    /// directions afterwards: it becomes the raw carrier for the session's
    /// client-side ciphertext, and LANDING never answers the transfer itself —
    /// its first byte on this connection is already session downlink.
    ///
    /// # Errors
    ///
    /// Returns a descriptor-budget, deadline, connection, clock, or transfer
    /// sealing error. A complete transfer write is the irreversible cutoff;
    /// bounded retries before it always construct new authenticated bytes.
    pub(crate) async fn transfer(
        &self,
        fd_budget: &FdBudget,
        state: &ContinuationState,
        client_random: [u8; 32],
    ) -> Result<(TcpStream, HandoffTransportPermit), HandoffLineError> {
        if let Some(pool) = &self.pool {
            if let Some(checkout) = pool.checkout() {
                let deadline = Instant::now()
                    .checked_add(self.connect_timeout)
                    .ok_or(HandoffLineError::Timeout)?;
                let (connection, warm) = checkout.into_parts();
                let (mut stream, fd_permit) = connection.into_parts();
                let message = self.seal_fresh(state, client_random)?;
                match write_all_counted_before(&mut stream, &message, deadline).await {
                    Ok(committed) => {
                        // The warm socket carried its own fresh authentication
                        // to completion, so it now owns this session.
                        committed.commit_transport_ownership();
                        return Ok((
                            stream,
                            HandoffTransportPermit {
                                _fd: fd_permit,
                                _warm: Some(warm),
                            },
                        ));
                    }
                    Err(error) => {
                        // The error type proves no byte was authenticated, and
                        // the warm transport is the speculative attempt, so an
                        // alternate attempt remains.
                        debug_assert!(AttemptTransport::Warm.permits_alternate_attempt());
                        let _discarded = error.progress().bytes_discarded();
                        pool.record_stale_checkout();
                        // Dropping the stream and permits permanently discards
                        // every partial byte. The immediate cold fallback is
                        // the sole alternate attempt and constructs fresh state.
                    }
                }
            }
            pool.record_cold_fallback();
        }

        // The required cold path owns a fresh per-attempt deadline. A stale
        // warm socket may consume its complete write allowance before failing;
        // carrying that expired absolute deadline into the cold dial would
        // make pool availability a correctness dependency.
        let deadline = Instant::now()
            .checked_add(self.connect_timeout)
            .ok_or(HandoffLineError::Timeout)?;
        let connected = time::timeout_at(
            deadline,
            self.connector
                .connect_host_accounted(self.address.as_ref(), self.port, fd_budget),
        )
        .await
        .map_err(|_| HandoffLineError::Timeout)?
        .map_err(|error| match error {
            DestinationConnectError::DescriptorBudget => HandoffLineError::DescriptorBudget,
            DestinationConnectError::TimedOut { .. } => HandoffLineError::Timeout,
            error => HandoffLineError::Connect(error.into_io()),
        })?;
        let (mut stream, fd_permit) = connected.into_parts();
        let message = self.seal_fresh(state, client_random)?;
        write_all_counted_before(&mut stream, &message, deadline)
            .await
            .map_err(|error| {
                let source = error.into_source();
                if source.kind() == io::ErrorKind::TimedOut {
                    HandoffLineError::Timeout
                } else {
                    HandoffLineError::Connect(source)
                }
            })?;
        Ok((
            stream,
            HandoffTransportPermit {
                _fd: fd_permit,
                _warm: None,
            },
        ))
    }

    fn seal_fresh(
        &self,
        state: &ContinuationState,
        client_random: [u8; 32],
    ) -> Result<Vec<u8>, HandoffLineError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HandoffLineError::Clock)?
            .as_secs();
        let mut message = Vec::new();
        seal_transfer(
            state,
            &self.psk,
            &self.landing_public,
            client_random,
            timestamp,
            &mut message,
        )
        .map_err(HandoffLineError::Transfer)?;
        Ok(message)
    }
}

/// Session-lifetime authority for one permanently checked-out Handoff socket.
pub(crate) struct HandoffTransportPermit {
    _fd: FdPermit,
    _warm: Option<WarmUsePermit>,
}

impl fmt::Debug for HandoffLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffLine")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("key_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// TLS record content type for application data: the resumed session's first
/// record is always sealed application data.
const TLS_APPLICATION_DATA: u8 = 23;

/// Waits, without consuming, for LANDING's first byte after the transfer and
/// classifies it.
///
/// Returns `true` only when a byte arrived before `deadline` and carries the
/// TLS application-data content type. Anything else — a silent close, a
/// reset, a stall past the deadline, or the handshake/alert bytes a misdialed
/// REALITY cover target would mirror back — is the silent protocol's
/// rejection signal, and the caller must reset the client socket rather than
/// relay on. Peeking leaves the byte in the kernel buffer for the raw relay.
pub(crate) async fn first_downlink_landed(stream: &TcpStream, deadline: Duration) -> bool {
    let mut probe = [0_u8; 1];
    match time::timeout(deadline, stream.peek(&mut probe)).await {
        Ok(Ok(bytes)) => bytes > 0 && probe[0] == TLS_APPLICATION_DATA,
        Ok(Err(_)) | Err(_) => false,
    }
}
