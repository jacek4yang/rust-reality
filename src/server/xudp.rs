//! Server-side XUDP association and egress authorization.
//!
//! Framing and Vision UDP/443 policy live in [`crate::protocol::vless`] (`encode_xudp_packet` / `decode_xudp_packet`).
//! This module owns Direct UDP sockets, GlobalID affinity, resource limits, and
//! capability-aware egress authorization ([`authorize_xudp_egress`]).
//!
//! ADR 0060 / Issue #314: NXR and Handoff are **authorized** route classes (not
//! silently remapped to Direct). NXR landward uses framed datagrams over the
//! existing LINE→LANDING TCP hop ([`XudpNxrAssociation`]). Handoff UDP uses the
//! native LINE→LANDING UDP channel (ADR 0069,
//! [`crate::server::handoff::udp::XudpHandoffUdpAssociation`]) — never silently as Direct.

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::protocol::{
    nxr_udp::{
        DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM,
        NxrUdpError, NxrUdpSeq, NxrUdpSessionKey, drain_frames, encode_frame,
    },
    vless::{
        Address, Destination, XudpCodecError, XudpGlobalId, XudpPacket, XudpSessionStatus,
        decode_xudp_packet, encode_xudp_packet,
    },
};
use crate::server::outbound::{OutboundPermit, OutboundRegistry};

/// Maximum concurrent GlobalID-keyed associations retained by this process.
pub const XUDP_MAX_ASSOCIATIONS: usize = 256;

/// Idle time after which an association is eligible for cleanup.
pub const XUDP_ASSOCIATION_IDLE: Duration = Duration::from_secs(60);

/// Maximum UDP payload accepted from an XUDP frame (matches codec bound).
pub const XUDP_MAX_DATAGRAM: usize = crate::protocol::vless::XUDP_MAX_PAYLOAD_LEN;

/// One FD-budget unit charged per Direct UDP socket.
pub const XUDP_FD_UNITS: u32 = 1;

/// Why an XUDP session cannot use a selected outbound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XudpOutboundUnsupported {
    Nxr,
    Handoff,
    Block,
    /// SOCKS5 or any other non-Direct outbound.
    Other,
}

impl fmt::Display for XudpOutboundUnsupported {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nxr => formatter.write_str(
                "XUDP NXR egress cannot open Direct landward sockets (use the NXR framed carrier)",
            ),
            Self::Handoff => formatter.write_str(
                "XUDP Handoff egress uses the native Handoff UDP channel; LINE opens no direct landward sockets for it",
            ),
            Self::Block => formatter.write_str("XUDP destination is blocked by routing"),
            Self::Other => formatter.write_str(
                "XUDP outbound is not UDP-capable (SOCKS5 or unknown); Block/unknown stay fail-closed",
            ),
        }
    }
}

impl Error for XudpOutboundUnsupported {}

/// Public classification of a routed outbound for XUDP eligibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XudpRouteClass {
    /// Builtin or equivalent Direct TCP/UDP egress.
    Direct,
    Nxr,
    Handoff,
    Block,
    /// SOCKS5 or other non-UDP-capable outbounds.
    Unsupported,
}

/// Authorized XUDP egress owner for a routed destination (ADR 0060).
///
/// Distinct variants are intentional: NXR/Handoff MUST NOT be collapsed into
/// [`Self::Direct`]. Callers that only speak Direct UDP sockets must call
/// [`require_direct_xudp_landward`]. NXR landward uses [`XudpNxrAssociation`].
/// Handoff landward UDP is never opened on LINE (transfer to LANDING instead).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XudpEgressCapability {
    /// Local Direct UDP sockets on the entry / LINE process.
    Direct,
    /// LINE→LANDING NXR UDP (framed TCP carrier per ADR 0060 Option A).
    Nxr,
    /// LINE→LANDING Handoff UDP (TLS ownership on LANDING; policy snapshot).
    Handoff,
}

/// Authorize an XUDP New/Keep destination's routed outbound class.
///
/// Returns a distinct capability for Direct, NXR, and Handoff. Block and
/// unknown/non-UDP outbounds fail closed. Never remaps NXR/Handoff to Direct.
///
/// # Errors
///
/// [`XudpOutboundUnsupported::Block`] or [`XudpOutboundUnsupported::Other`].
pub fn authorize_xudp_egress(
    class: XudpRouteClass,
) -> Result<XudpEgressCapability, XudpOutboundUnsupported> {
    match class {
        XudpRouteClass::Direct => Ok(XudpEgressCapability::Direct),
        XudpRouteClass::Nxr => Ok(XudpEgressCapability::Nxr),
        XudpRouteClass::Handoff => Ok(XudpEgressCapability::Handoff),
        XudpRouteClass::Block => Err(XudpOutboundUnsupported::Block),
        XudpRouteClass::Unsupported => Err(XudpOutboundUnsupported::Other),
    }
}

/// Returns `Ok(())` only when local Direct UDP landward sockets may be opened.
///
/// Use after [`authorize_xudp_egress`] when the caller is the Direct association
/// path. NXR/Handoff capabilities fail closed here so they cannot silently open
/// Direct sockets.
///
/// # Errors
///
/// Any non-Direct capability or rejected class maps to [`XudpOutboundUnsupported`].
pub fn require_direct_xudp_landward(
    capability: XudpEgressCapability,
) -> Result<(), XudpOutboundUnsupported> {
    match capability {
        XudpEgressCapability::Direct => Ok(()),
        XudpEgressCapability::Nxr => Err(XudpOutboundUnsupported::Nxr),
        XudpEgressCapability::Handoff => Err(XudpOutboundUnsupported::Handoff),
    }
}

/// Returns `Ok(())` only when the NXR framed landward carrier may be opened.
///
/// # Errors
///
/// Non-NXR capabilities (including Direct and Handoff) fail closed.
pub fn require_nxr_xudp_landward(
    capability: XudpEgressCapability,
) -> Result<(), XudpOutboundUnsupported> {
    match capability {
        XudpEgressCapability::Nxr => Ok(()),
        XudpEgressCapability::Direct => Err(XudpOutboundUnsupported::Other),
        XudpEgressCapability::Handoff => Err(XudpOutboundUnsupported::Handoff),
    }
}

/// Admits Handoff landward UDP on LINE: datagrams go to LANDING over the
/// native UDP channel (ADR 0069) after LINE authorized them.
///
/// # Errors
///
/// Direct and NXR capabilities fail closed here so they cannot silently use
/// the Handoff channel.
pub fn require_handoff_xudp_landward(
    capability: XudpEgressCapability,
) -> Result<(), XudpOutboundUnsupported> {
    match capability {
        XudpEgressCapability::Handoff => Ok(()),
        XudpEgressCapability::Direct => Err(XudpOutboundUnsupported::Other),
        XudpEgressCapability::Nxr => Err(XudpOutboundUnsupported::Nxr),
    }
}

/// Errors from server XUDP association handling.
#[derive(Debug)]
pub enum XudpSessionError {
    Codec(XudpCodecError),
    Outbound(XudpOutboundUnsupported),
    Io(std::io::Error),
    /// LINE→LANDING NXR UDP carrier failed to dial or authenticate.
    NxrConnect(crate::server::outbound::OutboundConnectError),
    /// NXR UDP frame codec / MAC / sequence error on the LINE carrier.
    NxrCarrier(NxrUdpError),
    /// Mid-association Keep rewrite changed egress capability (no silent remapping).
    EgressCapabilityChanged,
    AssociationLimit,
    FdBudgetExhausted,
    MissingNewDestination,
    /// Keep/New carried a destination but the caller did not supply an
    /// authorized rewrite (routing/DNS/outbound must run first).
    UnauthorizedRewrite,
    ResolveFailed,
    IdleTimeout,
    AssociationConflict,
    /// Client sent a Vision Direct command on an XUDP (UDP-only) session.
    UnexpectedVisionDirect,
    /// Native Handoff UDP channel packet construction failed on LINE.
    HandoffUdp(crate::protocol::handoff::udp::UdpPacketError),
    /// LANDING never acknowledged the native Handoff UDP open.
    HandoffUdpOpenTimeout,
    /// LANDING closed the native Handoff UDP session.
    HandoffUdpClosed,
}

impl fmt::Display for XudpSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "XUDP framing error: {error}"),
            Self::Outbound(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "XUDP UDP I/O error: {error}"),
            Self::NxrConnect(error) => write!(formatter, "XUDP NXR carrier connect error: {error}"),
            Self::NxrCarrier(error) => write!(formatter, "XUDP NXR carrier frame error: {error}"),
            Self::EgressCapabilityChanged => formatter
                .write_str("XUDP Keep rewrite changed egress capability (no silent remapping)"),
            Self::AssociationLimit => write!(
                formatter,
                "XUDP association limit ({XUDP_MAX_ASSOCIATIONS}) reached"
            ),
            Self::FdBudgetExhausted => formatter.write_str("XUDP UDP socket FD budget exhausted"),
            Self::MissingNewDestination => {
                formatter.write_str("XUDP New frame missing UDP destination")
            }
            Self::UnauthorizedRewrite => {
                formatter.write_str("XUDP destination rewrite was not authorized by routing policy")
            }
            Self::ResolveFailed => formatter.write_str("XUDP destination could not be resolved"),
            Self::IdleTimeout => formatter.write_str("XUDP association idle timeout"),
            Self::AssociationConflict => {
                formatter.write_str("XUDP GlobalID association conflict while initializing")
            }
            Self::UnexpectedVisionDirect => {
                formatter.write_str("Vision Direct is not valid on an XUDP session")
            }
            Self::HandoffUdp(error) => write!(formatter, "XUDP Handoff UDP channel error: {error}"),
            Self::HandoffUdpOpenTimeout => formatter.write_str(
                "XUDP Handoff UDP open was not acknowledged by LANDING \
                 (check that the landing UDP port is reachable from this node)",
            ),
            Self::HandoffUdpClosed => {
                formatter.write_str("XUDP Handoff UDP session was closed by LANDING")
            }
        }
    }
}

impl Error for XudpSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Outbound(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::NxrConnect(error) => Some(error),
            Self::NxrCarrier(error) => Some(error),
            Self::HandoffUdp(error) => Some(error),
            _ => None,
        }
    }
}

impl From<XudpCodecError> for XudpSessionError {
    fn from(error: XudpCodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<XudpOutboundUnsupported> for XudpSessionError {
    fn from(error: XudpOutboundUnsupported) -> Self {
        Self::Outbound(error)
    }
}

/// Resolve a VLESS [`Destination`] to a UDP [`SocketAddr`] for Direct egress.
pub fn destination_to_socket_addr(
    destination: &Destination,
) -> Result<SocketAddr, XudpSessionError> {
    match destination.address() {
        Address::Ipv4(addr) => Ok(SocketAddr::from((*addr, destination.port()))),
        Address::Ipv6(addr) => Ok(SocketAddr::from((*addr, destination.port()))),
        Address::Domain(_) => Err(XudpSessionError::ResolveFailed),
    }
}

/// GlobalID map (cone-NAT affinity), mirroring stock `XUDPManager`.
///
/// Use [`process_xudp_global_map`] for the process-wide instance. Capacity
/// [`XUDP_MAX_ASSOCIATIONS`] is enforced on that shared map, not per session.
#[derive(Default)]
pub struct XudpGlobalMap {
    inner: Mutex<HashMap<XudpGlobalId, GlobalEntry>>,
}

struct GlobalEntry {
    expire: Instant,
    active_leases: usize,
    /// Authenticated VLESS user that owns all active leases and the following
    /// expiration grace. Prevents cross-user claim of a live id.
    owner: [u8; 16],
}

/// One association's ownership of a GlobalID. Dropping it starts the existing
/// grace period only when no other association of the same user owns the ID.
#[must_use = "the lease must live as long as its association"]
pub struct XudpGlobalLease<'a> {
    map: Option<&'a XudpGlobalMap>,
    id: XudpGlobalId,
}

impl XudpGlobalLease<'_> {
    /// Releases this owner at an explicit time (for orderly close and tests).
    pub fn release(mut self, now: Instant) {
        if let Some(map) = self.map.take() {
            map.release_lease(self.id, now);
        }
    }
}

impl Drop for XudpGlobalLease<'_> {
    fn drop(&mut self) {
        if let Some(map) = self.map.take() {
            map.release_lease(self.id, Instant::now());
        }
    }
}

impl XudpGlobalMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires one association lease for `owner` before fallible setup.
    ///
    /// Capacity [`XUDP_MAX_ASSOCIATIONS`] is process-wide. An Active (or still
    /// Expiring) id owned by a *different* user fails closed with
    /// [`XudpSessionError::AssociationConflict`] — no cross-user takeover.
    pub fn acquire(
        &self,
        id: XudpGlobalId,
        owner: [u8; 16],
        now: Instant,
    ) -> Result<XudpGlobalLease<'_>, XudpSessionError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.purge_locked(&mut guard, now);
        if let Some(entry) = guard.get_mut(&id) {
            if entry.owner != owner {
                return Err(XudpSessionError::AssociationConflict);
            }
            entry.active_leases = entry
                .active_leases
                .checked_add(1)
                .ok_or(XudpSessionError::AssociationLimit)?;
            return Ok(XudpGlobalLease {
                map: Some(self),
                id,
            });
        }
        if guard.len() >= XUDP_MAX_ASSOCIATIONS {
            return Err(XudpSessionError::AssociationLimit);
        }
        guard.insert(
            id,
            GlobalEntry {
                expire: now + XUDP_ASSOCIATION_IDLE,
                active_leases: 1,
                owner,
            },
        );
        Ok(XudpGlobalLease {
            map: Some(self),
            id,
        })
    }

    fn release_lease(&self, id: XudpGlobalId, now: Instant) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(&id) {
            entry.active_leases -= 1;
            if entry.active_leases == 0 {
                entry.expire = now + XUDP_ASSOCIATION_IDLE;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Returns whether no GlobalID associations are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn purge_locked(&self, map: &mut HashMap<XudpGlobalId, GlobalEntry>, now: Instant) {
        map.retain(|_, entry| !(entry.active_leases == 0 && now >= entry.expire));
    }

    pub fn purge(&self, now: Instant) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.purge_locked(&mut guard, now);
    }
}

/// Returns the process-wide GlobalID association map (stock `XUDPManager`).
///
/// All Vision XUDP sessions share this map so capacity and affinity accounting
/// are truly process-wide, not per Mux/TLS session.
pub fn process_xudp_global_map() -> &'static XudpGlobalMap {
    static GLOBALS: OnceLock<XudpGlobalMap> = OnceLock::new();
    GLOBALS.get_or_init(XudpGlobalMap::new)
}

/// One Direct UDP association for an XUDP Mux session (session id 0).
///
/// XUDP Keep frames may name a new destination on every packet, and a
/// resolved domain may be IPv4 or IPv6 independently of the first
/// destination. The association therefore owns one ephemeral socket per
/// address family, created lazily, exactly like the LANDING per-session
/// egress slots of the native Handoff UDP channel (ADR 0069). A datagram the
/// host cannot route (no IPv6 route, IPv6 disabled, a family the bind address
/// cannot reach) is dropped like any lost UDP datagram instead of tearing down
/// every other flow multiplexed on the same XUDP session.
pub struct XudpDirectAssociation<'a> {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    bind_ip: Option<IpAddr>,
    destination: SocketAddr,
    global_lease: Option<XudpGlobalLease<'a>>,
    last_activity: Instant,
    uplink_datagrams: u64,
    downlink_datagrams: u64,
    dropped_datagrams: u64,
}

/// Wildcard or configured bind address for an egress socket of `family`.
///
/// A configured `bind_ip` of the other family cannot source this family's
/// datagrams, so that family falls back to the wildcard address.
fn egress_bind_address(bind_ip: Option<IpAddr>, ipv6: bool) -> SocketAddr {
    match (bind_ip, ipv6) {
        (Some(ip @ IpAddr::V4(_)), false) | (Some(ip @ IpAddr::V6(_)), true) => {
            SocketAddr::new(ip, 0)
        }
        (_, false) => SocketAddr::from(([0, 0, 0, 0], 0)),
        (_, true) => SocketAddr::from(([0_u16; 8], 0)),
    }
}

/// Whether a UDP send error only means "this datagram cannot be routed from
/// this host" (UDP loss), rather than a broken association.
pub(crate) fn is_unroutable_datagram_error(error: &std::io::Error) -> bool {
    const EAFNOSUPPORT: i32 = 97;
    const EMSGSIZE: i32 = 90;
    matches!(
        error.kind(),
        std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::PermissionDenied
    ) || matches!(error.raw_os_error(), Some(EAFNOSUPPORT | EMSGSIZE))
}

/// Whether this host has a route toward `ip` for UDP egress.
///
/// `connect(2)` on an unbound UDP socket performs only the kernel route
/// lookup; no packet is sent. A host without an IPv6 default route (or with
/// IPv6 disabled) answers `ENETUNREACH` / `EAFNOSUPPORT` here.
pub fn udp_route_available(ip: IpAddr) -> bool {
    let bind = egress_bind_address(None, ip.is_ipv6());
    std::net::UdpSocket::bind(bind)
        .and_then(|socket| socket.connect(SocketAddr::new(ip, 9)))
        .is_ok()
}

async fn bind_egress(bind_ip: Option<IpAddr>, ipv6: bool) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(egress_bind_address(bind_ip, ipv6)).await
}

/// Receives the next datagram from whichever family socket has one.
///
/// Cancel-safe: `recv_from` and `readable` are cancel-safe, and the
/// non-blocking read after readiness completes synchronously.
async fn recv_either(
    v4: Option<&UdpSocket>,
    v6: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match (v4, v6) {
        (Some(socket), None) | (None, Some(socket)) => socket.recv_from(buf).await,
        (Some(v4), Some(v6)) => loop {
            let socket = tokio::select! {
                ready = v4.readable() => { ready?; v4 }
                ready = v6.readable() => { ready?; v6 }
            };
            match socket.try_recv_from(buf) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                received => return received,
            }
        },
        (None, None) => std::future::pending().await,
    }
}

impl<'a> XudpDirectAssociation<'a> {
    /// Bind an ephemeral UDP socket for the first destination's family and
    /// remember that destination. The other family's socket is created on
    /// first use.
    ///
    /// When `bind_ip` is set (Handoff/NXR LANDING), sockets of that family are
    /// bound to that address so peers observe LANDING's IP on multi-address
    /// hosts (e.g. LANDING on `127.0.0.2`). Direct egress passes `None`
    /// (wildcard).
    pub async fn open(
        destination: &Destination,
        global_id: Option<XudpGlobalId>,
        owner: [u8; 16],
        globals: &'a XudpGlobalMap,
        now: Instant,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Result<Self, XudpSessionError> {
        let addr = destination_to_socket_addr(destination)?;
        let global_lease = global_id
            .map(|id| globals.acquire(id, owner, now))
            .transpose()?;
        let socket = bind_egress(bind_ip, addr.is_ipv6())
            .await
            .map_err(XudpSessionError::Io)?;
        let (v4, v6) = if addr.is_ipv6() {
            (None, Some(socket))
        } else {
            (Some(socket), None)
        };
        Ok(Self {
            v4,
            v6,
            bind_ip,
            destination: addr,
            global_lease,
            last_activity: now,
            uplink_datagrams: 0,
            downlink_datagrams: 0,
            dropped_datagrams: 0,
        })
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn uplink_datagrams(&self) -> u64 {
        self.uplink_datagrams
    }

    pub fn downlink_datagrams(&self) -> u64 {
        self.downlink_datagrams
    }

    /// Uplink datagrams dropped because this host cannot route them.
    pub fn dropped_datagrams(&self) -> u64 {
        self.dropped_datagrams
    }

    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns the egress socket for `destination`'s family, creating it on
    /// first use. `Ok(None)` means the host cannot open that family.
    async fn egress_socket(
        &mut self,
        destination: SocketAddr,
    ) -> Result<Option<&UdpSocket>, XudpSessionError> {
        let ipv6 = destination.is_ipv6();
        let slot = if ipv6 { &mut self.v6 } else { &mut self.v4 };
        if slot.is_none() {
            match bind_egress(self.bind_ip, ipv6).await {
                Ok(socket) => *slot = Some(socket),
                Err(error) if is_unroutable_datagram_error(&error) => return Ok(None),
                Err(error) => return Err(XudpSessionError::Io(error)),
            }
        }
        Ok(slot.as_ref())
    }

    /// Apply one decoded uplink XUDP packet: send UDP after an authorized rewrite.
    ///
    /// When `packet.destination` is present (New, or Keep rewrite), the caller
    /// MUST supply `authorized_destination`: the same logical destination after
    /// canonical routing, DNS resolution, and capability-aware egress checks.
    /// Associations never inherit a prior Direct decision across a rewrite.
    pub async fn handle_uplink_packet(
        &mut self,
        packet: &XudpPacket,
        authorized_destination: Option<&Destination>,
        now: Instant,
    ) -> Result<(), XudpSessionError> {
        match packet.status {
            XudpSessionStatus::End | XudpSessionStatus::KeepAlive => {
                self.last_activity = now;
                return Ok(());
            }
            XudpSessionStatus::New | XudpSessionStatus::Keep => {}
        }
        if packet.destination.is_some() {
            let dest = authorized_destination.ok_or(XudpSessionError::UnauthorizedRewrite)?;
            self.destination = destination_to_socket_addr(dest)?;
        } else if packet.status == XudpSessionStatus::New {
            return Err(XudpSessionError::MissingNewDestination);
        }
        if !packet.payload.is_empty() {
            let destination = self.destination;
            let sent = match self.egress_socket(destination).await? {
                Some(socket) => match socket.send_to(&packet.payload, destination).await {
                    Ok(_) => true,
                    Err(error) if is_unroutable_datagram_error(&error) => false,
                    Err(error) => return Err(XudpSessionError::Io(error)),
                },
                None => false,
            };
            if sent {
                self.uplink_datagrams = self.uplink_datagrams.saturating_add(1);
            } else {
                self.dropped_datagrams = self.dropped_datagrams.saturating_add(1);
            }
        }
        self.last_activity = now;
        Ok(())
    }

    /// Receive one downlink UDP datagram and encode an XUDP Keep frame.
    pub async fn recv_downlink_frame(
        &mut self,
        buf: &mut [u8],
        output: &mut Vec<u8>,
        now: Instant,
    ) -> Result<usize, XudpSessionError> {
        let (n, from) = recv_either(self.v4.as_ref(), self.v6.as_ref(), buf)
            .await
            .map_err(XudpSessionError::Io)?;
        // Preserve peer address in the Keep frame so multi-address sessions work.
        let dest = Destination::from(from);
        output.clear();
        encode_xudp_packet(&dest, &buf[..n], false, None, true, output)?;
        self.downlink_datagrams = self.downlink_datagrams.saturating_add(1);
        self.last_activity = now;
        Ok(output.len())
    }

    pub fn close(self, now: Instant) {
        if let Some(lease) = self.global_lease {
            lease.release(now);
        }
    }
}

/// Bound on unreassembled NXR UDP frame bytes buffered on the LINE carrier.
const NXR_LINE_FRAME_BUFFER: usize = 256 * 1024;

/// One XUDP association whose landward UDP sockets live on an NXR LANDING node.
///
/// LINE retains routing authority: every New/Keep destination is authorized
/// locally, then integrity-protected inside NXR UDP frames (ADR 0060 Option A).
pub struct XudpNxrAssociation<'a> {
    stream: TcpStream,
    _permit: OutboundPermit,
    session: NxrUdpSessionKey,
    seq_out: NxrUdpSeq,
    seq_in: NxrUdpSeq,
    last_uplink_destination: Destination,
    inbound_buf: Vec<u8>,
    pending_downlink: VecDeque<crate::protocol::nxr_udp::NxrUdpFrame>,
    global_lease: Option<XudpGlobalLease<'a>>,
    last_activity: Instant,
    uplink_datagrams: u64,
    downlink_datagrams: u64,
}

impl<'a> XudpNxrAssociation<'a> {
    /// Dial LANDING with a UDP-mode open and register GlobalID affinity.
    pub async fn open(
        outbounds: &OutboundRegistry,
        outbound_tag: &str,
        destination: &Destination,
        user_id: [u8; 16],
        global_id: Option<XudpGlobalId>,
        globals: &'a XudpGlobalMap,
        now: Instant,
    ) -> Result<Self, XudpSessionError> {
        let global_lease = global_id
            .map(|id| globals.acquire(id, user_id, now))
            .transpose()?;
        let (connection, session) = outbounds
            .connect_nxr_udp(outbound_tag, destination, user_id)
            .await
            .map_err(XudpSessionError::NxrConnect)?;
        let (stream, permit) = connection.into_parts();
        Ok(Self {
            stream,
            _permit: permit,
            session,
            seq_out: NxrUdpSeq::new(),
            seq_in: NxrUdpSeq::new(),
            last_uplink_destination: destination.clone(),
            inbound_buf: Vec::new(),
            pending_downlink: VecDeque::new(),
            global_lease,
            last_activity: now,
            uplink_datagrams: 0,
            downlink_datagrams: 0,
        })
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    pub fn uplink_datagrams(&self) -> u64 {
        self.uplink_datagrams
    }

    pub fn downlink_datagrams(&self) -> u64 {
        self.downlink_datagrams
    }

    /// Apply one uplink XUDP packet over the NXR framed carrier.
    pub async fn handle_uplink_packet(
        &mut self,
        packet: &XudpPacket,
        authorized_destination: Option<&Destination>,
        now: Instant,
    ) -> Result<(), XudpSessionError> {
        match packet.status {
            XudpSessionStatus::End | XudpSessionStatus::KeepAlive => {
                self.last_activity = now;
                return Ok(());
            }
            XudpSessionStatus::New | XudpSessionStatus::Keep => {}
        }
        let mut dest_for_frame = None;
        if packet.destination.is_some() {
            let dest = authorized_destination.ok_or(XudpSessionError::UnauthorizedRewrite)?;
            if dest != &self.last_uplink_destination {
                dest_for_frame = Some(dest.clone());
                self.last_uplink_destination = dest.clone();
            } else if packet.status == XudpSessionStatus::New {
                // Open already carried this destination; omit redundant field.
                dest_for_frame = None;
            }
        } else if packet.status == XudpSessionStatus::New {
            return Err(XudpSessionError::MissingNewDestination);
        }
        if !packet.payload.is_empty() || dest_for_frame.is_some() {
            let seq = self
                .seq_out
                .next_out()
                .map_err(XudpSessionError::NxrCarrier)?;
            let mut wire = Vec::new();
            encode_frame(
                &self.session,
                DIR_LINE_TO_LANDING,
                FRAME_TYPE_DATAGRAM,
                seq,
                dest_for_frame.as_ref(),
                &packet.payload,
                &mut wire,
            )
            .map_err(XudpSessionError::NxrCarrier)?;
            self.stream
                .write_all(&wire)
                .await
                .map_err(XudpSessionError::Io)?;
            if !packet.payload.is_empty() {
                self.uplink_datagrams = self.uplink_datagrams.saturating_add(1);
            }
        }
        self.last_activity = now;
        Ok(())
    }

    /// Receive one downlink NXR datagram frame and encode an XUDP Keep frame.
    pub async fn recv_downlink_frame(
        &mut self,
        _buf: &mut [u8],
        output: &mut Vec<u8>,
        now: Instant,
    ) -> Result<usize, XudpSessionError> {
        loop {
            if let Some(frame) = self.pending_downlink.pop_front() {
                return self.finish_downlink_frame(frame, output, now);
            }
            while self.inbound_buf.len() >= 4 {
                let frames =
                    drain_frames(&mut self.inbound_buf, &self.session, DIR_LANDING_TO_LINE)
                        .map_err(XudpSessionError::NxrCarrier)?;
                if frames.is_empty() {
                    break;
                }
                self.pending_downlink.extend(frames);
                if let Some(frame) = self.pending_downlink.pop_front() {
                    return self.finish_downlink_frame(frame, output, now);
                }
            }
            let n = self
                .stream
                .read_buf(&mut self.inbound_buf)
                .await
                .map_err(XudpSessionError::Io)?;
            if n == 0 {
                return Err(XudpSessionError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "NXR UDP carrier closed",
                )));
            }
            if self.inbound_buf.len() > NXR_LINE_FRAME_BUFFER {
                return Err(XudpSessionError::NxrCarrier(NxrUdpError::Length));
            }
        }
    }

    fn finish_downlink_frame(
        &mut self,
        frame: crate::protocol::nxr_udp::NxrUdpFrame,
        output: &mut Vec<u8>,
        now: Instant,
    ) -> Result<usize, XudpSessionError> {
        self.seq_in
            .accept_in(frame.seq)
            .map_err(XudpSessionError::NxrCarrier)?;
        if frame.frame_type == FRAME_TYPE_CLOSE {
            return Err(XudpSessionError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "NXR UDP association closed by LANDING",
            )));
        }
        if frame.frame_type != FRAME_TYPE_DATAGRAM {
            return Err(XudpSessionError::NxrCarrier(NxrUdpError::FrameType));
        }
        // LANDING must identify the actual UDP source. Inferring it from an
        // uplink target mislabels delayed replies after a destination rewrite.
        let dest = frame
            .destination
            .as_ref()
            .ok_or(XudpSessionError::NxrCarrier(NxrUdpError::Address))?;
        output.clear();
        encode_xudp_packet(dest, &frame.payload, false, None, true, output)?;
        self.downlink_datagrams = self.downlink_datagrams.saturating_add(1);
        self.last_activity = now;
        Ok(output.len())
    }

    pub async fn close(mut self, now: Instant) {
        let mut wire = Vec::new();
        if let Ok(seq) = self.seq_out.next_out()
            && encode_frame(
                &self.session,
                DIR_LINE_TO_LANDING,
                FRAME_TYPE_CLOSE,
                seq,
                None,
                &[],
                &mut wire,
            )
            .is_ok()
        {
            let _ = self.stream.write_all(&wire).await;
        }
        let _ = self.stream.shutdown().await;
        if let Some(lease) = self.global_lease {
            lease.release(now);
        }
    }
}

/// Decode and drain complete XUDP frames from a Vision plaintext buffer.
pub fn drain_xudp_frames(buffer: &mut Vec<u8>) -> Result<Vec<XudpPacket>, XudpSessionError> {
    let mut packets = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() {
        match decode_xudp_packet(&buffer[offset..]) {
            Ok((packet, consumed)) => {
                offset += consumed;
                packets.push(packet);
            }
            Err(XudpCodecError::Truncated { .. }) => break,
            Err(error) => return Err(XudpSessionError::Codec(error)),
        }
    }
    if offset > 0 {
        buffer.drain(..offset);
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vless::VISION_FLOW;
    use std::net::Ipv4Addr;

    #[test]
    fn authorize_direct_ok_and_landward_direct() {
        let cap = authorize_xudp_egress(XudpRouteClass::Direct).unwrap();
        assert_eq!(cap, XudpEgressCapability::Direct);
        require_direct_xudp_landward(cap).unwrap();
    }

    #[test]
    fn require_nxr_xudp_landward_only_accepts_nxr() {
        require_nxr_xudp_landward(XudpEgressCapability::Nxr).unwrap();
        assert_eq!(
            require_nxr_xudp_landward(XudpEgressCapability::Direct),
            Err(XudpOutboundUnsupported::Other)
        );
        assert_eq!(
            require_nxr_xudp_landward(XudpEgressCapability::Handoff),
            Err(XudpOutboundUnsupported::Handoff)
        );
        // ADR 0069: Handoff XUDP is served on LINE over the native channel.
        require_handoff_xudp_landward(XudpEgressCapability::Handoff).unwrap();
        assert_eq!(
            require_handoff_xudp_landward(XudpEgressCapability::Direct),
            Err(XudpOutboundUnsupported::Other)
        );
        assert_eq!(
            require_handoff_xudp_landward(XudpEgressCapability::Nxr),
            Err(XudpOutboundUnsupported::Nxr)
        );
    }

    #[test]
    fn authorize_nxr_and_handoff_are_distinct_not_direct() {
        let nxr = authorize_xudp_egress(XudpRouteClass::Nxr).unwrap();
        let handoff = authorize_xudp_egress(XudpRouteClass::Handoff).unwrap();
        assert_eq!(nxr, XudpEgressCapability::Nxr);
        assert_eq!(handoff, XudpEgressCapability::Handoff);
        assert_ne!(nxr, XudpEgressCapability::Direct);
        assert_ne!(handoff, XudpEgressCapability::Direct);
        // Direct landward path must not accept them (no silent Direct sockets).
        assert_eq!(
            require_direct_xudp_landward(nxr),
            Err(XudpOutboundUnsupported::Nxr)
        );
        assert_eq!(
            require_direct_xudp_landward(handoff),
            Err(XudpOutboundUnsupported::Handoff)
        );
    }

    #[test]
    fn authorize_block_and_unsupported_fail_closed() {
        assert_eq!(
            authorize_xudp_egress(XudpRouteClass::Block),
            Err(XudpOutboundUnsupported::Block)
        );
        assert_eq!(
            authorize_xudp_egress(XudpRouteClass::Unsupported),
            Err(XudpOutboundUnsupported::Other)
        );
    }

    #[test]
    fn process_global_map_is_shared_across_calls() {
        let a = process_xudp_global_map() as *const XudpGlobalMap;
        let b = process_xudp_global_map() as *const XudpGlobalMap;
        assert_eq!(a, b);
    }

    #[test]
    fn global_map_respects_capacity_and_expire() {
        let map = XudpGlobalMap::new();
        let now = Instant::now();
        let mut leases = Vec::new();
        for i in 0..XUDP_MAX_ASSOCIATIONS {
            let mut id = [0_u8; 8];
            id[0] = (i / 256) as u8;
            id[1] = (i % 256) as u8;
            leases.push(map.acquire(id, [1; 16], now).unwrap());
        }
        assert!(matches!(
            map.acquire([0xff; 8], [1; 16], now),
            Err(XudpSessionError::AssociationLimit)
        ));
        leases.remove(0).release(now);
        map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert_eq!(map.len(), XUDP_MAX_ASSOCIATIONS - 1);
        let _replacement = map.acquire([0xff; 8], [1; 16], now).unwrap();
    }

    #[test]
    fn cancelling_a_pending_owner_releases_its_global_lease() {
        let map = XudpGlobalMap::new();
        let mut pending = Box::pin(async {
            let _lease = map.acquire([0x55; 8], [0x55; 16], Instant::now()).unwrap();
            std::future::pending::<()>().await;
        });
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(pending.as_mut(), &mut context).is_pending());
        let after_grace = Instant::now() + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1);
        map.purge(after_grace);
        assert_eq!(map.len(), 1, "a pending owner still holds its lease");
        drop(pending);
        map.purge(Instant::now() + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert!(map.is_empty());
    }

    #[test]
    fn drain_frames_round_trip() {
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 9);
        let mut wire = Vec::new();
        encode_xudp_packet(&dest, b"ping", true, Some([1; 8]), false, &mut wire).unwrap();
        encode_xudp_packet(&dest, b"pong", false, None, false, &mut wire).unwrap();
        let mut buffer = wire;
        let packets = drain_xudp_frames(&mut buffer).unwrap();
        assert!(buffer.is_empty());
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].payload, b"ping");
        assert_eq!(packets[1].payload, b"pong");
        let _ = VISION_FLOW;
    }

    #[tokio::test]
    async fn direct_udp_echo_round_trip() {
        let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let dest = Destination::from(echo_addr);
        let globals = XudpGlobalMap::new();
        let now = Instant::now();
        let mut assoc =
            XudpDirectAssociation::open(&dest, Some([9; 8]), [9; 16], &globals, now, None)
                .await
                .unwrap();

        let packet = {
            let mut wire = Vec::new();
            encode_xudp_packet(&dest, b"hello-xudp", true, Some([9; 8]), false, &mut wire).unwrap();
            decode_xudp_packet(&wire).unwrap().0
        };
        assoc
            .handle_uplink_packet(&packet, packet.destination.as_ref(), Instant::now())
            .await
            .unwrap();

        let mut buf = [0_u8; 64];
        let (n, from) = echo.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello-xudp");
        echo.send_to(b"echo-ok", from).await.unwrap();

        let mut out = Vec::new();
        let mut recv_buf = [0_u8; 2048];
        assoc
            .recv_downlink_frame(&mut recv_buf, &mut out, Instant::now())
            .await
            .unwrap();
        let (reply, _) = decode_xudp_packet(&out).unwrap();
        assert_eq!(reply.payload, b"echo-ok");
        assert_eq!(reply.status, XudpSessionStatus::Keep);
        assert_eq!(assoc.uplink_datagrams(), 1);
        assert_eq!(assoc.downlink_datagrams(), 1);
        assoc.close(Instant::now());
    }

    fn keep_to(dest: &Destination, payload: &[u8]) -> XudpPacket {
        let mut wire = Vec::new();
        encode_xudp_packet(dest, payload, false, None, true, &mut wire).unwrap();
        decode_xudp_packet(&wire).unwrap().0
    }

    async fn downlink(assoc: &mut XudpDirectAssociation<'_>) -> XudpPacket {
        let mut out = Vec::new();
        let mut recv_buf = vec![0_u8; 64 * 1024];
        tokio::time::timeout(
            Duration::from_secs(5),
            assoc.recv_downlink_frame(&mut recv_buf, &mut out, Instant::now()),
        )
        .await
        .expect("downlink datagram")
        .unwrap();
        decode_xudp_packet(&out).unwrap().0
    }

    /// v2.4.0 field bug: the association socket followed the first
    /// destination's family, so a later Keep rewrite to the other family (a
    /// domain whose AAAA answer sorts first on a dual-stack LINE) failed with
    /// `EAFNOSUPPORT` and tore down every flow of the XUDP session.
    #[tokio::test]
    async fn keep_rewrite_across_address_families_keeps_the_association() {
        let Ok(echo6) = UdpSocket::bind(SocketAddr::from(([0_u16, 0, 0, 0, 0, 0, 0, 1], 0))).await
        else {
            eprintln!("skipping: no IPv6 loopback on this host");
            return;
        };
        let echo4 = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let dest4 = Destination::from(echo4.local_addr().unwrap());
        let dest6 = Destination::from(echo6.local_addr().unwrap());
        let globals = XudpGlobalMap::new();
        let mut assoc = XudpDirectAssociation::open(
            &dest4,
            Some([7; 8]),
            [7; 16],
            &globals,
            Instant::now(),
            None,
        )
        .await
        .unwrap();
        let mut buf = [0_u8; 64];
        for (round, (dest, echo)) in [(&dest4, &echo4), (&dest6, &echo6), (&dest4, &echo4)]
            .into_iter()
            .enumerate()
        {
            let payload = format!("round-{round}");
            let packet = keep_to(dest, payload.as_bytes());
            assoc
                .handle_uplink_packet(&packet, packet.destination.as_ref(), Instant::now())
                .await
                .expect("cross-family Keep rewrite must not fail the association");
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], payload.as_bytes());
            echo.send_to(payload.as_bytes(), from).await.unwrap();
            let reply = downlink(&mut assoc).await;
            assert_eq!(reply.payload, payload.as_bytes());
            assert_eq!(
                reply.destination.as_ref(),
                Some(dest),
                "reply names its real source"
            );
        }
        assert_eq!(assoc.uplink_datagrams(), 3);
        assert_eq!(assoc.downlink_datagrams(), 3);
        assert_eq!(assoc.dropped_datagrams(), 0);
        assoc.close(Instant::now());
    }

    /// A datagram the host cannot route is UDP loss, not a session failure:
    /// the next routable datagram on the same association still flows.
    #[tokio::test]
    async fn unroutable_datagram_is_dropped_without_closing_the_association() {
        let echo4 = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let dest4 = Destination::from(echo4.local_addr().unwrap());
        let globals = XudpGlobalMap::new();
        // LANDING-style IPv4 bind address; 2001:db8::/32 is documentation
        // space: unroutable on IPv4-only hosts (`ENETUNREACH`) and silently
        // lost elsewhere. Either way the association must survive.
        let mut assoc = XudpDirectAssociation::open(
            &dest4,
            None,
            [8; 16],
            &globals,
            Instant::now(),
            Some(IpAddr::from([127, 0, 0, 1])),
        )
        .await
        .unwrap();
        let doc6 = Destination::new(Address::Ipv6("2001:db8::1".parse().unwrap()), 9);
        let packet = keep_to(&doc6, b"nowhere");
        assoc
            .handle_uplink_packet(&packet, packet.destination.as_ref(), Instant::now())
            .await
            .expect("an unroutable datagram must not fail the association");
        let packet = keep_to(&dest4, b"still-here");
        assoc
            .handle_uplink_packet(&packet, packet.destination.as_ref(), Instant::now())
            .await
            .unwrap();
        let mut buf = [0_u8; 64];
        let (n, from) = echo4.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"still-here");
        echo4.send_to(b"ok", from).await.unwrap();
        assert_eq!(downlink(&mut assoc).await.payload, b"ok");
        assert_eq!(
            assoc.uplink_datagrams() + assoc.dropped_datagrams(),
            2,
            "every datagram is either sent or counted as dropped"
        );
        assoc.close(Instant::now());
    }

    #[test]
    fn unroutable_errors_are_classified_as_datagram_loss() {
        use std::io::Error;
        for errno in [97, 90, 101, 113, 99, 1, 13] {
            assert!(
                is_unroutable_datagram_error(&Error::from_raw_os_error(errno)),
                "errno {errno}"
            );
        }
        for errno in [9, 24, 105] {
            assert!(
                !is_unroutable_datagram_error(&Error::from_raw_os_error(errno)),
                "errno {errno}"
            );
        }
    }

    #[test]
    fn egress_bind_address_falls_back_to_wildcard_for_the_other_family() {
        let v4: IpAddr = [127, 0, 0, 2].into();
        assert_eq!(egress_bind_address(Some(v4), false), SocketAddr::new(v4, 0));
        assert_eq!(
            egress_bind_address(Some(v4), true),
            SocketAddr::from(([0_u16; 8], 0))
        );
        assert_eq!(
            egress_bind_address(None, false),
            SocketAddr::from(([0, 0, 0, 0], 0))
        );
    }

    #[tokio::test]
    async fn uplink_rewrite_without_authorization_fails_closed() {
        let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let dest = Destination::from(echo.local_addr().unwrap());
        let globals = XudpGlobalMap::new();
        let mut assoc =
            XudpDirectAssociation::open(&dest, None, [2; 16], &globals, Instant::now(), None)
                .await
                .unwrap();
        let blocked = Destination::new(Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), 9);
        let packet = {
            let mut wire = Vec::new();
            encode_xudp_packet(&blocked, b"nope", false, None, true, &mut wire).unwrap();
            decode_xudp_packet(&wire).unwrap().0
        };
        assert!(packet.destination.is_some());
        let err = assoc
            .handle_uplink_packet(&packet, None, Instant::now())
            .await
            .expect_err("rewrite without authorization must fail closed");
        assert!(matches!(err, XudpSessionError::UnauthorizedRewrite));
        assert_eq!(assoc.uplink_datagrams(), 0);
        assoc.close(Instant::now());
    }

    #[test]
    fn keep_rewrite_route_class_red_green() {
        // GREEN: Direct→Direct rewrite stays authorized as Direct.
        assert_eq!(
            authorize_xudp_egress(XudpRouteClass::Direct).unwrap(),
            XudpEgressCapability::Direct
        );
        // RED: Block / Unsupported fail closed (no inheritance from a prior Direct).
        assert_eq!(
            authorize_xudp_egress(XudpRouteClass::Block),
            Err(XudpOutboundUnsupported::Block)
        );
        assert_eq!(
            authorize_xudp_egress(XudpRouteClass::Unsupported),
            Err(XudpOutboundUnsupported::Other)
        );
        // NXR/Handoff authorize as themselves — never as Direct — and Direct
        // landward still rejects them (no silent Direct fallback).
        for (class, cap, landward_err) in [
            (
                XudpRouteClass::Nxr,
                XudpEgressCapability::Nxr,
                XudpOutboundUnsupported::Nxr,
            ),
            (
                XudpRouteClass::Handoff,
                XudpEgressCapability::Handoff,
                XudpOutboundUnsupported::Handoff,
            ),
        ] {
            assert_eq!(authorize_xudp_egress(class).unwrap(), cap);
            assert_eq!(require_direct_xudp_landward(cap), Err(landward_err));
        }
    }

    #[tokio::test]
    async fn association_close_then_purge_releases_global_slot() {
        let echo = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let dest = Destination::from(echo.local_addr().unwrap());
        let globals = XudpGlobalMap::new();
        let now = Instant::now();
        let gid = [7_u8; 8];
        let assoc = XudpDirectAssociation::open(&dest, Some(gid), [7; 16], &globals, now, None)
            .await
            .unwrap();
        assert_eq!(globals.len(), 1);
        // close marks the GlobalID expired; purge drops it (control-EOF / cancel path).
        assoc.close(now);
        globals.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert_eq!(globals.len(), 0);
        let again = XudpDirectAssociation::open(&dest, Some(gid), [7; 16], &globals, now, None)
            .await
            .unwrap();
        assert_eq!(globals.len(), 1);
        again.close(now);
    }

    #[test]
    fn global_id_rejects_cross_user_claim_while_active() {
        let map = XudpGlobalMap::new();
        let now = Instant::now();
        let gid = [0x42_u8; 8];
        let first = map.acquire(gid, [1; 16], now).unwrap();
        assert!(matches!(
            map.acquire(gid, [2; 16], now),
            Err(XudpSessionError::AssociationConflict)
        ));
        // Same owner may acquire an independent lease.
        let second = map.acquire(gid, [1; 16], now).unwrap();
        first.release(now);
        map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        assert_eq!(map.len(), 1);
        second.release(now);
        map.purge(now + XUDP_ASSOCIATION_IDLE + Duration::from_secs(1));
        // After purge, a different user may claim the id.
        let _replacement = map.acquire(gid, [2; 16], now).unwrap();
    }
}
