//! LANDING end of the native Handoff UDP channel.
//!
//! One task per bound landing address owns the channel socket. It
//! authenticates OPENs against the current generation's Handoff key material,
//! then forwards each authenticated datagram to the destination LINE
//! authorized and returns every reply through the same session. LANDING
//! evaluates no routing rules: authorization is LINE's, and only packets
//! sealed with a live session's keys are ever forwarded.
//!
//! Bounds: at most [`MAX_LANDING_UDP_SESSIONS`] sessions; each holds at most
//! one egress socket per address family, charged to the process descriptor
//! budget; sessions expire after [`LANDING_UDP_SESSION_IDLE`] without
//! authenticated traffic in either direction; reassembly is bounded per
//! session. Unauthenticated packets cost one header parse (or, for an OPEN,
//! one bounded replay reserve and the candidate trials) and are never
//! answered.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::{
    net::UdpSocket,
    sync::{Mutex, watch},
    task::JoinHandle,
    time,
};

use super::endpoint::{
    ChannelEndpoint, Received, Target, bind_dont_fragment, prober_for, production_timers,
};
use crate::logging::{HandoffUdpEndReason, LogEvent, Logger};
use crate::protocol::handoff::{
    HandoffLandingKeys, HandoffReplayCache,
    udp::{MAX_UDP_PAYLOAD_LEN, OPEN_LEN, PacketType, SESSION_ID_LEN, accept_open, parse_header},
};
use crate::transport::{FdBudget, FdPermit};

/// Most concurrent native UDP sessions one landing address serves.
pub const MAX_LANDING_UDP_SESSIONS: usize = 4096;

/// Idle bound of one session; exceeds LINE's XUDP association idle bound so
/// LINE always closes first.
pub const LANDING_UDP_SESSION_IDLE: Duration = Duration::from_secs(120);

/// OPEN nonce replay capacity per landing address.
const OPEN_REPLAY_CAPACITY: usize = 65_536;

/// OPEN nonce retention. An OPEN is accepted only while its timestamp is
/// within [`MAX_OPEN_TIME_DIFFERENCE`] of now, so a nonce retained for twice
/// that window plus one second can never be replayed while still fresh,
/// whatever `maxTimeDifferenceSeconds` a reload publishes.
const OPEN_REPLAY_RETENTION: Duration = Duration::from_secs(2 * MAX_OPEN_TIME_DIFFERENCE + 1);

/// Upper bound on the OPEN timestamp window; the configured
/// `maxTimeDifferenceSeconds` applies when smaller.
const MAX_OPEN_TIME_DIFFERENCE: u64 = 60;

const SWEEP_INTERVAL: Duration = Duration::from_millis(250);

/// The current generation's policy for this address, read per OPEN so key
/// rotation and reload apply to new sessions only (in-flight sessions keep
/// the keys they were opened with).
#[derive(Clone)]
pub struct LandingUdpPolicy {
    pub keys: HandoffLandingKeys,
    pub maximum_time_difference: u64,
    pub fixed_mtu: Option<u16>,
    /// LANDING forwards UDP only through direct egress; a configured egress
    /// outbound (SOCKS5/NXR) cannot carry it, so OPENs are refused.
    pub direct_egress: bool,
}

struct Session {
    endpoint: Mutex<ChannelEndpoint>,
    peer: StdMutex<SocketAddr>,
    open_packet: Vec<u8>,
    egress_v4: Mutex<Option<Egress>>,
    egress_v6: Mutex<Option<Egress>>,
    bind_ip: IpAddr,
    last_activity: AtomicU64,
    epoch: Instant,
    uplink: AtomicU64,
    downlink: AtomicU64,
}

struct Egress {
    socket: Arc<UdpSocket>,
    pump: JoinHandle<()>,
    _permit: FdPermit,
}

impl Drop for Egress {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

impl Session {
    fn touch(&self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.epoch).as_millis();
        self.last_activity.store(
            u64::try_from(elapsed).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn idle_for(&self, now: Instant) -> Duration {
        let last = Duration::from_millis(self.last_activity.load(Ordering::Relaxed));
        now.saturating_duration_since(self.epoch)
            .saturating_sub(last)
    }

    fn peer(&self) -> SocketAddr {
        *self
            .peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

type Sessions = Arc<StdMutex<HashMap<[u8; SESSION_ID_LEN], Arc<Session>>>>;

/// Counters for tests and telemetry.
#[derive(Default)]
pub struct LandingUdpStats {
    pub sessions_opened: AtomicU64,
    /// Sessions ended by CLOSE or the idle bound.
    pub sessions_closed: AtomicU64,
    pub uplink_datagrams: AtomicU64,
    pub downlink_datagrams: AtomicU64,
    pub rejected_packets: AtomicU64,
    pub refused_opens: AtomicU64,
}

/// Binds the channel socket for one landing address.
///
/// # Errors
///
/// Returns the bind or socket-option error.
pub fn bind_landing_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    bind_dont_fragment(address)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Emits the debug-only end-of-session evidence.
async fn session_ended(logger: &Logger, session: &Session, reason: HandoffUdpEndReason) {
    if !logger.debug_enabled() {
        return;
    }
    let (plpmtu, fragmented_datagrams) = {
        let endpoint = session.endpoint.lock().await;
        (endpoint.plpmtu(), endpoint.stats().fragmented_datagrams)
    };
    let _ignored = logger.emit(&LogEvent::HandoffUdpSessionEnded {
        peer: session.peer(),
        reason,
        uplink_datagrams: session.uplink.load(Ordering::Relaxed),
        downlink_datagrams: session.downlink.load(Ordering::Relaxed),
        plpmtu,
        fragmented_datagrams,
    });
}

/// Serves one landing channel socket until `shutdown` flips.
pub async fn run_landing_udp<P>(
    socket: UdpSocket,
    policy: P,
    fd_budget: FdBudget,
    stats: Arc<LandingUdpStats>,
    logger: Logger,
    mut shutdown: watch::Receiver<bool>,
) where
    P: Fn() -> Option<LandingUdpPolicy> + Send + Sync,
{
    let socket = Arc::new(socket);
    let bind_ip = socket
        .local_addr()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |address| address.ip());
    let Ok(replay) = HandoffReplayCache::new(OPEN_REPLAY_CAPACITY, OPEN_REPLAY_RETENTION) else {
        return;
    };
    let sessions: Sessions = Arc::new(StdMutex::new(HashMap::new()));
    let mut buffer = vec![0_u8; 65_536];
    let mut sweep = time::interval(SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, source)) = received else {
                    // ICMP errors from a previous send surface here; the
                    // socket stays usable.
                    continue;
                };
                let packet = &buffer[..length];
                handle_packet(
                    packet, source, &socket, bind_ip, &policy, &replay, &sessions,
                    &fd_budget, &stats, &logger,
                ).await;
            }
            _ = sweep.tick() => {
                sweep_sessions(&socket, &sessions, &stats, &logger).await;
            }
        }
    }
    let drained: Vec<_> = lock(&sessions)
        .drain()
        .map(|(_, session)| session)
        .collect();
    for session in drained {
        session_ended(&logger, &session, HandoffUdpEndReason::Shutdown).await;
        let peer = session.peer();
        let _ = session
            .endpoint
            .lock()
            .await
            .send_control(&socket, Target::To(peer), PacketType::Close)
            .await;
    }
}

fn lock(
    sessions: &Sessions,
) -> std::sync::MutexGuard<'_, HashMap<[u8; SESSION_ID_LEN], Arc<Session>>> {
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn sweep_sessions(
    socket: &Arc<UdpSocket>,
    sessions: &Sessions,
    stats: &LandingUdpStats,
    logger: &Logger,
) {
    let now = Instant::now();
    let snapshot: Vec<_> = lock(sessions)
        .iter()
        .map(|(id, session)| (*id, Arc::clone(session)))
        .collect();
    for (id, session) in snapshot {
        if session.idle_for(now) >= LANDING_UDP_SESSION_IDLE {
            if lock(sessions).remove(&id).is_some() {
                stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
                session_ended(logger, &session, HandoffUdpEndReason::Idle).await;
            }
            continue;
        }
        let peer = session.peer();
        let mut endpoint = session.endpoint.lock().await;
        endpoint.expire(now);
        if endpoint
            .next_deadline(now)
            .is_some_and(|deadline| deadline <= now)
        {
            let _ = endpoint.poll_probe(socket, Target::To(peer), now).await;
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per landing authority"
)]
async fn handle_packet<P>(
    packet: &[u8],
    source: SocketAddr,
    socket: &Arc<UdpSocket>,
    bind_ip: IpAddr,
    policy: &P,
    replay: &HandoffReplayCache,
    sessions: &Sessions,
    fd_budget: &FdBudget,
    stats: &Arc<LandingUdpStats>,
    logger: &Logger,
) where
    P: Fn() -> Option<LandingUdpPolicy>,
{
    let Ok((packet_type, session_id, _)) = parse_header(packet) else {
        stats.rejected_packets.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let existing = lock(sessions).get(&session_id).cloned();
    if packet_type == PacketType::Open {
        if let Some(session) = existing {
            // A retransmitted OPEN is byte-identical; re-acknowledge it to the
            // bound peer only (never to the packet's claimed source).
            if session.open_packet == packet {
                let peer = session.peer();
                let _ = session
                    .endpoint
                    .lock()
                    .await
                    .send_control(socket, Target::To(peer), PacketType::OpenAck)
                    .await;
            } else {
                stats.rejected_packets.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        open_session(
            packet, source, socket, bind_ip, policy, replay, sessions, stats,
        )
        .await;
        return;
    }
    let Some(session) = existing else {
        stats.rejected_packets.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let now = Instant::now();
    let peer = session.peer();
    let received = {
        let mut endpoint = session.endpoint.lock().await;
        // Replies to probes go to the authenticated sender's address.
        let received = endpoint
            .receive(socket, Target::To(source), packet, now)
            .await;
        if received.is_err() {
            endpoint.note_rejected();
        }
        received
    };
    let Ok(received) = received else {
        stats.rejected_packets.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // An authenticated packet with a fresh counter from a new address is LINE
    // behind a rebinding NAT: follow it.
    if source != peer {
        *session
            .peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = source;
    }
    session.touch(now);
    match received {
        Received::Data(destination, payload) => {
            let Some(egress) = egress_for(&session, destination, socket, fd_budget, stats).await
            else {
                return;
            };
            // Egress errors (unreachable destination) never end the session.
            if egress.send_to(&payload, destination).await.is_ok() {
                stats.uplink_datagrams.fetch_add(1, Ordering::Relaxed);
                session.uplink.fetch_add(1, Ordering::Relaxed);
            }
        }
        Received::Close => {
            if lock(sessions).remove(&session_id).is_some() {
                stats.sessions_closed.fetch_add(1, Ordering::Relaxed);
                session_ended(logger, &session, HandoffUdpEndReason::Close).await;
            }
        }
        Received::OpenAck | Received::Handled => {}
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per landing authority"
)]
async fn open_session<P>(
    packet: &[u8],
    source: SocketAddr,
    socket: &Arc<UdpSocket>,
    bind_ip: IpAddr,
    policy: &P,
    replay: &HandoffReplayCache,
    sessions: &Sessions,
    stats: &Arc<LandingUdpStats>,
) where
    P: Fn() -> Option<LandingUdpPolicy>,
{
    if packet.len() != OPEN_LEN {
        stats.rejected_packets.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(policy) = policy() else {
        stats.refused_opens.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if !policy.direct_egress || lock(sessions).len() >= MAX_LANDING_UDP_SESSIONS {
        stats.refused_opens.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Ok((open, channel)) = accept_open(
        packet,
        &policy.keys,
        replay,
        unix_now(),
        policy.maximum_time_difference.min(MAX_OPEN_TIME_DIFFERENCE),
    ) else {
        stats.rejected_packets.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let now = Instant::now();
    let prober = prober_for(
        policy.fixed_mtu,
        None,
        source.is_ipv6(),
        production_timers(),
        now,
    );
    let session = Arc::new(Session {
        endpoint: Mutex::new(ChannelEndpoint::new(channel, prober, source.is_ipv6())),
        peer: StdMutex::new(source),
        open_packet: packet.to_vec(),
        egress_v4: Mutex::new(None),
        egress_v6: Mutex::new(None),
        bind_ip,
        last_activity: AtomicU64::new(0),
        epoch: now,
        uplink: AtomicU64::new(0),
        downlink: AtomicU64::new(0),
    });
    {
        let mut map = lock(sessions);
        if map.contains_key(&open.session_id) || map.len() >= MAX_LANDING_UDP_SESSIONS {
            stats.refused_opens.fetch_add(1, Ordering::Relaxed);
            return;
        }
        map.insert(open.session_id, Arc::clone(&session));
    }
    stats.sessions_opened.fetch_add(1, Ordering::Relaxed);
    let _ = session
        .endpoint
        .lock()
        .await
        .send_control(socket, Target::To(source), PacketType::OpenAck)
        .await;
}

async fn egress_for(
    session: &Arc<Session>,
    destination: SocketAddr,
    channel: &Arc<UdpSocket>,
    fd_budget: &FdBudget,
    stats: &Arc<LandingUdpStats>,
) -> Option<Arc<UdpSocket>> {
    let slot = if destination.is_ipv6() {
        &session.egress_v6
    } else {
        &session.egress_v4
    };
    let mut slot = slot.lock().await;
    if let Some(egress) = slot.as_ref() {
        return Some(Arc::clone(&egress.socket));
    }
    let permit = fd_budget.try_acquire(1)?;
    let bind = match (session.bind_ip, destination) {
        (IpAddr::V4(ip), SocketAddr::V4(_)) if !ip.is_unspecified() => {
            SocketAddr::new(ip.into(), 0)
        }
        (IpAddr::V6(ip), SocketAddr::V6(_)) if !ip.is_unspecified() => {
            SocketAddr::new(ip.into(), 0)
        }
        (_, SocketAddr::V4(_)) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (_, SocketAddr::V6(_)) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    let socket = Arc::new(UdpSocket::bind(bind).await.ok()?);
    let pump = tokio::spawn(pump_downlink(
        Arc::clone(&socket),
        Arc::downgrade(session),
        Arc::clone(channel),
        Arc::clone(stats),
    ));
    *slot = Some(Egress {
        socket: Arc::clone(&socket),
        pump,
        _permit: permit,
    });
    Some(socket)
}

/// Returns every datagram an egress socket receives to LINE, naming its
/// real source (full-cone, exactly like Direct XUDP egress on LINE).
async fn pump_downlink(
    egress: Arc<UdpSocket>,
    session: std::sync::Weak<Session>,
    channel: Arc<UdpSocket>,
    stats: Arc<LandingUdpStats>,
) {
    let mut buffer = vec![0_u8; 65_536];
    loop {
        let Ok((length, source)) = egress.recv_from(&mut buffer).await else {
            continue;
        };
        let Some(session) = session.upgrade() else {
            return;
        };
        if length > MAX_UDP_PAYLOAD_LEN {
            // XUDP cannot carry it to the client; Direct egress has the same cap.
            continue;
        }
        let now = Instant::now();
        let peer = session.peer();
        let sent = session
            .endpoint
            .lock()
            .await
            .send_datagram(&channel, Target::To(peer), source, &buffer[..length])
            .await;
        if sent.is_ok() {
            session.touch(now);
            session.downlink.fetch_add(1, Ordering::Relaxed);
            stats.downlink_datagrams.fetch_add(1, Ordering::Relaxed);
        }
    }
}
