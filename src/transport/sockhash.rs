//! The production `SOCKHASH` arm path.
//!
//! Arming a relay hands both sockets to the kernel's stream-verdict redirect:
//! from that moment userspace must not read or write either socket's data,
//! because every ingress byte is delivered to the peer socket inside the
//! kernel. The properties this module is built around, each verified against
//! the running kernel (6.12) by the privileged gates in
//! `tests/sockhash_runtime.rs`:
//!
//! * **Decline before byte.** Every refusal — no controller, borrowed sockets,
//!   a touched ledger, queued input, admission exhausted, a failed map update
//!   with its rollback — happens before any byte is redirected, so the
//!   caller's fall-through to splice or buffered never replays anything.
//! * **Transactional arming.** Both directions are installed or neither is,
//!   through [`ArmTransaction`]; a partial install is rolled back with the
//!   idempotent `map_delete`.
//! * **The redirect does not propagate FIN.** A peer FIN is consumed by the
//!   receiving relay-side socket, which transitions to `CLOSE_WAIT` and
//!   becomes readable with an empty userspace queue; the peer socket of the
//!   pair stays `ESTABLISHED` and its peer never observes EOF. The relay
//!   therefore detects each half-close itself — readiness plus a one-byte
//!   nonblocking read probe (EOF versus `WouldBlock` versus a hard reset
//!   error), with a slow `TCP_INFO` state poll as fallback — and synthesizes
//!   it with `shutdown(2)` on the *other* socket's write side, exactly what
//!   the buffered backend does on source EOF. `SO_ERROR` is unusable for
//!   this: the redirect latches a soft, spurious `EPIPE` into it.
//! * **Drain before FIN, stability before counting.** Redirect delivery is
//!   asynchronous: measured on 6.12, the sending socket's `tcpi_bytes_acked`
//!   lagged the redirected payload for tens of milliseconds after the FIN
//!   arrived, and the source's `tcpi_bytes_received` lagged the backlog too
//!   (589339 of 3145729 sequence bytes counted at FIN time for a 3 MiB
//!   payload). A `shutdown` issued before the backlog drains overtakes it,
//!   and the peer sees EOF followed by protocol-violating data — measured as
//!   0 of 65536 bytes delivered. Each [`DrainBarrier`] therefore grows with
//!   the converging received counter and gates the synthesized FIN until the
//!   counter is stable across a poll *and* the kernel's acknowledgement
//!   counter covers it. A peer that stops acknowledging parks the session
//!   exactly the way a stuck destination parks a buffered relay.
//! * **Kernel-reported accounting.** Userspace never sees redirected bytes,
//!   so the ledger is populated from `TCP_INFO` deltas against arm-time
//!   baselines: each direction's count is the source socket's
//!   `tcpi_bytes_received` delta minus one sequence byte for the peer's FIN,
//!   snapshotted once the counter has stabilized at teardown. Both counters
//!   were measured to track redirected traffic exactly.
//! * **RAII cleanup.** The armed entries and the admission reservation live in
//!   one [`ArmedPair`] value whose `Drop` deletes both map entries, so a
//!   cancelled relay future leaves nothing in the map and holds no admission.

use std::{
    io,
    os::fd::{AsRawFd as _, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};

use rr_linux::{
    socket::{pending_input, tcp_counters},
    sockhash::{
        Admission, AdmissionGuard, ArmTransaction, Controller, DrainBarrier, FlowKey, map_delete,
        map_update,
    },
};
use tokio::{io::Interest, net::TcpStream};

use super::{
    backend::{BackendDeclineReason, BackendRun, RelayBackend, TransferLedger},
    tcp_relay::map_reason,
};

/// How often the wait loop re-checks `TCP_INFO` state as the fallback
/// teardown signal while no drain is in flight. Readiness is the primary
/// signal; this only bounds how long a missed readiness notification could
/// delay teardown.
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How often the wait loop re-checks a drain barrier while a synthesized FIN
/// is waiting on it. The drain phase is short — loopback drains in well under
/// one interval — so this poll is active only between a detected FIN and its
/// propagation.
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Process-wide bounded `SOCKHASH` state, shared by every clone of the relay.
///
/// Follows the same pattern as the splice pool: one `Arc` around the
/// controller (map and program descriptors) and the admission counter, built
/// once at relay construction and held for its lifetime.
#[derive(Clone)]
pub(crate) struct SockhashPool {
    inner: Arc<SockhashInner>,
}

struct SockhashInner {
    controller: Controller,
    admission: Admission,
}

impl SockhashPool {
    /// Builds the controller and admission state for `max_relays` armed relays.
    ///
    /// # Errors
    ///
    /// Returns the classified reason of the failed step. A verifier rejection
    /// carries its bounded log for diagnostics.
    pub(crate) fn new(max_relays: u32) -> Result<Self, SockhashPoolError> {
        let controller = Controller::new(max_relays).map_err(SockhashPoolError::Controller)?;
        let admission =
            Admission::new(max_relays).map_err(|_| SockhashPoolError::AdmissionOverflow)?;
        Ok(Self {
            inner: Arc::new(SockhashInner {
                controller,
                admission,
            }),
        })
    }

    /// Arms one owned socket pair and waits out the redirected session.
    ///
    /// Every decline happens before any byte is redirected. Once armed, the
    /// sockets are never read or written from userspace again; the only socket
    /// operation the session performs is the `shutdown(2)` that propagates
    /// each detected half-close. The wait ends when both directions have seen
    /// their peer's FIN and both synthesized FINs have been sent, or
    /// immediately when either socket reports an error, mirroring the
    /// buffered backend's abort semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger already moved bytes or when a socket
    /// reports an error mid-session. A decline is never an error: it is
    /// returned as [`BackendRun::Declined`].
    pub(crate) async fn relay(
        &self,
        inbound: &TcpStream,
        outbound: &TcpStream,
        owns_complete_sockets: bool,
        ledger: &TransferLedger,
        started: Instant,
        liveness: Option<Duration>,
    ) -> io::Result<BackendRun> {
        let keys = match arm_precheck(owns_complete_sockets, ledger, inbound, outbound)? {
            ArmPrecheck::Ready(keys) => keys,
            ArmPrecheck::Decline(reason) => return ledger.decline(reason),
        };
        // Baselines are captured after the queue guard and before arming, so
        // the counters describe exactly the connection state the redirect
        // inherits. A socket that cannot report its counters cannot be
        // accounted honestly and is declined before arming instead.
        let Some(baselines) = CounterSnapshot::capture(inbound, outbound) else {
            return ledger.decline(BackendDeclineReason::UnsafeToArm);
        };
        let admission = match self.inner.admission.try_admit() {
            Ok(guard) => guard,
            Err(_limit) => return ledger.decline(BackendDeclineReason::ResourceLimit),
        };
        let map_fd = self.inner.controller.map_fd();
        let mut transaction = ArmTransaction::new();
        if let Err(error) = map_update(map_fd, keys.inbound, outbound.as_raw_fd()) {
            return ledger.decline(classify_arm_error(&error));
        }
        transaction.record(keys.inbound);
        if let Err(error) = map_update(map_fd, keys.outbound, inbound.as_raw_fd()) {
            for installed in transaction.into_rollback() {
                let _ignored = map_delete(map_fd, installed);
            }
            return ledger.decline(classify_arm_error(&error));
        }
        transaction.record(keys.outbound);
        transaction.commit();

        // From here until `armed` drops, the map redirects both sockets.
        // Dropping `armed` — on completion, on error, or on cancellation of
        // this future — deletes both entries and releases the admission.
        let armed = ArmedPair {
            map_fd,
            keys,
            _admission: admission,
        };
        let totals = await_teardown(inbound, outbound, &baselines, liveness).await?;
        drop(armed);

        ledger.add_inbound_to_outbound(totals.inbound_to_outbound)?;
        ledger.add_outbound_to_inbound(totals.outbound_to_inbound)?;
        Ok(ledger.complete(RelayBackend::Sockhash, started.elapsed()))
    }
}

/// Pool construction failed; the relay falls back to other backends.
#[derive(Debug)]
pub(crate) enum SockhashPoolError {
    /// Controller construction failed.
    Controller(rr_linux::sockhash::ControllerError),
    /// The relay bound could not be represented as two directions per relay.
    AdmissionOverflow,
}

impl SockhashPoolError {
    /// Returns the fixed decline category for the startup report.
    #[must_use]
    pub(crate) fn reason(&self) -> BackendDeclineReason {
        match self {
            Self::Controller(error) => map_reason(error.reason()),
            Self::AdmissionOverflow => BackendDeclineReason::ResourceLimit,
        }
    }

    /// Returns the bounded verifier log when the verdict program was rejected.
    #[must_use]
    pub(crate) fn verifier_log(&self) -> Option<&str> {
        match self {
            Self::Controller(error) => error.verifier_log(),
            Self::AdmissionOverflow => None,
        }
    }
}

/// The two flow identities of one relay, captured before arming.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FlowKeys {
    /// The inbound socket's own identity; its map value is the outbound fd.
    inbound: FlowKey,
    /// The outbound socket's own identity; its map value is the inbound fd.
    outbound: FlowKey,
}

/// The result of the pre-arm safety checks.
enum ArmPrecheck {
    /// Every check passed; arming is safe.
    Ready(FlowKeys),
    /// A check refused before any byte moved.
    Decline(BackendDeclineReason),
}

/// Runs every check that must pass before the kernel redirect may be armed.
///
/// The order is deliberate: the free checks (ownership, ledger) run before
/// the system calls (address capture, queue inspection), and all of them run
/// before admission and the map updates in the caller.
///
/// # Errors
///
/// Returns an error — not a decline — when the ledger already moved bytes.
/// Arming after a transferred byte is forbidden outright, matching the
/// ledger's own refusal to construct a decline in that state.
fn arm_precheck(
    owns_complete_sockets: bool,
    ledger: &TransferLedger,
    inbound: &TcpStream,
    outbound: &TcpStream,
) -> io::Result<ArmPrecheck> {
    if !owns_complete_sockets {
        return Ok(ArmPrecheck::Decline(BackendDeclineReason::UnsafeToArm));
    }
    if !ledger.is_untouched() {
        return Err(io::Error::other(
            "the sockhash backend cannot arm after transferring bytes",
        ));
    }
    let Some(keys) = capture_flow_keys(inbound, outbound) else {
        return Ok(ArmPrecheck::Decline(BackendDeclineReason::UnsafeToArm));
    };
    if !queued_input_is_empty(inbound) || !queued_input_is_empty(outbound) {
        return Ok(ArmPrecheck::Decline(
            BackendDeclineReason::ExistingQueuedBytes,
        ));
    }
    Ok(ArmPrecheck::Ready(keys))
}

/// Captures both flow identities while both sockets are connected.
///
/// Capture must happen before arming: a socket that has already reset answers
/// `getpeername` with `ENOTCONN`, and a failed capture declines rather than
/// arming a flow whose identity is unknown.
fn capture_flow_keys(inbound: &TcpStream, outbound: &TcpStream) -> Option<FlowKeys> {
    Some(FlowKeys {
        inbound: FlowKey::capture(inbound.local_addr().ok()?, inbound.peer_addr().ok()?),
        outbound: FlowKey::capture(outbound.local_addr().ok()?, outbound.peer_addr().ok()?),
    })
}

/// Returns whether the socket has no userspace-visible queued input.
///
/// A socket armed with queued bytes would let the kernel redirect bypass data
/// userspace already owns, reordering the stream. A socket whose queue cannot
/// be inspected is treated as non-empty: arming what cannot be verified empty
/// is never safe.
fn queued_input_is_empty(stream: &TcpStream) -> bool {
    matches!(pending_input(stream.as_raw_fd()), Ok(0))
}

/// Classifies a `map_update` failure into the fixed decline vocabulary.
///
/// `E2BIG` is map exhaustion — a full map declines with `ResourceLimit` so
/// the caller falls through to splice, exactly like an exhausted splice pool.
/// The constant is spelled out because this crate deliberately has no `libc`
/// dependency.
fn classify_arm_error(error: &io::Error) -> BackendDeclineReason {
    const E2BIG: i32 = 7;
    match error.raw_os_error() {
        Some(E2BIG) => BackendDeclineReason::ResourceLimit,
        Some(_) => map_reason(rr_linux::DeclineReason::from_errno(error)),
        None => BackendDeclineReason::UnsafeToArm,
    }
}

/// The armed state of one relay, cleaned up by `Drop` on every exit path.
///
/// Deleting an entry for an absent key is idempotent, so teardown after a
/// rollback, a reset, or a cancelled future is always safe. The admission
/// guard rides in the same value so it cannot be forgotten.
struct ArmedPair<'admission> {
    map_fd: RawFd,
    keys: FlowKeys,
    _admission: AdmissionGuard<'admission>,
}

impl Drop for ArmedPair<'_> {
    fn drop(&mut self) {
        let _ignored = map_delete(self.map_fd, self.keys.inbound);
        let _ignored = map_delete(self.map_fd, self.keys.outbound);
    }
}

/// `TCP_INFO` counters for one socket at one instant.
#[derive(Clone, Copy, Debug)]
struct SocketCounters {
    received: u64,
    acked: u64,
}

/// Arm-time counter baselines for both sockets.
#[derive(Clone, Copy, Debug)]
struct CounterSnapshot {
    inbound: SocketCounters,
    outbound: SocketCounters,
}

/// Kernel-reported per-direction totals for one finished session.
#[derive(Clone, Copy, Debug)]
struct SessionTotals {
    inbound_to_outbound: u64,
    outbound_to_inbound: u64,
}

impl CounterSnapshot {
    /// Captures both sockets' counters, or `None` when either cannot report.
    fn capture(inbound: &TcpStream, outbound: &TcpStream) -> Option<Self> {
        Some(Self {
            inbound: read_counters(inbound)?,
            outbound: read_counters(outbound)?,
        })
    }
}

fn read_counters(stream: &TcpStream) -> Option<SocketCounters> {
    let counters = tcp_counters(stream.as_raw_fd()).ok()?;
    Some(SocketCounters {
        received: counters.bytes_received,
        acked: counters.bytes_acked,
    })
}

/// The payload a socket received since the baseline, excluding the FIN byte.
///
/// `tcpi_bytes_received` counts sequence bytes, and a FIN occupies one of
/// them: measured on 6.12, a connection that carried 65536 payload bytes and
/// then a FIN reports a delta of 65537. This function is called only when the
/// peer's FIN has been observed, so the subtraction is always warranted; it
/// saturates rather than wrapping for a hypothetical FIN-less close.
fn payload_delta(now: u64, baseline: u64) -> u64 {
    now.wrapping_sub(baseline).saturating_sub(1)
}

/// One direction's teardown progress.
struct DirectionState {
    /// Whether the peer's FIN was observed.
    peer_fin: bool,
    /// Whether the synthesized FIN was sent on the *propagation* socket.
    ///
    /// For the inbound direction the propagation socket is the outbound one
    /// and vice versa, so this flag lives with the direction that triggered
    /// it rather than with a socket.
    fin_propagated: bool,
    /// Redirected payload bytes known so far.
    ///
    /// `tcpi_bytes_received` lags the redirect backlog for large payloads —
    /// measured on 6.12: 589339 of 3145729 sequence bytes were counted when
    /// the FIN was already processed. The count grows as the backlog drains
    /// and is final once it has been stable across a drain poll, which the
    /// drain requires before propagating. Only then is this the value the
    /// ledger reports.
    payload: u64,
    /// The source socket's received counter at the previous observation,
    /// used to prove the backlog has finished draining.
    previous_received: Option<u64>,
}

impl DirectionState {
    const fn pending() -> Self {
        Self {
            peer_fin: false,
            fin_propagated: false,
            payload: 0,
            previous_received: None,
        }
    }
}

/// Waits out an armed session and returns its kernel-reported byte totals.
///
/// The state machine per direction is: peer FIN observed (readiness with an
/// empty userspace queue, or the state-poll fallback) → drain: grow the
/// barrier with the source socket's converging `tcpi_bytes_received` until
/// that counter is stable across a poll *and* the propagation socket's
/// `tcpi_bytes_acked` covers it → `shutdown(2)` on the propagation socket's
/// write side. The session ends when both directions reached their
/// synthesized FIN.
///
/// A socket error in any state — a reset surfacing as `ECONNRESET` from
/// `FIONREAD`, a `TCP_CLOSE` state, or an unreadable `TCP_INFO` — aborts the
/// session immediately, mirroring how the buffered backend's `try_join`
/// aborts both directions on the first error.
///
/// There is deliberately no deadline on the drain: propagating early would
/// truncate the stream (measured), and a peer that stops acknowledging parks
/// this future exactly the way a stuck destination parks a buffered relay's
/// `write_all`. Cancellation of the future stays fully effective — the
/// [`ArmedPair`] drop deletes the map entries.
///
/// With `liveness` set, the existing state-poll tick additionally samples both
/// sockets' `TCP_INFO` counters: any advance records progress, and a session
/// whose counters have not moved for the whole window ends with
/// [`io::ErrorKind::TimedOut`] instead of pinning its map entries and
/// admission forever. The drain and FIN semantics above are untouched; `None`
/// keeps the historical unbounded wait.
async fn await_teardown(
    inbound: &TcpStream,
    outbound: &TcpStream,
    baselines: &CounterSnapshot,
    liveness: Option<Duration>,
) -> io::Result<SessionTotals> {
    let mut uplink = DirectionState::pending();
    let mut downlink = DirectionState::pending();
    // Each barrier is armed with the propagation socket's arm-time
    // acknowledgement baseline: the uplink barrier watches the outbound
    // socket, which sends everything the client redirected to it.
    let mut uplink_barrier = DrainBarrier::armed(baselines.outbound.acked);
    let mut downlink_barrier = DrainBarrier::armed(baselines.inbound.acked);
    let mut last_progress = Instant::now();
    let mut sampled = *baselines;
    let mut state_poll = tokio::time::interval(STATE_POLL_INTERVAL);
    state_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut drain_poll = tokio::time::interval(DRAIN_POLL_INTERVAL);
    drain_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if uplink.fin_propagated && downlink.fin_propagated {
            return Ok(SessionTotals {
                inbound_to_outbound: uplink.payload,
                outbound_to_inbound: downlink.payload,
            });
        }
        let draining = (uplink.peer_fin && !uplink.fin_propagated)
            || (downlink.peer_fin && !downlink.fin_propagated);
        tokio::select! {
            readiness = inbound.async_io(Interest::READABLE, || end_of_stream(inbound)), if !uplink.peer_fin => {
                readiness?;
                observe_peer_fin(inbound, baselines.inbound, &mut uplink, &mut uplink_barrier)?;
            }
            readiness = outbound.async_io(Interest::READABLE, || end_of_stream(outbound)), if !downlink.peer_fin => {
                readiness?;
                observe_peer_fin(outbound, baselines.outbound, &mut downlink, &mut downlink_barrier)?;
            }
            _tick = state_poll.tick() => {
                if !uplink.peer_fin && fallback_says_peer_finished(inbound)? {
                    observe_peer_fin(inbound, baselines.inbound, &mut uplink, &mut uplink_barrier)?;
                }
                if !downlink.peer_fin && fallback_says_peer_finished(outbound)? {
                    observe_peer_fin(outbound, baselines.outbound, &mut downlink, &mut downlink_barrier)?;
                }
                if let Some(window) = liveness {
                    let current = CounterSnapshot {
                        inbound: read_counters(inbound).unwrap_or(sampled.inbound),
                        outbound: read_counters(outbound).unwrap_or(sampled.outbound),
                    };
                    if counters_advanced(&sampled, &current) {
                        last_progress = Instant::now();
                    }
                    sampled = current;
                    if last_progress.elapsed() > window {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "raw relay idle timeout",
                        ));
                    }
                }
            }
            _tick = drain_poll.tick(), if draining => {
                advance_drain(inbound, outbound, baselines.inbound, &mut uplink, &mut uplink_barrier)?;
                advance_drain(outbound, inbound, baselines.outbound, &mut downlink, &mut downlink_barrier)?;
            }
        }
    }
}

/// Returns whether any `TCP_INFO` counter moved since the previous sample.
fn counters_advanced(previous: &CounterSnapshot, current: &CounterSnapshot) -> bool {
    previous.inbound.received != current.inbound.received
        || previous.inbound.acked != current.inbound.acked
        || previous.outbound.received != current.outbound.received
        || previous.outbound.acked != current.outbound.acked
}

/// The liveness classification of one armed socket.
enum SocketVital {
    /// No queued bytes, no EOF, no error: the connection is alive.
    Alive,
    /// Empty queue and a read reports EOF: the peer closed gracefully.
    Eof,
}

/// Classifies one armed socket without consuming anything.
///
/// `SO_ERROR` is deliberately *not* used: measured on 6.12, the redirect
/// latches a soft `EPIPE` into it on the peer socket of a pair whose other
/// side merely FIN'd — spurious, and reading `SO_ERROR` also clears a
/// genuine error. A nonblocking `read(2)` is the honest probe: soft errors
/// never surface through it, while a hard `ECONNRESET` from a reset peer
/// does. `FIONREAD` is checked first, so the one-byte read can only ever
/// return EOF, `WouldBlock`, or an error — it cannot steal redirected data.
///
/// # Errors
///
/// Returns an error when the socket reports one — a reset aborts the
/// session — or when userspace bytes appear on an armed socket, which the
/// arm-time queue guard makes impossible and which must abort rather than
/// corrupt the stream.
fn vital(stream: &TcpStream) -> io::Result<SocketVital> {
    match pending_input(stream.as_raw_fd()) {
        Ok(0) => {}
        Ok(_queued) => return Ok(SocketVital::Alive),
        Err(error) => return Err(error),
    }
    let mut byte = [0_u8; 1];
    match stream.try_read(&mut byte) {
        Ok(0) => Ok(SocketVital::Eof),
        Ok(_read) => Err(io::Error::other(
            "an armed socket yielded userspace-visible bytes",
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(SocketVital::Alive),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            // The redirect latches a spurious EPIPE as the socket's pending
            // error, and the first read returns it once and clears it —
            // `SO_ERROR` was measured unusable for exactly this reason. The
            // re-probe sees the truth: EOF, WouldBlock, or a genuine error.
            match stream.try_read(&mut byte) {
                Ok(0) => Ok(SocketVital::Eof),
                Ok(_read) => Err(io::Error::other(
                    "an armed socket yielded userspace-visible bytes",
                )),
                Err(reprobe) if reprobe.kind() == io::ErrorKind::WouldBlock => {
                    Ok(SocketVital::Alive)
                }
                Err(reprobe) => Err(reprobe),
            }
        }
        Err(error) => Err(error),
    }
}

/// Records a peer FIN: initializes the direction's payload from the source
/// socket's received counter.
///
/// # Errors
///
/// Returns an error when accounting arithmetic overflows.
fn observe_peer_fin(
    source: &TcpStream,
    baseline: SocketCounters,
    direction: &mut DirectionState,
    barrier: &mut DrainBarrier,
) -> io::Result<()> {
    let now = read_counters(source).unwrap_or(baseline);
    let payload = payload_delta(now.received, baseline.received);
    barrier.add_redirected(payload)?;
    direction.payload = payload;
    direction.previous_received = Some(now.received);
    direction.peer_fin = true;
    Ok(())
}

/// The fallback EOF signal, polled slowly in case readiness ever misses a
/// close: the connection state says the peer finished *and* the read probe
/// confirms a graceful EOF rather than a reset.
///
/// Local `FIN_WAIT` states are excluded deliberately — they appear on the
/// socket this relay itself shut down while propagating the *other*
/// direction's half-close, and treating them as peer-close truncates a live
/// direction (pinned by the privileged gates).
///
/// # Errors
///
/// Returns an error when the socket was reset or its state is unreadable:
/// both abort the session rather than parking it.
fn fallback_says_peer_finished(stream: &TcpStream) -> io::Result<bool> {
    let counters = tcp_counters(stream.as_raw_fd())?;
    if !counters.peer_closed() {
        return Ok(false);
    }
    Ok(matches!(vital(stream)?, SocketVital::Eof))
}

/// Reads counters for the drain, treating a dead socket as fatal to the
/// session.
///
/// Mid-drain there is no graceful reason for a socket to report an error: a
/// socket that dies while its direction still owes bytes means the session
/// is broken, and parking on it — or propagating a FIN into it — would hide
/// that.
///
/// # Errors
///
/// Returns an error on a reset, on unreadable counters, or on userspace
/// bytes appearing on an armed socket.
fn require_counters(stream: &TcpStream) -> io::Result<SocketCounters> {
    let _vital = vital(stream)?;
    let counters = tcp_counters(stream.as_raw_fd())?;
    Ok(SocketCounters {
        received: counters.bytes_received,
        acked: counters.bytes_acked,
    })
}

/// Advances one direction's drain by one poll step.
///
/// The barrier grows with the source socket's received counter as the
/// redirect backlog drains. Propagation requires both stability — the
/// counter unchanged since the previous poll, proving every arrived byte has
/// been counted — and the barrier drained, proving every counted byte was
/// acknowledged by the ultimate peer.
///
/// # Errors
///
/// Returns an error when either socket died mid-drain, or when accounting
/// arithmetic overflows.
fn advance_drain(
    source: &TcpStream,
    propagation: &TcpStream,
    baseline: SocketCounters,
    direction: &mut DirectionState,
    barrier: &mut DrainBarrier,
) -> io::Result<()> {
    if !direction.peer_fin || direction.fin_propagated {
        return Ok(());
    }
    let now = require_counters(source)?;
    let payload = payload_delta(now.received, baseline.received);
    if payload > direction.payload {
        barrier.add_redirected(payload - direction.payload)?;
        direction.payload = payload;
    }
    let stable = direction.previous_received == Some(now.received);
    direction.previous_received = Some(now.received);
    let drained = barrier.is_drained(require_counters(propagation)?.acked);
    if stable && drained {
        let _ignored = rustix::net::shutdown(propagation, rustix::net::Shutdown::Write);
        direction.fin_propagated = true;
    }
    Ok(())
}

/// The readiness closure: complete only when the socket is at a graceful
/// end-of-stream.
///
/// A readable armed socket with an empty userspace queue is either at EOF —
/// its TCP stack consumed the peer's FIN — or was woken for another reason,
/// in which case the read probe returns `WouldBlock` and the closure simply
/// re-arms. A reset surfaces as a hard error from the probe and aborts the
/// session.
fn end_of_stream(stream: &TcpStream) -> io::Result<()> {
    match vital(stream)? {
        SocketVital::Eof => Ok(()),
        SocketVital::Alive => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "an armed socket is not at end-of-stream",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::{TcpListener, TcpStream};

    use super::{
        ArmPrecheck, arm_precheck, capture_flow_keys, classify_arm_error, payload_delta,
        queued_input_is_empty,
    };
    use crate::transport::{BackendDeclineReason, backend::TransferLedger};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener must bind");
        let address = listener.local_addr().expect("address must exist");
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (
            client.expect("client must connect"),
            accepted.expect("server must accept").0,
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_borrowed_pair_is_unsafe_to_arm() {
        let (inbound, _client) = tcp_pair().await;
        let (outbound, _target) = tcp_pair().await;
        let ledger = TransferLedger::new();

        match arm_precheck(false, &ledger, &inbound, &outbound).expect("checks must run") {
            ArmPrecheck::Decline(reason) => {
                assert_eq!(reason, BackendDeclineReason::UnsafeToArm);
            }
            ArmPrecheck::Ready(_) => panic!("a borrowed pair must never arm"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn arming_after_a_transferred_byte_is_forbidden() {
        let (inbound, _client) = tcp_pair().await;
        let (outbound, _target) = tcp_pair().await;
        let ledger = TransferLedger::new();
        ledger
            .add_inbound_to_outbound(1)
            .expect("one byte must record");

        assert!(
            arm_precheck(true, &ledger, &inbound, &outbound).is_err(),
            "a touched ledger must be an error, never a decline and never an arm"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_input_declines_before_arming() {
        use tokio::io::AsyncWriteExt as _;

        let (inbound, mut client) = tcp_pair().await;
        let (outbound, _target) = tcp_pair().await;
        client.write_all(b"peeked").await.expect("write must land");
        for _ in 0..1_000 {
            if !queued_input_is_empty(&inbound) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!queued_input_is_empty(&inbound));

        let ledger = TransferLedger::new();
        match arm_precheck(true, &ledger, &inbound, &outbound).expect("checks must run") {
            ArmPrecheck::Decline(reason) => {
                assert_eq!(reason, BackendDeclineReason::ExistingQueuedBytes);
            }
            ArmPrecheck::Ready(_) => panic!("queued bytes must decline the arm"),
        }
        assert!(
            ledger.is_untouched(),
            "the decline must happen before any byte is accounted"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_clean_owned_pair_passes_every_precheck() {
        let (inbound, _client) = tcp_pair().await;
        let (outbound, _target) = tcp_pair().await;
        let ledger = TransferLedger::new();

        match arm_precheck(true, &ledger, &inbound, &outbound).expect("checks must run") {
            ArmPrecheck::Ready(keys) => {
                let expected = capture_flow_keys(&inbound, &outbound).expect("capture must repeat");
                assert_eq!(keys, expected);
                assert_eq!(keys.inbound.reversed().reversed(), keys.inbound);
            }
            ArmPrecheck::Decline(reason) => panic!("a clean pair must arm; declined: {reason}"),
        }
    }

    #[test]
    fn map_exhaustion_is_a_resource_limit_decline() {
        let error = std::io::Error::from_raw_os_error(7); // E2BIG
        assert_eq!(
            classify_arm_error(&error),
            BackendDeclineReason::ResourceLimit
        );
    }

    #[test]
    fn the_payload_delta_excludes_exactly_the_fin_byte() {
        assert_eq!(payload_delta(65_537, 0), 65_536);
        assert_eq!(payload_delta(1, 0), 0, "a bare FIN carries no payload");
        assert_eq!(payload_delta(0, 0), 0, "subtraction saturates, never wraps");
    }
}
