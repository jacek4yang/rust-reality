//! Bidirectional TCP relay between an inbound and an outbound socket.
//!
//! `TcpRelay` picks a backend (splice where supported, otherwise pooled
//! userspace buffers) per `TcpRelayConfig`, copies each direction with idle and
//! write-stall timeouts, records bytes in the transfer ledger, and classifies
//! aborts (peer reset/gone vs. stall). Pipe and buffer pools are reused across
//! sessions.

use std::{
    error::Error,
    fmt, io,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{OwnedSemaphorePermit, Semaphore},
};

#[cfg(target_os = "linux")]
use super::{FdPermit, UNITS_SPLICE_DIRECTION, UNITS_SPLICE_RELAY};

use super::{
    FdBudget,
    backend::{
        BackendCapability, BackendDeclineReason, BackendReport, BackendRequest, BackendRun,
        DirectionalRelayContext, DirectionalRelayOutcome, RelayBackend, RelayContext,
        RelayDirection, RelayOutcome, TransferLedger,
    },
    idle::{RelayIdleDeadline as IdleDeadline, RelayIdleError as IdleError},
};

/// Concrete pool and backend settings consumed by [`TcpRelay`].
///
/// This is deliberately separate from the serialized operator policy: the
/// server/runtime composition layer validates and translates configuration,
/// while Transport owns only the mechanism values it actually consumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpRelayConfig {
    /// Bytes per pooled userspace buffer.
    pub buffer_bytes: usize,
    /// Maximum pooled buffers.
    pub max_pooled_buffers: usize,
    /// Maximum concurrent Linux splice relays.
    pub max_splice_relays: u32,
    /// Whether nonblocking splice is enabled on plaintext TCP boundaries.
    pub splice: bool,
    /// Whether drained splice pipes are retained process-wide.
    pub pipe_pool: bool,
    /// Maximum retained pipe pairs.
    pub max_pooled_pipes: u32,
}

#[cfg(test)]
impl TcpRelayConfig {
    /// Supplies ordinary bounded settings to crate-local behavior tests.
    pub(crate) const fn for_test() -> Self {
        Self {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 4_096,
            max_splice_relays: 256,
            splice: true,
            pipe_pool: true,
            max_pooled_pipes: 256,
        }
    }
}

/// Process-wide bounded relay state for plaintext TCP-to-TCP boundaries.
///
/// The type cannot accept encrypted application streams, which keeps Linux
/// zero-copy outside the REALITY/TLS record boundary. Linux splice capacity is
/// admitted without waiting; exhausted or unavailable splice resources fall
/// back to the bounded userspace buffer pool.
#[derive(Clone)]
pub struct TcpRelay {
    buffers: BufferPool,
    #[cfg(target_os = "linux")]
    splice: Option<SplicePool>,
    report: BackendReport,
    fd_budget: FdBudget,
}

/// Owns the sockets until the relay future settles. Cancellation must never
/// manufacture a clean short EOF; Drop runs before either descriptor closes.
/// Owning the streams (rather than caching raw descriptor numbers) also makes
/// recycled-descriptor resets impossible.
struct OwnedRelaySockets {
    inbound: TcpStream,
    outbound: TcpStream,
    completed: bool,
}

impl Drop for OwnedRelaySockets {
    fn drop(&mut self) {
        if !self.completed {
            let _ignored = rr_linux::socket::abort_linger(&self.inbound);
            let _ignored = rr_linux::socket::abort_linger(&self.outbound);
        }
    }
}

impl TcpRelay {
    /// Compiles immutable relay settings and pre-reserves all pool metadata.
    ///
    /// # Errors
    ///
    /// Returns an allocation error before any listener is bound.
    pub fn new(config: TcpRelayConfig, fd_budget: FdBudget) -> Result<Self, TcpRelayConfigError> {
        let buffers = BufferPool::new(config.buffer_bytes, config.max_pooled_buffers)?;
        #[cfg(target_os = "linux")]
        let splice = config.splice.then(|| {
            SplicePool::new(
                config.max_splice_relays,
                fd_budget.clone(),
                Some((config.pipe_pool, config.max_pooled_pipes)),
            )
        });
        let report = BackendReport {
            buffered: BackendCapability::available(),
            splice: splice_capability(config),
        };
        Ok(Self {
            buffers,
            #[cfg(target_os = "linux")]
            splice,
            report,
            fd_budget,
        })
    }

    /// Returns the process descriptor budget this relay admits against.
    #[must_use]
    pub fn fd_budget(&self) -> &FdBudget {
        &self.fd_budget
    }

    /// Returns pipe-pool counters when the process pool is enabled.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn pipe_pool_stats(&self) -> Option<PipePoolSnapshot> {
        self.splice
            .as_ref()
            .and_then(|splice| splice.pipes.as_ref())
            .map(PipePool::snapshot)
    }

    /// Returns the one stable capability line per backend for startup reporting.
    #[must_use]
    pub const fn report(&self) -> &BackendReport {
        &self.report
    }

    /// Relays one plaintext TCP pair that this relay owns completely.
    ///
    /// Complete ownership is the precondition for any backend that has to
    /// duplicate or register a descriptor, and it makes "this backend
    /// transferred zero bytes" a provable state rather than an assumption.
    ///
    /// # Errors
    ///
    /// Returns allocation, socket, pipe, or shutdown errors. A backend error
    /// after transfer starts terminates the relay and is never replayed through
    /// another backend.
    pub async fn relay_owned(
        &self,
        inbound: TcpStream,
        outbound: TcpStream,
        context: RelayContext,
    ) -> io::Result<RelayOutcome> {
        let mut sockets = OwnedRelaySockets {
            inbound,
            outbound,
            completed: false,
        };
        let outcome = self
            .run(&mut sockets.inbound, &mut sockets.outbound, context)
            .await;
        // `run` owns normal EOF and returned-error semantics. Only a dropped
        // pending future needs the cancellation backstop below.
        sockets.completed = true;
        outcome
    }

    /// Relays a single direction between two owned socket halves.
    ///
    /// A Vision direction at its raw boundary holds exactly the two halves this
    /// entry point needs, so the raw phase never waits for the peer direction.
    /// Source EOF gracefully shuts down the destination write side and leaves
    /// the peer direction untouched. Linux splice capacity is admitted without
    /// waiting; an exhausted pool or descriptor budget declines *before* the
    /// first byte and falls through to one pooled userspace buffer.
    ///
    /// The policy argument is [`DirectionalRelayContext`] rather than
    /// [`RelayContext`] because this capability does not implement
    /// reset-as-EOF. That option is therefore unrepresentable here instead of
    /// accepted and ignored.
    ///
    /// # Errors
    ///
    /// Returns allocation, socket, pipe, or shutdown errors. A backend error
    /// after transfer starts terminates the relay and is never replayed through
    /// another backend. With `write_stall` set, a direction that moves no byte for
    /// that long fails with [`io::ErrorKind::TimedOut`].
    pub async fn relay_direction(
        &self,
        mut source: OwnedReadHalf,
        mut destination: OwnedWriteHalf,
        direction: RelayDirection,
        context: DirectionalRelayContext,
    ) -> io::Result<DirectionalRelayOutcome> {
        let DirectionalRelayContext {
            request,
            write_stall,
            activity,
        } = context;
        let order = directional_selection_order(request);
        let mut last_decline = BackendDeclineReason::Disabled;
        for backend in order {
            let ledger = TransferLedger::with_activity(activity.clone());
            let attempt = DirectionalAttempt {
                direction,
                write_stall,
                ledger: &ledger,
                started: Instant::now(),
            };
            let run = self
                .run_direction_backend(*backend, &mut source, &mut destination, &attempt)
                .await;
            let run = match run {
                Err(error) if !ledger.is_untouched() => {
                    // True abort: the peer must observe a reset, not a clean
                    // short EOF. Pre-first-byte declines never reach here.
                    let _ignored = rr_linux::socket::abort_linger(source.as_ref());
                    let _ignored = rr_linux::socket::abort_linger(destination.as_ref());
                    return Err(classify_abort(error));
                }
                run => run?,
            };
            match run {
                BackendRun::Completed(outcome) => {
                    let bytes = if direction.is_inbound_to_outbound() {
                        outcome.inbound_to_outbound()
                    } else {
                        outcome.outbound_to_inbound()
                    };
                    return Ok(DirectionalRelayOutcome::new(
                        bytes,
                        outcome.backend(),
                        outcome.duration(),
                        outcome.pipe_downgrade(),
                    ));
                }
                BackendRun::Declined(decline) => last_decline = decline.reason(),
            }
        }
        Err(io::Error::other(format!(
            "no relay backend accepted the {direction} direction: {last_decline}"
        )))
    }

    async fn run_direction_backend(
        &self,
        backend: RelayBackend,
        source: &mut OwnedReadHalf,
        destination: &mut OwnedWriteHalf,
        attempt: &DirectionalAttempt<'_>,
    ) -> io::Result<BackendRun> {
        let DirectionalAttempt {
            direction,
            write_stall,
            ledger,
            started,
        } = *attempt;
        match backend {
            RelayBackend::Buffered => {
                self.buffers
                    .relay_direction(source, destination, direction, ledger, write_stall)
                    .await?;
                Ok(ledger.complete(RelayBackend::Buffered, started.elapsed()))
            }
            RelayBackend::Splice => {
                self.run_splice_direction(source, destination, attempt)
                    .await
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn run_splice_direction(
        &self,
        source: &mut OwnedReadHalf,
        destination: &mut OwnedWriteHalf,
        attempt: &DirectionalAttempt<'_>,
    ) -> io::Result<BackendRun> {
        let DirectionalAttempt {
            direction,
            write_stall,
            ledger,
            started,
        } = *attempt;
        let Some(splice) = &self.splice else {
            return ledger.decline(BackendDeclineReason::Disabled);
        };
        match splice
            .try_relay_direction(source, destination, direction, ledger, write_stall)
            .await?
        {
            Some(()) => Ok(ledger.complete(RelayBackend::Splice, started.elapsed())),
            None => ledger.decline(BackendDeclineReason::ResourceLimit),
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn run_splice_direction(
        &self,
        _source: &mut OwnedReadHalf,
        _destination: &mut OwnedWriteHalf,
        attempt: &DirectionalAttempt<'_>,
    ) -> io::Result<BackendRun> {
        attempt
            .ledger
            .decline(BackendDeclineReason::UnsupportedOperatingSystem)
    }

    async fn run(
        &self,
        inbound: &mut TcpStream,
        outbound: &mut TcpStream,
        context: RelayContext,
    ) -> io::Result<RelayOutcome> {
        let order = selection_order(context.request);
        let mut last_decline = BackendDeclineReason::Disabled;
        for backend in order {
            let ledger = TransferLedger::with_activity(context.activity.clone());
            let started = Instant::now();
            let run = self
                .run_backend(*backend, inbound, outbound, &context, &ledger, started)
                .await;
            let run = match run {
                Err(error) if !ledger.is_untouched() => {
                    // True abort: the peer must observe a reset, not a clean
                    // short EOF. Pre-first-byte declines never reach here.
                    let _ignored = rr_linux::socket::abort_linger(&*inbound);
                    let _ignored = rr_linux::socket::abort_linger(&*outbound);
                    return Err(classify_abort(error));
                }
                run => run?,
            };
            match run {
                BackendRun::Completed(outcome) => return Ok(outcome),
                BackendRun::Declined(decline) => last_decline = decline.reason(),
            }
        }
        Err(io::Error::other(format!(
            "no relay backend accepted the connection: {last_decline}"
        )))
    }

    async fn run_backend(
        &self,
        backend: RelayBackend,
        inbound: &mut TcpStream,
        outbound: &mut TcpStream,
        context: &RelayContext,
        ledger: &TransferLedger,
        started: Instant,
    ) -> io::Result<BackendRun> {
        match backend {
            RelayBackend::Buffered => {
                self.buffers
                    .relay(
                        inbound,
                        outbound,
                        ledger,
                        context.write_stall,
                        context.source_reset_is_eof,
                    )
                    .await?;
                Ok(ledger.complete(RelayBackend::Buffered, started.elapsed()))
            }
            RelayBackend::Splice => {
                self.run_splice(
                    inbound,
                    outbound,
                    ledger,
                    started,
                    context.write_stall,
                    context.source_reset_is_eof,
                )
                .await
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn run_splice(
        &self,
        inbound: &mut TcpStream,
        outbound: &mut TcpStream,
        ledger: &TransferLedger,
        started: Instant,
        write_stall: Option<Duration>,
        source_reset_is_eof: bool,
    ) -> io::Result<BackendRun> {
        let Some(splice) = &self.splice else {
            return ledger.decline(BackendDeclineReason::Disabled);
        };
        match splice
            .try_relay(inbound, outbound, ledger, write_stall, source_reset_is_eof)
            .await?
        {
            Some(()) => Ok(ledger.complete(RelayBackend::Splice, started.elapsed())),
            None => ledger.decline(BackendDeclineReason::ResourceLimit),
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn run_splice(
        &self,
        _inbound: &mut TcpStream,
        _outbound: &mut TcpStream,
        ledger: &TransferLedger,
        _started: Instant,
        _write_stall: Option<Duration>,
        _source_reset_is_eof: bool,
    ) -> io::Result<BackendRun> {
        ledger.decline(BackendDeclineReason::UnsupportedOperatingSystem)
    }
}

/// One directional backend attempt: the direction, its idle write_stall bound,
/// the shared transfer ledger, and the attempt's start instant.
///
/// Bundling these keeps the directional runners inside the repository's
/// argument-count lint without hiding anything.
#[derive(Clone, Copy)]
struct DirectionalAttempt<'a> {
    direction: RelayDirection,
    write_stall: Option<Duration>,
    ledger: &'a TransferLedger,
    started: Instant,
}

/// Returns the backend order for one request.
fn selection_order(request: BackendRequest) -> &'static [RelayBackend] {
    match request {
        BackendRequest::Automatic => RelayBackend::automatic_preference(),
        BackendRequest::Explicit(RelayBackend::Buffered) => &[RelayBackend::Buffered],
        BackendRequest::Explicit(RelayBackend::Splice) => {
            &[RelayBackend::Splice, RelayBackend::Buffered]
        }
    }
}

/// Returns the backend order for one single-direction request.
fn directional_selection_order(request: BackendRequest) -> &'static [RelayBackend] {
    match request {
        BackendRequest::Automatic | BackendRequest::Explicit(RelayBackend::Splice) => {
            &[RelayBackend::Splice, RelayBackend::Buffered]
        }
        BackendRequest::Explicit(RelayBackend::Buffered) => &[RelayBackend::Buffered],
    }
}

/// Reclassifies a write_stall timeout that truncated a live transfer.
///
/// An idle timeout before the first byte is a clean teardown, and callers may
/// treat it as one. Once the ledger has moved bytes, the timeout aborts both
/// sockets with RST; surfacing it as `TimedOut` would let the session layer
/// mistake a truncated transfer for a clean idle close, so the abort is
/// reported as `ConnectionAborted` with the original error as its payload.
fn classify_abort(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::TimedOut {
        io::Error::new(io::ErrorKind::ConnectionAborted, error)
    } else {
        error
    }
}

/// Returns whether an error is the mid-transfer write_stall abort that
/// `classify_abort` produces: `ConnectionAborted` carrying the original
/// `TimedOut` as its payload.
///
/// The rewrap exists so the session layer never mistakes a truncated transfer
/// for a clean idle close, but the underlying cause is still the write_stall
/// policy, not a protocol violation — the session's rejection classification
/// uses this to file the event as a timeout.
#[must_use]
pub fn is_write_stall_timeout_abort(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ConnectionAborted
        && error
            .get_ref()
            .and_then(|payload| payload.downcast_ref::<io::Error>())
            .is_some_and(|payload| payload.kind() == io::ErrorKind::TimedOut)
}

fn splice_capability(config: TcpRelayConfig) -> BackendCapability {
    if !cfg!(target_os = "linux") {
        return BackendCapability::declined(
            config.splice,
            BackendDeclineReason::UnsupportedOperatingSystem,
        );
    }
    if config.splice {
        BackendCapability::available()
    } else {
        BackendCapability::declined(false, BackendDeclineReason::Disabled)
    }
}

impl fmt::Debug for TcpRelay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpRelay")
            .field("buffer_bytes", &self.buffers.inner.buffer_bytes)
            .field("max_buffers", &self.buffers.inner.max_buffers)
            .field("splice_enabled", &{
                #[cfg(target_os = "linux")]
                {
                    self.splice.is_some()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

/// Relay pool construction failed before serving traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpRelayConfigError {
    /// Pool metadata could not be allocated within the validated limit.
    Allocation,
}

impl fmt::Display for TcpRelayConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("failed to allocate bounded TCP relay state")
    }
}

impl Error for TcpRelayConfigError {}

#[derive(Clone)]
struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

struct BufferPoolInner {
    available: Mutex<Vec<Vec<u8>>>,
    permits: Arc<Semaphore>,
    buffer_bytes: usize,
    max_buffers: usize,
}

impl BufferPool {
    fn new(buffer_bytes: usize, max_buffers: usize) -> Result<Self, TcpRelayConfigError> {
        let mut available = Vec::new();
        available
            .try_reserve_exact(max_buffers)
            .map_err(|_| TcpRelayConfigError::Allocation)?;
        Ok(Self {
            inner: Arc::new(BufferPoolInner {
                available: Mutex::new(available),
                permits: Arc::new(Semaphore::new(max_buffers)),
                buffer_bytes,
                max_buffers,
            }),
        })
    }

    async fn relay(
        &self,
        inbound: &mut TcpStream,
        outbound: &mut TcpStream,
        ledger: &TransferLedger,
        write_stall: Option<Duration>,
        source_reset_is_eof: bool,
    ) -> io::Result<()> {
        let mut pair = self.acquire_pair().await?;
        let (inbound_reader, inbound_writer) = tokio::io::split(inbound);
        let (outbound_reader, outbound_writer) = tokio::io::split(outbound);
        let (inbound_buffer, outbound_buffer) = pair.buffers_mut()?;
        let uplink = copy_direction(
            inbound_reader,
            outbound_writer,
            inbound_buffer,
            ledger,
            true,
            write_stall,
            source_reset_is_eof,
        );
        let downlink = copy_direction(
            outbound_reader,
            inbound_writer,
            outbound_buffer,
            ledger,
            false,
            write_stall,
            source_reset_is_eof,
        );
        tokio::try_join!(uplink, downlink)?;
        Ok(())
    }

    /// Relays one direction through a single pooled buffer.
    async fn relay_direction(
        &self,
        source: &mut OwnedReadHalf,
        destination: &mut OwnedWriteHalf,
        direction: RelayDirection,
        ledger: &TransferLedger,
        write_stall: Option<Duration>,
    ) -> io::Result<()> {
        let mut lease = self.acquire_single().await?;
        let buffer = lease.buffer_mut()?;
        copy_direction(
            source,
            destination,
            buffer,
            ledger,
            direction.is_inbound_to_outbound(),
            write_stall,
            false,
        )
        .await
    }

    async fn acquire_pair(&self) -> io::Result<BufferPair> {
        let permit = Arc::clone(&self.inner.permits)
            .acquire_many_owned(2)
            .await
            .map_err(|_| io::Error::other("TCP relay buffer pool is unavailable"))?;
        let first = self.take_buffer()?;
        let second = match self.take_buffer() {
            Ok(buffer) => buffer,
            Err(error) => {
                self.return_buffer(first);
                return Err(error);
            }
        };
        Ok(BufferPair {
            pool: self.clone(),
            first: Some(first),
            second: Some(second),
            _permit: permit,
        })
    }

    async fn acquire_single(&self) -> io::Result<PooledBuffer> {
        let permit = Arc::clone(&self.inner.permits)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("TCP relay buffer pool is unavailable"))?;
        let buffer = self.take_buffer()?;
        Ok(PooledBuffer {
            pool: self.clone(),
            buffer: Some(buffer),
            _permit: permit,
        })
    }

    fn take_buffer(&self) -> io::Result<Vec<u8>> {
        if let Some(buffer) = lock_recover(&self.inner.available).pop() {
            return Ok(buffer);
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(self.inner.buffer_bytes)
            .map_err(|_| io::Error::other("TCP relay buffer allocation failed"))?;
        buffer.resize(self.inner.buffer_bytes, 0);
        Ok(buffer)
    }

    fn return_buffer(&self, buffer: Vec<u8>) {
        let mut available = lock_recover(&self.inner.available);
        if available.len() < self.inner.max_buffers {
            available.push(buffer);
        }
    }
}

struct BufferPair {
    pool: BufferPool,
    first: Option<Vec<u8>>,
    second: Option<Vec<u8>>,
    _permit: OwnedSemaphorePermit,
}

impl BufferPair {
    fn buffers_mut(&mut self) -> io::Result<(&mut [u8], &mut [u8])> {
        match (self.first.as_deref_mut(), self.second.as_deref_mut()) {
            (Some(first), Some(second)) => Ok((first, second)),
            _ => Err(io::Error::other("TCP relay buffer lease is unavailable")),
        }
    }
}

impl Drop for BufferPair {
    fn drop(&mut self) {
        if let Some(first) = self.first.take() {
            self.pool.return_buffer(first);
        }
        if let Some(second) = self.second.take() {
            self.pool.return_buffer(second);
        }
    }
}

/// One pooled buffer and its permit, returned to the pool on every exit path.
struct PooledBuffer {
    pool: BufferPool,
    buffer: Option<Vec<u8>>,
    _permit: OwnedSemaphorePermit,
}

impl PooledBuffer {
    fn buffer_mut(&mut self) -> io::Result<&mut [u8]> {
        self.buffer
            .as_deref_mut()
            .ok_or_else(|| io::Error::other("TCP relay buffer lease is unavailable"))
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.return_buffer(buffer);
        }
    }
}

/// Copies one direction, recording every transferred byte in the shared ledger.
///
/// The count is recorded only after the write completes, so a byte is never
/// claimed as transferred before it actually reached the peer socket.
///
/// With `write_stall` set, one idle window is armed per chunk and shared by that
/// chunk's read and write: steady progress never times out, while a peer that
/// stalls for the whole window ends the direction with
/// [`io::ErrorKind::TimedOut`] instead of parking on its permit forever.
/// `None` keeps the unbounded behavior and constructs no timer at all.
///
/// With `source_reset_is_eof`, a source reset ends the direction like an EOF
/// and a closing shutdown that only reports the destination is already gone
/// is tolerated; see [`RelayContext::source_reset_is_eof`].
async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer: &mut [u8],
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    write_stall: Option<Duration>,
    source_reset_is_eof: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut idle = write_stall.map(|_| IdleDeadline::new());
    loop {
        // Quiet reads are not stalled writes. TCP keepalive and peer FIN
        // govern raw lifetime, including when only the other direction moves.
        let read = reader.read(buffer).await;
        let read = match read {
            Ok(read) => read,
            Err(error) if source_reset_is_eof && is_peer_reset(&error) => 0,
            Err(error) => return Err(error),
        };
        ledger.progress(read);
        if read == 0 {
            if let (Some(idle), Some(window)) = (&mut idle, write_stall) {
                idle.reset(window).map_err(idle_io_error)?;
            }
            let shutdown = match &mut idle {
                Some(idle) => idle.shutdown(&mut writer).await.map_err(idle_io_error),
                None => writer.shutdown().await,
            };
            if let Err(error) = shutdown
                && !(source_reset_is_eof && is_peer_gone(&error))
            {
                return Err(error);
            }
            return Ok(());
        }
        let mut payload = buffer
            .get(..read)
            .ok_or_else(|| io::Error::other("TCP relay read exceeded its buffer"))?;
        while !payload.is_empty() {
            let written = match (&mut idle, write_stall) {
                (Some(idle), Some(window)) => {
                    idle.reset(window).map_err(idle_io_error)?;
                    idle.guard(writer.write(payload))
                        .await
                        .map_err(idle_io_error)?
                }
                _ => writer.write(payload).await?,
            };
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            record(ledger, inbound_to_outbound, written)?;
            payload = &payload[written..];
        }
    }
}

/// Whether the error reports the source peer reset the connection.
fn is_peer_reset(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ConnectionReset
}

/// Whether the error only reports the destination peer is already gone, which
/// carries no information once the direction is ending anyway.
fn is_peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected
    )
}

/// Maps an idle-guard failure back to the relay's `io::Error` surface.
fn idle_io_error(error: IdleError) -> io::Error {
    match error {
        IdleError::Timeout => io::Error::new(io::ErrorKind::TimedOut, "raw relay idle timeout"),
        IdleError::Io(error) => error,
    }
}

fn record(ledger: &TransferLedger, inbound_to_outbound: bool, bytes: usize) -> io::Result<()> {
    ledger.progress(bytes);
    let bytes = u64::try_from(bytes).map_err(|_| io::Error::other("relay byte count overflow"))?;
    if inbound_to_outbound {
        ledger.add_inbound_to_outbound(bytes)
    } else {
        ledger.add_outbound_to_inbound(bytes)
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Process-lifetime splice pipe pool, after the Go/Xray model: pipes are
/// sized once at creation and reused without a single pipe syscall on a hit.
///
/// A pipe is returned only when it is fully drained; a pipe that still holds
/// unread bytes at relay end is discarded, never recycled across sessions.
/// Descriptor units travel with the pipe itself (`PooledPipe` drops the pipe
/// before releasing its units), so pool retention, in-flight use, and idle
/// shrink are all exactly accounted.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct PipePool {
    free: Arc<Mutex<Vec<PooledPipe>>>,
    keep: usize,
    fd_budget: FdBudget,
    stats: Arc<PipePoolStats>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct PipePoolStats {
    hits: AtomicU64,
    misses: AtomicU64,
    discards: AtomicU64,
    downgrades: AtomicU64,
    shrinks: AtomicU64,
}

/// Snapshot of pool counters for tests and future metrics surfaces.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipePoolSnapshot {
    /// Immutable maximum number of idle pairs retained by this pool.
    pub retained_capacity: u64,
    /// Empty pipe pairs currently owned by the idle pool.
    pub retained_pairs: u64,
    /// Sum of queued bytes in retained pipes; `None` means inspection failed.
    pub pending_bytes: Option<u64>,
    /// Retrievals answered without any pipe syscall.
    pub hits: u64,
    /// Retrievals that created a pipe.
    pub misses: u64,
    /// Pipes discarded for holding unread bytes.
    pub discards: u64,
    /// Pipes created below the requested capacity (pipe-page cliff).
    pub downgrades: u64,
    /// Pipes closed because the pool was full on return.
    pub shrinks: u64,
}

#[cfg(target_os = "linux")]
struct PooledPipe {
    pair: PipePair,
    // Declared after the pipe: struct fields drop in declaration order, so
    // the pipe closes before its units are released.
    _units: FdPermit,
}

#[cfg(target_os = "linux")]
impl PipePool {
    fn new(keep: u32, fd_budget: FdBudget) -> Self {
        Self {
            free: Arc::new(Mutex::new(Vec::new())),
            keep: usize::try_from(keep).unwrap_or(usize::MAX),
            fd_budget,
            stats: Arc::new(PipePoolStats::default()),
        }
    }

    /// Returns a pipe with no syscall on a pool hit; creates one on a miss.
    ///
    /// A miss reserves two descriptor units before `pipe2`; a denied budget or
    /// a failed creation declines before any byte moves.
    fn take(&self) -> Option<PooledPipe> {
        if let Some(pipe) = lock_recover(&self.free).pop() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(pipe);
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        let units = self.fd_budget.try_acquire(UNITS_SPLICE_DIRECTION)?;
        let pair = match PipePair::new() {
            Ok(pair) => pair,
            Err(_) => return None,
        };
        Some(PooledPipe {
            pair,
            _units: units,
        })
    }

    /// Returns a drained pipe to the pool, or discards it.
    ///
    /// A pipe that still holds unread bytes is never recycled: Go applies the
    /// same rule in `putPipe`. A returned pipe beyond the keep count is closed
    /// (its units release with it), which bounds idle retention.
    fn give_back(&self, pipe: PooledPipe) {
        let dirty = rr_linux::socket::pending_input(pipe.pair.read_fd())
            .map(|queued| queued > 0)
            .unwrap_or(true);
        if dirty {
            self.stats.discards.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut free = lock_recover(&self.free);
        if free.len() < self.keep {
            free.push(pipe);
        } else {
            self.stats.shrinks.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> PipePoolSnapshot {
        let free = lock_recover(&self.free);
        let pending_bytes = free.iter().try_fold(0_u64, |total, pipe| {
            total.checked_add(rr_linux::socket::pending_input(pipe.pair.read_fd()).ok()? as u64)
        });
        PipePoolSnapshot {
            retained_capacity: self.keep as u64,
            retained_pairs: free.len() as u64,
            pending_bytes,
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            discards: self.stats.discards.load(Ordering::Relaxed),
            downgrades: self.stats.downgrades.load(Ordering::Relaxed),
            shrinks: self.stats.shrinks.load(Ordering::Relaxed),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct SplicePool {
    permits: Arc<Semaphore>,
    fd_budget: FdBudget,
    pipes: Option<PipePool>,
}

#[cfg(target_os = "linux")]
impl SplicePool {
    fn new(max_relays: u32, fd_budget: FdBudget, pipe_pool: Option<(bool, u32)>) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(
                usize::try_from(max_relays).unwrap_or(usize::MAX),
            )),
            pipes: pipe_pool.and_then(|(enabled, keep)| {
                enabled.then(|| PipePool::new(keep, fd_budget.clone()))
            }),
            fd_budget,
        }
    }

    /// Attempts one splice relay, reserving descriptors before creating them.
    ///
    /// The production trace reached `pipe2(...) = -1 EMFILE` because two pipe
    /// pairs — four descriptors — were created with no reservation at all. The
    /// four units are acquired *before* `pipe2`, and the permit is owned by the
    /// same object as the pipes, so every completion, error and cancellation
    /// path releases it.
    ///
    /// Declining is safe here because it happens before any byte is
    /// transferred: the caller falls through to the buffered backend without
    /// replaying anything.
    fn reserve_descriptors(&self) -> Option<FdPermit> {
        self.fd_budget.try_acquire(UNITS_SPLICE_RELAY)
    }

    async fn try_relay(
        &self,
        inbound: &TcpStream,
        outbound: &TcpStream,
        ledger: &TransferLedger,
        write_stall: Option<Duration>,
        source_reset_is_eof: bool,
    ) -> io::Result<Option<()>> {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        if let Some(pool) = &self.pipes {
            let result = self
                .try_relay_pooled(
                    pool,
                    inbound,
                    outbound,
                    ledger,
                    write_stall,
                    source_reset_is_eof,
                )
                .await;
            drop(permit);
            return result;
        }
        let Some(fd_permit) = self.reserve_descriptors() else {
            return Ok(None);
        };
        let pipes = match SplicePipes::new(fd_permit) {
            Ok(pipes) => pipes,
            Err(_) => return Ok(None),
        };
        for pipe in [&pipes.uplink, &pipes.downlink] {
            if pipe.capacity() < SPLICE_PIPE_CAPACITY {
                ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity());
            }
        }
        let _permit = permit;
        let uplink = splice_direction(
            inbound,
            outbound,
            &pipes.uplink,
            pipes.uplink.capacity(),
            ledger,
            true,
            write_stall,
            source_reset_is_eof,
        );
        let downlink = splice_direction(
            outbound,
            inbound,
            &pipes.downlink,
            pipes.downlink.capacity(),
            ledger,
            false,
            write_stall,
            source_reset_is_eof,
        );
        tokio::try_join!(uplink, downlink)?;
        Ok(Some(()))
    }

    /// Runs one bilateral relay on pooled pipes and returns both afterwards.
    #[cfg(target_os = "linux")]
    async fn try_relay_pooled(
        &self,
        pool: &PipePool,
        inbound: &TcpStream,
        outbound: &TcpStream,
        ledger: &TransferLedger,
        write_stall: Option<Duration>,
        source_reset_is_eof: bool,
    ) -> io::Result<Option<()>> {
        let Some(uplink_pipe) = pool.take() else {
            return Ok(None);
        };
        let Some(downlink_pipe) = pool.take() else {
            pool.give_back(uplink_pipe);
            return Ok(None);
        };
        for pipe in [&uplink_pipe.pair, &downlink_pipe.pair] {
            if pipe.capacity() < SPLICE_PIPE_CAPACITY {
                ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity());
                pool.stats.downgrades.fetch_add(1, Ordering::Relaxed);
            }
        }
        let result = {
            let uplink = splice_direction(
                inbound,
                outbound,
                &uplink_pipe.pair,
                uplink_pipe.pair.capacity(),
                ledger,
                true,
                write_stall,
                source_reset_is_eof,
            );
            let downlink = splice_direction(
                outbound,
                inbound,
                &downlink_pipe.pair,
                downlink_pipe.pair.capacity(),
                ledger,
                false,
                write_stall,
                source_reset_is_eof,
            );
            tokio::try_join!(uplink, downlink)
        };
        pool.give_back(uplink_pipe);
        pool.give_back(downlink_pipe);
        result?;
        Ok(Some(()))
    }

    /// Attempts one single-direction splice relay: one permit, two descriptor
    /// units, one pipe pair.
    ///
    /// Every decline happens before any byte moves — pool exhausted, descriptor
    /// budget denied, or `pipe2` failed — so the caller falls through to the
    /// buffered backend without replaying anything.
    async fn try_relay_direction(
        &self,
        source: &mut OwnedReadHalf,
        destination: &mut OwnedWriteHalf,
        direction: RelayDirection,
        ledger: &TransferLedger,
        write_stall: Option<Duration>,
    ) -> io::Result<Option<()>> {
        let Ok(_permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        if let Some(pool) = &self.pipes {
            let Some(pooled) = pool.take() else {
                return Ok(None);
            };
            let pipe = &pooled.pair;
            if pipe.capacity() < SPLICE_PIPE_CAPACITY {
                ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity());
                pool.stats.downgrades.fetch_add(1, Ordering::Relaxed);
            }
            let result = splice_owned_direction(
                source,
                destination,
                pipe,
                pipe.capacity(),
                ledger,
                direction.is_inbound_to_outbound(),
                write_stall,
            )
            .await;
            pool.give_back(pooled);
            result?;
            return Ok(Some(()));
        }
        let Some(fd_permit) = self.fd_budget.try_acquire(UNITS_SPLICE_DIRECTION) else {
            return Ok(None);
        };
        // The permit binds before the pipe exists: locals drop in reverse
        // declaration order, so the pipe closes first and its two units are
        // released only afterwards — the budget never shows capacity for a
        // descriptor that is still open. A pipe2 failure drops the permit
        // with nothing created.
        let _fd_permit = fd_permit;
        let pipe = match PipePair::new() {
            Ok(pipe) => pipe,
            Err(_) => return Ok(None),
        };
        if pipe.capacity() < SPLICE_PIPE_CAPACITY {
            ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity());
        }
        splice_owned_direction(
            source,
            destination,
            &pipe,
            pipe.capacity(),
            ledger,
            direction.is_inbound_to_outbound(),
            write_stall,
        )
        .await?;
        Ok(Some(()))
    }
}

/// Two pipe pairs and the four descriptor units that account for them.
///
/// The permit lives in the same object as the descriptors, so it cannot outlive
/// them and cannot be forgotten on an error path.
#[cfg(target_os = "linux")]
struct SplicePipes {
    uplink: PipePair,
    downlink: PipePair,
    _fd_permit: FdPermit,
}

#[cfg(target_os = "linux")]
impl SplicePipes {
    fn new(fd_permit: FdPermit) -> io::Result<Self> {
        // If the second pair fails, the first is dropped by `?` — closing its
        // two descriptors — and `fd_permit` is dropped with it, releasing all
        // four units. Releasing two units that were never spent is the
        // conservative direction: the reservation outlived nothing.
        Ok(Self {
            uplink: PipePair::new()?,
            downlink: PipePair::new()?,
            _fd_permit: fd_permit,
        })
    }
}

#[cfg(target_os = "linux")]
struct PipePair {
    inner: rr_linux::pipe::NonblockingPipe,
}

/// Target pipe capacity for splice relays.
///
/// A splice call is availability-limited, not chunk-limited, so a larger pipe
/// only helps when the kernel has more than the default 64 KiB ready — exactly
/// the sustained-stream case where splice call rate dominates. Measured on the
/// loopback reference workload, sustained senders keep 250–500 KiB queued:
/// 512 KiB halves the splice syscall rate and server CPU per GiB against
/// 256 KiB, while 1 MiB showed no further gain. 512 KiB stays at or below the
/// default 1 MiB unprivileged `pipe-max-size`.
#[cfg(target_os = "linux")]
const SPLICE_PIPE_CAPACITY: usize = 512 * 1024;

#[cfg(target_os = "linux")]
impl PipePair {
    fn new() -> io::Result<Self> {
        rr_linux::pipe::NonblockingPipe::open(SPLICE_PIPE_CAPACITY, SPLICE_PIPE_CAPACITY / 4)
            .map(|inner| Self { inner })
            .map_err(io::Error::from)
    }

    fn read_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.read_fd()
    }
    fn write_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.write_fd()
    }
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per splice direction input"
)]
async fn splice_direction(
    source: &TcpStream,
    destination: &TcpStream,
    pipe: &PipePair,
    chunk_bytes: usize,
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    write_stall: Option<Duration>,
    source_reset_is_eof: bool,
) -> io::Result<()> {
    splice_pump(
        source,
        destination,
        pipe,
        chunk_bytes,
        ledger,
        inbound_to_outbound,
        write_stall,
        source_reset_is_eof,
    )
    .await?;
    rr_linux::socket::shutdown_write(destination)
        .map_err(io::Error::from)
        .or_else(|error| {
            if source_reset_is_eof && is_peer_gone(&error) {
                Ok(())
            } else {
                Err(error)
            }
        })
}

/// Splices one direction between owned socket halves until source EOF.
///
/// The halves share their sockets' existing reactor registrations, so
/// readiness comes from the streams behind them (`AsRef<TcpStream>`) rather
/// than from new `AsyncFd` registrations, which would fail with a duplicate
/// epoll entry. Source EOF gracefully shuts down the destination write side
/// through the owned half; the peer direction is unaffected.
#[cfg(target_os = "linux")]
async fn splice_owned_direction(
    source: &mut OwnedReadHalf,
    destination: &mut OwnedWriteHalf,
    pipe: &PipePair,
    chunk_bytes: usize,
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    write_stall: Option<Duration>,
) -> io::Result<()> {
    splice_pump(
        source.as_ref(),
        destination.as_ref(),
        pipe,
        chunk_bytes,
        ledger,
        inbound_to_outbound,
        write_stall,
        false,
    )
    .await?;
    destination.shutdown().await
}

/// Moves bytes source -> pipe -> destination until source EOF.
///
/// Every transferred byte is recorded in the shared ledger only after the
/// destination accepted it, so a byte is never claimed before it moved.
///
/// With `write_stall` set, one idle window is armed per chunk and shared by that
/// chunk's splice-in and splice-out steps: steady progress never times out,
/// while a stalled peer ends the direction with [`io::ErrorKind::TimedOut`]
/// instead of parking on its pipes and permits forever. `None` keeps the
/// unbounded behavior and constructs no timer at all.
///
/// With `source_reset_is_eof`, a source reset ends the direction like an EOF;
/// see [`RelayContext::source_reset_is_eof`].
#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per splice pump input"
)]
async fn splice_pump(
    source: &TcpStream,
    destination: &TcpStream,
    pipe: &PipePair,
    chunk_bytes: usize,
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    write_stall: Option<Duration>,
    source_reset_is_eof: bool,
) -> io::Result<()> {
    use tokio::io::Interest;

    let mut idle = write_stall.map(|_| IdleDeadline::new());
    loop {
        let read = source
            .async_io(Interest::READABLE, || {
                rr_linux::pipe::splice_nonblocking(source, pipe.write_fd(), chunk_bytes)
                    .map_err(io::Error::from)
            })
            .await;
        let read = match read {
            Ok(read) => read,
            Err(error) if source_reset_is_eof && is_peer_reset(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Ok(());
        }

        ledger.progress(read);
        let mut pending = read;
        while pending != 0 {
            if let (Some(idle), Some(window)) = (&mut idle, write_stall) {
                idle.reset(window).map_err(idle_io_error)?;
            }
            let written = match &mut idle {
                Some(idle) => idle
                    .guard(destination.async_io(Interest::WRITABLE, || {
                        rr_linux::pipe::splice_nonblocking(pipe.read_fd(), destination, pending)
                            .map_err(io::Error::from)
                    }))
                    .await
                    .map_err(idle_io_error)?,
                None => {
                    destination
                        .async_io(Interest::WRITABLE, || {
                            rr_linux::pipe::splice_nonblocking(pipe.read_fd(), destination, pending)
                                .map_err(io::Error::from)
                        })
                        .await?
                }
            };
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice destination accepted zero bytes",
                ));
            }
            pending = pending.saturating_sub(written);
            record(ledger, inbound_to_outbound, written)?;
        }
    }
}

#[cfg(test)]
mod tests;
