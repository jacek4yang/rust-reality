use std::{
    error::Error,
    fmt, io,
    os::fd::AsRawFd as _,
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

use crate::{
    config::RelayPolicy,
    protocol::reality::tls13::{IdleDeadline, IdleError},
    runtime::FdBudget,
};

#[cfg(target_os = "linux")]
use crate::runtime::{FdPermit, UNITS_SPLICE_DIRECTION, UNITS_SPLICE_RELAY};

use super::{
    backend::{
        BackendCapability, BackendDeclineReason, BackendReport, BackendRequest, BackendRun,
        DirectionalRelayOutcome, RelayBackend, RelayContext, RelayDirection, RelayOutcome,
        TransferLedger,
    },
    relay::RelayStats,
};

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

impl TcpRelay {
    /// Compiles immutable relay policy and pre-reserves all pool metadata.
    ///
    /// # Errors
    ///
    /// Returns an allocation error before any listener is bound.
    pub fn new(policy: &RelayPolicy, fd_budget: FdBudget) -> Result<Self, TcpRelayConfigError> {
        let buffers = BufferPool::new(policy.buffer_bytes, policy.max_pooled_buffers)?;
        #[cfg(target_os = "linux")]
        let splice = policy.splice.then(|| {
            SplicePool::new(
                policy.max_splice_relays,
                fd_budget.clone(),
                Some((policy.pipe_pool, policy.max_pooled_pipes)),
            )
        });
        let report = BackendReport {
            buffered: BackendCapability::available(),
            splice: splice_capability(policy),
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
        mut inbound: TcpStream,
        mut outbound: TcpStream,
        context: RelayContext,
    ) -> io::Result<RelayOutcome> {
        self.run(&mut inbound, &mut outbound, context).await
    }

    /// Relays one plaintext TCP pair through borrowed sockets.
    ///
    /// This compatibility entry point exists for call sites that cannot yield
    /// complete ownership yet. Backends that require a complete descriptor
    /// decline here rather than weakening any invariant.
    ///
    /// # Errors
    ///
    /// Returns allocation, socket, pipe, or shutdown errors.
    pub async fn relay_borrowed(
        &self,
        inbound: &mut TcpStream,
        outbound: &mut TcpStream,
        context: RelayContext,
    ) -> io::Result<RelayOutcome> {
        let context = RelayContext {
            owns_complete_sockets: false,
            ..context
        };
        self.run(inbound, outbound, context).await
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
    /// # Errors
    ///
    /// Returns allocation, socket, pipe, or shutdown errors. A backend error
    /// after transfer starts terminates the relay and is never replayed through
    /// another backend. With `liveness` set, a direction that moves no byte for
    /// that long fails with [`io::ErrorKind::TimedOut`].
    pub async fn relay_direction(
        &self,
        mut source: OwnedReadHalf,
        mut destination: OwnedWriteHalf,
        direction: RelayDirection,
        request: BackendRequest,
        liveness: Option<Duration>,
    ) -> io::Result<DirectionalRelayOutcome> {
        let order = directional_selection_order(request);
        let mut last_decline = BackendDeclineReason::Disabled;
        for backend in order {
            let ledger = TransferLedger::new();
            let attempt = DirectionalAttempt {
                direction,
                liveness,
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
                    let _ignored = rr_linux::socket::abort_linger(source.as_ref().as_raw_fd());
                    let _ignored = rr_linux::socket::abort_linger(destination.as_ref().as_raw_fd());
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
            liveness,
            ledger,
            started,
        } = *attempt;
        match backend {
            RelayBackend::Buffered => {
                self.buffers
                    .relay_direction(source, destination, direction, ledger, liveness)
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
            liveness,
            ledger,
            started,
        } = *attempt;
        let Some(splice) = &self.splice else {
            return ledger.decline(BackendDeclineReason::Disabled);
        };
        match splice
            .try_relay_direction(source, destination, direction, ledger, liveness)
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
            let ledger = TransferLedger::new();
            let started = Instant::now();
            let run = self
                .run_backend(*backend, inbound, outbound, context, &ledger, started)
                .await;
            let run = match run {
                Err(error) if !ledger.is_untouched() => {
                    // True abort: the peer must observe a reset, not a clean
                    // short EOF. Pre-first-byte declines never reach here.
                    let _ignored = rr_linux::socket::abort_linger(inbound.as_raw_fd());
                    let _ignored = rr_linux::socket::abort_linger(outbound.as_raw_fd());
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
        context: RelayContext,
        ledger: &TransferLedger,
        started: Instant,
    ) -> io::Result<BackendRun> {
        match backend {
            RelayBackend::Buffered => {
                self.buffers
                    .relay(inbound, outbound, ledger, context.liveness)
                    .await?;
                Ok(ledger.complete(RelayBackend::Buffered, started.elapsed()))
            }
            RelayBackend::Splice => {
                self.run_splice(inbound, outbound, ledger, started, context.liveness)
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
        liveness: Option<Duration>,
    ) -> io::Result<BackendRun> {
        let Some(splice) = &self.splice else {
            return ledger.decline(BackendDeclineReason::Disabled);
        };
        match splice
            .try_relay(inbound, outbound, ledger, liveness)
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
        _liveness: Option<Duration>,
    ) -> io::Result<BackendRun> {
        ledger.decline(BackendDeclineReason::UnsupportedOperatingSystem)
    }

    /// Relays one plaintext TCP pair while preserving both half-close directions.
    ///
    /// # Errors
    ///
    /// Returns allocation, socket, pipe, or shutdown errors. A splice error after
    /// transfer starts is never retried through userspace because byte ownership
    /// can no longer be reconstructed safely.
    pub async fn relay(
        &self,
        inbound: &mut TcpStream,
        outbound: &mut TcpStream,
    ) -> io::Result<RelayStats> {
        let outcome = self
            .relay_borrowed(inbound, outbound, RelayContext::borrowed())
            .await?;
        Ok(RelayStats::new(
            outcome.inbound_to_outbound(),
            outcome.outbound_to_inbound(),
        ))
    }
}

/// One directional backend attempt: the direction, its idle liveness bound,
/// the shared transfer ledger, and the attempt's start instant.
///
/// Bundling these keeps the directional runners inside the repository's
/// argument-count lint without hiding anything.
#[derive(Clone, Copy)]
struct DirectionalAttempt<'a> {
    direction: RelayDirection,
    liveness: Option<Duration>,
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

/// Reclassifies a liveness timeout that truncated a live transfer.
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

fn splice_capability(policy: &RelayPolicy) -> BackendCapability {
    if !cfg!(target_os = "linux") {
        return BackendCapability::declined(
            policy.splice,
            BackendDeclineReason::UnsupportedOperatingSystem,
        );
    }
    if policy.splice {
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
        liveness: Option<Duration>,
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
            liveness,
        );
        let downlink = copy_direction(
            outbound_reader,
            inbound_writer,
            outbound_buffer,
            ledger,
            false,
            liveness,
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
        liveness: Option<Duration>,
    ) -> io::Result<()> {
        let mut lease = self.acquire_single().await?;
        let buffer = lease.buffer_mut()?;
        copy_direction(
            source,
            destination,
            buffer,
            ledger,
            direction.is_inbound_to_outbound(),
            liveness,
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
/// With `liveness` set, one idle window is armed per chunk and shared by that
/// chunk's read and write: steady progress never times out, while a peer that
/// stalls for the whole window ends the direction with
/// [`io::ErrorKind::TimedOut`] instead of parking on its permit forever.
/// `None` keeps the unbounded behavior and constructs no timer at all.
async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer: &mut [u8],
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    liveness: Option<Duration>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut idle = liveness.map(|_| IdleDeadline::new());
    loop {
        let read = match (&mut idle, liveness) {
            (Some(idle), Some(window)) => {
                idle.reset(window).map_err(idle_io_error)?;
                idle.read(&mut reader, buffer)
                    .await
                    .map_err(idle_io_error)?
            }
            _ => reader.read(buffer).await?,
        };
        if read == 0 {
            match &mut idle {
                Some(idle) => idle.shutdown(&mut writer).await.map_err(idle_io_error)?,
                None => writer.shutdown().await?,
            }
            return Ok(());
        }
        let payload = buffer
            .get(..read)
            .ok_or_else(|| io::Error::other("TCP relay read exceeded its buffer"))?;
        match &mut idle {
            Some(idle) => idle
                .write_all(&mut writer, payload)
                .await
                .map_err(idle_io_error)?,
            None => writer.write_all(payload).await?,
        }
        record(ledger, inbound_to_outbound, read)?;
    }
}

/// Maps an idle-guard failure back to the relay's `io::Error` surface.
fn idle_io_error(error: IdleError) -> io::Error {
    match error {
        IdleError::Timeout => io::Error::new(io::ErrorKind::TimedOut, "raw relay idle timeout"),
        IdleError::Io(error) => error,
    }
}

fn record(ledger: &TransferLedger, inbound_to_outbound: bool, bytes: usize) -> io::Result<()> {
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
        let dirty = rr_linux::socket::pending_input(pipe.pair.read.as_raw_fd())
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
        PipePoolSnapshot {
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
                usize::try_from(max_relays).map_or(usize::MAX, |value| value),
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
        liveness: Option<Duration>,
    ) -> io::Result<Option<()>> {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        if let Some(pool) = &self.pipes {
            let result = self
                .try_relay_pooled(pool, inbound, outbound, ledger, liveness)
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
            if pipe.capacity < SPLICE_PIPE_CAPACITY {
                ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity);
            }
        }
        let _permit = permit;
        let uplink = splice_direction(
            inbound,
            outbound,
            &pipes.uplink,
            pipes.uplink.capacity,
            ledger,
            true,
            liveness,
        );
        let downlink = splice_direction(
            outbound,
            inbound,
            &pipes.downlink,
            pipes.downlink.capacity,
            ledger,
            false,
            liveness,
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
        liveness: Option<Duration>,
    ) -> io::Result<Option<()>> {
        let Some(uplink_pipe) = pool.take() else {
            return Ok(None);
        };
        let Some(downlink_pipe) = pool.take() else {
            pool.give_back(uplink_pipe);
            return Ok(None);
        };
        for pipe in [&uplink_pipe.pair, &downlink_pipe.pair] {
            if pipe.capacity < SPLICE_PIPE_CAPACITY {
                ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity);
                pool.stats.downgrades.fetch_add(1, Ordering::Relaxed);
            }
        }
        let result = {
            let uplink = splice_direction(
                inbound,
                outbound,
                &uplink_pipe.pair,
                uplink_pipe.pair.capacity,
                ledger,
                true,
                liveness,
            );
            let downlink = splice_direction(
                outbound,
                inbound,
                &downlink_pipe.pair,
                downlink_pipe.pair.capacity,
                ledger,
                false,
                liveness,
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
        liveness: Option<Duration>,
    ) -> io::Result<Option<()>> {
        let Ok(_permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        if let Some(pool) = &self.pipes {
            let Some(pooled) = pool.take() else {
                return Ok(None);
            };
            let pipe = &pooled.pair;
            if pipe.capacity < SPLICE_PIPE_CAPACITY {
                ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity);
                pool.stats.downgrades.fetch_add(1, Ordering::Relaxed);
            }
            let result = splice_owned_direction(
                source,
                destination,
                pipe,
                pipe.capacity,
                ledger,
                direction.is_inbound_to_outbound(),
                liveness,
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
        if pipe.capacity < SPLICE_PIPE_CAPACITY {
            ledger.note_pipe_downgrade(SPLICE_PIPE_CAPACITY, pipe.capacity);
        }
        splice_owned_direction(
            source,
            destination,
            &pipe,
            pipe.capacity,
            ledger,
            direction.is_inbound_to_outbound(),
            liveness,
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
    read: rustix::fd::OwnedFd,
    write: rustix::fd::OwnedFd,
    capacity: usize,
}

/// Target pipe capacity for splice relays.
///
/// A splice call is availability-limited, not chunk-limited, so a larger pipe
/// only helps when the kernel has more than the default 64 KiB ready — exactly
/// the sustained-stream case where splice call rate dominates. 256 KiB stays
/// below the default 1 MiB unprivileged `pipe-max-size`.
#[cfg(target_os = "linux")]
const SPLICE_PIPE_CAPACITY: usize = 256 * 1024;

#[cfg(target_os = "linux")]
impl PipePair {
    fn new() -> io::Result<Self> {
        let (read, write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .map_err(io::Error::from)?;
        // Best effort: a host that refuses the raise keeps the default
        // capacity, and the relay remains correct with the smaller chunk.
        let capacity = rustix::pipe::fcntl_setpipe_size(&write, SPLICE_PIPE_CAPACITY)
            .or_else(|_| rustix::pipe::fcntl_getpipe_size(&write))
            .unwrap_or(SPLICE_PIPE_CAPACITY / 4);
        Ok(Self {
            read,
            write,
            capacity,
        })
    }
}

#[cfg(target_os = "linux")]
async fn splice_direction(
    source: &TcpStream,
    destination: &TcpStream,
    pipe: &PipePair,
    chunk_bytes: usize,
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    liveness: Option<Duration>,
) -> io::Result<()> {
    splice_pump(
        source,
        destination,
        pipe,
        chunk_bytes,
        ledger,
        inbound_to_outbound,
        liveness,
    )
    .await?;
    rustix::net::shutdown(destination, rustix::net::Shutdown::Write).map_err(io::Error::from)?;
    Ok(())
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
    liveness: Option<Duration>,
) -> io::Result<()> {
    splice_pump(
        source.as_ref(),
        destination.as_ref(),
        pipe,
        chunk_bytes,
        ledger,
        inbound_to_outbound,
        liveness,
    )
    .await?;
    destination.shutdown().await
}

/// Moves bytes source -> pipe -> destination until source EOF.
///
/// Every transferred byte is recorded in the shared ledger only after the
/// destination accepted it, so a byte is never claimed before it moved.
///
/// With `liveness` set, one idle window is armed per chunk and shared by that
/// chunk's splice-in and splice-out steps: steady progress never times out,
/// while a stalled peer ends the direction with [`io::ErrorKind::TimedOut`]
/// instead of parking on its pipes and permits forever. `None` keeps the
/// unbounded behavior and constructs no timer at all.
#[cfg(target_os = "linux")]
async fn splice_pump(
    source: &TcpStream,
    destination: &TcpStream,
    pipe: &PipePair,
    chunk_bytes: usize,
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
    liveness: Option<Duration>,
) -> io::Result<()> {
    use tokio::io::Interest;

    let flags = rustix::pipe::SpliceFlags::MOVE | rustix::pipe::SpliceFlags::NONBLOCK;
    let mut idle = liveness.map(|_| IdleDeadline::new());
    loop {
        if let (Some(idle), Some(window)) = (&mut idle, liveness) {
            idle.reset(window).map_err(idle_io_error)?;
        }
        let read = match &mut idle {
            Some(idle) => idle
                .guard(source.async_io(Interest::READABLE, || {
                    splice_retry(source, &pipe.write, chunk_bytes, flags)
                }))
                .await
                .map_err(idle_io_error)?,
            None => {
                source
                    .async_io(Interest::READABLE, || {
                        splice_retry(source, &pipe.write, chunk_bytes, flags)
                    })
                    .await?
            }
        };
        if read == 0 {
            return Ok(());
        }

        let mut pending = read;
        while pending != 0 {
            let written = match &mut idle {
                Some(idle) => idle
                    .guard(destination.async_io(Interest::WRITABLE, || {
                        splice_retry(&pipe.read, destination, pending, flags)
                    }))
                    .await
                    .map_err(idle_io_error)?,
                None => {
                    destination
                        .async_io(Interest::WRITABLE, || {
                            splice_retry(&pipe.read, destination, pending, flags)
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

#[cfg(target_os = "linux")]
fn splice_retry<FdIn, FdOut>(
    input: FdIn,
    output: FdOut,
    length: usize,
    flags: rustix::pipe::SpliceFlags,
) -> io::Result<usize>
where
    FdIn: std::os::fd::AsFd + Copy,
    FdOut: std::os::fd::AsFd + Copy,
{
    loop {
        match rustix::pipe::splice(input, None, output, None, length, flags) {
            Ok(transferred) => return Ok(transferred),
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, os::fd::AsRawFd as _, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time,
    };

    use super::TcpRelay;
    use crate::{
        config::RelayPolicy,
        runtime::FdBudget,
        transport::{
            BackendRequest, DirectionalRelayOutcome, RelayBackend, RelayContext, RelayDirection,
        },
    };

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_buffered_relay_preserves_half_close() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                buffer_bytes: 4 * 1024,
                max_pooled_buffers: 2,
                max_splice_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            FdBudget::new(4_096),
        )
        .expect("relay policy must compile");
        exercise_tcp_relay(relay).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn nonblocking_splice_relay_preserves_half_close() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                buffer_bytes: 32 * 1024,
                max_pooled_buffers: 2,
                max_splice_relays: 1,
                max_relay_memory_bytes: u64::MAX,
                splice: true,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            FdBudget::new(4_096),
        )
        .expect("relay policy must compile");
        exercise_tcp_relay(relay).await;
    }

    async fn exercise_tcp_relay(relay: TcpRelay) {
        let (mut client, mut relay_inbound) = tcp_pair().await;
        let (mut relay_outbound, mut target) = tcp_pair().await;
        let operation = async {
            let relay_io = relay.relay(&mut relay_inbound, &mut relay_outbound);
            let client_io = async {
                client.write_all(b"request").await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let target_io = async {
                let mut request = Vec::new();
                target.read_to_end(&mut request).await?;
                target.write_all(b"response").await?;
                target.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(relay_io, client_io, target_io)
        };
        let (stats, response, request) = time::timeout(Duration::from_secs(2), operation)
            .await
            .expect("relay must complete");
        let stats = stats.expect("relay must succeed");
        assert_eq!(request.expect("target I/O must succeed"), b"request");
        assert_eq!(response.expect("client I/O must succeed"), b"response");
        assert_eq!(stats.inbound_to_outbound_bytes(), 7);
        assert_eq!(stats.outbound_to_inbound_bytes(), 8);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_splice_relay_reserves_four_descriptor_units_before_creating_pipes() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        assert_eq!(budget.in_use(), 0);

        let (mut client, mut relay_inbound) = tcp_pair().await;
        let (mut relay_outbound, mut target) = tcp_pair().await;
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sampler = {
            let budget = budget.clone();
            let observed = std::sync::Arc::clone(&observed);
            async move {
                for _ in 0..512 {
                    observed.fetch_max(budget.in_use(), std::sync::atomic::Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        };
        let exchange = async {
            let relay_io = relay.relay(&mut relay_inbound, &mut relay_outbound);
            let client_io = async {
                client.write_all(b"request").await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let target_io = async {
                let mut request = Vec::new();
                target.read_to_end(&mut request).await?;
                target.write_all(b"response").await?;
                target.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(relay_io, client_io, target_io)
        };
        let (result, _sampled) = time::timeout(Duration::from_secs(5), async {
            tokio::join!(exchange, sampler)
        })
        .await
        .expect("relay must complete");
        result.0.expect("splice relay must succeed");

        assert_eq!(
            observed.load(std::sync::atomic::Ordering::Relaxed),
            u64::from(crate::runtime::UNITS_SPLICE_RELAY),
            "a bidirectional splice relay uses two pipe pairs, all four accounted"
        );
        assert!(
            budget.in_use() <= u64::from(crate::runtime::UNITS_SPLICE_RELAY),
            "after completion the pool may retain drained pipes within its keep count"
        );
        drop(relay);
        assert_eq!(
            budget.in_use(),
            0,
            "dropping the relay (and its pool) releases every pipe descriptor unit"
        );
        assert_eq!(budget.underflows(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn splice_declines_to_buffered_when_descriptors_are_exhausted() {
        // Three units cannot satisfy the four a splice relay requires, so the
        // backend must decline *before* `pipe2` and fall through.
        let budget = FdBudget::new(3);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        let (mut client, mut relay_inbound) = tcp_pair().await;
        let (mut relay_outbound, mut target) = tcp_pair().await;
        let exchange = async {
            let relay_io = relay.relay(&mut relay_inbound, &mut relay_outbound);
            let client_io = async {
                client.write_all(b"request").await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let target_io = async {
                let mut request = Vec::new();
                target.read_to_end(&mut request).await?;
                target.write_all(b"response").await?;
                target.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(relay_io, client_io, target_io)
        };
        let (stats, response, request) = time::timeout(Duration::from_secs(5), exchange)
            .await
            .expect("relay must complete");
        let stats = stats.expect("the buffered backend must carry the connection");
        assert_eq!(request.expect("target I/O must succeed"), b"request");
        assert_eq!(response.expect("client I/O must succeed"), b"response");
        assert_eq!(stats.inbound_to_outbound_bytes(), 7);
        assert!(
            budget.in_use() <= u64::from(crate::runtime::UNITS_SPLICE_DIRECTION),
            "a declined attempt may retain one drained pipe in the pool"
        );
        drop(relay);
        assert_eq!(
            budget.in_use(),
            0,
            "dropping the relay (and its pool) releases everything"
        );
        assert!(
            budget.denials() >= 1,
            "the decline must be recorded as a descriptor denial, not hidden"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn repeated_splice_relays_return_descriptor_units_to_baseline() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        for _ in 0..16 {
            let (mut client, mut relay_inbound) = tcp_pair().await;
            let (mut relay_outbound, mut target) = tcp_pair().await;
            let exchange = async {
                let relay_io = relay.relay(&mut relay_inbound, &mut relay_outbound);
                let client_io = async {
                    client.write_all(b"request").await?;
                    client.shutdown().await?;
                    let mut response = Vec::new();
                    client.read_to_end(&mut response).await?;
                    Ok::<_, io::Error>(response)
                };
                let target_io = async {
                    let mut request = Vec::new();
                    target.read_to_end(&mut request).await?;
                    target.write_all(b"response").await?;
                    target.shutdown().await?;
                    Ok::<_, io::Error>(request)
                };
                tokio::join!(relay_io, client_io, target_io)
            };
            let (stats, _, _) = time::timeout(Duration::from_secs(5), exchange)
                .await
                .expect("relay must complete");
            stats.expect("relay must succeed");
            assert!(
                budget.in_use() <= u64::from(crate::runtime::UNITS_SPLICE_RELAY),
                "each cycle's pool retention stays within two pipe pairs"
            );
        }
        drop(relay);
        assert_eq!(
            budget.in_use(),
            0,
            "dropping the relay (and its pool) returns the counter to baseline"
        );
        assert_eq!(budget.underflows(), 0);
        assert!(budget.peak_in_use() <= u64::from(crate::runtime::UNITS_SPLICE_RELAY));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_cancelled_splice_relay_releases_its_descriptor_units() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        let (_client, mut relay_inbound) = tcp_pair().await;
        let (mut relay_outbound, _target) = tcp_pair().await;
        // Neither peer sends or closes, so the relay parks with its pipes open.
        let cancelled = time::timeout(
            Duration::from_millis(50),
            relay.relay(&mut relay_inbound, &mut relay_outbound),
        )
        .await;
        assert!(cancelled.is_err(), "the relay must still be running");
        assert_eq!(
            budget.in_use(),
            0,
            "cancellation must release pipe descriptors and their permit"
        );
        assert_eq!(budget.underflows(), 0);
    }

    #[cfg(target_os = "linux")]
    fn splice_policy() -> RelayPolicy {
        RelayPolicy {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 4,
            max_splice_relays: 8,
            max_relay_memory_bytes: u64::MAX,
            splice: true,
            pipe_pool: true,
            max_pooled_pipes: 8,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_aborted_relay_resets_the_surviving_peer() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                splice: false,
                ..RelayPolicy::default()
            },
            FdBudget::new(4_096),
        )
        .expect("relay must build");
        let payload = vec![0x5a_u8; 256 * 1024];
        let (mut source_peer, relay_inbound) = tcp_pair().await;
        let (relay_outbound, mut sink_peer) = tcp_pair().await;
        let relaying = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
        let drive = async {
            time::timeout(Duration::from_secs(5), source_peer.write_all(&payload))
                .await
                .expect("source write must not stall")
                .expect("source write must succeed");
            // The sink receives part of the payload, then resets mid-transfer.
            let mut received = vec![0_u8; payload.len() / 2];
            time::timeout(Duration::from_secs(5), sink_peer.read_exact(&mut received))
                .await
                .expect("the first half must not stall")
                .expect("the first half must arrive");
            rr_linux::socket::abort_linger(std::os::fd::AsRawFd::as_raw_fd(&sink_peer))
                .expect("abort linger must apply");
            drop(sink_peer);
        };
        let (relay_result, ()) = tokio::join!(relaying, drive);
        let _ignored = relay_result;

        let mut byte = [0_u8; 1];
        let mut attempts = 0_usize;
        let error = loop {
            match source_peer.try_read(&mut byte) {
                Ok(read) => panic!("the surviving peer must not read cleanly ({read})"),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break error,
                Err(_) if attempts < 200 => {
                    attempts += 1;
                    time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("expected ConnectionReset, got {error}"),
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn an_aborted_splice_relay_resets_the_surviving_peer() {
        let relay =
            TcpRelay::new(&RelayPolicy::default(), FdBudget::new(4_096)).expect("relay must build");
        let payload = vec![0x5a_u8; 256 * 1024];
        let (mut source_peer, relay_inbound) = tcp_pair().await;
        let (relay_outbound, mut sink_peer) = tcp_pair().await;
        let relaying = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
        let drive = async {
            time::timeout(Duration::from_secs(5), source_peer.write_all(&payload))
                .await
                .expect("source write must not stall")
                .expect("source write must succeed");
            let mut received = vec![0_u8; payload.len() / 2];
            time::timeout(Duration::from_secs(5), sink_peer.read_exact(&mut received))
                .await
                .expect("the first half must not stall")
                .expect("the first half must arrive");
            rr_linux::socket::abort_linger(std::os::fd::AsRawFd::as_raw_fd(&sink_peer))
                .expect("abort linger must apply");
            drop(sink_peer);
        };
        let (relay_result, ()) = tokio::join!(relaying, drive);
        let _ignored = relay_result;

        let mut byte = [0_u8; 1];
        let mut attempts = 0_usize;
        let error = loop {
            match source_peer.try_read(&mut byte) {
                Ok(read) => panic!("the surviving peer must not read cleanly ({read})"),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => break error,
                Err(_) if attempts < 200 => {
                    attempts += 1;
                    time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => panic!("expected ConnectionReset, got {error}"),
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_graceful_relay_close_is_a_clean_eof_without_abort_marks() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                splice: false,
                ..RelayPolicy::default()
            },
            FdBudget::new(4_096),
        )
        .expect("relay must build");
        let payload = vec![0x5a_u8; 64 * 1024];
        let (mut source_peer, relay_inbound) = tcp_pair().await;
        let (relay_outbound, mut sink_peer) = tcp_pair().await;
        let relaying = relay.relay_owned(relay_inbound, relay_outbound, RelayContext::owned());
        let source_io = async {
            source_peer.write_all(&payload).await?;
            source_peer.shutdown().await?;
            Ok::<_, io::Error>(())
        };
        let sink_io = async {
            let mut received = Vec::new();
            sink_peer.read_to_end(&mut received).await?;
            sink_peer.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        let (outcome, source_result, received) = tokio::join!(relaying, source_io, sink_io);
        outcome.expect("a graceful relay must succeed");
        source_result.expect("source I/O must succeed");
        assert_eq!(
            received.expect("sink I/O must succeed"),
            payload,
            "a graceful relay must deliver every byte"
        );
        let mut byte = [0_u8; 1];
        let read = source_peer
            .read(&mut byte)
            .await
            .expect("the post-close read must succeed");
        assert_eq!(read, 0, "a graceful close must read as a clean EOF");
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("address must exist"));
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(client, accept);
        (
            client.expect("client must connect"),
            accepted.expect("server must accept").0,
        )
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_pool_hit_reuses_the_same_pipe_without_syscalls() {
        let budget = FdBudget::new(4_096);
        let pool = super::PipePool::new(8, budget.clone());

        let first = pool.take().expect("first take must create a pipe");
        let first_read_fd = first.pair.read.as_raw_fd();
        let baseline = budget.in_use();
        pool.give_back(first);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.hits, 0);

        let second = pool.take().expect("second take must be a pool hit");
        assert_eq!(
            second.pair.read.as_raw_fd(),
            first_read_fd,
            "a pool hit must return the exact same pipe without pipe2"
        );
        assert_eq!(pool.snapshot().hits, 1);
        assert_eq!(budget.in_use(), baseline, "a hit acquires nothing new");
        drop(second);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_dirty_pipe_is_discarded_never_recycled() {
        let budget = FdBudget::new(4_096);
        let pool = super::PipePool::new(8, budget);
        let pipe = pool.take().expect("take must create a pipe");
        // Poison the pipe with an unread byte: it must never come back.
        rustix::io::write(&pipe.pair.write, b"x").expect("poison write");
        pool.give_back(pipe);

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.discards, 1);
        assert_eq!(snapshot.hits, 0, "nothing returned to the free list");
        let fresh = pool.take().expect("the discard forces a fresh pipe");
        assert_eq!(
            pool.snapshot().misses,
            2,
            "a dirty pipe must never be recycled into a session"
        );
        drop(fresh);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn the_pool_shrinks_past_its_keep_count_and_releases_units() {
        let budget = FdBudget::new(4_096);
        let pool = super::PipePool::new(1, budget.clone());
        let baseline = budget.in_use();

        let one = pool.take().expect("first pipe");
        let two = pool.take().expect("second pipe");
        let in_flight = budget.in_use();
        assert!(
            in_flight > baseline,
            "both pipes are accounted while in flight"
        );
        pool.give_back(one);
        assert_eq!(pool.snapshot().shrinks, 0, "the first return fits the keep");
        pool.give_back(two);
        assert_eq!(pool.snapshot().shrinks, 1, "the second return shrinks");
        assert_eq!(
            budget.in_use(),
            in_flight - u64::from(crate::runtime::UNITS_SPLICE_DIRECTION),
            "the shrunk pipe releases its units"
        );
        drop(pool);
        assert_eq!(
            budget.in_use(),
            baseline,
            "draining the pool returns every descriptor unit"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn pooled_splice_relays_are_byte_exact_and_reuse_pipes() {
        let relay =
            TcpRelay::new(&splice_policy(), FdBudget::new(4_096)).expect("relay must compile");
        let payload = vec![0x5a_u8; 64 * 1024];
        for round in 0..3 {
            let (outcome, received) = run_one_direction(
                &relay,
                RelayDirection::Downlink,
                BackendRequest::Explicit(RelayBackend::Splice),
                &payload,
            )
            .await;
            let outcome = outcome.expect("directional relay must succeed");
            assert_eq!(received, payload, "round {round} must be byte exact");
            assert_eq!(outcome.backend(), RelayBackend::Splice);
        }
        let stats = relay
            .pipe_pool_stats()
            .expect("the default policy enables the pool");
        assert!(
            stats.hits >= 2,
            "repeated relays must hit the pool, stats: {stats:?}"
        );
        assert_eq!(stats.discards, 0, "clean relays never discard pipes");
    }

    /// Drives one owned-half directional relay over loopback.
    ///
    /// The receiver's `read_to_end` only terminates when the relay propagates
    /// the source EOF as a destination write-side shutdown, so every test
    /// through this helper also proves the half-close semantics.
    async fn run_one_direction(
        relay: &TcpRelay,
        direction: RelayDirection,
        request: BackendRequest,
        payload: &[u8],
    ) -> (io::Result<DirectionalRelayOutcome>, Vec<u8>) {
        let (mut sender, relay_source) = tcp_pair().await;
        let (relay_sink, mut receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = relay_source.into_split();
        let (_sink_reader, sink_writer) = relay_sink.into_split();
        let exchange = async {
            let relay_io =
                relay.relay_direction(source_reader, sink_writer, direction, request, None);
            let sender_io = async {
                sender.write_all(payload).await?;
                sender.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let receiver_io = async {
                let mut received = Vec::new();
                receiver.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(relay_io, sender_io, receiver_io)
        };
        let (outcome, sent, received) = time::timeout(Duration::from_secs(5), exchange)
            .await
            .expect("directional relay must complete");
        sent.expect("sender I/O must succeed");
        (outcome, received.expect("receiver I/O must succeed"))
    }

    fn directional_payload() -> Vec<u8> {
        (0..300_000_u32).map(|value| value as u8).collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn directional_buffered_relay_is_byte_exact_in_both_directions() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                buffer_bytes: 4 * 1024,
                max_pooled_buffers: 2,
                max_splice_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            FdBudget::new(4_096),
        )
        .expect("relay policy must compile");
        let payload = directional_payload();

        for direction in [RelayDirection::Uplink, RelayDirection::Downlink] {
            let (outcome, received) =
                run_one_direction(&relay, direction, BackendRequest::Automatic, &payload).await;
            let outcome = outcome.expect("directional relay must succeed");
            assert_eq!(received, payload, "{direction} bytes must arrive in order");
            assert_eq!(
                outcome.bytes(),
                u64::try_from(payload.len()).unwrap_or(u64::MAX)
            );
            assert_eq!(outcome.backend(), RelayBackend::Buffered);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn directional_splice_relay_is_byte_exact_in_both_directions() {
        let relay = TcpRelay::new(&splice_policy(), FdBudget::new(4_096))
            .expect("relay policy must compile");
        let payload = directional_payload();

        for direction in [RelayDirection::Uplink, RelayDirection::Downlink] {
            let (outcome, received) =
                run_one_direction(&relay, direction, BackendRequest::Automatic, &payload).await;
            let outcome = outcome.expect("directional splice relay must succeed");
            assert_eq!(received, payload, "{direction} bytes must arrive in order");
            assert_eq!(
                outcome.bytes(),
                u64::try_from(payload.len()).unwrap_or(u64::MAX)
            );
            assert_eq!(outcome.backend(), RelayBackend::Splice);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_directional_splice_relay_reserves_two_descriptor_units() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        assert_eq!(budget.in_use(), 0);

        let payload = directional_payload();
        let (outcome, received) = run_one_direction(
            &relay,
            RelayDirection::Uplink,
            BackendRequest::Automatic,
            &payload,
        )
        .await;
        let outcome = outcome.expect("directional splice relay must succeed");
        assert_eq!(outcome.backend(), RelayBackend::Splice);
        assert_eq!(received.len(), payload.len());
        assert_eq!(
            budget.peak_in_use(),
            u64::from(crate::runtime::UNITS_SPLICE_DIRECTION),
            "one pipe pair is exactly two descriptor units"
        );
        assert!(
            budget.in_use() <= u64::from(crate::runtime::UNITS_SPLICE_DIRECTION),
            "after completion the pool may retain the drained pipe within its keep count"
        );
        drop(relay);
        assert_eq!(
            budget.in_use(),
            0,
            "dropping the relay (and its pool) releases the pipe descriptors and permit"
        );
        assert_eq!(budget.underflows(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn repeated_directional_splice_relays_return_descriptor_units_to_baseline() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        for cycle in 0..8 {
            let (outcome, _) = run_one_direction(
                &relay,
                RelayDirection::Downlink,
                BackendRequest::Automatic,
                b"x",
            )
            .await;
            outcome.expect("directional relay must succeed");
            assert!(
                budget.in_use() <= u64::from(crate::runtime::UNITS_SPLICE_DIRECTION),
                "cycle {cycle}: pool retention stays within one pipe pair"
            );
        }
        drop(relay);
        assert_eq!(
            budget.in_use(),
            0,
            "dropping the relay (and its pool) returns the counter to baseline"
        );
        assert_eq!(budget.underflows(), 0);
        assert!(budget.peak_in_use() <= u64::from(crate::runtime::UNITS_SPLICE_DIRECTION));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn directional_splice_declines_to_buffered_with_bytes_intact() {
        // One unit cannot satisfy the two a directional splice relay requires,
        // so the backend must decline *before* `pipe2` and fall through.
        let budget = FdBudget::new(1);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        let payload = directional_payload();

        let (outcome, received) = run_one_direction(
            &relay,
            RelayDirection::Uplink,
            BackendRequest::Automatic,
            &payload,
        )
        .await;
        let outcome = outcome.expect("the buffered backend must carry the direction");
        assert_eq!(received, payload);
        assert_eq!(outcome.backend(), RelayBackend::Buffered);
        assert_eq!(
            outcome.bytes(),
            u64::try_from(payload.len()).unwrap_or(u64::MAX)
        );
        assert_eq!(budget.in_use(), 0);
        assert!(
            budget.denials() >= 1,
            "the decline must be recorded as a descriptor denial, not hidden"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn an_explicit_buffered_directional_request_bypasses_splice() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        let payload = directional_payload();

        let (outcome, received) = run_one_direction(
            &relay,
            RelayDirection::Uplink,
            BackendRequest::Explicit(RelayBackend::Buffered),
            &payload,
        )
        .await;
        let outcome = outcome.expect("explicit buffered direction must succeed");
        assert_eq!(received, payload);
        assert_eq!(outcome.backend(), RelayBackend::Buffered);
        assert_eq!(
            budget.peak_in_use(),
            0,
            "a buffered direction never reserves splice descriptors"
        );
    }

    /// Drives one directional relay against a peer that sends a prefix and
    /// then stalls without ever closing, returning the relay's error.
    ///
    /// The prefix touches the transfer ledger, so the liveness timeout is a
    /// true abort: RST on both sockets and `ConnectionAborted`, never the
    /// clean `TimedOut` an untouched direction produces.
    async fn run_stalled_direction(
        relay: &TcpRelay,
        request: BackendRequest,
        liveness: Duration,
    ) -> io::Error {
        let (mut sender, relay_source) = tcp_pair().await;
        let (relay_sink, _receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = relay_source.into_split();
        let (_sink_reader, sink_writer) = relay_sink.into_split();
        sender
            .write_all(b"partial")
            .await
            .expect("the prefix must land");
        let outcome = time::timeout(
            Duration::from_secs(2),
            relay.relay_direction(
                source_reader,
                sink_writer,
                RelayDirection::Uplink,
                request,
                Some(liveness),
            ),
        )
        .await
        .expect("a stalled peer must end the relay well within two seconds");
        drop(sender);
        outcome.expect_err("a stalled peer must fail the relay")
    }

    /// Asserts that a mid-transfer liveness abort reports `ConnectionAborted`
    /// while preserving the original `TimedOut` as its payload.
    fn assert_timeout_abort(error: &io::Error) {
        assert_eq!(
            error.kind(),
            io::ErrorKind::ConnectionAborted,
            "a timeout that truncated a live transfer is an abort, not a clean close"
        );
        let payload = error
            .get_ref()
            .and_then(|payload| payload.downcast_ref::<io::Error>())
            .expect("the abort must preserve the original error as its payload");
        assert_eq!(payload.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_idle_direction_without_any_byte_stays_a_clean_timeout() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                buffer_bytes: 4 * 1024,
                max_pooled_buffers: 2,
                max_splice_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            FdBudget::new(4_096),
        )
        .expect("relay policy must compile");
        let (_sender, relay_source) = tcp_pair().await;
        let (relay_sink, _receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = relay_source.into_split();
        let (_sink_reader, sink_writer) = relay_sink.into_split();

        let outcome = time::timeout(
            Duration::from_secs(2),
            relay.relay_direction(
                source_reader,
                sink_writer,
                RelayDirection::Uplink,
                BackendRequest::Explicit(RelayBackend::Buffered),
                Some(Duration::from_millis(200)),
            ),
        )
        .await
        .expect("an idle direction must end well within two seconds");
        let error = outcome.expect_err("an idle direction must fail the relay");
        assert_eq!(
            error.kind(),
            io::ErrorKind::TimedOut,
            "an untouched ledger means nothing was truncated: the timeout stays clean"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_directional_buffered_relay_times_out_and_returns_its_permit() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                buffer_bytes: 4 * 1024,
                max_pooled_buffers: 2,
                max_splice_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                splice: false,
                pipe_pool: true,
                max_pooled_pipes: 8,
            },
            FdBudget::new(4_096),
        )
        .expect("relay policy must compile");

        let error = run_stalled_direction(
            &relay,
            BackendRequest::Explicit(RelayBackend::Buffered),
            Duration::from_millis(200),
        )
        .await;
        assert_timeout_abort(&error);
        assert_eq!(
            relay.buffers.inner.permits.available_permits(),
            2,
            "the stalled direction's buffer permit must return to the pool"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_directional_splice_relay_times_out_and_returns_its_units() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");

        let error = run_stalled_direction(
            &relay,
            BackendRequest::Explicit(RelayBackend::Splice),
            Duration::from_millis(200),
        )
        .await;
        assert_timeout_abort(&error);
        assert!(
            budget.in_use() <= u64::from(crate::runtime::UNITS_SPLICE_DIRECTION),
            "on the timeout path the drained pipe may be retained within the keep count"
        );
        drop(relay);
        assert_eq!(
            budget.in_use(),
            0,
            "dropping the relay (and its pool) releases everything on the timeout path"
        );
        assert_eq!(budget.underflows(), 0);
    }

    /// Drives one directional relay whose peer makes steady progress for
    /// longer than three liveness windows, then half-closes.
    async fn run_active_direction(
        relay: &TcpRelay,
        request: BackendRequest,
        liveness: Duration,
    ) -> (io::Result<DirectionalRelayOutcome>, Vec<u8>) {
        let (mut sender, relay_source) = tcp_pair().await;
        let (relay_sink, mut receiver) = tcp_pair().await;
        let (source_reader, _source_writer) = relay_source.into_split();
        let (_sink_reader, sink_writer) = relay_sink.into_split();
        let exchange = async {
            let relay_io = relay.relay_direction(
                source_reader,
                sink_writer,
                RelayDirection::Uplink,
                request,
                Some(liveness),
            );
            let sender_io = async {
                for chunk in 0..8_u8 {
                    sender.write_all(&[chunk; 256]).await?;
                    time::sleep(liveness / 2).await;
                }
                sender.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let receiver_io = async {
                let mut received = Vec::new();
                receiver.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            tokio::join!(relay_io, sender_io, receiver_io)
        };
        let (outcome, sent, received) = time::timeout(Duration::from_secs(5), exchange)
            .await
            .expect("an active directional relay must complete");
        sent.expect("sender I/O must succeed");
        (outcome, received.expect("receiver I/O must succeed"))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn an_active_directional_relay_never_times_out_across_many_windows() {
        let relay =
            TcpRelay::new(&splice_policy(), FdBudget::new(4_096)).expect("relay must compile");
        let liveness = Duration::from_millis(200);
        let expected: Vec<u8> = (0..8_u8).flat_map(|chunk| [chunk; 256]).collect();

        for backend in [RelayBackend::Splice, RelayBackend::Buffered] {
            let (outcome, received) =
                run_active_direction(&relay, BackendRequest::Explicit(backend), liveness).await;
            let outcome = outcome.expect("steady progress must never time out");
            assert_eq!(received, expected, "{backend} bytes must arrive in order");
            assert_eq!(
                outcome.bytes(),
                u64::try_from(expected.len()).unwrap_or(u64::MAX)
            );
            assert_eq!(outcome.backend(), backend);
            assert!(
                outcome.duration() > 3 * liveness,
                "the transfer must span several liveness windows"
            );
        }
    }
}
